// Package engine is git-enc's core: it finds every secret, works out what
// state each is in, and carries out add, update and merge.
//
// The state of a secret F comes from four facts:
//
//	P     the plaintext F in the worktree (its sha256)
//	E     the decrypted worktree F.enc (the sha256 of its secret)
//	base  the last committed version P was known to equal (see package state)
//	index whether git has F.enc unmerged (a merge or rebase conflict)
//
// and the rules, checked in this order, are:
//
//	unmerged stages          merging   (git enc merge)
//	no F.enc, P present      new       (git enc add)
//	no key for the block     no-key    (git enc key add)
//	no P                     missing   (git enc update)
//	P == E                   clean
//	P == base                outdated  (git enc update)
//	E == base                modified  (git enc add)
//	otherwise                conflict  (git enc update writes F.incoming)
//
// When the base is unknown (no state yet, or its blob is no longer in
// history), git-enc looks for P among every committed version of F.enc; if
// P is one of them the copy is outdated, and if not the secret is diverged
// and git-enc refuses to guess.
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"
	"github.com/shreeve/git-enc/internal/envelope"
	"github.com/shreeve/git-enc/internal/fsx"
	"github.com/shreeve/git-enc/internal/gitx"
	"github.com/shreeve/git-enc/internal/keys"
	"github.com/shreeve/git-enc/internal/spec"
	"github.com/shreeve/git-enc/internal/state"
)

// Kind is a secret's state.
type Kind string

const (
	Clean    Kind = "clean"
	Modified Kind = "modified"
	Outdated Kind = "outdated"
	Conflict Kind = "conflict"
	Diverged Kind = "diverged"
	Merging  Kind = "merging"
	New      Kind = "new"
	Missing  Kind = "missing"
	NoKey    Kind = "no-key"
	Corrupt  Kind = "corrupt"
	Orphaned Kind = "orphaned"
)

// Secret is one secret and everything known about it.
type Secret struct {
	Path    string
	EncPath string
	Block   *spec.Block
	Key     *keys.Key
	Kind    Kind
	Message string // why it is in this state
	Action  string // the command that moves it forward

	plain     []byte // nil if absent (or unreadable: see plainErr)
	plainErr  error  // the plaintext is there but cannot be read
	PlainHash string
	EncBlob   string // worktree F.enc blob id, "" if absent
	EncHash   string // sha256 of the secret in the worktree F.enc
	encBody   []byte
	HeadBlob  string
	IndexBlob string         // stage 0
	Unmerged  map[int]string // stage -> blob
	Staged    bool           // F.enc in the index differs from HEAD
	EncDirty  bool           // worktree F.enc differs from the index
	Incoming  string         // path of F.incoming, if present
	// EncDeleted: F.enc is gone from the worktree but git still has it;
	// EncBlob then names git's copy, so a deleted .enc cannot make an old
	// plaintext look new.
	EncDeleted   bool
	PlainTracked bool // git tracks the plaintext itself
	NotIgnored   bool // git does not ignore the plaintext (a `!` rule)
	PlainIgnored bool // git's ignore rules match the plaintext (tracked or not)
	EncIgnored   bool // git's ignore rules match F.enc, so it can't be committed
	// Skipped: no-key, for a key enc.skipKeys says this user does not hold
	// on purpose (another group's block). It is listed but asks for nothing.
	Skipped bool
	entry   *state.Entry
}

// Problem is something wrong that is not tied to one secret's state.
type Problem struct {
	Code    string `json:"code"`
	Path    string `json:"path,omitempty"`
	Line    int    `json:"line,omitempty"`
	Message string `json:"message"`
	Action  string `json:"action,omitempty"`
}

// Engine is an open repository.
type Engine struct {
	Repo     *gitx.Repo
	Spec     *spec.Spec
	Keys     *keys.Store
	State    *state.State
	Cache    *state.Cache
	Secrets  []*Secret
	Problems []Problem

	ignoreCase bool
	lock       *state.Lock
	baseDir    string                 // per-worktree git-enc dir
	ignored    map[string]bool        // paths git ignores, from this scan's one check-ignore
	shared     map[*spec.Block]string // blocks whose key another block uses too
}

// Open opens the repository at dir, takes the git-enc lock, and scans it.
func Open(dir string) (*Engine, error) { return open(dir, true, false) }

// OpenStatus opens the repository for a command that only reports (status,
// check, diff): it takes the lock if it is free, to save what it learns,
// and otherwise scans without saving rather than wait for another git-enc.
func OpenStatus(dir string) (*Engine, error) { return open(dir, false, true) }

// OpenReadOnly scans without taking the lock or saving anything, for hooks:
// they must work (and the pre-commit guard must hold) even while another
// git-enc runs or after one was killed holding the lock.
func OpenReadOnly(dir string) (*Engine, error) { return open(dir, false, false) }

func open(dir string, write, try bool) (*Engine, error) {
	repo, err := gitx.Open(dir)
	if err != nil {
		return nil, err
	}
	e := &Engine{Repo: repo, ignoreCase: repo.ConfigBool("core.ignorecase", false)}
	if e.baseDir, err = repo.GitPath("git-enc"); err != nil {
		return nil, err
	}
	common := filepath.Join(repo.CommonDir, "git-enc")
	fail := func(err error) (*Engine, error) {
		if e.lock != nil {
			e.lock.Release()
		}
		return nil, err
	}
	switch {
	case write:
		if e.lock, err = state.Acquire(filepath.Join(e.baseDir, "lock")); err != nil {
			return nil, err
		}
	case try && !repo.Rebasing():
		// Mid-rebase, what it would learn (a commit about to be rewritten
		// as committed) would not hold once the rebase ends: read only.
		if e.lock, err = state.TryAcquire(filepath.Join(e.baseDir, "lock")); err != nil {
			return nil, err
		}
	}
	if e.State, err = state.Load(filepath.Join(e.baseDir, "state")); err != nil {
		return fail(err)
	}
	e.Cache = state.LoadCache(filepath.Join(common, "cache"))
	if e.Keys, err = keys.Load(); err != nil {
		return fail(err)
	}
	if e.lock != nil {
		// Before anything is written: keep temporary files out of commits.
		if err := e.syncExclude(); err != nil {
			return fail(err)
		}
	}
	if err := e.Scan(); err != nil {
		return fail(err)
	}
	return e, nil
}

// Close saves state and releases the lock (read-only engines save nothing).
func (e *Engine) Close() error {
	if e.lock == nil {
		return nil
	}
	defer e.lock.Release()
	e.Cache.Save()
	if err := e.State.Save(); err != nil {
		return err
	}
	return e.syncExclude()
}

// Secret returns the secret at path, or nil.
func (e *Engine) Secret(path string) *Secret {
	for _, s := range e.Secrets {
		if s.Path == path {
			return s
		}
	}
	return nil
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Scan reads .gitignore and the repository and classifies every secret.
func (e *Engine) Scan() error {
	e.Secrets, e.Problems = nil, nil
	data, err := os.ReadFile(filepath.Join(e.Repo.Root, ".gitignore"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var probs []spec.Problem
	e.Spec, probs = spec.Parse(data, e.ignoreCase)
	for _, p := range probs {
		e.Problems = append(e.Problems, Problem{Code: "gitignore", Path: ".gitignore", Line: p.Line, Message: p.Msg})
	}
	e.findSharedKeys()

	paths, err := e.candidates()
	if err != nil {
		return err
	}
	byPath := map[string]*Secret{}
	for _, p := range paths {
		if err := spec.CheckPath(p); err != nil {
			e.Problems = append(e.Problems, Problem{Code: "unsafe-path", Path: p, Message: err.Error()})
			continue
		}
		if err := fsx.CheckInside(e.Repo.Root, p); err != nil {
			e.Problems = append(e.Problems, Problem{Code: "unsafe-path", Path: p, Message: err.Error()})
			continue
		}
		b, _, err := e.Spec.Match(p)
		if err != nil {
			e.Problems = append(e.Problems, Problem{Code: "two-blocks", Path: p, Message: err.Error()})
			continue
		}
		if b == nil && !e.managed(p) {
			continue // an unrelated *.enc file
		}
		byPath[p] = &Secret{Path: p, EncPath: p + ".enc", Block: b, entry: e.State.Get(p), Unmerged: map[int]string{}}
	}
	for _, s := range byPath {
		e.Secrets = append(e.Secrets, s)
	}
	sort.Slice(e.Secrets, func(i, j int) bool { return e.Secrets[i].Path < e.Secrets[j].Path })

	if err := e.readIndex(); err != nil {
		return err
	}
	if err := e.readFiles(); err != nil {
		return err
	}
	if err := e.promote(); err != nil {
		return err
	}
	if err := e.classify(); err != nil {
		return err
	}
	skip := e.SkippedKeys()
	for _, s := range e.Secrets {
		s.Skipped = s.Kind == NoKey && s.Key == nil && s.Block != nil && skip[s.Block.Key]
	}
	kept := e.Secrets[:0]
	for _, s := range e.Secrets {
		if s.Kind != "" {
			kept = append(kept, s)
		}
	}
	e.Secrets = kept
	return nil
}

// findSharedKeys marks blocks that use the same key as another block. Each
// block has its own key; two sharing one means .gitignore was changed to
// point one group's secrets at another group's key, so git-enc encrypts
// and writes nothing for either until it is fixed.
func (e *Engine) findSharedKeys() {
	e.shared = map[*spec.Block]string{}
	first := map[string]*spec.Block{}
	for _, b := range e.Spec.Blocks {
		ids := []string{"name " + b.Key}
		if b.Fingerprint != "" {
			ids = append(ids, "fingerprint "+b.Fingerprint)
		}
		for _, id := range ids {
			o := first[id]
			if o == nil {
				first[id] = b
				continue
			}
			msg := fmt.Sprintf("the git-enc blocks at .gitignore lines %d and %d use the same key (%s); each block needs its own key. If you did not do this, someone changed .gitignore: check `git log -p .gitignore`", o.Start, b.Start, id)
			e.shared[o], e.shared[b] = msg, msg
			e.Problems = append(e.Problems, Problem{Code: "shared-key", Path: ".gitignore", Line: b.Start, Message: msg})
			break
		}
	}
}

// SkippedKeys are the key names in enc.skipKeys (separated by spaces or
// commas): blocks whose key this user does not hold on purpose, such as
// another group's secrets, or a CI job's.
func (e *Engine) SkippedKeys() map[string]bool {
	res := map[string]bool{}
	for _, k := range strings.FieldsFunc(e.Repo.ConfigString("enc.skipKeys"), func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		res[k] = true
	}
	return res
}

func (e *Engine) managed(p string) bool {
	for _, m := range e.State.Managed {
		if m == p {
			return true
		}
	}
	_, ok := e.State.Secrets[p]
	return ok
}

// candidates lists every path that might be a secret: names of *.enc files
// git knows about, plaintext files the blocks match, and paths git-enc has
// managed before. A pattern for any directory (`.env`) does not reach into
// a directory git ignores anyway (a fixture .env under node_modules/): its
// .enc could never be committed. A path a pattern names explicitly
// (`/build/*.yml`) is kept, so an ignored directory is reported.
func (e *Engine) candidates() ([]string, error) {
	set := map[string]bool{}
	var maybe []string // kept unless inside an ignored directory
	encs, err := e.Repo.Git("ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "*.enc")
	if err != nil {
		return nil, err
	}
	for _, p := range gitx.SplitZ(encs) {
		if name := strings.TrimSuffix(p, ".enc"); name != p && name != "" && !strings.HasSuffix(name, "/") {
			set[name] = true
		}
	}
	// Blocks hold no `!` rules, so every block's patterns can go in one
	// call: a path matches the union exactly when it matches one block.
	var globs []string
	for _, b := range e.Spec.Blocks {
		for _, p := range b.Patterns {
			if lit := p.Literal(); lit != "" {
				if fi, err := os.Lstat(e.Repo.Abs(lit)); err == nil && !fi.IsDir() {
					set[lit] = true
				}
				continue
			}
			globs = append(globs, "--exclude="+spec.TrimTrailingSpace(p.Raw))
		}
	}
	if len(globs) > 0 {
		// git itself decides which files the patterns match: untracked
		// ones ("?"), and tracked ones (plaintext committed before it was
		// listed), in one call told apart by -t.
		args := append([]string{"ls-files", "-z", "-t", "--cached", "--others", "--ignored"}, globs...)
		out, err := e.Repo.Git(args...)
		if err != nil {
			return nil, err
		}
		for _, rec := range gitx.SplitZ(out) {
			tag, p, ok := strings.Cut(rec, " ")
			if !ok {
				continue
			}
			switch {
			case strings.HasSuffix(p, ".enc"), strings.HasSuffix(p, ".incoming"):
			case tag == "?" && !e.Spec.Anchored(p):
				maybe = append(maybe, p)
			default:
				set[p] = true
			}
		}
	}
	maybe = append(maybe, e.State.Managed...)
	for p := range e.State.Secrets {
		maybe = append(maybe, p)
	}
	if err := e.dropIgnoredDirs(maybe, set); err != nil {
		return nil, err
	}
	var out []string
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

// dropIgnoredDirs adds each path to set unless git ignores a directory
// above it, or it already is there. The one check-ignore it runs also
// answers, for checkIgnores, whether git ignores each candidate and its
// .enc.
func (e *Engine) dropIgnoredDirs(paths []string, set map[string]bool) error {
	seen := map[string]bool{}
	var list []string
	// git refuses the whole call for a path beneath a symlink, so those
	// are not asked about (no secret can be there: Scan refuses them).
	ask := func(p string) {
		if !seen[p] && e.askable(p) {
			seen[p] = true
			list = append(list, p)
		}
	}
	for _, p := range paths {
		if d := path.Dir(p); d != "." {
			ask(d)
		}
	}
	for _, group := range [][]string{paths, setKeys(set)} {
		for _, p := range group {
			if spec.CheckPath(p) == nil {
				ask(p)
				ask(p + ".enc")
			}
		}
	}
	// git reports a directory inside an ignored one as ignored too.
	ignored, err := e.checkIgnore(list)
	if err != nil {
		return err
	}
	e.ignored = ignored
	for _, p := range paths {
		if !ignored[path.Dir(p)] {
			set[p] = true
		}
	}
	return nil
}

// askable reports whether git can be asked about rel: no directory above
// it is a symlink (or not a directory at all).
func (e *Engine) askable(rel string) bool {
	d := path.Dir(rel)
	if d == "." {
		return true
	}
	cur := e.Repo.Root
	for _, c := range strings.Split(d, "/") {
		cur = filepath.Join(cur, c)
		fi, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			return true
		}
		if err != nil || !fi.IsDir() {
			return false
		}
	}
	return true
}

func setKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	return out
}

// readIndex fills in the index and HEAD blobs of every F.enc.
func (e *Engine) readIndex() error {
	if len(e.Secrets) == 0 {
		return nil
	}
	enc := map[string]*Secret{}
	plain := map[string]*Secret{}
	var pathspec []string
	for _, s := range e.Secrets {
		enc[s.EncPath] = s
		plain[s.Path] = s
		pathspec = append(pathspec, ":(literal)"+s.EncPath)
	}
	for _, s := range e.Secrets {
		pathspec = append(pathspec, ":(literal)"+s.Path)
	}
	// One call for both: whether git tracks each plaintext, and each
	// F.enc's index entries.
	out, err := e.Repo.Git(append([]string{"ls-files", "-z", "--stage", "--"}, pathspec...)...)
	if err != nil {
		return err
	}
	for _, rec := range gitx.SplitZ(out) {
		// "mode blob stage\tpath"
		tab := strings.IndexByte(rec, '\t')
		if tab < 0 {
			continue
		}
		f := strings.Fields(rec[:tab])
		if s := plain[rec[tab+1:]]; s != nil {
			s.PlainTracked = true
		}
		s := enc[rec[tab+1:]]
		if s == nil || len(f) != 3 {
			continue
		}
		if f[2] == "0" {
			s.IndexBlob = f[1]
		} else {
			s.Unmerged[int(f[2][0]-'0')] = f[1]
		}
	}
	if e.Repo.HasHead() {
		out, err := e.Repo.Git(append([]string{"ls-tree", "-r", "-z", "--full-tree", "HEAD", "--"}, pathspec[:len(e.Secrets)]...)...)
		if err != nil {
			return err
		}
		for _, rec := range gitx.SplitZ(out) {
			tab := strings.IndexByte(rec, '\t')
			if tab < 0 {
				continue
			}
			f := strings.Fields(rec[:tab])
			if s := enc[rec[tab+1:]]; s != nil && len(f) == 3 {
				s.HeadBlob = f[2]
			}
		}
	}
	return nil
}

// readFiles reads each plaintext and decrypts each worktree F.enc.
func (e *Engine) readFiles() error {
	var encPaths []string
	var withEnc []*Secret
	for _, s := range e.Secrets {
		s.Key = e.blockKey(s.Block)
		plain, err := fsx.ReadRegular(e.Repo.Root, s.Path)
		if err != nil {
			s.plainErr = err
			e.Problems = append(e.Problems, Problem{Code: "unsafe-path", Path: s.Path, Message: err.Error()})
		} else if plain != nil {
			s.plain = plain
			s.PlainHash = sum(plain)
		}
		if gitx.Exists(e.Repo.Abs(s.Path + ".incoming")) {
			s.Incoming = s.Path + ".incoming"
		}
		if fi, err := os.Lstat(e.Repo.Abs(s.EncPath)); err == nil && fi.Mode().IsRegular() {
			encPaths = append(encPaths, s.EncPath)
			withEnc = append(withEnc, s)
		}
	}
	ids, err := e.Repo.HashFiles(encPaths)
	if err != nil {
		return err
	}
	for i, s := range withEnc {
		s.EncBlob = ids[i]
	}
	for _, s := range e.Secrets {
		if s.EncBlob == "" && (s.IndexBlob != "" || s.HeadBlob != "") && len(s.Unmerged) == 0 {
			s.EncDeleted = true
			s.EncBlob = s.IndexBlob
			if s.EncBlob == "" {
				s.EncBlob = s.HeadBlob
			}
		}
		if h, ok := e.Cache.Hashes[s.EncBlob]; ok && s.EncBlob != "" {
			s.EncHash = h
		}
	}
	return e.checkIgnores()
}

// checkIgnores uses git's answers to whether every plaintext is
// ignored (it must be: otherwise it can be committed) and every F.enc is
// not (otherwise it can't be).
func (e *Engine) checkIgnores() error {
	if len(e.Secrets) == 0 {
		return nil
	}
	pi, ei := e.ignored, e.ignored // asked with the candidates, in one call
	for _, s := range e.Secrets {
		if s.Block == nil || s.plain == nil && s.EncBlob == "" && !s.PlainTracked {
			continue // nothing there to commit by mistake, or to fail to commit
		}
		s.PlainIgnored, s.EncIgnored = pi[s.Path], ei[s.EncPath]
		if !pi[s.Path] && !s.PlainTracked {
			s.NotIgnored = true
			e.Problems = append(e.Problems, Problem{Code: "not-ignored", Path: s.Path,
				Message: "git does not ignore this secret's plaintext (a `!` rule in a .gitignore?), so it could be committed"})
		}
		if ei[s.EncPath] {
			e.Problems = append(e.Problems, Problem{Code: "enc-ignored", Path: s.EncPath,
				Message: "git ignores this encrypted file, so it can't be committed; add `!*.enc` after the rule that matches it (`git check-ignore -v " + s.EncPath + "` names it; a rule for a whole directory, like `config/`, must become `config/*` first), or narrow that rule"})
		}
		if s.PlainTracked {
			e.Problems = append(e.Problems, Problem{Code: "tracked-plaintext", Path: s.Path,
				Message: "git tracks this secret in plain text", Action: "git enc add " + s.Path})
		}
	}
	return nil
}

// checkIgnore asks git, in one call, which of paths it ignores.
func (e *Engine) checkIgnore(paths []string) (map[string]bool, error) {
	res := map[string]bool{}
	if len(paths) == 0 {
		return res, nil
	}
	out, err := e.Repo.GitIn([]byte(strings.Join(paths, "\x00")+"\x00"), "check-ignore", "-z", "--no-index", "--stdin")
	var ge *gitx.Error
	if err != nil && !(errors.As(err, &ge) && ge.ExitCode() == 1) {
		return nil, err
	}
	for _, p := range gitx.SplitZ(out) {
		res[p] = true
	}
	return res, nil
}

// blockKey returns the key that opens a block's secrets, or nil.
//
// .gitignore is written by everyone who can push, so a block's header only
// selects a key file whose name and fingerprint both match it (a key from
// $GIT_ENC_KEY, which has no name, by fingerprint). Changing the header
// alone can never point a block at another of the user's keys.
func (e *Engine) blockKey(b *spec.Block) *keys.Key {
	if b == nil || e.shared[b] != "" {
		return nil
	}
	if b.Fingerprint == "" {
		return e.Keys.ByName(b.Key)
	}
	for _, k := range e.Keys.Keys {
		if k.Fingerprint == b.Fingerprint && (k.File == "" || k.Name == b.Key) {
			return k
		}
	}
	return nil
}

// body returns the decrypted secret in the worktree F.enc.
func (e *Engine) body(s *Secret) ([]byte, error) {
	if s.encBody != nil {
		return s.encBody, nil
	}
	data, err := e.encData(s)
	if err != nil {
		return nil, err
	}
	body, err := e.open(s, data)
	if err != nil {
		return nil, err
	}
	s.encBody = body
	s.EncHash = sum(body)
	e.Cache.Put(s.EncBlob, s.EncHash)
	return body, nil
}

// encData returns the ciphertext of the worktree F.enc (git's copy when
// the file is deleted).
func (e *Engine) encData(s *Secret) ([]byte, error) {
	var data []byte
	if s.EncDeleted {
		blobs, err := e.Repo.Blobs([]string{s.EncBlob})
		if err != nil {
			return nil, err
		}
		data = blobs[s.EncBlob]
	} else {
		var err error
		if data, err = fsx.ReadRegular(e.Repo.Root, s.EncPath); err != nil {
			return nil, err
		}
	}
	if data == nil {
		return nil, fmt.Errorf("%s does not exist", s.EncPath)
	}
	return data, nil
}

// open decrypts one version of s's ciphertext with its block's key.
func (e *Engine) open(s *Secret, data []byte) ([]byte, error) {
	if s.Key == nil {
		return nil, errNoKey
	}
	_, body, err := envelope.Open(data, s.Path, s.Key.Identity)
	return body, err
}

// sealedBy returns which of the user's keys can open the worktree F.enc
// that the block's key cannot, or nil. It only names the key in a message:
// ciphertext is only ever trusted when its block's key opens it.
func (e *Engine) sealedBy(s *Secret) *keys.Key {
	data, err := e.encData(s)
	if err != nil {
		return nil
	}
	for _, k := range e.Keys.Keys {
		if _, _, err := envelope.Open(data, s.Path, k.Identity); err == nil {
			return k
		}
	}
	return nil
}

var errNoKey = errors.New("no key")

// Refusal is an operation git-enc declines because of a secret's state
// (exit code 3: something needs doing first).
type Refusal struct{ Msg string }

func (r *Refusal) Error() string { return r.Msg }

// KeyError is an operation that needs a key the user doesn't have
// (exit code 4).
type KeyError struct{ Msg string }

func (k *KeyError) Error() string { return k.Msg }

func refuse(format string, a ...any) error { return &Refusal{fmt.Sprintf(format, a...)} }

// hashOf returns the plaintext hash of a committed blob of s, decrypting
// (and caching) as needed. blobs must hold the data if it is not cached.
func (e *Engine) hashOf(s *Secret, blob string, blobs map[string][]byte) (string, error) {
	if h, ok := e.Cache.Hashes[blob]; ok {
		return h, nil
	}
	data, ok := blobs[blob]
	if !ok {
		return "", fmt.Errorf("blob %s is missing", blob)
	}
	body, err := e.open(s, data)
	if err != nil {
		return "", err
	}
	h := sum(body)
	e.Cache.Put(blob, h)
	return h, nil
}

// committed reports which blobs of each secret's F.enc are in shared
// history. It only asks git when a blob is not simply HEAD's.
func (e *Engine) committed(need map[*Secret][]string) (map[*Secret]map[string]bool, error) {
	res := map[*Secret]map[string]bool{}
	var ask []string
	askFor := map[string]*Secret{}
	for s, blobs := range need {
		res[s] = map[string]bool{}
		for _, b := range blobs {
			if b != "" && b == s.HeadBlob {
				res[s][b] = true
			} else if b != "" {
				if askFor[s.EncPath] == nil {
					askFor[s.EncPath] = s
					ask = append(ask, s.EncPath)
				}
			}
		}
	}
	if len(ask) == 0 {
		return res, nil
	}
	// Ask about every secret at once: compare may need the others next,
	// and one `git log` walks history once however many paths it follows.
	for _, s := range e.Secrets {
		if askFor[s.EncPath] == nil {
			ask = append(ask, s.EncPath)
		}
	}
	hist, err := e.Repo.History(ask)
	if err != nil {
		return nil, err
	}
	for p, s := range askFor {
		for b := range hist[p] {
			res[s][b] = true
		}
	}
	return res, nil
}

// promote moves each base forward to the newest committed version the
// plaintext is known to equal:
//   - a version `git enc add` wrote, once it is committed;
//   - the worktree F.enc, once it is committed, if the plaintext equals it.
//
// Both keep the invariant: the base is always committed, so a plaintext
// equal to it can be recovered from git.
func (e *Engine) promote() error {
	need := map[*Secret][]string{}
	for _, s := range e.Secrets {
		if s.Key == nil || len(s.Unmerged) > 0 {
			continue
		}
		if e.lock == nil && !e.differs(s) {
			// Read-only (a hook): nothing is saved, and the base only
			// matters when the plaintext and F.enc differ.
			continue
		}
		if s.entry.Pending != "" {
			need[s] = append(need[s], s.entry.Pending)
		}
		if s.EncBlob != "" && s.plain != nil && s.EncBlob != s.entry.BaseBlob {
			if _, err := e.body(s); err == nil && s.EncHash == s.PlainHash {
				need[s] = append(need[s], s.EncBlob)
			}
		}
	}
	if len(need) == 0 {
		return nil
	}
	com, err := e.committed(need)
	if err != nil {
		return err
	}
	for s, blobs := range need {
		for _, b := range blobs {
			if !com[s][b] {
				continue
			}
			if b == s.entry.Pending {
				// The cache may have been deleted since `git enc add`.
				blobs := map[string][]byte{}
				if _, ok := e.Cache.Hashes[b]; !ok {
					if blobs, err = e.Repo.Blobs([]string{b}); err != nil {
						return err
					}
				}
				if h, err := e.hashOf(s, b, blobs); err == nil {
					s.entry.BaseBlob, s.entry.BaseHash = b, h
				}
				s.entry.Pending = ""
			}
			if b == s.EncBlob && s.EncHash == s.PlainHash {
				s.entry.BaseBlob, s.entry.BaseHash = b, s.EncHash
			}
		}
	}
	return nil
}

// differs reports whether s has a plaintext and a readable F.enc that
// differ: the only case classify consults the base for.
func (e *Engine) differs(s *Secret) bool {
	if s.plain == nil || s.EncBlob == "" || s.Block == nil {
		return false
	}
	_, err := e.body(s)
	return err == nil && s.EncHash != s.PlainHash
}

// classify sets each secret's Kind.
func (e *Engine) classify() error {
	var rebuild []*Secret
	for _, s := range e.Secrets {
		s.Staged = s.IndexBlob != "" && s.IndexBlob != s.HeadBlob
		s.EncDirty = s.EncBlob != "" && s.IndexBlob != "" && s.EncBlob != s.IndexBlob
		if s.plain != nil || s.EncBlob != "" {
			e.State.Manage(s.Path)
		}
		switch {
		case s.Block == nil:
			if s.plain == nil && s.EncBlob == "" {
				delete(e.State.Secrets, s.Path)
				continue // nothing left to report
			}
			s.set(Orphaned, "no longer listed in a git-enc block of .gitignore; declare it again with `git enc add "+s.Path+"`, or delete it", "git enc add "+s.Path)
			if s.EncBlob != "" {
				s.Message = "no longer listed in a git-enc block, but " + s.EncPath + " still exists; declare it again with `git enc add " + s.Path + "`, or delete both"
			}
			continue
		case len(s.Unmerged) > 0:
			s.set(Merging, "git has a merge conflict on "+s.EncPath, "git enc merge "+s.Path)
			continue
		case s.plainErr != nil:
			// Never "missing": update would write over what may be an edit.
			s.set(Corrupt, "cannot read "+s.Path+" ("+s.plainErr.Error()+"); git-enc will not touch it until it can", "")
			continue
		case s.EncBlob == "":
			if s.plain == nil {
				continue // declared, but there is nothing yet
			}
			s.set(New, "not encrypted yet", "git enc add "+s.Path)
			continue
		case s.Key == nil:
			s.set(NoKey, e.noKeyMessage(s.Block), "git enc key add "+s.Block.Key)
			continue
		}
		defer func(s *Secret) {
			if s.EncDeleted && strings.Contains(s.Message, " is deleted; ") {
				return
			}
			if s.EncDeleted && s.Message != "" {
				s.Message += " (" + s.EncPath + " is deleted in the worktree; `git enc update` restores it)"
			} else if s.EncDeleted {
				s.Message = s.EncPath + " is deleted in the worktree; `git enc update` restores it"
			}
		}(s)
		if _, err := e.body(s); err != nil {
			if errors.Is(err, envelope.ErrPath) {
				s.set(Corrupt, s.EncPath+" "+err.Error(), "")
			} else if isNoMatch(err) {
				if k := e.sealedBy(s); k != nil {
					s.set(NoKey, fmt.Sprintf("%s is encrypted with your key %s, not %s as its block in .gitignore says. If you moved it to that block, `git enc rekey %s %s %s` re-encrypts it; if not, someone changed .gitignore: check `git log -p .gitignore`", s.EncPath, k.Name, s.Block.Key, k.Name, s.Block.Key, s.Path), "")
				} else {
					s.set(NoKey, fmt.Sprintf("key %s cannot decrypt %s (it was encrypted with a different key)", s.Block.Key, s.EncPath), "")
				}
			} else {
				s.set(Corrupt, s.EncPath+" cannot be decrypted ("+err.Error()+"); if you changed it, restore git's copy with `git restore "+s.EncPath+"`", "")
			}
			continue
		}
		switch {
		case s.plain == nil:
			s.set(Missing, "no plaintext yet", "git enc update "+s.Path)
		case s.PlainHash == s.EncHash && s.EncDeleted:
			// Committing now would delete the only encrypted copy.
			s.set(Missing, s.EncPath+" is deleted; `git enc update` restores it (to stop encrypting "+s.Path+", remove its line from .gitignore)", "git enc update "+s.Path)
		case s.PlainHash == s.EncHash:
			s.set(Clean, "", "")
		default:
			rebuild = append(rebuild, s)
		}
	}
	return e.compare(rebuild)
}

// compare classifies secrets whose plaintext and .enc differ, using the
// base, or git history when the base is unknown or no longer committed.
func (e *Engine) compare(list []*Secret) error {
	if len(list) == 0 {
		return nil
	}
	need := map[*Secret][]string{}
	for _, s := range list {
		if (s.entry.Seen != "" && s.entry.Seen == s.EncBlob) || (s.entry.Pending != "" && s.entry.Pending == s.EncBlob) {
			continue
		}
		need[s] = []string{s.entry.BaseBlob}
	}
	com, err := e.committed(need)
	if err != nil {
		return err
	}
	var hist map[string]map[string]bool
	for _, s := range list {
		if s.entry.Seen != "" && s.entry.Seen == s.EncBlob {
			if s.Incoming != "" {
				s.set(Conflict, "merge "+s.Incoming+" into it, then `git enc add "+s.Path+"`", "git enc add "+s.Path)
			} else {
				s.set(Modified, "edited (with the committed version merged in)", "git enc add "+s.Path)
			}
			continue
		}
		if s.entry.Pending != "" && s.entry.Pending == s.EncBlob {
			// Edited again after `git enc add`, before committing.
			s.set(Modified, "edited again since `git enc add`", "git enc add "+s.Path)
			continue
		}
		if s.entry.BaseBlob != "" && com[s][s.entry.BaseBlob] {
			e.decide(s, s.entry.BaseHash)
			continue
		}
		// No usable base: look for the plaintext among committed versions.
		if hist == nil {
			var paths []string
			for _, t := range list {
				paths = append(paths, t.EncPath)
			}
			if hist, err = e.Repo.History(paths); err != nil {
				return err
			}
		}
		var missing []string
		for b := range hist[s.EncPath] {
			if _, ok := e.Cache.Hashes[b]; !ok {
				missing = append(missing, b)
			}
		}
		blobs, err := e.Repo.Blobs(missing)
		if err != nil {
			return err
		}
		found := ""
		for b := range hist[s.EncPath] {
			if h, err := e.hashOf(s, b, blobs); err == nil && h == s.PlainHash {
				found = b
				break
			}
		}
		switch {
		case found != "":
			s.entry.BaseBlob, s.entry.BaseHash = found, s.PlainHash
			e.decide(s, s.PlainHash)
		default:
			s.set(Diverged, "differs from "+s.EncPath+" and from every committed version, so git-enc cannot tell whether it is your edit or out of date",
				"git enc update "+s.Path)
		}
	}
	return nil
}

func (e *Engine) decide(s *Secret, base string) {
	switch {
	case s.PlainHash == base:
		s.set(Outdated, s.EncPath+" has a newer version than your copy", "git enc update "+s.Path)
	case s.EncHash == base:
		s.set(Modified, "edited", "git enc add "+s.Path)
	default:
		s.set(Conflict, "you edited it and "+s.EncPath+" changed too", "git enc update "+s.Path)
	}
}

func (s *Secret) set(k Kind, msg, action string) { s.Kind, s.Message, s.Action = k, msg, action }

func (e *Engine) noKeyMessage(b *spec.Block) string {
	if msg := e.shared[b]; msg != "" {
		return msg
	}
	if why, ok := e.Keys.Skipped[b.Key]; ok {
		return why
	}
	if b.Fingerprint != "" {
		if k := e.Keys.ByFingerprint(b.Fingerprint); k != nil && k.File != "" && k.Name != b.Key {
			return fmt.Sprintf("the block for key %s has the fingerprint of your key %s (%s); git-enc will not use %s for it. If you did not do this, someone changed .gitignore: check `git log -p .gitignore`", b.Key, k.Name, b.Fingerprint, k.Name)
		}
		if k := e.Keys.ByName(b.Key); k != nil {
			return fmt.Sprintf("your key %q is %s, but this repo uses %s %s", b.Key, k.Fingerprint, b.Key, b.Fingerprint)
		}
		if os.Getenv("GIT_ENC_KEY") != "" {
			return fmt.Sprintf("you don't have key %s (%s): no key in $GIT_ENC_KEY has that fingerprint", b.Key, b.Fingerprint)
		}
		return fmt.Sprintf("you don't have key %s (%s)", b.Key, b.Fingerprint)
	}
	return fmt.Sprintf("you don't have key %s", b.Key)
}

func isNoMatch(err error) bool {
	var nm *age.NoIdentityMatchError
	return errors.As(err, &nm)
}
