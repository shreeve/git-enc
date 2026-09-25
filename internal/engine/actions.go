package engine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/shreeve/git-enc/internal/envelope"
	"github.com/shreeve/git-enc/internal/fsx"
	"github.com/shreeve/git-enc/internal/gitx"
	"github.com/shreeve/git-enc/internal/keys"
	"github.com/shreeve/git-enc/internal/spec"
)

// AddOptions controls Add.
type AddOptions struct {
	All   bool
	Force bool   // also encrypt outdated, conflicting or diverged secrets
	Key   string // block to declare new secrets in
}

// Add encrypts secrets and stages their .enc files. Paths not yet declared
// are added to a git-enc block first. It returns what it did, line by line.
func (e *Engine) Add(paths []string, opt AddOptions) ([]string, error) {
	var out []string
	declared, err := e.declare(paths, opt.Key, &out)
	if err != nil {
		return out, err
	}
	if declared {
		if err := e.Scan(); err != nil {
			return out, err
		}
	}
	var targets []*Secret
	if opt.All {
		for _, s := range e.Secrets {
			switch {
			case s.Incoming != "":
				out = append(out, "skipping "+s.Path+": merge "+s.Incoming+" into it first, then `git enc add "+s.Path+"`")
			case s.Kind == New, s.Kind == Modified,
				s.Kind == Clean && (s.EncDirty || s.IndexBlob == ""),
				s.Kind == Merging && s.entry.Merge == stageKey(s):
				targets = append(targets, s)
			}
		}
	}
	for _, p := range paths {
		s := e.Secret(p)
		if s == nil {
			return out, fmt.Errorf("%s: not a secret (is it listed in a git-enc block?)", p)
		}
		targets = appendNew(targets, s)
	}
	if len(targets) == 0 {
		out = append(out, "nothing to add")
		return out, nil
	}
	if err := e.ensureAttributes(); err != nil {
		return out, err
	}
	explicit := map[*Secret]bool{}
	for _, p := range paths {
		explicit[e.Secret(p)] = true
	}
	for _, s := range targets {
		msg, err := e.addOne(s, opt.Force, explicit[s])
		if err != nil {
			return out, err
		}
		out = append(out, msg...)
	}
	return out, e.Scan()
}

func (e *Engine) addOne(s *Secret, force, explicit bool) ([]string, error) {
	resolved := explicit && s.entry.Seen != "" && s.entry.Seen == s.EncBlob
	switch s.Kind {
	case New, Modified:
	case Clean:
		if s.PlainTracked {
			break // still untrack the plaintext below
		}
		if s.EncDirty || s.IndexBlob == "" || s.EncDeleted {
			if s.EncDeleted {
				if err := e.restoreEnc(s); err != nil {
					return nil, err
				}
			}
			if _, err := e.Repo.Git("add", "--", ":(literal)"+s.EncPath); err != nil {
				return nil, err
			}
			return []string{"staged " + s.EncPath}, nil
		}
		return []string{s.Path + " is unchanged"}, nil
	case Conflict:
		if !force && !resolved {
			return nil, refuse("%s is %s: %s\n  run `%s` first (or add --force to overwrite %s)", s.Path, s.Kind, s.Message, s.Action, s.EncPath)
		}
	case Outdated, Diverged:
		if !force {
			return nil, refuse("%s is %s: %s\n  run `%s` first (or add --force to overwrite %s)", s.Path, s.Kind, s.Message, s.Action, s.EncPath)
		}
	case Merging:
		if s.entry.Merge != stageKey(s) {
			return nil, refuse("%s: git has a merge conflict on %s; run `git enc merge %s` first", s.Path, s.EncPath, s.Path)
		}
	case NoKey:
		return nil, &KeyError{fmt.Sprintf("%s: %s", s.Path, s.Message)}
	default:
		return nil, refuse("%s is %s: %s", s.Path, s.Kind, s.Message)
	}
	if s.plain == nil {
		return nil, fmt.Errorf("%s does not exist", s.Path)
	}
	if s.Key == nil {
		return nil, &KeyError{fmt.Sprintf("%s: %s", s.Path, e.noKeyMessage(s.Block))}
	}
	if !force && hasMarkers(s.plain) {
		return nil, refuse("%s has conflict markers (<<<<<<<); resolve them, or add --force", s.Path)
	}
	var out []string
	if s.PlainTracked {
		if _, err := e.Repo.Git("rm", "--cached", "-q", "--", ":(literal)"+s.Path); err != nil {
			return nil, err
		}
		n := "some"
		if c, err := e.Repo.Git("rev-list", "--count", "HEAD", "--", ":(literal)"+s.Path); err == nil {
			n = strings.TrimSpace(string(c))
		}
		out = append(out,
			fmt.Sprintf("stopped tracking the plaintext %s (staged its removal)", s.Path),
			fmt.Sprintf("  warning: %s is in %s past commit(s) in plain text; change these secrets, since history keeps the old values", s.Path, n))
		s.PlainTracked = false
		if s.Kind == Clean && !s.EncDirty && s.IndexBlob != "" {
			return out, nil
		}
	}
	if err := e.checkIgnored(s); err != nil {
		return nil, err
	}
	if s.Block.Fingerprint == "" {
		if err := e.setFingerprint(s.Block, s.Key.Fingerprint); err != nil {
			return nil, err
		}
	}
	sealed, err := envelope.Seal(s.Path, s.plain, s.Key.Recipient)
	if err != nil {
		return nil, err
	}
	if err := fsx.WriteWorktree(e.Repo.Root, s.EncPath, sealed, 0o644); err != nil {
		return nil, err
	}
	blob := e.Repo.BlobID(sealed)
	e.Cache.Put(blob, s.PlainHash)
	if _, err := e.Repo.Git("add", "--", ":(literal)"+s.EncPath); err != nil {
		return nil, err
	}
	s.entry.Pending, s.entry.Seen, s.entry.Merge = blob, "", ""
	e.State.Manage(s.Path)
	if s.Incoming != "" {
		os.Remove(e.Repo.Abs(s.Incoming))
	}
	return append(out, fmt.Sprintf("encrypted %s → %s (staged)", s.Path, s.EncPath)), nil
}

// checkIgnored makes sure git ignores the plaintext and does not ignore the
// ciphertext. A later negation in .gitignore, or a pattern broad enough to
// match F.enc, would break one or the other.
func (e *Engine) checkIgnored(s *Secret) error {
	if _, err := e.Repo.Git("check-ignore", "-q", "--no-index", "--", s.Path); err != nil {
		return refuse("%s is declared in .gitignore but git does not ignore it (a `!` rule?); fix that first", s.Path)
	}
	// Decide with -q: with -v, git also reports a path matched by a `!`
	// rule (which un-ignores it), and exits 0 for it.
	if _, err := e.Repo.Git("check-ignore", "-q", "--no-index", "--", s.EncPath); err == nil {
		out, _ := e.Repo.Git("check-ignore", "-v", "--no-index", "--", s.EncPath)
		src := strings.SplitN(strings.TrimSpace(string(out)), "\t", 2)[0]
		hint := ""
		if strings.HasSuffix(src, "/") {
			hint = " (a rule for a whole directory cannot be undone that way: write `dir/*` instead of `dir/`)"
		}
		return refuse("%s would be ignored by git (%s); add a line `!*.enc` after that rule, or narrow it%s", s.EncPath, src, hint)
	}
	return nil
}

// declare adds undeclared paths to a git-enc block.
func (e *Engine) declare(paths []string, keyName string, out *[]string) (bool, error) {
	var todo []string
	for _, p := range paths {
		if err := spec.CheckPath(p); err != nil {
			return false, err
		}
		if b, pat, err := e.Spec.Match(p); err != nil {
			return false, err
		} else if b != nil {
			if keyName != "" && b.Key != keyName {
				return false, fmt.Errorf("%s is already declared for key %s (.gitignore line %d); to change its key, move that line into a `# git-enc: %s` block, then run `git enc rekey`", p, b.Key, pat.Line, keyName)
			}
			continue
		}
		if e.Secret(p) != nil && e.Secret(p).Kind != Orphaned {
			continue
		}
		fi, err := os.Lstat(e.Repo.Abs(p))
		if err != nil {
			return false, fmt.Errorf("%s: no such file", p)
		}
		if !fi.Mode().IsRegular() {
			return false, fmt.Errorf("%s is not a regular file", p)
		}
		todo = append(todo, p)
	}
	if len(todo) == 0 {
		return false, nil
	}
	if len(e.Problems) > 0 {
		for _, p := range e.Problems {
			if p.Code == "gitignore" {
				return false, fmt.Errorf(".gitignore:%d: %s", p.Line, p.Message)
			}
		}
	}
	block, key, err := e.chooseBlock(keyName)
	if err != nil {
		return false, err
	}
	for _, p := range todo {
		if block == nil {
			e.Spec.NewBlock(key.Name, key.Fingerprint, p)
			e.Spec, _ = spec.Parse(e.Spec.Bytes(), e.ignoreCase)
			block = e.Spec.Block(key.Name)
		} else {
			e.Spec.AddPath(block, p, key.Fingerprint)
			e.Spec, _ = spec.Parse(e.Spec.Bytes(), e.ignoreCase)
			block = e.Spec.Block(block.Key)
		}
		*out = append(*out, fmt.Sprintf("declared %s in .gitignore (key %s)", p, key.Name))
	}
	if err := fsx.WriteWorktree(e.Repo.Root, ".gitignore", e.Spec.Bytes(), 0o644); err != nil {
		return false, err
	}
	if _, err := e.Repo.Git("add", "--", ".gitignore"); err != nil {
		return false, err
	}
	return true, nil
}

// chooseBlock picks the block new secrets go into, or the key for a new
// block (block nil).
func (e *Engine) chooseBlock(keyName string) (*spec.Block, *keys.Key, error) {
	if keyName != "" {
		if b := e.Spec.Block(keyName); b != nil {
			k := e.blockKey(b)
			if k == nil {
				return nil, nil, fmt.Errorf("%s", e.noKeyMessage(b))
			}
			return b, k, nil
		}
		k := e.Keys.ByName(keyName)
		if k == nil {
			return nil, nil, fmt.Errorf("no key named %s (create one with `git enc key new %s`, or import one with `git enc key add %s`)", keyName, keyName, keyName)
		}
		return nil, k, nil
	}
	switch len(e.Spec.Blocks) {
	case 0:
		return nil, nil, errors.New("no git-enc block in .gitignore yet: choose a key with --key NAME (create one with `git enc key new NAME`)")
	case 1:
		b := e.Spec.Blocks[0]
		k := e.blockKey(b)
		if k == nil {
			return nil, nil, fmt.Errorf("%s", e.noKeyMessage(b))
		}
		return b, k, nil
	default:
		return nil, nil, fmt.Errorf(".gitignore has several git-enc blocks (%s); choose one with --key", strings.Join(e.Spec.Keys(), ", "))
	}
}

func (e *Engine) setFingerprint(b *spec.Block, fp string) error {
	e.Spec.Lines[b.Start-1] = spec.Header(b.Key, fp)
	b.Fingerprint = fp
	if err := fsx.WriteWorktree(e.Repo.Root, ".gitignore", e.Spec.Bytes(), 0o644); err != nil {
		return err
	}
	_, err := e.Repo.Git("add", "--", ".gitignore")
	return err
}

func hasMarkers(b []byte) bool {
	return bytes.HasPrefix(b, []byte("<<<<<<< ")) || bytes.Contains(b, []byte("\n<<<<<<< "))
}

// UpdateOptions controls Update.
type UpdateOptions struct {
	Discard bool // replace local edits with the committed version
}

// Update refreshes plaintext from the .enc files. It never loses an edit:
// it only overwrites a plaintext that git history can reproduce, and saves
// an encrypted backup first whenever it replaces a file.
func (e *Engine) Update(paths []string, opt UpdateOptions) ([]string, error) {
	var targets []*Secret
	if len(paths) == 0 {
		for _, s := range e.Secrets {
			switch s.Kind {
			case Missing, Outdated, Conflict, Diverged:
				targets = append(targets, s)
			}
		}
	}
	for _, p := range paths {
		s := e.Secret(p)
		if s == nil {
			return nil, fmt.Errorf("%s: not a secret", p)
		}
		targets = appendNew(targets, s)
	}
	var out []string
	if len(targets) == 0 {
		return []string{"everything is up to date"}, nil
	}
	for _, s := range targets {
		msg, err := e.updateOne(s, opt.Discard)
		if err != nil {
			return out, err
		}
		if msg != "" {
			out = append(out, msg)
		}
	}
	return out, e.Scan()
}

func (e *Engine) updateOne(s *Secret, discard bool) (string, error) {
	switch s.Kind {
	case Merging:
		return "", refuse("%s: git has a merge conflict on %s; run `git enc merge %s`", s.Path, s.EncPath, s.Path)
	case NoKey:
		return "", &KeyError{fmt.Sprintf("%s: %s", s.Path, s.Message)}
	case Corrupt, Orphaned:
		return "", refuse("%s is %s: %s", s.Path, s.Kind, s.Message)
	case New:
		return s.Path + " is not encrypted yet; nothing to update", nil
	}
	if s.NotIgnored {
		return "", refuse("%s: git does not ignore it (a `!` rule in a .gitignore?); refusing to write plaintext git could commit", s.Path)
	}
	if s.EncDeleted {
		if err := e.restoreEnc(s); err != nil {
			return "", err
		}
	}
	if s.Kind == Clean {
		if s.EncDeleted {
			return "restored " + s.EncPath, nil
		}
		return "", nil
	}
	body, err := e.body(s)
	if err != nil {
		return "", err
	}
	switch s.Kind {
	case Missing:
		if err := fsx.WriteWorktree(e.Repo.Root, s.Path, body, 0o600); err != nil {
			return "", err
		}
		return "wrote " + s.Path, nil
	case Outdated:
		// The old copy equals a committed version, so git already has it.
		return e.replace(s, body, "updated "+s.Path, false)
	case Modified:
		if !discard {
			return s.Path + " has your edits; nothing to update (add --discard to throw them away)", nil
		}
		return e.replace(s, body, "discarded your edits to "+s.Path, true)
	}
	// Conflict or Diverged.
	if discard {
		return e.replace(s, body, "replaced "+s.Path+" with the committed version", true)
	}
	if s.Kind == Conflict {
		if merged, ok, err := e.merge3(s, body); err != nil {
			return "", err
		} else if ok {
			if _, err := e.replace(s, merged, "", true); err != nil {
				return "", err
			}
			s.entry.Seen = s.EncBlob
			return fmt.Sprintf("merged the new version of %s into your edits; check it, then `git enc add %s`", s.Path, s.Path), nil
		}
	}
	inc := s.Path + ".incoming"
	e.State.Manage(s.Path)
	if err := e.syncExclude(); err != nil {
		return "", err
	}
	if err := fsx.WriteWorktree(e.Repo.Root, inc, body, 0o600); err != nil {
		return "", err
	}
	s.entry.Seen = s.EncBlob
	return fmt.Sprintf("%s: kept your copy; the committed version is in %s\n  merge what you need into %s, then `git enc add %s` (or `git enc update --discard %s` to take theirs)",
		s.Path, inc, s.Path, s.Path, s.Path), nil
}

// restoreEnc puts back a deleted F.enc from git's copy (the index's, or
// HEAD's after `git rm`), and stages it if the index had lost it. It
// writes the file itself: `git checkout` and `git restore` would run the
// user's post-checkout hook in the middle of a git-enc command.
func (e *Engine) restoreEnc(s *Secret) error {
	data, err := e.encData(s)
	if err != nil {
		return err
	}
	if err := fsx.WriteWorktree(e.Repo.Root, s.EncPath, data, 0o644); err != nil {
		return err
	}
	if s.IndexBlob == "" {
		if _, err := e.Repo.Git("add", "--", ":(literal)"+s.EncPath); err != nil {
			return err
		}
	}
	return nil
}

// replace overwrites the plaintext with body, first saving an encrypted
// backup when the old copy is not something git history already holds.
func (e *Engine) replace(s *Secret, body []byte, msg string, keep bool) (string, error) {
	backup := ""
	if keep {
		var err error
		if backup, err = e.backup(s); err != nil {
			return "", err
		}
	}
	if err := fsx.WriteWorktree(e.Repo.Root, s.Path, body, 0o600); err != nil {
		return "", err
	}
	if s.Incoming != "" {
		os.Remove(e.Repo.Abs(s.Incoming))
	}
	s.entry.Seen = ""
	if backup != "" && msg != "" {
		msg += " (your old copy: `git enc cat " + backup + "`)"
	}
	return msg, nil
}

// backup saves the current plaintext, encrypted, under the git dir.
func (e *Engine) backup(s *Secret) (string, error) {
	if s.plain == nil || s.Key == nil {
		return "", nil
	}
	sealed, err := envelope.Seal(s.Path, s.plain, s.Key.Recipient)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(e.baseDir, "backup")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + strings.ReplaceAll(s.Path, "/", "%") + ".enc"
	file := filepath.Join(dir, name)
	if err := fsx.WriteAtomic(file, sealed, 0o600); err != nil {
		return "", err
	}
	return e.display(file), nil
}

// display renders a file under the worktree relative to the current
// directory, so a command printed with it works where it was run; other
// files keep their absolute path.
func (e *Engine) display(abs string) string {
	if rel, err := filepath.Rel(e.Repo.Root, abs); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return abs
	}
	cwd, err := os.Getwd()
	if err != nil {
		return abs
	}
	if real, err := filepath.EvalSymlinks(cwd); err == nil {
		cwd = real
	}
	rel, err := filepath.Rel(cwd, abs)
	if err != nil {
		return abs
	}
	return filepath.ToSlash(rel)
}

// merge3 merges the committed version into the local edits against their
// common base. ok is false when the edits overlap.
func (e *Engine) merge3(s *Secret, theirs []byte) ([]byte, bool, error) {
	if s.entry.BaseBlob == "" {
		return nil, false, nil
	}
	blobs, err := e.Repo.Blobs([]string{s.entry.BaseBlob})
	if err != nil {
		return nil, false, err
	}
	data, ok := blobs[s.entry.BaseBlob]
	if !ok {
		return nil, false, nil
	}
	base, err := e.openAny(s, data)
	if err != nil {
		return nil, false, nil
	}
	merged, n, err := e.mergeFile(s.plain, base, theirs, "yours", "base", "committed")
	if err != nil || n != 0 {
		return nil, false, nil // binary, or overlapping edits: fall back to F.incoming
	}
	return merged, true, nil
}

// mergeFile runs `git merge-file` on three versions and returns the result
// and the number of conflicts.
func (e *Engine) mergeFile(ours, base, theirs []byte, lo, lb, lt string) ([]byte, int, error) {
	dir, done, err := fsx.TempDir(e.baseDir, "merge-")
	if err != nil {
		return nil, 0, err
	}
	defer done()
	files := []string{filepath.Join(dir, "ours"), filepath.Join(dir, "base"), filepath.Join(dir, "theirs")}
	for i, b := range [][]byte{ours, base, theirs} {
		if err := os.WriteFile(files[i], b, 0o600); err != nil {
			return nil, 0, err
		}
	}
	out, err := gitx.Run(dir, nil, "merge-file", "-p", "-L", lo, "-L", lb, "-L", lt, files[0], files[1], files[2])
	if err != nil {
		var ge *gitx.Error
		if errors.As(err, &ge) && ge.ExitCode() > 0 && ge.ExitCode() < 128 {
			return out, ge.ExitCode(), nil
		}
		return nil, 0, err
	}
	return out, 0, nil
}

func stageKey(s *Secret) string {
	return s.Unmerged[1] + ":" + s.Unmerged[2] + ":" + s.Unmerged[3]
}

// Merge resolves git merge or rebase conflicts on .enc files by merging the
// decrypted versions into the plaintext.
func (e *Engine) Merge(paths []string) ([]string, error) {
	var targets []*Secret
	for _, s := range e.Secrets {
		if s.Kind == Merging && (len(paths) == 0 || contains(paths, s.Path)) {
			targets = append(targets, s)
		}
	}
	for _, p := range paths {
		if s := e.Secret(p); s == nil || s.Kind != Merging {
			return nil, fmt.Errorf("%s has no merge conflict", p)
		}
	}
	if len(targets) == 0 {
		return []string{"no secret has a merge conflict"}, nil
	}
	rebasing := false
	for _, d := range []string{"rebase-merge", "rebase-apply"} {
		if p, err := e.Repo.GitPath(d); err == nil && gitx.Exists(p) {
			rebasing = true
		}
	}
	var out []string
	for _, s := range targets {
		if s.Key == nil {
			return out, &KeyError{fmt.Sprintf("%s: %s", s.Path, e.noKeyMessage(s.Block))}
		}
		if s.Unmerged[2] == "" || s.Unmerged[3] == "" {
			return out, refuse("%s: one side of the merge deleted %s; keep it with `git add %s` or delete it with `git rm %s`", s.Path, s.EncPath, s.EncPath, s.EncPath)
		}
		var ids []string
		for _, st := range []int{1, 2, 3} {
			if b := s.Unmerged[st]; b != "" {
				ids = append(ids, b)
			}
		}
		blobs, err := e.Repo.Blobs(ids)
		if err != nil {
			return out, err
		}
		side := map[int][]byte{}
		for st, b := range s.Unmerged {
			body, err := e.openAny(s, blobs[b])
			if err != nil {
				return out, fmt.Errorf("%s: cannot decrypt stage %d: %v", s.Path, st, err)
			}
			side[st] = body
		}
		if s.plain != nil && !anyEqual(s.plain, side) {
			return out, refuse("%s has changes that are in neither side of the merge; move them aside and run `git enc merge %s` again", s.Path, s.Path)
		}
		lo, lt := "yours", "incoming"
		if rebasing {
			lo, lt = "upstream", "yours"
		}
		var result []byte
		conflicts := 0
		switch b, o, t := side[1], side[2], side[3]; {
		case bytes.Equal(o, t):
			result = o
		case s.Unmerged[1] != "" && bytes.Equal(b, o):
			result = t
		case s.Unmerged[1] != "" && bytes.Equal(b, t):
			result = o
		default:
			result, conflicts, err = e.mergeFile(o, b, t, lo, "base", lt)
			if err != nil {
				return out, refuse("%s: cannot merge the two versions (%v)\n  pick one side: `git checkout --ours %s` or `git checkout --theirs %s`, `git add %s`, then `git enc update --discard %s`",
					s.Path, err, s.EncPath, s.EncPath, s.EncPath, s.Path)
			}
		}
		if err := fsx.WriteWorktree(e.Repo.Root, s.Path, result, 0o600); err != nil {
			return out, err
		}
		s.entry.Merge = stageKey(s)
		s.entry.Seen = ""
		if conflicts > 0 {
			out = append(out, fmt.Sprintf("%s: %d conflict(s) marked in the file; resolve them, then `git enc add %s`", s.Path, conflicts, s.Path))
		} else {
			out = append(out, fmt.Sprintf("merged both sides into %s; check it, then `git enc add %s`", s.Path, s.Path))
		}
	}
	return out, e.Scan()
}

func anyEqual(b []byte, sides map[int][]byte) bool {
	for _, s := range sides {
		if bytes.Equal(b, s) {
			return true
		}
	}
	return false
}

// appendNew appends s to list unless it is already there.
func appendNew(list []*Secret, s *Secret) []*Secret {
	for _, t := range list {
		if t == s {
			return list
		}
	}
	return append(list, s)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Diff writes a diff of each secret's committed version against the local
// plaintext.
func (e *Engine) Diff(paths []string, color bool, w io.Writer) error {
	var targets []*Secret
	for _, s := range e.Secrets {
		if len(paths) > 0 && !contains(paths, s.Path) {
			continue
		}
		if s.plain == nil || s.Kind == Clean || s.Kind == NoKey || s.Kind == Corrupt || s.Kind == Merging {
			continue
		}
		targets = append(targets, s)
	}
	for _, p := range paths {
		if e.Secret(p) == nil {
			return fmt.Errorf("%s: not a secret", p)
		}
	}
	dir, done, err := fsx.TempDir(e.baseDir, "diff-")
	if err != nil {
		return err
	}
	defer done()
	for _, s := range targets {
		var committed []byte
		if s.EncBlob != "" {
			if committed, err = e.body(s); err != nil {
				return err
			}
		}
		a := filepath.Join(dir, "a", filepath.FromSlash(s.Path))
		b := filepath.Join(dir, "b", filepath.FromSlash(s.Path))
		for f, data := range map[string][]byte{a: committed, b: s.plain} {
			if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(f, data, 0o600); err != nil {
				return err
			}
		}
		args := []string{"diff", "--no-index", "--no-prefix", "--no-ext-diff"}
		if color {
			args = append(args, "--color=always")
		}
		args = append(args, "--", "a/"+s.Path, "b/"+s.Path)
		out, err := gitx.Run(dir, nil, args...)
		var ge *gitx.Error
		if err != nil && !(errors.As(err, &ge) && ge.ExitCode() == 1) {
			return err
		}
		w.Write(out)
	}
	return nil
}

// Cat decrypts any git-enc file (a .enc or a backup) with every key.
func Cat(data []byte) ([]byte, error) {
	st, err := keys.Load()
	if err != nil {
		return nil, err
	}
	if len(st.Keys) == 0 {
		return nil, errors.New("you have no keys (import one with `git enc key add NAME`)")
	}
	_, body, err := envelope.Open(data, "", st.Identities()...)
	if isNoMatch(err) {
		return nil, errors.New("none of your keys can decrypt it")
	}
	return body, err
}

// plural renders a count and a noun: "1 secret", "2 secrets".
func plural(n int, one string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + one + "s"
}
