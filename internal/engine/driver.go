package engine

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shreeve/git-enc/internal/envelope"
	"github.com/shreeve/git-enc/internal/fsx"
	"github.com/shreeve/git-enc/internal/gitx"
	"github.com/shreeve/git-enc/internal/keys"
	"github.com/shreeve/git-enc/internal/spec"
)

// DriverLine turns the merge driver on for .enc files. It goes in the
// clone's own .git/info/attributes, next to the driver's definition in its
// config, both written by `git enc init`: git falls back to a text merge
// for a driver it has no definition for, which could write conflict
// markers into ciphertext, so the committed .gitattributes keeps
// `merge=binary`.
const DriverLine = "*.enc merge=git-enc"

// installDriver defines the merge driver in the clone's config and turns
// it on in .git/info/attributes.
func (e *Engine) installDriver(binary string) error {
	cmd := shellQuote(binary) + " merge-driver %O %A %B %P"
	for _, kv := range [][2]string{
		{"merge.git-enc.name", "git-enc: merge decrypted secrets"},
		{"merge.git-enc.driver", cmd},
	} {
		if _, err := e.Repo.Git("config", "--local", kv[0], kv[1]); err != nil {
			return err
		}
	}
	file, err := e.Repo.GitPath("info/attributes")
	if err != nil {
		return err
	}
	data, err := os.ReadFile(file)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) == DriverLine {
			return nil
		}
	}
	if len(data) > 0 && !bytes.HasSuffix(data, []byte("\n")) {
		data = append(data, '\n')
	}
	data = append(data, "# git-enc: merge secrets by their plaintext (git enc init)\n"+DriverLine+"\n"...)
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	return fsx.WriteAtomic(file, data, 0o644)
}

// DriverInstalled reports whether the merge driver is on in this clone.
func (e *Engine) DriverInstalled() bool {
	file, err := e.Repo.GitPath("info/attributes")
	if err != nil {
		return false
	}
	data, _ := os.ReadFile(file)
	return bytes.Contains(data, []byte(DriverLine))
}

// MergeDriver merges one .enc file for git (`merge-driver %O %A %B %P`):
// it decrypts the base, ours and theirs versions with the key of the block
// that declares the secret, merges the plaintext as git merges any text
// file, and writes the result, encrypted, over ours. It returns false,
// leaving ours alone, when the edits overlap or any version cannot be read
// with the block's key: git then reports a conflict, which
// `git enc merge` resolves in the plaintext.
func MergeDriver(dir, baseFile, oursFile, theirsFile, encPath string) (bool, error) {
	name := strings.TrimSuffix(encPath, ".enc")
	if name == encPath {
		return false, nil
	}
	repo, err := gitx.Open(dir)
	if err != nil {
		return false, err
	}
	e := &Engine{Repo: repo, ignoreCase: repo.ConfigBool("core.ignorecase", false)}
	if e.baseDir, err = repo.GitPath("git-enc"); err != nil {
		return false, err
	}
	if e.Keys, err = keys.Load(); err != nil {
		return false, err
	}
	data, err := os.ReadFile(filepath.Join(repo.Root, ".gitignore"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	e.Spec, _ = spec.Parse(data, e.ignoreCase)
	e.findSharedKeys()
	b, _, err := e.Spec.Match(name)
	if err != nil || b == nil {
		return false, nil
	}
	k := e.blockKey(b)
	if k == nil {
		return false, nil
	}
	var sealed [3][]byte
	var plain [3][]byte
	for i, f := range []string{baseFile, oursFile, theirsFile} {
		if sealed[i], err = os.ReadFile(f); err != nil {
			return false, err
		}
		if i == 0 && len(sealed[i]) == 0 {
			continue // no common ancestor: both sides added it
		}
		if _, plain[i], err = envelope.Open(sealed[i], name, k.Identity); err != nil {
			return false, nil
		}
	}
	base, ours, theirs := plain[0], plain[1], plain[2]
	switch {
	case bytes.Equal(ours, theirs), bytes.Equal(base, theirs):
		return true, nil // ours already is the result
	case bytes.Equal(base, ours):
		return true, os.WriteFile(oursFile, sealed[2], 0o644)
	}
	merged, conflicts, err := e.mergeFile(ours, base, theirs, "ours", "base", "theirs")
	if err != nil || conflicts > 0 {
		return false, nil
	}
	out, err := envelope.Seal(name, merged, k.Recipient)
	if err != nil {
		return false, err
	}
	return true, os.WriteFile(oursFile, out, 0o644)
}

// stagedOneSided lists secrets whose merge is about to be committed with
// one side's .enc taken whole although both sides changed the secret: the
// resolution GitHub Desktop offers for a binary conflict ("use mine" or
// "use theirs"), which drops the other side's change without a word.
func (e *Engine) stagedOneSided() ([]string, error) {
	mergeHead, err := e.Repo.GitPath("MERGE_HEAD")
	if err != nil || !gitx.Exists(mergeHead) {
		return nil, err
	}
	var staged []*Secret
	var specs []string
	for _, s := range e.Secrets {
		// Not only staged changes: taking ours whole leaves the index as HEAD.
		if s.IndexBlob != "" {
			staged = append(staged, s)
			specs = append(specs, ":(literal)"+s.EncPath)
		}
	}
	if len(staged) == 0 {
		return nil, nil
	}
	mb, err := e.Repo.Git("merge-base", "HEAD", "MERGE_HEAD")
	if err != nil {
		return nil, err
	}
	blobsAt := func(rev string) (map[string]string, error) {
		out, err := e.Repo.Git(append([]string{"ls-tree", "-r", "-z", "--full-tree", rev, "--"}, specs...)...)
		if err != nil {
			return nil, err
		}
		res := map[string]string{}
		for _, rec := range gitx.SplitZ(out) {
			if tab := strings.IndexByte(rec, '\t'); tab >= 0 {
				if f := strings.Fields(rec[:tab]); len(f) == 3 {
					res[rec[tab+1:]] = f[2]
				}
			}
		}
		return res, nil
	}
	theirs, err := blobsAt("MERGE_HEAD")
	if err != nil {
		return nil, err
	}
	base, err := blobsAt(strings.TrimSpace(string(mb)))
	if err != nil {
		return nil, err
	}
	var bad []string
	for _, s := range staged {
		o, t, b := s.HeadBlob, theirs[s.EncPath], base[s.EncPath]
		if o == "" || t == "" || o == t || b == o || b == t || (s.IndexBlob != o && s.IndexBlob != t) {
			continue
		}
		// Both sides changed it and the commit takes one whole. That loses
		// nothing only if both sides hold the same secret.
		if e.samePlaintext(s, o, t) {
			continue
		}
		bad = append(bad, s.Path)
	}
	return bad, nil
}

// samePlaintext reports whether two committed versions of s decrypt to the
// same secret; without the key it cannot tell, and says no.
func (e *Engine) samePlaintext(s *Secret, a, b string) bool {
	if s.Key == nil {
		return false
	}
	blobs, err := e.Repo.Blobs([]string{a, b})
	if err != nil {
		return false
	}
	pa, err1 := e.open(s, blobs[a])
	pb, err2 := e.open(s, blobs[b])
	return err1 == nil && err2 == nil && bytes.Equal(pa, pb)
}

// oneSidedMessage explains the refusal for a secret stagedOneSided found.
func oneSidedMessage(p string) string {
	return fmt.Sprintf("git-enc: refusing to commit the merge: %s.enc is one side's version whole, and both sides changed %s, so the other side's change would be lost\n  bring the conflict back with: git checkout -m -- %s.enc\n  then merge both sides with: git enc merge %s   (commit with --no-verify to drop the other side on purpose)", p, p, p, p)
}
