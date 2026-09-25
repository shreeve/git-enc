package engine

import (
	"fmt"

	"github.com/shreeve/git-enc/internal/envelope"
	"github.com/shreeve/git-enc/internal/fsx"
	"github.com/shreeve/git-enc/internal/keys"
	"github.com/shreeve/git-enc/internal/spec"
)

// Rekey re-encrypts secrets from key `from` to key `to`. Both keys are
// named by the person running it, never taken from .gitignore alone, which
// anyone who can push may have edited.
//
// Without paths it rotates a key: every block for `from` switches to `to`
// in .gitignore and all their secrets are re-encrypted. With paths it
// re-encrypts only those secrets, which must already be declared in a
// block for `to` (a line moved there by hand).
//
// Each F.enc must open with `from`. The version in F.enc is re-sealed,
// never the plaintext, so an edit stays an edit and an outdated copy stays
// outdated. Running it again after an interruption finishes the job.
func (e *Engine) Rekey(from, to string, paths []string) ([]string, error) {
	if from == to {
		return nil, fmt.Errorf("the old and new key are both %s", from)
	}
	oldKey, newKey := e.Keys.ByName(from), e.Keys.ByName(to)
	if oldKey == nil {
		return nil, &KeyError{fmt.Sprintf("no key named %s: rekey needs the old key to read the secrets", from)}
	}
	if newKey == nil {
		return nil, fmt.Errorf("no key named %s (create one with `git enc key new %s`)", to, to)
	}

	var blocks []*spec.Block // blocks to switch from `from` to `to`
	var targets []*Secret
	if len(paths) == 0 {
		for _, b := range e.Spec.Blocks {
			if b.Key == from {
				blocks = append(blocks, b)
			}
		}
		if len(blocks) > 0 && e.Spec.Block(to) != nil {
			return nil, fmt.Errorf("a block for key %s already exists; move the lines from the %s block into it by hand, then `git enc rekey %s %s FILE…`", to, from, from, to)
		}
		for _, s := range e.Secrets {
			// Secrets of the blocks being switched, and those a rekey that
			// was interrupted left behind in a `to` block.
			if s.Block != nil && (s.Block.Key == from || s.Block.Key == to) {
				targets = append(targets, s)
			}
		}
		if len(blocks) == 0 && len(targets) == 0 {
			return nil, fmt.Errorf("no git-enc block in .gitignore uses key %s", from)
		}
	} else {
		for _, p := range paths {
			s := e.Secret(p)
			if s == nil || s.Block == nil || s.Block.Key != to {
				return nil, refuse("%s is not declared in a block for key %s; move its line into that block first", p, to)
			}
			targets = appendNew(targets, s)
		}
	}
	for _, b := range blocks {
		if b.Unterminated {
			return nil, fmt.Errorf(".gitignore:%d: block is never ended (add `# git-enc: end`)", b.Start)
		}
	}

	// Read everything before changing anything.
	type job struct {
		s    *Secret
		body []byte
	}
	var jobs []job
	for _, s := range targets {
		if len(s.Unmerged) > 0 {
			return nil, refuse("%s: git has a merge conflict on %s; finish the merge first", s.Path, s.EncPath)
		}
		if s.EncBlob == "" {
			continue // nothing encrypted yet; `git enc add` will use the block's key
		}
		data, err := e.encData(s)
		if err != nil {
			return nil, err
		}
		_, body, err := envelope.Open(data, s.Path, oldKey.Identity)
		if err != nil {
			if _, _, err2 := envelope.Open(data, s.Path, newKey.Identity); err2 == nil {
				continue // already done
			}
			if len(paths) == 0 && s.Block.Key == to {
				continue // was never under the old key
			}
			return nil, refuse("%s cannot be opened with key %s: %v", s.EncPath, from, err)
		}
		jobs = append(jobs, job{s, body})
	}

	var out []string
	if len(blocks) > 0 {
		for _, b := range blocks {
			e.Spec.Lines[b.Start-1] = spec.Header(newKey.Name, newKey.Fingerprint)
		}
		if err := fsx.WriteWorktree(e.Repo.Root, ".gitignore", e.Spec.Bytes(), 0o644); err != nil {
			return nil, err
		}
		if _, err := e.Repo.Git("add", "--", ".gitignore"); err != nil {
			return nil, err
		}
		out = append(out, fmt.Sprintf("switched %s from key %s to %s (%s) in .gitignore", plural(len(blocks), "block"), from, newKey.Name, newKey.Fingerprint))
	}
	for _, j := range jobs {
		if j.s.Block.Key == to && j.s.Block.Fingerprint == "" {
			if err := e.setFingerprint(j.s.Block, newKey.Fingerprint); err != nil {
				return out, err
			}
		}
		if err := e.reseal(j.s, j.body, newKey); err != nil {
			return out, err
		}
		out = append(out, fmt.Sprintf("re-encrypted %s with key %s (staged)", j.s.EncPath, newKey.Name))
	}
	if len(jobs) == 0 {
		out = append(out, "nothing to re-encrypt")
	} else {
		out = append(out, fmt.Sprintf("next: commit, give key %s to the people who should keep access, and change the secrets themselves (anyone with key %s can still read every old version in git history)", newKey.Name, from))
	}
	return out, e.Scan()
}

// reseal writes body, sealed with k, as the worktree F.enc of s and stages it.
func (e *Engine) reseal(s *Secret, body []byte, k *keys.Key) error {
	sealed, err := envelope.Seal(s.Path, body, k.Recipient)
	if err != nil {
		return err
	}
	if err := fsx.WriteWorktree(e.Repo.Root, s.EncPath, sealed, 0o644); err != nil {
		return err
	}
	blob := e.Repo.BlobID(sealed)
	e.Cache.Put(blob, sum(body))
	if _, err := e.Repo.Git("add", "--", ":(literal)"+s.EncPath); err != nil {
		return err
	}
	// The new blob is the same version as the old one, so the plaintext
	// keeps being compared against the same base. What `add` wrote and
	// what the user has seen carry over to the new blob.
	old := s.EncBlob
	if s.entry.Pending == old {
		s.entry.Pending = blob
	}
	if s.entry.Seen == old {
		s.entry.Seen = blob
	}
	return nil
}
