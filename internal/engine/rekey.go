package engine

import (
	"fmt"

	"github.com/shreeve/git-enc/internal/envelope"
	"github.com/shreeve/git-enc/internal/fsx"
	"github.com/shreeve/git-enc/internal/spec"
)

// Rekey re-encrypts, with its block's key, every secret whose .enc only
// another of the user's keys can open. With from and to, it first switches
// every block for key `from` to key `to` (rotating a key); without them it
// finishes a change made by hand, such as moving a line to another block.
//
// It re-seals the version in F.enc, never the plaintext, so an edit stays
// an edit and an outdated copy stays outdated.
func (e *Engine) Rekey(from, to string) ([]string, error) {
	var out []string
	if from != "" {
		msg, err := e.switchKey(from, to)
		if err != nil {
			return nil, err
		}
		out = append(out, msg)
		if err := e.Scan(); err != nil {
			return out, err
		}
	}
	n := 0
	for _, s := range e.Secrets {
		if s.OtherKey == nil {
			continue
		}
		if err := e.rekeyOne(s); err != nil {
			return out, err
		}
		out = append(out, fmt.Sprintf("re-encrypted %s with key %s (was %s; staged)", s.EncPath, s.Key.Name, s.OtherKey.Name))
		n++
	}
	if n == 0 {
		out = append(out, "nothing to re-encrypt")
	}
	return out, e.Scan()
}

// switchKey points every block for key `from` at key `to`.
func (e *Engine) switchKey(from, to string) (string, error) {
	if from == to {
		return "", fmt.Errorf("the old and new key are both %s", from)
	}
	k := e.Keys.ByName(to)
	if k == nil {
		return "", fmt.Errorf("no key named %s (create one with `git enc key new %s`)", to, to)
	}
	var blocks []*spec.Block
	for _, b := range e.Spec.Blocks {
		if b.Key == from {
			blocks = append(blocks, b)
		}
	}
	if len(blocks) == 0 {
		return "", fmt.Errorf("no git-enc block in .gitignore uses key %s", from)
	}
	for _, b := range blocks {
		if b.Unterminated {
			return "", fmt.Errorf(".gitignore:%d: block is never ended (add `# git-enc: end`)", b.Start)
		}
		// Every secret must be readable before anything changes.
		for _, s := range e.Secrets {
			if s.Block == b && s.EncBlob != "" && len(s.Unmerged) == 0 && s.Key == nil {
				return "", &KeyError{fmt.Sprintf("%s: %s; git enc rekey needs the old key to re-encrypt it", s.Path, e.noKeyMessage(b))}
			}
		}
	}
	for _, b := range blocks {
		e.Spec.Lines[b.Start-1] = spec.Header(k.Name, k.Fingerprint)
	}
	if err := fsx.WriteWorktree(e.Repo.Root, ".gitignore", e.Spec.Bytes(), 0o644); err != nil {
		return "", err
	}
	if _, err := e.Repo.Git("add", "--", ".gitignore"); err != nil {
		return "", err
	}
	return fmt.Sprintf("switched %s from key %s to %s (%s) in .gitignore", plural(len(blocks), "block"), from, k.Name, k.Fingerprint), nil
}

// rekeyOne re-seals the worktree F.enc of s with its block's key.
func (e *Engine) rekeyOne(s *Secret) error {
	data, err := e.encData(s)
	if err != nil {
		return err
	}
	_, body, err := envelope.Open(data, s.Path, s.OtherKey.Identity)
	if err != nil {
		return fmt.Errorf("%s: %v", s.EncPath, err)
	}
	if s.Block.Fingerprint == "" {
		if err := e.setFingerprint(s.Block, s.Key.Fingerprint); err != nil {
			return err
		}
	}
	sealed, err := envelope.Seal(s.Path, body, s.Key.Recipient)
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
