package engine

import (
	"fmt"
	"strings"

	"github.com/shreeve/git-enc/internal/envelope"
	"github.com/shreeve/git-enc/internal/gitx"
)

// Verify checks the repository the way CI can: with no key, and whatever
// hooks anyone ran or skipped. It is the server's half of the hooks. It
// reports every problem `git enc status` would (a secret git does not
// ignore, one .gitignore points at another block's key…), any plaintext or
// git-enc copy in the index, and any secret's .enc that is not an
// encrypted file. With a revision range (the commits a
// pull request adds, say `origin/main..HEAD`) it also checks every file
// those commits add or change, so plaintext committed and then deleted
// again still fails.
func (e *Engine) Verify(revRange string) ([]string, error) {
	var out []string
	for _, p := range e.Problems {
		where := p.Path
		if p.Line > 0 {
			where = fmt.Sprintf("%s:%d", p.Path, p.Line)
		}
		out = append(out, fmt.Sprintf("%s: %s", where, p.Message))
	}
	tracked, err := e.Repo.Git("ls-files", "-z", "--cached")
	if err != nil {
		return nil, err
	}
	byGit, err := e.blockMatches()
	if err != nil {
		return nil, err
	}
	reported := map[string]bool{}
	for _, p := range e.Problems {
		reported[p.Path] = true
	}
	for _, p := range gitx.SplitZ(tracked) {
		if e.plaintextPath(p, byGit) && !reported[p] {
			out = append(out, p+": a secret's plaintext is committed")
		}
	}
	var ids []string
	var encs []*Secret
	for _, s := range e.Secrets {
		if s.IndexBlob != "" {
			ids = append(ids, s.IndexBlob)
			encs = append(encs, s)
		}
	}
	blobs, err := e.Repo.Blobs(ids)
	if err != nil {
		return nil, err
	}
	for _, s := range encs {
		if !envelope.IsSealed(blobs[s.IndexBlob]) {
			out = append(out, s.EncPath+": not an encrypted file")
		}
	}

	if revRange != "" {
		more, err := e.verifyCommits(revRange)
		if err != nil {
			return nil, err
		}
		out = append(out, more...)
	}
	return out, nil
}

// verifyCommits checks every file the commits in revRange add or change.
func (e *Engine) verifyCommits(revRange string) ([]string, error) {
	if strings.HasPrefix(revRange, "-") {
		return nil, fmt.Errorf("%q is not a revision range", revRange)
	}
	raw, err := e.Repo.Git("log", "--format=", "--raw", "-z", "--no-abbrev", "--no-renames", "--diff-filter=ACMRT", revRange, "--")
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	sealed := map[string]string{} // blob -> .enc path
	fields := gitx.SplitZ(raw)
	for i := 0; i+1 < len(fields); i++ {
		// -z raw records: ":mode mode old new status\0path\0"
		rec := strings.TrimLeft(fields[i], "\n")
		if !strings.HasPrefix(rec, ":") {
			continue
		}
		f := strings.Fields(rec)
		p := fields[i+1]
		i++
		if len(f) < 5 || seen[p+" "+f[3]] {
			continue
		}
		seen[p+" "+f[3]] = true
		if name := strings.TrimSuffix(p, ".enc"); name != p {
			if b, _, _ := e.Spec.Match(name); b != nil {
				sealed[f[3]] = p
			}
			continue
		}
		if e.plaintextPath(p, nil) && !seen[p] {
			seen[p] = true
			out = append(out, p+": a secret's plaintext is in a commit of "+revRange)
		}
	}
	var ids []string
	for id := range sealed {
		ids = append(ids, id)
	}
	blobs, err := e.Repo.Blobs(ids)
	if err != nil {
		return nil, err
	}
	for id, p := range sealed {
		if !envelope.IsSealed(blobs[id]) {
			out = append(out, fmt.Sprintf("%s: a commit of %s has a version that is not an encrypted file (blob %s)", p, revRange, id[:12]))
		}
	}
	return out, nil
}

// rollbackWarning explains when updating s would take it back to a value
// its history had before a different one: nobody without the key can see
// what a .enc holds, but anyone who can push can commit an older .enc (of
// a secret that was changed because it leaked, say) over a newer one.
// Versions this user cannot decrypt only count when they are the same
// blob.
func (e *Engine) rollbackWarning(s *Secret) string {
	if s.Key == nil || s.EncHash == "" {
		return ""
	}
	versions, err := e.Repo.Versions(s.EncPath)
	if err != nil || len(versions) < 3 {
		return ""
	}
	var missing []string
	for _, b := range versions {
		if _, ok := e.Cache.Hashes[b]; !ok {
			missing = append(missing, b)
		}
	}
	blobs, err := e.Repo.Blobs(missing)
	if err != nil {
		return ""
	}
	same := func(b string) (same, known bool) {
		if b == s.EncBlob {
			return true, true
		}
		h, err := e.hashOf(s, b, blobs)
		return err == nil && h == s.EncHash, err == nil
	}
	// Newest first: the current value, then a different one, then the
	// current value again further back.
	i := 0
	for i < len(versions) && versions[i] != s.EncBlob {
		i++
	}
	changed := false
	for _, b := range versions[i+1:] {
		switch eq, known := same(b); {
		case eq && changed:
			return fmt.Sprintf("warning: the committed %s takes %s back to a value it had before, not a new one; if nobody meant to revert it, it may have been rolled back (see `git log -- %s`)", s.EncPath, s.Path, s.EncPath)
		case known && !eq:
			changed = true
		}
	}
	return ""
}
