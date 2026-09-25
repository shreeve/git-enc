package engine

import (
	"fmt"
	"path"
	"strings"

	"github.com/shreeve/git-enc/internal/envelope"
	"github.com/shreeve/git-enc/internal/fsx"
	"github.com/shreeve/git-enc/internal/gitx"
	"github.com/shreeve/git-enc/internal/spec"
)

// Hook runs one git hook. It returns the lines to print and whether the git
// operation must stop. Only pre-commit (plaintext staged) and, when
// enc.requireAdded is set, pre-commit and pre-push (edits not added) ever
// stop anything.
func (e *Engine) Hook(name string) ([]string, bool) {
	var out []string
	stop := false
	if name == "pre-commit" {
		// If the check cannot run, the commit stops: this guard fails closed.
		bad, err := e.stagedPlaintext()
		if err != nil {
			return []string{"git-enc: cannot check this commit for plaintext secrets: " + err.Error()}, true
		}
		for _, p := range bad {
			out = append(out, fmt.Sprintf("git-enc: refusing to commit the plaintext secret %s\n  unstage it with: git rm --cached -- %s", p, p))
			stop = true
		}
		deleted, err := e.stagedEncDeletions()
		if err != nil {
			return []string{"git-enc: cannot check this commit for plaintext secrets: " + err.Error()}, true
		}
		for _, p := range deleted {
			out = append(out, fmt.Sprintf("git-enc: refusing to delete %s.enc: %s is still declared in .gitignore\n  to stop encrypting it, remove its line from .gitignore too; to keep it: git enc update %s", p, p, p))
			stop = true
		}
		unsealed, err := e.stagedUnsealed()
		if err != nil {
			return []string{"git-enc: cannot check this commit for plaintext secrets: " + err.Error()}, true
		}
		for _, p := range unsealed {
			out = append(out, fmt.Sprintf("git-enc: refusing to commit %s: it is not encrypted (only `git enc add` should write it)\n  unstage it with: git restore --staged -- %s", p, p))
			stop = true
		}
	}
	require := e.Repo.ConfigBool("enc.requireAdded", false)
	switch name {
	case "pre-commit", "pre-push":
		if pending := e.kinds(New, Modified); len(pending) > 0 {
			verb := "not added"
			if require {
				stop = true
				verb = "not added (enc.requireAdded is set)"
			}
			out = append(out, fmt.Sprintf("git-enc: %s edited but %s: %s — run `git enc add`", plural(len(pending), "secret"), verb, list(pending)))
		}
	default:
		out = append(out, e.Reminders()...)
	}
	return out, stop
}

// OutgoingPlaintext lists secret plaintext in the commits a push would send.
// refs is the pre-push hook's input: "<local ref> <local sha> <remote ref>
// <remote sha>" per line. Commits any remote already has are left out:
// what they hold has left this machine either way.
func (e *Engine) OutgoingPlaintext(refs string) ([]string, error) {
	var tips []string
	for _, line := range strings.Split(refs, "\n") {
		f := strings.Fields(line)
		if len(f) == 4 && strings.Trim(f[1], "0") != "" {
			tips = append(tips, f[1])
		}
	}
	if len(tips) == 0 {
		return nil, nil
	}
	args := append([]string{"log", "--format=", "--name-only", "-z", "--no-renames", "--diff-filter=ACMRT"}, tips...)
	out, err := e.Repo.Git(append(args, "--not", "--remotes")...)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var bad []string
	for _, p := range gitx.SplitZ(out) {
		p = strings.TrimLeft(p, "\n")
		if p == "" || seen[p] || strings.HasSuffix(p, ".enc") {
			continue
		}
		seen[p] = true
		name := strings.TrimSuffix(p, ".incoming")
		if b, _, err := e.Spec.Match(p); b != nil || err != nil || e.managed(p) || (name != p && e.managed(name)) || isTemp(p) {
			bad = append(bad, p)
		}
	}
	return bad, nil
}

// SameSecrets reports whether commits a and b (a post-checkout hook's
// arguments) have the same .enc files and root .gitignore, so a switch
// between them changed nothing the reminders are about. It costs one
// `git diff-tree` and never opens the repository; any doubt (a null id
// after a clone, an error) answers false.
func SameSecrets(dir, a, b string) bool {
	if a == b {
		return true
	}
	out, err := gitx.Run(dir, nil, "diff-tree", "-r", "-z", "--no-renames", "--name-only", a, b)
	if err != nil {
		return false
	}
	for _, p := range gitx.SplitZ(out) {
		if p == ".gitignore" || strings.HasSuffix(p, ".enc") {
			return false
		}
	}
	return true
}

// Reminders describes secrets that need `git enc update` or attention.
func (e *Engine) Reminders() []string {
	var out []string
	if l := e.kinds(Outdated, Missing); len(l) > 0 {
		out = append(out, fmt.Sprintf("git-enc: %s changed in git: %s — run `git enc update`", plural(len(l), "secret"), list(l)))
	}
	if l := e.kinds(Conflict, Diverged); len(l) > 0 {
		out = append(out, fmt.Sprintf("git-enc: %s changed both here and in git: %s — run `git enc update` to see both", plural(len(l), "secret"), list(l)))
	}
	if l := e.kinds(Merging); len(l) > 0 {
		out = append(out, fmt.Sprintf("git-enc: merge conflict on %s — run `git enc merge`", list(l)))
	}
	if l := e.kinds(NoKey); len(l) > 0 {
		out = append(out, fmt.Sprintf("git-enc: no key for %s — see `git enc status`", list(l)))
	}
	return out
}

// stagedPlaintext lists staged files that are secret plaintext: matched by
// a line of a block (as git itself reads it, or as git-enc does), managed
// by this clone before, or an .incoming or temporary copy.
func (e *Engine) stagedPlaintext() ([]string, error) {
	out, err := e.Repo.Git("diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT")
	if err != nil {
		return nil, err
	}
	staged := gitx.SplitZ(out)
	if len(staged) == 0 {
		return nil, nil
	}
	byGit, err := e.blockMatches()
	if err != nil {
		return nil, err
	}
	var bad []string
	for _, p := range staged {
		if strings.HasSuffix(p, ".enc") {
			continue
		}
		name := strings.TrimSuffix(p, ".incoming")
		b, _, err := e.Spec.Match(p)
		if b != nil || err != nil || byGit[p] || e.managed(p) || (name != p && e.managed(name)) || isTemp(p) {
			bad = append(bad, p)
		}
	}
	return bad, nil
}

// blockMatches lists the files in the index that git matches with the lines
// of the git-enc blocks, including lines git-enc refuses (`secrets/`,
// `[[:digit:]]`…): whatever git-enc thinks of them, git ignores those
// files, so they are secrets. `!` lines are left out: in a block they
// would only un-declare a secret.
func (e *Engine) blockMatches() (map[string]bool, error) {
	args := []string{"ls-files", "-z", "--cached", "--ignored"}
	for _, b := range e.Spec.Blocks {
		for _, l := range b.Lines {
			if !strings.HasPrefix(l, "!") {
				args = append(args, "--exclude="+spec.TrimTrailingSpace(l))
			}
		}
	}
	res := map[string]bool{}
	if len(args) == 4 {
		return res, nil
	}
	out, err := e.Repo.Git(args...)
	if err != nil {
		return nil, err
	}
	for _, p := range gitx.SplitZ(out) {
		res[p] = true
	}
	return res, nil
}

// stagedEncDeletions lists secrets still declared in a block whose F.enc
// the commit would delete: the only encrypted copy of a secret someone
// still relies on.
func (e *Engine) stagedEncDeletions() ([]string, error) {
	out, err := e.Repo.Git("diff", "--cached", "--name-only", "-z", "--no-renames", "--diff-filter=D")
	if err != nil {
		return nil, err
	}
	var bad []string
	for _, p := range gitx.SplitZ(out) {
		name := strings.TrimSuffix(p, ".enc")
		if name == p {
			continue
		}
		if b, _, _ := e.Spec.Match(name); b != nil {
			bad = append(bad, name)
		}
	}
	return bad, nil
}

// stagedUnsealed lists staged .enc files of secrets that are not age files:
// plaintext copied over one (`cp .env .env.enc`) would otherwise be
// committed, since the plaintext check skips .enc names.
func (e *Engine) stagedUnsealed() ([]string, error) {
	var ids []string
	for _, s := range e.Secrets {
		if s.Staged {
			ids = append(ids, s.IndexBlob)
		}
	}
	blobs, err := e.Repo.Blobs(ids)
	if err != nil {
		return nil, err
	}
	var bad []string
	for _, s := range e.Secrets {
		if s.Staged && !envelope.IsSealed(blobs[s.IndexBlob]) {
			bad = append(bad, s.EncPath)
		}
	}
	return bad, nil
}

// isTemp reports git-enc's own temporary files, which may hold plaintext.
func isTemp(p string) bool {
	ok, _ := path.Match(fsx.TempPattern, path.Base(p))
	return ok
}

func (e *Engine) kinds(ks ...Kind) []string {
	var out []string
	for _, s := range e.Secrets {
		for _, k := range ks {
			if s.Kind == k {
				out = append(out, s.Path)
			}
		}
	}
	return out
}

func list(paths []string) string {
	if len(paths) > 3 {
		return strings.Join(paths[:3], ", ") + fmt.Sprintf(", and %d more", len(paths)-3)
	}
	return strings.Join(paths, ", ")
}
