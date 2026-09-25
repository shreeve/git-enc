package engine

import (
	"fmt"
	"path"
	"strings"

	"github.com/shreeve/git-enc/internal/envelope"
	"github.com/shreeve/git-enc/internal/fsx"
	"github.com/shreeve/git-enc/internal/gitx"
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

// stagedPlaintext lists staged files that are secret plaintext: declared
// in a block, managed by this clone before, or an .incoming copy.
func (e *Engine) stagedPlaintext() ([]string, error) {
	out, err := e.Repo.Git("diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT")
	if err != nil {
		return nil, err
	}
	var bad []string
	for _, p := range gitx.SplitZ(out) {
		if strings.HasSuffix(p, ".enc") {
			continue
		}
		name := strings.TrimSuffix(p, ".incoming")
		b, _, err := e.Spec.Match(p)
		if b != nil || err != nil || e.managed(p) || (name != p && e.managed(name)) || isTemp(p) {
			bad = append(bad, p)
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
