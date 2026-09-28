package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shreeve/git-enc/internal/fsx"
)

// GitHub Desktop shows a hook's output only when the hook fails, in a
// dialog ("The pre-commit hook failed. What would you like to do?") with
// the output in a terminal, and two buttons: Ignore and Continue, and
// Abort. The output of a hook that succeeds, and of every hook after a
// pull or a checkout, it never shows.
//
// So under Desktop the commit and push hooks show one list, with a mark
// per secret:
//
//	✘  blocks, every time (plaintext staged, an edit not encrypted…)
//	!  needs you (a conflict, a missing key, a rollback), shown once:
//	   after that, the commit goes ahead
//	✔  what git-enc did since the last list (secrets a pull updated)
//
// The hooks after a pull or a checkout leave what they did and saw in
// .git/git-enc/desktop.json for the next list, since nobody sees theirs.

// note is one line of that list.
type note struct {
	Key  string `json:"key"` // the same thing has the same key: "!" shows once
	Mark string `json:"mark"`
	Path string `json:"path"`
	Text string `json:"text"`
	Hint string `json:"hint,omitempty"` // what to run
}

// desktopFile is what the hooks keep between Desktop's operations.
type desktopFile struct {
	Pending []note   `json:"pending"` // from hooks after a pull or checkout
	Shown   []string `json:"shown"`   // keys of "!" notes already shown
	// Notified: keys of problems a system notification already told of.
	Notified []string `json:"notified,omitempty"`
}

const (
	markStop = "✘"
	markNeed = "!"
	markDone = "✔"
)

func (e *Engine) desktopPath() string { return filepath.Join(e.baseDir, "desktop.json") }

func (e *Engine) loadDesktop() *desktopFile {
	var d desktopFile
	if data, err := os.ReadFile(e.desktopPath()); err == nil {
		_ = json.Unmarshal(data, &d)
	}
	return &d
}

// saveDesktop writes the file. It is only ever a record of what to tell
// the user, so hooks write it without the lock, and a failure is ignored.
func (e *Engine) saveDesktop(d *desktopFile) {
	if len(d.Shown) > 200 {
		d.Shown = d.Shown[len(d.Shown)-200:]
	}
	if len(d.Notified) > 200 {
		d.Notified = d.Notified[len(d.Notified)-200:]
	}
	if data, err := json.MarshalIndent(d, "", "  "); err == nil && os.MkdirAll(e.baseDir, 0o700) == nil {
		_ = fsx.WriteAtomic(e.desktopPath(), append(data, '\n'), 0o600)
	}
}

// RecordForDesktop keeps, for the next commit or push under Desktop, what
// a hook after a pull or checkout did (secrets it updated, and which of
// them went back to an earlier value).
func (e *Engine) RecordForDesktop(what string) {
	if len(e.updated) == 0 && len(e.rolledBack) == 0 {
		return
	}
	d := e.loadDesktop()
	for _, s := range e.updated {
		d.Pending = append(d.Pending, note{Key: "updated|" + s.Path + "|" + s.EncBlob, Mark: markDone, Path: s.Path, Text: "updated after the " + what})
	}
	for _, s := range e.rolledBack {
		d.Pending = append(d.Pending, note{Key: "rollback|" + s.Path + "|" + s.EncBlob, Mark: markNeed, Path: s.Path,
			Text: "the " + what + " took it back to an earlier value; if nobody meant to revert it, it was rolled back", Hint: "git log -- " + s.EncPath})
	}
	e.saveDesktop(d)
}

// DesktopReport is the pre-commit or pre-push hook under GitHub Desktop:
// the text to show, and whether to fail (so that Desktop shows it). refs
// is pre-push's input. Like the hooks elsewhere, it fails closed.
func (e *Engine) DesktopReport(name, refs string) (string, bool, error) {
	var notes []note
	stop := func(path, text, hint string) {
		notes = append(notes, note{Mark: markStop, Path: path, Text: text, Hint: hint})
	}
	if name == "pre-commit" {
		plain, err := e.stagedPlaintext()
		if err != nil {
			return "", true, err
		}
		for _, p := range plain {
			stop(p, "a secret's plaintext is staged", "git rm --cached -- "+p)
		}
		deleted, err := e.stagedEncDeletions()
		if err != nil {
			return "", true, err
		}
		for _, p := range deleted {
			stop(p, p+".enc would be deleted, but it is still declared", "git enc update "+p)
		}
		oneSided, err := e.stagedOneSided()
		if err != nil {
			return "", true, err
		}
		for _, p := range oneSided {
			stop(p, "the merge keeps one side whole and drops the other's change", "git checkout -m -- "+p+".enc && git enc merge "+p)
		}
		unsealed, err := e.stagedUnsealed()
		if err != nil {
			return "", true, err
		}
		for _, p := range unsealed {
			stop(p, "not encrypted (only `git enc add` should write it)", "git restore --staged -- "+p)
		}
	}
	if name == "pre-push" {
		bad, err := e.OutgoingPlaintext(refs)
		if err != nil {
			return "", true, err
		}
		for _, p := range bad {
			stop(p, "a commit being pushed contains this plaintext", "git log --oneline --not --remotes -- "+p)
		}
	}
	require := e.Repo.ConfigBool("enc.requireAdded", true)
	for _, s := range e.Secrets {
		if s.Skipped {
			continue
		}
		key := s.Path + "|" + string(s.Kind) + "|" + s.EncBlob
		switch s.Kind {
		case New, Modified:
			text := "edited, but not encrypted: Desktop can't see it until you add it"
			if require {
				stop(s.Path, text, "git enc add "+s.Path)
			} else {
				notes = append(notes, note{Key: key, Mark: markNeed, Path: s.Path, Text: text, Hint: "git enc add " + s.Path})
			}
		case Outdated, Missing, Conflict, Diverged, Merging, NoKey, Corrupt:
			notes = append(notes, note{Key: key, Mark: markNeed, Path: s.Path, Text: shortState(s), Hint: s.Action})
		}
	}

	d := e.loadDesktop()
	notes = append(notes, d.Pending...)
	shown := map[string]bool{}
	for _, k := range d.Shown {
		shown[k] = true
	}
	var list []note
	fail, seen := false, 0
	for _, n := range notes {
		switch {
		case n.Mark == markStop:
			fail = true
		case n.Mark == markNeed && shown[n.Key]:
			seen++
			continue // seen already: don't stop the commit for it again
		case n.Mark == markNeed:
			fail = true
			d.Shown = append(d.Shown, n.Key)
		}
		list = append(list, n)
	}
	d.Pending = nil
	e.saveDesktop(d)
	return renderDesktop(name, list, len(e.Secrets), seen, fail), fail, nil
}

// shortState says in a few words what a secret's state means.
func shortState(s *Secret) string {
	switch s.Kind {
	case Outdated:
		return "changed in git; your copy is older"
	case Missing:
		return "not here yet (or its .enc was deleted)"
	case Conflict:
		return "you edited it, and it changed in git too"
	case Diverged:
		return "matches no committed version; git-enc won't guess"
	case Merging:
		return "git has a merge conflict on " + s.EncPath
	case NoKey:
		if s.Block != nil {
			return "no key " + s.Block.Key + " on this machine"
		}
	}
	return s.Message
}

// renderDesktop draws the list for Desktop's terminal (80 columns, colors).
// seen counts secrets that still need the user but were shown before.
func renderDesktop(name string, notes []note, secrets, seen int, fail bool) string {
	const (
		bold   = "\x1b[1m"
		dim    = "\x1b[2m"
		red    = "\x1b[31m"
		yellow = "\x1b[33m"
		green  = "\x1b[32m"
		reset  = "\x1b[0m"
	)
	var b strings.Builder
	if len(notes) == 0 && seen > 0 {
		fmt.Fprintf(&b, "%s%s%s git-enc: %s still %s you (shown before; `git enc status` in a terminal lists %s)\n",
			yellow, markNeed, reset, plural(seen, "secret"), pick(seen == 1, "needs", "need"), pick(seen == 1, "it", "them"))
		return b.String()
	}
	if len(notes) == 0 {
		fmt.Fprintf(&b, "%s%s%s git-enc: %s, all encrypted and current\n", green, markDone, reset, plural(secrets, "secret"))
		return b.String()
	}
	stops, needs := 0, 0
	width := 4
	for _, n := range notes {
		width = max(width, min(len(n.Path), 24))
		switch n.Mark {
		case markStop:
			stops++
		case markNeed:
			needs++
		}
	}
	what := "commit"
	if name == "pre-push" {
		what = "push"
	}
	switch {
	case stops > 0:
		fmt.Fprintf(&b, "%sgit-enc: this %s is stopped%s\n", bold, what, reset)
	case needs > 0:
		fmt.Fprintf(&b, "%sgit-enc: before this %s, %s you%s\n", bold, what, plural(needs, "secret")+" "+pick(needs == 1, "needs", "need"), reset)
	default:
		fmt.Fprintf(&b, "%sgit-enc%s\n", bold, reset)
	}
	for _, n := range notes {
		color := map[string]string{markStop: red, markNeed: yellow, markDone: green}[n.Mark]
		fmt.Fprintf(&b, " %s%s%s %-*s  %s\n", color, n.Mark, reset, width, n.Path, n.Text)
		if n.Hint != "" {
			fmt.Fprintf(&b, "   %-*s  %sin a terminal: %s%s\n", width, "", dim, n.Hint, reset)
		}
	}
	// Desktop's dialog is 80 columns wide, and its buttons depend on its
	// settings: with its hook handling on (GITHUB_DESKTOP set), "Ignore and
	// Continue" and "Abort"; with it off, only "Close".
	buttons := os.Getenv("GITHUB_DESKTOP") != ""
	switch {
	case stops > 0 && buttons:
		fmt.Fprintf(&b, "%sAbort, fix each %s, and %s again.\nIgnore and Continue would %s it as it is.%s\n", dim, markStop, what, what, reset)
	case stops > 0:
		fmt.Fprintf(&b, "%sFix each %s, then %s again.%s\n", dim, markStop, what, reset)
	case fail && buttons:
		fmt.Fprintf(&b, "%sIgnore and Continue to go ahead: git-enc won't stop you for these again.%s\n", dim, reset)
	case fail:
		fmt.Fprintf(&b, "%s%s again to go ahead: git-enc won't stop you for these again.%s\n", dim, strings.ToUpper(what[:1])+what[1:], reset)
	}
	return b.String()
}

func pick(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}
