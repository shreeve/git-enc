package engine

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/shreeve/git-enc/internal/fsx"
	"github.com/shreeve/git-enc/internal/spec"
)

// AttrLine keeps git from treating ciphertext as text (line-ending
// conversion would corrupt it, and a text merge would write conflict
// markers into it), names the diff driver `git enc reveal` will use, and
// makes git (and GitHub Desktop) handle .enc conflicts as binary files.
const AttrLine = "*.enc -text diff=git-enc merge=binary"

// ensureAttributes adds AttrLine to the root .gitattributes and stages it.
func (e *Engine) ensureAttributes() error {
	data, err := fsx.ReadRegular(e.Repo.Root, ".gitattributes")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == AttrLine {
			return nil
		}
	}
	var b bytes.Buffer
	b.Write(data)
	if len(data) > 0 && !bytes.HasSuffix(data, []byte("\n")) {
		b.WriteByte('\n')
	}
	b.WriteString("# git-enc: encrypted secrets are binary\n" + AttrLine + "\n")
	if err := fsx.WriteWorktree(e.Repo.Root, ".gitattributes", b.Bytes(), 0o644); err != nil {
		return err
	}
	_, err = e.Repo.Git("add", "--", ".gitattributes")
	return err
}

const (
	excludeBegin = "# >>> git-enc: secrets this clone manages (keeps them out of commits; do not edit)"
	excludeEnd   = "# <<< git-enc"
)

// syncExclude lists every plaintext git-enc has managed, and its
// .incoming file, in .git/info/exclude. Those stay ignored even on a branch
// whose .gitignore lacks the block, or after a teammate removes one, so
// they can never be committed by accident. The list only grows.
func (e *Engine) syncExclude() error {
	file, err := e.Repo.GitPath("info/exclude")
	if err != nil {
		return err
	}
	data, err := os.ReadFile(file)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(data) == 0 {
		lines = nil
	}
	var before, after []string
	entries := map[string]bool{}
	in, seen := false, false
	for _, l := range lines {
		switch {
		case l == excludeBegin:
			in, seen = true, true
		case l == excludeEnd && in:
			in = false
		case in:
			if l != "" {
				entries[l] = true
			}
		case seen:
			after = append(after, l)
		default:
			before = append(before, l)
		}
	}
	entries[fsx.TempPattern] = true
	for _, p := range e.State.Managed {
		if spec.CheckPath(p) == nil {
			entries[spec.EscapePath(p)] = true
			entries[spec.EscapePath(p+".incoming")] = true
		}
	}
	var list []string
	for l := range entries {
		list = append(list, l)
	}
	sort.Strings(list)
	var out []string
	out = append(out, before...)
	if len(before) > 0 && before[len(before)-1] != "" {
		out = append(out, "")
	}
	out = append(out, excludeBegin)
	out = append(out, list...)
	out = append(out, excludeEnd)
	out = append(out, after...)
	text := strings.Join(out, "\n") + "\n"
	if text == string(data) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	return fsx.WriteAtomic(file, []byte(text), 0o644)
}

// HookNames are the hooks `git enc init` installs. None of them encrypts
// or decrypts anything: pre-commit refuses to commit plaintext, and the
// rest only remind.
var HookNames = []string{"pre-commit", "pre-push", "post-checkout", "post-merge", "post-rewrite"}

const (
	hookMarker  = "# git-enc hook"
	hookVersion = "# git-enc hook version 2" // bump when hookScript changes
)

func hookScript(name, binary string) string {
	// The binary is called by absolute path: GitHub Desktop started from the
	// Dock may not have Homebrew on PATH.
	onFail := "exit $?"
	if name != "pre-commit" && name != "pre-push" {
		onFail = ":"
	}
	if name == "pre-push" {
		// git-enc and the chained hook both read the refs being pushed.
		return fmt.Sprintf(`#!/bin/sh
%s (installed by `+"`git enc init`"+`; safe to delete)
%s
GIT_ENC=%s
input=$(cat)
if [ -x "$GIT_ENC" ]; then
	printf '%%s' "$input" | "$GIT_ENC" hook %s "$@" || %s
else
	echo "git-enc: $GIT_ENC not found; reinstall git-enc, then run 'git enc init'" >&2
fi
if [ -x "$0.git-enc-chained" ]; then
	if [ -n "$input" ]; then printf '%%s
' "$input"; fi | "$0.git-enc-chained" "$@"
	exit $?
fi
`, hookMarker, hookVersion, shellQuote(binary), name, onFail)
	}
	// stdin goes to the chained hook, not to git-enc (post-rewrite reads
	// its input there).
	return fmt.Sprintf(`#!/bin/sh
%s (installed by `+"`git enc init`"+`; safe to delete)
%s
GIT_ENC=%s
if [ -x "$GIT_ENC" ]; then
	"$GIT_ENC" hook %s "$@" </dev/null || %s
else
	echo "git-enc: $GIT_ENC not found; reinstall git-enc, then run 'git enc init'" >&2
fi
if [ -x "$0.git-enc-chained" ]; then
	exec "$0.git-enc-chained" "$@"
fi
`, hookMarker, hookVersion, shellQuote(binary), name, onFail)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// installHooks writes the hooks, keeping any existing hook by chaining to it.
func (e *Engine) installHooks(binary string) ([]string, error) {
	dir, err := e.Repo.GitPath("hooks")
	if err != nil {
		return nil, err
	}
	var out []string
	if hp := e.Repo.Config("core.hooksPath"); hp != "" {
		// A shared hooks directory (a hook manager, or a global one that
		// serves every repository) is not git-enc's to rewrite.
		return []string{fmt.Sprintf("hooks not installed: core.hooksPath is set (%s).\n  Call `%s hook <name> \"$@\"` from its pre-commit, pre-push, post-checkout, post-merge and post-rewrite hooks.", hp, binary)}, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	for _, name := range HookNames {
		file := filepath.Join(dir, name)
		if data, err := os.ReadFile(file); err == nil && !bytes.Contains(data, []byte(hookMarker)) {
			chained := file + ".git-enc-chained"
			if _, err := os.Stat(chained); err == nil {
				return out, fmt.Errorf("%s exists and is not git-enc's, and %s is taken too; merge them by hand", file, chained)
			}
			if err := os.Rename(file, chained); err != nil {
				return out, err
			}
			out = append(out, fmt.Sprintf("kept your existing %s hook (it now runs after git-enc's)", name))
		}
		if err := fsx.WriteAtomic(file, []byte(hookScript(name, binary)), 0o755); err != nil {
			return out, err
		}
	}
	return out, nil
}

// HooksInstalled reports whether every git-enc hook is in place and
// current (an older one lacks checks; `git enc init` updates it).
func (e *Engine) HooksInstalled() bool {
	dir, err := e.Repo.GitPath("hooks")
	if err != nil {
		return false
	}
	for _, name := range HookNames {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Contains(data, []byte(hookVersion)) {
			return false
		}
	}
	return true
}

// Init prepares this clone: attributes, hooks, the exclude list, and the
// plaintext of every secret the user has a key for and does not have yet.
func (e *Engine) Init(binary string) ([]string, error) {
	var out []string
	if len(e.Spec.Blocks) > 0 {
		if err := e.ensureAttributes(); err != nil {
			return out, err
		}
	}
	msgs, err := e.installHooks(binary)
	out = append(out, msgs...)
	if err != nil {
		return out, err
	}
	if err := e.installDriver(binary); err != nil {
		return out, err
	}
	out = append(out, "set up merging: git merges secrets by their plaintext in this clone")
	if e.HooksInstalled() {
		out = append(out, "installed hooks (they remind; they never encrypt or decrypt)")
	}
	var missing []string
	for _, s := range e.Secrets {
		if s.Kind == Missing {
			missing = append(missing, s.Path)
		}
	}
	if len(missing) > 0 {
		msgs, err := e.Update(missing, UpdateOptions{})
		out = append(out, msgs...)
		if err != nil {
			return out, err
		}
	}
	skip := e.SkippedKeys()
	for _, b := range e.Spec.Blocks {
		if e.blockKey(b) == nil && !skip[b.Key] {
			out = append(out, fmt.Sprintf("%s: import it with `git enc key add %s` (paste the key, then Ctrl-D), then run `git enc update`", e.noKeyMessage(b), b.Key))
		}
	}
	if len(e.Spec.Blocks) == 0 {
		out = append(out, "no secrets yet: `git enc key new NAME`, then `git enc add --key NAME FILE`")
	}
	return out, nil
}
