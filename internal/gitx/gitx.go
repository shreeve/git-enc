// Package gitx runs git. Every git-enc operation that reads or changes a
// repository goes through here, so the git binary on PATH is the single
// source of truth for ignore rules, the index, and history.
package gitx

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Error is a failed git command, with its stderr.
type Error struct {
	Args   []string
	Stderr string
	Err    error
}

func (e *Error) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	if msg == "" {
		msg = e.Err.Error()
	}
	return fmt.Sprintf("git %s: %s", strings.Join(e.Args, " "), msg)
}

func (e *Error) Unwrap() error { return e.Err }

// ExitCode returns the git exit status, or -1 if git did not run.
func (e *Error) ExitCode() int {
	var ee *exec.ExitError
	if errors.As(e.Err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// Run runs git in dir with the given stdin (may be nil).
func Run(dir string, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return out.Bytes(), &Error{Args: args, Stderr: errb.String(), Err: err}
	}
	return out.Bytes(), nil
}

// Repo is a non-bare git worktree.
type Repo struct {
	Root      string // absolute worktree top level
	GitDir    string // absolute, per worktree
	CommonDir string // absolute, shared by all worktrees
	sha256    bool   // the repository uses SHA-256 object ids
}

// Open finds the repository containing dir.
func Open(dir string) (*Repo, error) {
	out, err := Run(dir, nil, "rev-parse", "--path-format=absolute",
		"--is-bare-repository", "--show-toplevel", "--git-dir", "--git-common-dir")
	if err != nil {
		if old := checkVersion(dir); old != nil {
			return nil, old
		}
		// git's own words: not a repository, dubious ownership, bad config…
		var ge *Error
		if errors.As(err, &ge) && strings.TrimSpace(ge.Stderr) != "" {
			return nil, errors.New(strings.TrimPrefix(strings.TrimSpace(ge.Stderr), "fatal: "))
		}
		return nil, fmt.Errorf("cannot run git: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) >= 1 && lines[0] == "true" {
		return nil, fmt.Errorf("git-enc needs a worktree; this is a bare repository")
	}
	if len(lines) != 4 || lines[1] == "" {
		if old := checkVersion(dir); old != nil {
			return nil, old
		}
		return nil, fmt.Errorf("not inside a git worktree")
	}
	r := &Repo{Root: lines[1], GitDir: lines[2], CommonDir: lines[3]}
	if f, err := r.Git("rev-parse", "--show-object-format"); err == nil && strings.TrimSpace(string(f)) == "sha256" {
		r.sha256 = true
	}
	return r, nil
}

// MinVersion is the oldest git git-enc works with (for `rev-parse
// --path-format`).
var MinVersion = [2]int{2, 31}

// checkVersion returns an error if git is older than MinVersion. It is only
// consulted to explain a failure, so it costs nothing when git works.
func checkVersion(dir string) error {
	out, err := Run(dir, nil, "version")
	if err != nil {
		return nil
	}
	// "git version 2.39.3 (Apple Git-145)"
	f := strings.Fields(string(out))
	if len(f) < 3 {
		return nil
	}
	var major, minor int
	if _, err := fmt.Sscanf(f[2], "%d.%d", &major, &minor); err != nil {
		return nil
	}
	if major < MinVersion[0] || major == MinVersion[0] && minor < MinVersion[1] {
		return fmt.Errorf("git-enc needs git %d.%d or later; this is git %s", MinVersion[0], MinVersion[1], f[2])
	}
	return nil
}

// Git runs git at the worktree root.
func (r *Repo) Git(args ...string) ([]byte, error) { return Run(r.Root, nil, args...) }

// GitIn runs git at the worktree root with stdin.
func (r *Repo) GitIn(stdin []byte, args ...string) ([]byte, error) {
	return Run(r.Root, stdin, args...)
}

// GitPath resolves a path inside the git directory the way git does
// (`git rev-parse --git-path`), so per-worktree and shared files land
// where git itself keeps them.
func (r *Repo) GitPath(name string) (string, error) {
	out, err := r.Git("rev-parse", "--path-format=absolute", "--git-path", name)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(out), "\n"), nil
}

// Abs turns a repository-relative slash path into an absolute OS path.
func (r *Repo) Abs(rel string) string {
	return filepath.Join(r.Root, filepath.FromSlash(rel))
}

// Config returns a config value, or "" if it is unset.
func (r *Repo) Config(key string) string {
	out, err := r.Git("config", "--get", key)
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(out), "\n")
}

// ConfigBool reads a boolean config value with a default.
func (r *Repo) ConfigBool(key string, def bool) bool {
	out, err := r.Git("config", "--type=bool", "--get", key)
	if err != nil {
		return def
	}
	v, err := strconv.ParseBool(strings.TrimSpace(string(out)))
	if err != nil {
		return def
	}
	return v
}

// SplitZ splits NUL-terminated output.
func SplitZ(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	parts := strings.Split(string(b), "\x00")
	if parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

// HashFiles returns the git blob ids of worktree files, hashed as raw
// bytes (no filters), in order. The ids are computed here rather than by
// `git hash-object --stdin-paths`, which would misread a path that starts
// with a double quote.
func (r *Repo) HashFiles(rels []string) ([]string, error) {
	ids := make([]string, len(rels))
	for i, rel := range rels {
		data, err := os.ReadFile(r.Abs(rel))
		if err != nil {
			return nil, err
		}
		ids[i] = r.BlobID(data)
	}
	return ids, nil
}

// BlobID computes the id git gives a blob with these contents.
func (r *Repo) BlobID(data []byte) string {
	var h hash.Hash
	if r.sha256 {
		h = sha256.New()
	} else {
		h = sha1.New()
	}
	fmt.Fprintf(h, "blob %d\x00", len(data))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// Blobs reads blob contents by id with one `git cat-file --batch`.
// Missing objects are absent from the result.
func (r *Repo) Blobs(ids []string) (map[string][]byte, error) {
	res := make(map[string][]byte, len(ids))
	if len(ids) == 0 {
		return res, nil
	}
	cmd := exec.Command("git", "cat-file", "--batch")
	cmd.Dir = r.Root
	cmd.Stdin = strings.NewReader(strings.Join(ids, "\n") + "\n")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	br := bufio.NewReader(stdout)
	for range ids {
		header, err := br.ReadString('\n')
		if err != nil {
			break
		}
		f := strings.Fields(header)
		if len(f) == 2 && f[1] == "missing" {
			continue
		}
		if len(f) != 3 {
			return nil, fmt.Errorf("git cat-file: unexpected header %q", header)
		}
		size, err := strconv.Atoi(f[2])
		if err != nil {
			return nil, fmt.Errorf("git cat-file: bad size in %q", header)
		}
		buf := make([]byte, size+1) // contents plus trailing LF
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		res[f[0]] = buf[:size]
	}
	if err := cmd.Wait(); err != nil {
		return nil, &Error{Args: []string{"cat-file", "--batch"}, Stderr: errb.String(), Err: err}
	}
	return res, nil
}

// HasHead reports whether HEAD points at a commit.
func (r *Repo) HasHead() bool {
	_, err := r.Git("rev-parse", "--verify", "--quiet", "HEAD^{commit}")
	return err == nil
}

// History returns, for each path, every blob id it has had in commits
// reachable from HEAD, local branches, remote-tracking branches and tags.
// Stashes do not count: a version counts as "committed" only if it can be
// reached from history people share.
func (r *Repo) History(paths []string) (map[string]map[string]bool, error) {
	res := make(map[string]map[string]bool, len(paths))
	for _, p := range paths {
		res[p] = map[string]bool{}
	}
	if len(paths) == 0 {
		return res, nil
	}
	args := []string{"log", "--branches", "--remotes", "--tags"}
	if r.HasHead() {
		args = append(args, "HEAD")
	} else if refs, _ := r.Git("for-each-ref", "--count=1", "refs/heads", "refs/remotes", "refs/tags"); len(refs) == 0 {
		return res, nil // no commits anywhere yet
	}
	args = append(args, "--format=", "--raw", "--no-abbrev", "--no-renames", "-m", "-z", "--")
	args = append(args, paths...)
	out, err := r.Git(args...)
	if err != nil {
		return nil, err
	}
	// -z raw records: ":mode mode old new status\0path\0"
	fields := SplitZ(out)
	for i := 0; i < len(fields); i++ {
		rec := strings.TrimLeft(fields[i], "\n")
		if !strings.HasPrefix(rec, ":") || i+1 >= len(fields) {
			continue
		}
		f := strings.Fields(rec)
		path := fields[i+1]
		i++
		if len(f) < 5 {
			continue
		}
		set, ok := res[path]
		if !ok {
			continue
		}
		for _, id := range f[2:4] {
			if strings.Trim(id, "0") != "" {
				set[id] = true
			}
		}
	}
	return res, nil
}

// Exists reports whether anything (a file, directory or symlink) is at abs.
func Exists(abs string) bool {
	_, err := os.Lstat(abs)
	return err == nil
}
