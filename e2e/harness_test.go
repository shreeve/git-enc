// Package e2e drives the real git-enc binary against real git repositories:
// a shared bare origin and several clones, each with its own keys, the way
// a team uses it.
//
// Set GIT_ENC_TEST_GIT to a git binary to run the suite with that git (for
// example GitHub Desktop's bundled one).
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var binDir, gitDir string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "git-enc-e2e-bin-")
	if err != nil {
		panic(err)
	}
	binDir = dir
	exe := filepath.Join(dir, "git-enc")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	build := exec.Command("go", "build", "-o", exe, "github.com/shreeve/git-enc/cmd/git-enc")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		panic(err)
	}
	if g := os.Getenv("GIT_ENC_TEST_GIT"); g != "" {
		// That git's own directory goes first on PATH, so it finds its
		// helpers the way it would when installed.
		gitDir = filepath.Dir(g)
		out, err := exec.Command(g, "--version").Output()
		if err != nil {
			panic(err)
		}
		fmt.Printf("using %s", out)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// World is an origin repository and the people who clone it.
type World struct {
	t    *testing.T
	root string
}

func newWorld(t *testing.T) *World {
	t.Helper()
	w := &World{t: t, root: t.TempDir()}
	w.git(w.root, "init", "-q", "--bare", "-b", "main", "origin.git")
	return w
}

func (w *World) env(home string) []string {
	var env []string
	for _, kv := range os.Environ() {
		k := strings.SplitN(kv, "=", 2)[0]
		if strings.HasPrefix(k, "GIT_") || k == "HOME" || k == "XDG_CONFIG_HOME" || k == "PATH" {
			continue
		}
		env = append(env, kv)
	}
	return append(env,
		"PATH="+pathList(),
		"HOME="+home,
		"GIT_ENC_KEYS_DIR="+filepath.Join(home, "keys"),
		"GIT_CONFIG_GLOBAL="+filepath.Join(home, ".gitconfig"),
		"GIT_CONFIG_NOSYSTEM=1",
	)
}

func pathList() string {
	parts := []string{binDir}
	if gitDir != "" {
		parts = append(parts, gitDir)
	}
	return strings.Join(append(parts, os.Getenv("PATH")), string(os.PathListSeparator))
}

func (w *World) git(dir string, args ...string) string {
	w.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = w.env(w.root)
	out, err := cmd.CombinedOutput()
	if err != nil {
		w.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// Person is one clone with its own home directory and keys.
type Person struct {
	w    *World
	Name string
	Dir  string
	home string
}

// clone makes a new person with a clone of origin.
func (w *World) clone(name string, gitConfig ...string) *Person {
	w.t.Helper()
	p := &Person{w: w, Name: name, Dir: filepath.Join(w.root, name), home: filepath.Join(w.root, "home-"+name)}
	os.MkdirAll(filepath.Join(p.home, "keys"), 0o700)
	cfg := fmt.Sprintf("[user]\n\tname = %s\n\temail = %s@example.com\n[init]\n\tdefaultBranch = main\n[pull]\n\trebase = false\n[advice]\n\tdetachedHead = false\n", name, name)
	for _, c := range gitConfig {
		cfg += c + "\n"
	}
	os.WriteFile(filepath.Join(p.home, ".gitconfig"), []byte(cfg), 0o644)
	cmd := exec.Command("git", "clone", "-q", filepath.Join(w.root, "origin.git"), p.Dir)
	cmd.Env = w.env(p.home)
	if out, err := cmd.CombinedOutput(); err != nil {
		w.t.Fatalf("clone: %v\n%s", err, out)
	}
	return p
}

// Result is a finished command.
type Result struct {
	Out, Err string
	Code     int
}

func (p *Person) exec(stdin string, name string, args ...string) Result {
	return p.execIn(p.Dir, stdin, name, args...)
}

func (p *Person) execIn(dir, stdin string, name string, args ...string) Result {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = p.w.env(p.home)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		p.w.t.Fatalf("%s %v: %v", name, args, err)
	}
	return Result{out.String(), errb.String(), code}
}

// Git runs git and fails the test if it fails.
func (p *Person) Git(args ...string) string {
	p.w.t.Helper()
	r := p.exec("", "git", args...)
	if r.Code != 0 {
		p.w.t.Fatalf("%s: git %s: exit %d\n%s%s", p.Name, strings.Join(args, " "), r.Code, r.Out, r.Err)
	}
	return r.Out + r.Err
}

// TryGit runs git and returns the result.
func (p *Person) TryGit(args ...string) Result { return p.exec("", "git", args...) }

// Enc runs git enc and fails the test if it fails.
func (p *Person) Enc(args ...string) string {
	p.w.t.Helper()
	r := p.exec("", "git", append([]string{"enc"}, args...)...)
	if r.Code != 0 {
		p.w.t.Fatalf("%s: git enc %s: exit %d\n%s%s", p.Name, strings.Join(args, " "), r.Code, r.Out, r.Err)
	}
	return r.Out + r.Err
}

// TryEnc runs git enc and returns the result.
func (p *Person) TryEnc(args ...string) Result {
	return p.exec("", "git", append([]string{"enc"}, args...)...)
}

// EncAt runs git enc in a subdirectory of the worktree.
func (p *Person) EncAt(sub string, args ...string) Result {
	return p.execIn(filepath.Join(p.Dir, filepath.FromSlash(sub)), "", "git", append([]string{"enc"}, args...)...)
}

// Binary runs the git-enc binary itself, not through git.
func (p *Person) Binary(args ...string) Result {
	return p.exec("", filepath.Join(binDir, "git-enc"), args...)
}

// EncIn runs git enc with stdin.
func (p *Person) EncIn(stdin string, args ...string) Result {
	return p.exec(stdin, "git", append([]string{"enc"}, args...)...)
}

// Write writes a worktree file.
func (p *Person) Write(rel, content string) {
	p.w.t.Helper()
	abs := filepath.Join(p.Dir, filepath.FromSlash(rel))
	os.MkdirAll(filepath.Dir(abs), 0o755)
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		p.w.t.Fatal(err)
	}
}

// Read reads a worktree file ("" if absent).
func (p *Person) Read(rel string) string {
	data, err := os.ReadFile(filepath.Join(p.Dir, filepath.FromSlash(rel)))
	if err != nil {
		return ""
	}
	return string(data)
}

// Exists reports whether a worktree file exists.
func (p *Person) Exists(rel string) bool {
	_, err := os.Lstat(filepath.Join(p.Dir, filepath.FromSlash(rel)))
	return err == nil
}

// Report is the parsed `git enc status --json`.
type Report struct {
	Version int `json:"version"`
	Repo    struct {
		Initialized bool `json:"initialized"`
		Uses        bool `json:"uses_git_enc"`
	} `json:"repo"`
	Keys []struct {
		Name        string `json:"name"`
		Fingerprint string `json:"fingerprint"`
		Available   bool   `json:"available"`
	} `json:"keys"`
	Secrets []struct {
		Path     string `json:"path"`
		State    string `json:"state"`
		Staged   bool   `json:"staged"`
		Incoming string `json:"incoming"`
		Message  string `json:"message"`
	} `json:"secrets"`
	Problems []struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"problems"`
}

// Status returns the JSON report.
func (p *Person) Status() Report {
	p.w.t.Helper()
	var r Report
	if err := json.Unmarshal([]byte(p.Enc("status", "--json")), &r); err != nil {
		p.w.t.Fatal(err)
	}
	return r
}

// State returns one secret's state ("" if not listed).
func (p *Person) State(path string) string {
	p.w.t.Helper()
	for _, s := range p.Status().Secrets {
		if s.Path == path {
			return s.State
		}
	}
	return ""
}

// expectState fails unless path is in state want.
func (p *Person) expectState(path, want string) {
	p.w.t.Helper()
	if got := p.State(path); got != want {
		p.w.t.Fatalf("%s: %s is %q, want %q\n%s", p.Name, path, got, want, p.Enc("status"))
	}
}

// shareKey gives `to` a copy of `from`'s key.
func shareKey(t *testing.T, from, to *Person, name string) {
	t.Helper()
	key := from.Enc("key", "show", name)
	if r := to.EncIn(key, "key", "add", name); r.Code != 0 {
		t.Fatalf("key add: %s%s", r.Out, r.Err)
	}
}

// commitPush commits everything staged and pushes.
func (p *Person) commitPush(msg string) {
	p.w.t.Helper()
	p.Git("commit", "-q", "-m", msg)
	p.Git("push", "-q", "origin", "HEAD")
}

// team sets up Alice with a committed secret .env ("API_KEY=one") and a
// pushed repository, and Bob with a clone and the key, initialized.
func team(t *testing.T) (*World, *Person, *Person) {
	t.Helper()
	w := newWorld(t)
	a := w.clone("alice")
	a.Write("app.txt", "app\n")
	a.Git("add", "app.txt")
	a.Git("commit", "-q", "-m", "init")
	a.Enc("key", "new", "team")
	a.Enc("init")
	a.Write(".env", "API_KEY=one\n")
	a.Enc("add", "--key", "team", ".env")
	a.commitPush("add secret")
	b := w.clone("bob")
	shareKey(t, a, b, "team")
	b.Enc("init")
	return w, a, b
}
