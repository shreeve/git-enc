package spec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseBlocks(t *testing.T) {
	src := `.DS_Store
*.log

# git-enc: team 3f9a1c2e
.env
# a comment inside is fine

config/*.yml
# git-enc: end

# git-enc: ops
/deploy/prod.env
# git-enc: end
`
	s, probs := Parse([]byte(src), false)
	if len(probs) != 0 {
		t.Fatalf("problems: %v", probs)
	}
	if len(s.Blocks) != 2 {
		t.Fatalf("blocks = %d", len(s.Blocks))
	}
	b := s.Blocks[0]
	if b.Key != "team" || b.Fingerprint != "3f9a1c2e" || b.Start != 4 || b.End != 9 || len(b.Patterns) != 2 {
		t.Fatalf("block 0 = %+v", b)
	}
	if s.Blocks[1].Fingerprint != "" || s.Blocks[1].Patterns[0].Literal() != "deploy/prod.env" {
		t.Fatalf("block 1 = %+v", s.Blocks[1])
	}
	for path, want := range map[string]string{
		".env": "team", "sub/.env": "team", "config/a.yml": "team", "config/x/a.yml": "",
		"deploy/prod.env": "ops", "prod.env": "", "app.log": "",
	} {
		b, _, err := s.Match(path)
		got := ""
		if b != nil {
			got = b.Key
		}
		if err != nil || got != want {
			t.Errorf("Match(%q) = %q, %v; want %q", path, got, err, want)
		}
	}
	if string(s.Bytes()) != src {
		t.Errorf("round trip changed the file")
	}
}

func TestParseProblems(t *testing.T) {
	for _, tc := range []struct{ src, want string }{
		{"# git-enc: team\n.env\n", "never ended"},
		{"# git-enc: end\n", "without a block"},
		{"# git-enc: a\n# git-enc: b\n# git-enc: end\n", "before the block"},
		{"# git-enc: team\n!.env\n# git-enc: end\n", "negated"},
		{"# git-enc: team\nsecrets/\n# git-enc: end\n", "directory pattern"},
		{"# git-enc: team\nx/**/y\n# git-enc: end\n", "`**`"},
		{"# git-enc: team\n.env.enc\n# git-enc: end\n", "encrypted files"},
		{"# git-enc: team ZZZ\n# git-enc: end\n", "fingerprint"},
		{"# git-enc: bad/name\n# git-enc: end\n", "expected"},
		{"# git-enc: team\n.env    # the env file\n# git-enc: end\n", "no end-of-line comments"},
		{"# git-enc: team\nsecrets/*\n# git-enc: end\n", "also matches the .enc files"},
		{"# git-enc: team\n.env*\n# git-enc: end\n", "also matches the .enc files"},
	} {
		_, probs := Parse([]byte(tc.src), false)
		if len(probs) == 0 || !strings.Contains(probs[0].Msg, tc.want) {
			t.Errorf("Parse(%q) problems = %v; want %q", tc.src, probs, tc.want)
		}
	}
}

func TestAddPathAndNewBlock(t *testing.T) {
	s, _ := Parse([]byte("# git-enc: team\n.env\n# git-enc: end\n"), false)
	s.AddPath(s.Blocks[0], "config/a b*.yml", "3f9a1c2e")
	want := "# git-enc: team 3f9a1c2e\n.env\n/config/a b\\*.yml\n# git-enc: end\n"
	if got := string(s.Bytes()); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	s2, probs := Parse(s.Bytes(), false)
	if len(probs) != 0 {
		t.Fatal(probs)
	}
	if b, _, _ := s2.Match("config/a b*.yml"); b == nil {
		t.Fatal("escaped path does not match itself")
	}
	if b, _, _ := s2.Match("config/a bX.yml"); b != nil {
		t.Fatal("escaped * still acts as a wildcard")
	}
	s3, _ := Parse([]byte("*.log"), false)
	s3.NewBlock("ops", "a1b2c3d4", "deploy/prod.env")
	if got := string(s3.Bytes()); got != "*.log\n\n# git-enc: ops a1b2c3d4\n/deploy/prod.env\n# git-enc: end\n" {
		t.Fatalf("NewBlock: %q", got)
	}
}

func TestCRLF(t *testing.T) {
	s, probs := Parse([]byte("# git-enc: team\r\n.env\r\n# git-enc: end\r\n"), false)
	if len(probs) != 0 || len(s.Blocks) != 1 {
		t.Fatalf("problems %v, blocks %d", probs, len(s.Blocks))
	}
	if b, _, _ := s.Match(".env"); b == nil {
		t.Fatal("CRLF block not parsed")
	}
	if !strings.HasSuffix(string(s.Bytes()), "\r\n") {
		t.Fatal("CRLF not preserved")
	}
}

// TestMatchAgreesWithGit checks the matcher against `git check-ignore`,
// which is the authority on what .gitignore means.
func TestMatchAgreesWithGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found")
	}
	patterns := []string{
		".env", "/.env", "config/secrets.yml", "config/*.yml", "*.pem", "a?c.txt",
		"[abc].key", "[!abc].key", "/deploy/*/prod.env", "sub/.env", `x\*y`, "trail  ",
	}
	paths := []string{
		".env", "sub/.env", "a/b/.env", "config/secrets.yml", "config/a.yml", "config/x/a.yml",
		"x/config/a.yml", "k.pem", "d/k.pem", "abc.txt", "a/abc.txt", "ac.txt", "a.key", "d.key",
		"deploy/eu/prod.env", "deploy/prod.env", "deploy/eu/x/prod.env", "x*y", "xay", "trail",
	}
	dir := t.TempDir()
	git := func(args ...string) *exec.Cmd {
		c := exec.Command("git", args...)
		c.Dir = dir
		c.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
		return c
	}
	if out, err := git("init", "-q").CombinedOutput(); err != nil {
		t.Fatal(string(out))
	}
	git("config", "core.ignorecase", "false").Run()
	for _, pat := range patterns {
		p, msg := compile(pat, false)
		if msg != "" {
			t.Fatalf("compile(%q): %s", pat, msg)
		}
		if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(pat+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			err := git("check-ignore", "-q", "--no-index", "--", path).Run()
			want := err == nil
			if got := p.Match(path); got != want {
				t.Errorf("pattern %q path %q: matcher %v, git %v", pat, path, got, want)
			}
		}
	}
}

func TestCheckPath(t *testing.T) {
	for _, ok := range []string{".env", "config/secrets.yml", "a b/c.txt", ".github/x"} {
		if err := CheckPath(ok); err != nil {
			t.Errorf("CheckPath(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "/etc/passwd", "../x", "a/../../x", "a//b", "./a", ".git/hooks/pre-commit",
		"sub/.GIT/config", "GIT~1/config", ".g‌it/config", "a.", "a /b", "x\\y",
		".gitattributes", "sub/.gitignore", ".gitmodules", "a\nb",
	} {
		if err := CheckPath(bad); err == nil {
			t.Errorf("CheckPath(%q) accepted", bad)
		}
	}
}
