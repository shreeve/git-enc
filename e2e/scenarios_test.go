package e2e

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
)

// The everyday loop: Bob gets the secret on init, edits it, adds it,
// pushes; Alice pulls, sees it outdated, updates.
func TestEverydayLoop(t *testing.T) {
	_, a, b := team(t)
	if got := b.Read(".env"); got != "API_KEY=one\n" {
		t.Fatalf("bob's .env after init = %q", got)
	}
	b.expectState(".env", "clean")

	b.Write(".env", "API_KEY=two\n")
	b.expectState(".env", "modified")
	if d := b.Enc("diff"); !strings.Contains(d, "-API_KEY=one") || !strings.Contains(d, "+API_KEY=two") {
		t.Fatalf("diff:\n%s", d)
	}
	b.Enc("add", ".env")
	b.commitPush("rotate")

	pull := a.Git("pull", "-q")
	if !strings.Contains(pull, "run `git enc update`") {
		t.Errorf("post-merge hook did not remind:\n%s", pull)
	}
	a.expectState(".env", "outdated")
	out := a.Enc("update")
	if strings.Contains(out, "backup") || strings.Contains(out, "git enc cat") {
		t.Errorf("an outdated copy is in git history already; no backup expected:\n%s", out)
	}
	if got := a.Read(".env"); got != "API_KEY=two\n" {
		t.Fatalf("alice's .env = %q", got)
	}
	a.expectState(".env", "clean")
}

// Git never sees the plaintext, in any state.
func TestPlaintextNeverCommittable(t *testing.T) {
	_, a, _ := team(t)
	if out := a.Git("status", "--porcelain"); strings.Contains(out, ".env\n") {
		t.Fatalf("plaintext visible to git status:\n%s", out)
	}
	a.Git("add", "-f", ".env")
	r := a.TryGit("commit", "-q", "-m", "oops")
	if r.Code == 0 || !strings.Contains(r.Err, "refusing to commit the plaintext secret .env") {
		t.Fatalf("pre-commit let plaintext through (exit %d):\n%s%s", r.Code, r.Out, r.Err)
	}
	a.Git("rm", "--cached", "-q", ".env")

	// Remove the block entirely: .git/info/exclude still keeps .env out.
	a.Write(".gitignore", "")
	a.Git("add", ".gitignore")
	a.Git("add", ".")
	if out := a.Git("diff", "--cached", "--name-only"); strings.Contains(out, ".env\n") {
		t.Fatalf("plaintext staged after its block was removed:\n%s", out)
	}
}

// Red-team critical 1: add, then stash or reset, must not make update
// destroy the only copy of the edit.
func TestAddThenStashKeepsEdit(t *testing.T) {
	for _, undo := range [][]string{{"stash", "-q"}, {"reset", "-q", "--hard"}} {
		t.Run(undo[0], func(t *testing.T) {
			_, a, _ := team(t)
			a.Write(".env", "API_KEY=mine\n")
			a.Enc("add", ".env")
			a.Git(undo...)
			// .env.enc is back to the committed version; the edit lives only
			// in the plaintext. That is an edit, not an outdated copy.
			a.expectState(".env", "modified")
			a.Enc("update")
			if got := a.Read(".env"); got != "API_KEY=mine\n" {
				t.Fatalf("update destroyed the edit: .env = %q", got)
			}
		})
	}
}

// Both edited different lines: update merges.
func TestConflictMergesCleanly(t *testing.T) {
	_, a, b := team(t)
	for _, p := range []*Person{a, b} {
		p.Write(".env", "A=1\nB=1\nC=1\nD=1\nE=1\n")
	}
	a.Enc("add", ".env")
	a.commitPush("five lines")
	b.Git("pull", "-q")
	b.Enc("update")
	b.expectState(".env", "clean")

	a.Write(".env", "A=2\nB=1\nC=1\nD=1\nE=1\n")
	a.Enc("add", ".env")
	a.commitPush("A=2")
	b.Write(".env", "A=1\nB=1\nC=1\nD=1\nE=2\n")
	b.Git("pull", "-q")
	b.expectState(".env", "conflict")
	b.Enc("update")
	if got := b.Read(".env"); got != "A=2\nB=1\nC=1\nD=1\nE=2\n" {
		t.Fatalf("merged .env = %q", got)
	}
	b.expectState(".env", "modified")
	b.Enc("add", ".env")
	b.commitPush("E=2")
	a.Git("pull", "-q")
	a.Enc("update")
	if got := a.Read(".env"); got != "A=2\nB=1\nC=1\nD=1\nE=2\n" {
		t.Fatalf("alice after merge = %q", got)
	}
}

// Both edited the same line: update keeps the edit and writes .incoming;
// add resolves.
func TestConflictIncoming(t *testing.T) {
	_, a, b := team(t)
	a.Write(".env", "API_KEY=alice\n")
	a.Enc("add", ".env")
	a.commitPush("alice")
	b.Write(".env", "API_KEY=bob\n")
	b.Git("pull", "-q")
	b.expectState(".env", "conflict")

	r := b.TryEnc("add", ".env")
	if r.Code == 0 {
		t.Fatal("add of a conflicting secret succeeded without --force")
	}
	b.Enc("update")
	if b.Read(".env") != "API_KEY=bob\n" || b.Read(".env.incoming") != "API_KEY=alice\n" {
		t.Fatalf(".env=%q incoming=%q", b.Read(".env"), b.Read(".env.incoming"))
	}
	if out := b.Git("status", "--porcelain", "--untracked-files=all"); strings.Contains(out, "incoming") {
		t.Fatalf(".incoming is visible to git:\n%s", out)
	}
	// Still a conflict until .env.incoming is merged; `add --all` skips it.
	b.expectState(".env", "conflict")
	if out := b.Enc("add", "--all"); !strings.Contains(out, "skipping .env") {
		t.Fatalf("add --all did not skip the unresolved secret:\n%s", out)
	}
	b.Write(".env", "API_KEY=both\n")
	b.Enc("add", ".env")
	if b.Exists(".env.incoming") {
		t.Fatal(".incoming left behind after add")
	}
	b.commitPush("both")
	a.Git("pull", "-q")
	a.Enc("update")
	if a.Read(".env") != "API_KEY=both\n" {
		t.Fatalf("alice .env = %q", a.Read(".env"))
	}
}

// update --discard takes the committed version and keeps a backup.
func TestDiscardKeepsBackup(t *testing.T) {
	_, a, _ := team(t)
	a.Write(".env", "API_KEY=scratch\n")
	out := a.Enc("update", "--discard", ".env")
	if a.Read(".env") != "API_KEY=one\n" {
		t.Fatalf(".env = %q", a.Read(".env"))
	}
	i := strings.Index(out, "git enc cat ")
	if i < 0 {
		t.Fatalf("no backup mentioned:\n%s", out)
	}
	file := strings.TrimRight(strings.Fields(out[i+len("git enc cat "):])[0], "`)")
	if got := a.Enc("cat", file); got != "API_KEY=scratch\n" {
		t.Fatalf("backup = %q", got)
	}
}

// Red-team critical 2: a git merge conflict on .enc must not look clean.
func TestGitMergeConflict(t *testing.T) {
	_, a, b := team(t)
	for _, p := range []*Person{a, b} {
		p.Write(".env", "A=1\nM=0\nB=1\n")
	}
	a.Enc("add", ".env")
	a.commitPush("base")
	b.Git("pull", "-q")
	b.Enc("update", "--discard", ".env")

	a.Write(".env", "A=9\nM=0\nB=1\n")
	a.Enc("add", ".env")
	a.commitPush("A=9")
	b.Write(".env", "A=1\nM=0\nB=2\n")
	b.Enc("add", ".env")
	b.Git("commit", "-q", "-m", "B=2")
	r := b.TryGit("pull", "-q", "--no-rebase")
	if r.Code == 0 {
		t.Fatal("expected a merge conflict on .env.enc")
	}
	b.expectState(".env", "merging")
	if r := b.TryEnc("add", ".env"); r.Code == 0 {
		t.Fatal("add during an unresolved merge succeeded")
	}
	b.Enc("merge")
	if got := b.Read(".env"); got != "A=9\nM=0\nB=2\n" {
		t.Fatalf("merged = %q", got)
	}
	b.Enc("add", ".env")
	b.Git("commit", "-q", "--no-edit")
	b.expectState(".env", "clean")
	b.Git("push", "-q")
	a.Git("pull", "-q")
	a.Enc("update")
	if a.Read(".env") != "A=9\nM=0\nB=2\n" {
		t.Fatalf("alice = %q", a.Read(".env"))
	}
}

// A rebase conflict: `ours` and `theirs` swap, and the user's side must win
// the label "yours".
func TestRebaseConflict(t *testing.T) {
	_, a, b := team(t)
	a.Write(".env", "KEY=alice\n")
	a.Enc("add", ".env")
	a.commitPush("alice")
	b.Write(".env", "KEY=bob\n")
	b.Enc("add", ".env")
	b.Git("commit", "-q", "-m", "bob")
	r := b.TryGit("pull", "-q", "--rebase")
	if r.Code == 0 {
		t.Fatal("expected a rebase conflict")
	}
	b.expectState(".env", "merging")
	b.Enc("merge")
	got := b.Read(".env")
	if !strings.Contains(got, "<<<<<<< upstream") || !strings.Contains(got, ">>>>>>> yours") ||
		!strings.Contains(got, "KEY=alice") || !strings.Contains(got, "KEY=bob") {
		t.Fatalf("conflict file:\n%s", got)
	}
	if r := b.TryEnc("add", ".env"); r.Code == 0 {
		t.Fatal("add accepted a file with conflict markers")
	}
	b.Write(".env", "KEY=both\n")
	b.Enc("add", ".env")
	b.exec("", "git", "-c", "core.editor=true", "rebase", "--continue")
	b.expectState(".env", "clean")
	if b.Read(".env") != "KEY=both\n" {
		t.Fatal("lost the resolution")
	}
}

// Adopting git-enc where the plaintext is already committed.
func TestAdoptTrackedPlaintext(t *testing.T) {
	w := newWorld(t)
	a := w.clone("alice")
	a.Write(".env", "API_KEY=leaked\n")
	a.Git("add", ".env")
	a.Git("commit", "-q", "-m", "oops")
	a.Enc("key", "new", "team")
	out := a.Enc("add", "--key", "team", ".env")
	if !strings.Contains(out, "stopped tracking the plaintext .env") || !strings.Contains(out, "past commit") {
		t.Fatalf("add output:\n%s", out)
	}
	a.Git("commit", "-q", "-m", "encrypt")
	if files := a.Git("ls-files"); strings.Contains(files, ".env\n") || !strings.Contains(files, ".env.enc") {
		t.Fatalf("tracked files:\n%s", files)
	}
	if a.Read(".env") != "API_KEY=leaked\n" {
		t.Fatal("plaintext removed from disk")
	}
}

// A clone without the key works normally and says what to do.
func TestNoKey(t *testing.T) {
	w, _, _ := team(t)
	c := w.clone("carol")
	init := c.Enc("init")
	if !strings.Contains(init, "git enc key add team") {
		t.Fatalf("init output:\n%s", init)
	}
	c.expectState(".env", "no-key")
	if r := c.TryEnc("check"); r.Code != 4 {
		t.Fatalf("check exit = %d, want 4", r.Code)
	}
	c.Write("app.txt", "carol\n")
	c.Git("add", "app.txt")
	c.Git("commit", "-q", "-m", "carol can still work")

	// A different key with the same name is told apart by fingerprint.
	c.Enc("key", "new", "team")
	st := c.Status()
	if st.Secrets[0].State != "no-key" || !strings.Contains(st.Secrets[0].Message, "but this repo uses team") {
		t.Fatalf("wrong-key message: %+v", st.Secrets[0])
	}
}

// Line-ending conversion must never touch ciphertext. Whether git would
// guess a given ciphertext is text varies file to file, so use many.
func TestAutocrlfLeavesCiphertextAlone(t *testing.T) {
	w, a, _ := team(t)
	for i := 0; i < 16; i++ {
		a.Write(fmt.Sprintf("s/%02d.env", i), fmt.Sprintf("K=%d\n", i))
	}
	a.Enc("add", "--key", "team", "s/00.env", "s/01.env", "s/02.env", "s/03.env", "s/04.env", "s/05.env",
		"s/06.env", "s/07.env", "s/08.env", "s/09.env", "s/10.env", "s/11.env", "s/12.env", "s/13.env", "s/14.env", "s/15.env")
	a.commitPush("many")
	c := w.clone("carol", "[core]\n\tautocrlf = true")
	shareKey(t, a, c, "team")
	c.Enc("init")
	if c.Read(".env") != "API_KEY=one\n" || c.Read("s/07.env") != "K=7\n" {
		t.Fatalf(".env = %q, s/07.env = %q", c.Read(".env"), c.Read("s/07.env"))
	}
	if out := c.Git("status", "--porcelain"); out != "" {
		t.Fatalf("autocrlf clone is dirty:\n%s", out)
	}
	for i := 0; i < 16; i++ {
		f := fmt.Sprintf("s/%02d.env.enc", i)
		if a.Read(f) != c.Read(f) {
			t.Fatalf("%s: ciphertext bytes differ in the autocrlf clone", f)
		}
	}
	c.expectState("s/07.env", "clean")

	// Any *.enc git might mistake for text is still never converted.
	a.Write("plain-looking.enc", "line1\nline2\n")
	a.Git("add", "plain-looking.enc")
	a.commitPush("text-like enc")
	c.Git("pull", "-q")
	if got := c.Read("plain-looking.enc"); got != "line1\nline2\n" {
		t.Fatalf("autocrlf converted a .enc file: %q", got)
	}
}

// Adding an unchanged secret changes nothing (no fresh ciphertext churn),
// and re-adding an old value never reuses its old blob.
func TestNoChurnAndNoBlobReuse(t *testing.T) {
	_, a, _ := team(t)
	before := a.Git("rev-parse", "HEAD:.env.enc")
	a.Enc("add", ".env")
	a.Enc("add", "--all")
	if out := a.Git("status", "--porcelain"); out != "" {
		t.Fatalf("no-op add changed the tree:\n%s", out)
	}
	a.Write(".env", "API_KEY=two\n")
	a.Enc("add", ".env")
	a.commitPush("two")
	a.Write(".env", "API_KEY=one\n")
	a.Enc("add", ".env")
	a.commitPush("back to one")
	if after := a.Git("rev-parse", "HEAD:.env.enc"); after == before {
		t.Fatal("reverting reused the old blob; the revert is visible")
	}
}

// Globs, unsafe paths, and patterns that would hide ciphertext.
func TestPatterns(t *testing.T) {
	w := newWorld(t)
	a := w.clone("alice")
	a.Enc("key", "new", "team")
	a.Write(".gitignore", "# git-enc: team\n/certs/*.pem\n# git-enc: end\n")
	a.Write("certs/a.pem", "A\n")
	a.Write("certs/b.pem", "B\n")
	a.Write("certs/sub/c.pem", "C\n")
	st := a.Status()
	var got []string
	for _, s := range st.Secrets {
		got = append(got, s.Path+"="+s.State)
	}
	if strings.Join(got, " ") != "certs/a.pem=new certs/b.pem=new" {
		t.Fatalf("secrets: %v", got)
	}
	a.Enc("add", "--all")
	a.Git("commit", "-q", "-m", "certs")
	a.expectState("certs/a.pem", "clean")

	a.Write(".gitignore", "# git-enc: team\n/certs/*.pem\nsecrets/\n# git-enc: end\n")
	if st := a.Status(); len(st.Problems) == 0 || !strings.Contains(st.Problems[0].Message, "directory pattern") {
		t.Fatalf("directory pattern accepted: %+v", st.Problems)
	}

	for _, bad := range []string{".env*", "secrets/*", ".env    # the env file"} {
		a.Write(".gitignore", "# git-enc: team\n/certs/*.pem\n"+bad+"\n# git-enc: end\n")
		if st := a.Status(); len(st.Problems) == 0 {
			t.Fatalf("pattern %q accepted", bad)
		}
	}
	// A pattern that slips past the parser but still hides ciphertext is
	// reported by git itself.
	a.Write(".gitignore", "# git-enc: team\n/certs/*.pem\n.en?\n# git-enc: end\n*.enc\n")
	a.Write(".env", "X=1\n")
	if r := a.TryEnc("add", ".env"); r.Code != 3 || !strings.Contains(r.Err, "would be ignored") {
		t.Fatalf("hidden ciphertext accepted (exit %d): %s%s", r.Code, r.Out, r.Err)
	}
}

// A block can never make git-enc write into .git or through a symlink.
func TestUnsafePaths(t *testing.T) {
	w, a, _ := team(t)
	c := w.clone("carol")
	shareKey(t, a, c, "team")
	victim := filepath.Join(w.root, "victim")

	// A key holder commits a valid link.enc, plus the plaintext `link`
	// itself as a symlink pointing outside the repository.
	a.Write("link", "pwned\n")
	a.Enc("add", "--key", "team", "link")
	os.Remove(filepath.Join(a.Dir, "link"))
	if err := os.Symlink(victim, filepath.Join(a.Dir, "link")); err != nil {
		t.Skip("no symlinks here")
	}
	a.Git("add", "-f", "link")
	// And a block naming a file inside .git.
	a.Write(".gitignore", a.Read(".gitignore")+"# git-enc: team\n/.git/hooks/pre-commit\n# git-enc: end\n")
	a.Git("add", ".gitignore")
	// Our own pre-commit hook refuses this; an attacker skips hooks.
	if r := a.TryGit("commit", "-q", "-m", "evil"); r.Code == 0 {
		t.Fatal("pre-commit allowed committing a secret's plaintext")
	}
	a.Git("commit", "-q", "--no-verify", "-m", "evil")
	a.Git("push", "-q", "origin", "HEAD")

	c.Git("pull", "-q")
	c.TryEnc("init")
	c.TryEnc("update", "link")
	if _, err := os.Stat(victim); err == nil {
		t.Fatal("wrote through a symlink")
	}
	st := c.Status()
	var codes []string
	for _, p := range st.Problems {
		codes = append(codes, p.Code+": "+p.Message)
	}
	joined := strings.Join(codes, "\n")
	// Where git checks symlinks out as symlinks, git-enc must refuse the
	// path; where it writes them as plain files (Windows by default), the
	// attack cannot happen and the committed plaintext is reported instead.
	wantLink := "link is a symlink"
	if fi, err := os.Lstat(filepath.Join(c.Dir, "link")); err == nil && fi.Mode()&os.ModeSymlink == 0 {
		wantLink = "tracked-plaintext"
	}
	if !strings.Contains(joined, ".git/hooks/pre-commit") || !strings.Contains(joined, wantLink) {
		t.Fatalf("problems (want %q):\n%s", wantLink, joined)
	}
	hook, _ := os.ReadFile(filepath.Join(c.Dir, ".git", "hooks", "pre-commit"))
	if strings.Contains(string(hook), "API_KEY") || strings.Contains(string(hook), "pwned") {
		t.Fatal("decrypted into .git/hooks")
	}

	// A tracked symlinked directory must not let git-enc read or write
	// outside the worktree.
	outside := filepath.Join(w.root, "outside")
	os.MkdirAll(outside, 0o755)
	os.WriteFile(filepath.Join(outside, "secret"), []byte("not yours\n"), 0o644)
	if os.Symlink(outside, filepath.Join(c.Dir, "sub")) == nil {
		c.Write(".gitignore", c.Read(".gitignore")+"# git-enc: team\n/sub/secret\n# git-enc: end\n")
		c.TryEnc("add", "--all")
		c.TryEnc("add", "sub/secret")
		if _, err := os.Stat(filepath.Join(outside, "secret.enc")); err == nil {
			t.Fatal("wrote through a symlinked directory")
		}
		if s := c.State("sub/secret"); s == "new" || s == "clean" {
			t.Fatalf("read a file through a symlinked directory (state %q)", s)
		}
	}

	// Swapping one secret's ciphertext onto another name is detected.
	c.Write("other.env.enc", c.Read(".env.enc"))
	c.Write(".gitignore", c.Read(".gitignore")+"# git-enc: team\n/other.env\n# git-enc: end\n")
	if s := c.State("other.env"); s != "corrupt" {
		t.Fatalf("swapped ciphertext state = %q", s)
	}
}

// Without state, git history tells an outdated copy from an edit; an
// edit it cannot place is "diverged", never guessed.
func TestLostState(t *testing.T) {
	_, a, b := team(t)
	b.Write(".env", "API_KEY=two\n")
	b.Enc("add", ".env")
	b.commitPush("two")
	a.Git("pull", "-q")
	os.RemoveAll(filepath.Join(a.Dir, ".git", "git-enc"))
	a.expectState(".env", "outdated")

	os.RemoveAll(filepath.Join(a.Dir, ".git", "git-enc"))
	a.Write(".env", "API_KEY=unknown\n")
	a.expectState(".env", "diverged")
	if r := a.TryEnc("add", ".env"); r.Code == 0 {
		t.Fatal("diverged secret added without --force")
	}
	a.Enc("update")
	if a.Read(".env.incoming") != "API_KEY=two\n" {
		t.Fatal("diverged update did not write .incoming")
	}
	a.Enc("add", ".env")
	a.expectState(".env", "clean")
}

// Hooks remind but never block, unless enc.requireAdded is set.
func TestRequireAdded(t *testing.T) {
	_, a, _ := team(t)
	a.Write(".env", "API_KEY=edited\n")
	a.Write("app.txt", "change\n")
	a.Git("add", "app.txt")
	out := a.Git("commit", "-q", "-m", "app only")
	if !strings.Contains(out, "edited but not added") {
		t.Fatalf("no reminder:\n%s", out)
	}
	a.Git("config", "enc.requireAdded", "true")
	a.Write("app.txt", "change 2\n")
	a.Git("add", "app.txt")
	if r := a.TryGit("commit", "-q", "-m", "blocked"); r.Code == 0 {
		t.Fatal("enc.requireAdded did not block")
	}
}

// A second worktree has its own state and works independently.
func TestWorktree(t *testing.T) {
	_, a, _ := team(t)
	wt := filepath.Join(a.w.root, "alice-wt")
	a.Git("worktree", "add", "-q", wt, "-b", "feature")
	p := &Person{w: a.w, Name: "alice-wt", Dir: wt, home: a.home}
	p.Enc("update")
	if p.Read(".env") != "API_KEY=one\n" {
		t.Fatalf("worktree .env = %q", p.Read(".env"))
	}
	p.Write(".env", "API_KEY=feature\n")
	p.expectState(".env", "modified")
	a.expectState(".env", "clean")
}

// Short secrets all produce the same ciphertext size.
func TestSizeHidden(t *testing.T) {
	_, a, _ := team(t)
	size := func() int { fi, _ := os.Stat(filepath.Join(a.Dir, ".env.enc")); return int(fi.Size()) }
	s1 := size()
	a.Write(".env", "K=1\n")
	a.Enc("add", ".env")
	if size() != s1 {
		t.Fatalf("size changed with length: %d vs %d", size(), s1)
	}
}

// Status exit codes for scripts.
func TestCheckExitCodes(t *testing.T) {
	_, a, _ := team(t)
	if r := a.TryEnc("check"); r.Code != 0 || r.Err != "" {
		t.Fatalf("clean check: %d %q", r.Code, r.Err)
	}
	a.Write(".env", "X\n")
	if r := a.TryEnc("check"); r.Code != 3 || !strings.Contains(r.Err, "1 modified") {
		t.Fatalf("dirty check: %d %q", r.Code, r.Err)
	}
	if r := a.TryEnc("status", "--exit-code"); r.Code != 3 {
		t.Fatalf("status --exit-code = %d", r.Code)
	}
}

// A .enc is a plain age file: any age implementation can open it with the
// key file, and the payload is the documented header plus the secret.
func TestPlainAgeFile(t *testing.T) {
	_, a, _ := team(t)
	keyFile, err := os.Open(filepath.Join(a.home, "keys", "team"))
	if err != nil {
		t.Fatal(err)
	}
	ids, err := age.ParseIdentities(keyFile)
	keyFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.Decrypt(bytes.NewReader([]byte(a.Read(".env.enc"))), ids...)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := io.ReadAll(r)
	if !bytes.HasPrefix(payload, []byte("git-enc 1 12 .env\nAPI_KEY=one\n")) {
		t.Fatalf("payload starts %q", payload[:40])
	}
}

// Hooks: existing ones are kept and chained; reminders reach pull --rebase
// (post-rewrite) and push; a tracked hook manager directory is left alone.
func TestHooks(t *testing.T) {
	w := newWorld(t)
	a := w.clone("alice")
	hook := filepath.Join(a.Dir, ".git", "hooks", "pre-commit")
	os.WriteFile(hook, []byte("#!/bin/sh\necho mine-ran >&2\n"), 0o755)
	a.Write("app.txt", "x\n")
	a.Git("add", "app.txt")
	a.Git("commit", "-q", "-m", "init")
	a.Enc("key", "new", "team")
	if out := a.Enc("init"); !strings.Contains(out, "kept your existing pre-commit hook") {
		t.Fatalf("init:\n%s", out)
	}
	a.Write(".env", "K=1\n")
	a.Enc("add", "--key", "team", ".env")
	if out := a.Git("commit", "-q", "-m", "secret"); !strings.Contains(out, "mine-ran") {
		t.Fatalf("chained hook did not run:\n%s", out)
	}
	a.Git("push", "-q", "origin", "HEAD")

	b := w.clone("bob")
	shareKey(t, a, b, "team")
	b.Enc("init")
	b.Write("b.txt", "b\n")
	b.Git("add", "b.txt")
	b.Git("commit", "-q", "-m", "bob's work")

	a.Write(".env", "K=2\n")
	a.Enc("add", ".env")
	a.commitPush("K=2")
	if out := b.Git("pull", "--rebase"); !strings.Contains(out, "run `git enc update`") {
		t.Fatalf("no reminder after pull --rebase:\n%s", out)
	}
	b.Write(".env", "K=bob\n")
	b.Enc("update", "--discard", ".env")
	b.Write(".env", "K=3\n")
	if out := b.Git("push", "-q", "origin", "HEAD"); !strings.Contains(out, "edited but not added") {
		t.Fatalf("no reminder on push:\n%s", out)
	}

	c := w.clone("carol")
	os.MkdirAll(filepath.Join(c.Dir, ".husky"), 0o755)
	c.Write(".husky/pre-commit", "#!/bin/sh\n")
	c.Git("add", ".husky")
	c.Git("commit", "-q", "-m", "husky")
	c.Git("config", "core.hooksPath", ".husky")
	if out := c.Enc("init"); !strings.Contains(out, "hooks not installed") || !strings.Contains(out, "hook <name>") {
		t.Fatalf("init with a tracked hooksPath:\n%s", out)
	}
	if got := c.Read(".husky/pre-commit"); got != "#!/bin/sh\n" {
		t.Fatalf("init modified the tracked hook: %q", got)
	}
}

// Regressions for the independent review of v0.1 (labels C1…L5).
func TestReviewFindings(t *testing.T) {
	t.Run("H1 deleted .enc cannot revert a teammate's change", func(t *testing.T) {
		_, a, b := team(t)
		b.Write(".env", "API_KEY=two\n")
		b.Enc("add", ".env")
		b.commitPush("two")
		a.Git("pull", "-q")
		os.Remove(filepath.Join(a.Dir, ".env.enc"))
		a.expectState(".env", "outdated")
		if r := a.TryEnc("add", ".env"); r.Code != 3 {
			t.Fatalf("add after deleting .env.enc: exit %d", r.Code)
		}
		a.Enc("update")
		if a.Read(".env") != "API_KEY=two\n" || !a.Exists(".env.enc") {
			t.Fatalf("update: .env=%q enc restored=%v", a.Read(".env"), a.Exists(".env.enc"))
		}
	})

	t.Run("H2 temporary files stay out of commits", func(t *testing.T) {
		_, a, _ := team(t)
		a.Write("..env.git-enc-tmp-123", "API_KEY=leak\n")
		a.Git("add", "-A")
		if out := a.Git("diff", "--cached", "--name-only"); strings.Contains(out, "git-enc-tmp") {
			t.Fatalf("temp file staged by add -A:\n%s", out)
		}
		a.Git("add", "-f", "..env.git-enc-tmp-123")
		if r := a.TryGit("commit", "-q", "-m", "x"); r.Code == 0 {
			t.Fatal("pre-commit let a temp file through")
		}
	})

	t.Run("H3 the guard holds while the lock is taken", func(t *testing.T) {
		_, a, _ := team(t)
		os.WriteFile(filepath.Join(a.Dir, ".git", "git-enc", "lock"), []byte("99999\n"), 0o600)
		a.Git("add", "-f", ".env")
		r := a.TryGit("commit", "-q", "-m", "x")
		if r.Code == 0 || !strings.Contains(r.Err, "refusing to commit the plaintext secret .env") {
			t.Fatalf("commit with a held lock: exit %d\n%s", r.Code, r.Err)
		}
	})

	t.Run("H4 a hand-declared tracked plaintext is untracked by add", func(t *testing.T) {
		w := newWorld(t)
		a := w.clone("alice")
		a.Enc("key", "new", "team")
		a.Write("config/secrets.yml", "pw=1\n")
		a.Write("config/other.yml", "x=1\n")
		a.Git("add", "config")
		a.Git("commit", "-q", "-m", "tracked")
		a.Write(".gitignore", "# git-enc: team\n/config/*.yml\n# git-enc: end\n")
		st := a.Status()
		if len(st.Problems) == 0 || st.Problems[0].Code != "tracked-plaintext" {
			t.Fatalf("problems: %+v", st.Problems)
		}
		out := a.Enc("add", "config/secrets.yml")
		if !strings.Contains(out, "stopped tracking the plaintext config/secrets.yml") {
			t.Fatalf("add:\n%s", out)
		}
		a.Enc("add", "--all")
		if files := a.Git("ls-files", "config"); strings.Contains(files, "secrets.yml\n") || strings.Contains(files, "other.yml\n") {
			t.Fatalf("plaintext still tracked:\n%s", files)
		}
	})

	t.Run("M1 add, edit, add again before committing", func(t *testing.T) {
		_, a, _ := team(t)
		a.Write(".env", "v1\n")
		a.Enc("add", ".env")
		a.Write(".env", "v2\n")
		a.expectState(".env", "modified")
		a.Enc("add", ".env")
		a.expectState(".env", "clean")
		w := newWorld(t)
		n := w.clone("nina")
		n.Enc("key", "new", "team")
		n.Write(".env", "v1\n")
		n.Enc("add", "--key", "team", ".env")
		n.Write(".env", "v2\n")
		n.Enc("add", ".env")
	})

	t.Run("M3 conflict markers are refused after a merge abort", func(t *testing.T) {
		_, a, b := team(t)
		a.Write(".env", "K=a\n")
		a.Enc("add", ".env")
		a.commitPush("a")
		b.Write(".env", "K=b\n")
		b.Enc("add", ".env")
		b.Git("commit", "-q", "-m", "b")
		b.TryGit("pull", "-q", "--no-rebase")
		b.Enc("merge")
		b.Git("merge", "--abort")
		if r := b.TryEnc("add", ".env"); r.Code != 3 || !strings.Contains(r.Err, "conflict markers") {
			t.Fatalf("markers accepted: exit %d %s", r.Code, r.Err)
		}
	})

	t.Run("M4 a name starting with a quote", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip(`Windows file names cannot contain "`)
		}
		_, a, b := team(t)
		a.Write(`"quoted.env`, "Q=1\n")
		a.Enc("add", `"quoted.env`)
		a.commitPush("quoted")
		b.Git("pull", "-q")
		b.Enc("update")
		if b.Read(`"quoted.env`) != "Q=1\n" {
			t.Fatal("quoted name did not round-trip")
		}
		b.expectState(".env", "clean")
	})

	t.Run("M5 a global hooksPath is left alone", func(t *testing.T) {
		w := newWorld(t)
		global := filepath.Join(w.root, "global-hooks")
		os.MkdirAll(global, 0o755)
		os.WriteFile(filepath.Join(global, "pre-commit"), []byte("#!/bin/sh\n"), 0o755)
		a := w.clone("alice", "[core]\n\thooksPath = "+filepath.ToSlash(global))
		if out := a.Enc("init"); !strings.Contains(out, "hooks not installed") {
			t.Fatalf("init:\n%s", out)
		}
		entries, _ := os.ReadDir(global)
		if len(entries) != 1 {
			t.Fatalf("init changed the global hooks directory: %v", entries)
		}
	})

	t.Run("L1 a nested negation is reported and not written into", func(t *testing.T) {
		_, a, b := team(t)
		a.Write("app/.env", "N=1\n")
		a.Enc("add", "app/.env")
		a.Write("app/.gitignore", "!.env\n")
		a.Git("add", "app/.gitignore")
		a.commitPush("negation")
		b.Git("pull", "-q")
		st := b.Status()
		found := false
		for _, p := range st.Problems {
			found = found || p.Code == "not-ignored"
		}
		if !found {
			t.Fatalf("no not-ignored problem: %+v", st.Problems)
		}
		if r := b.TryEnc("update", "app/.env"); r.Code != 3 || b.Exists("app/.env") {
			t.Fatalf("wrote unignored plaintext (exit %d)", r.Code)
		}
	})

	t.Run("L2 binary secrets in conflict fall back to .incoming", func(t *testing.T) {
		_, a, b := team(t)
		a.Write("key.bin", "\x00\x01A\n")
		a.Enc("add", "key.bin")
		a.commitPush("bin")
		b.Git("pull", "-q")
		b.Enc("update")
		a.Write("key.bin", "\x00\x01B\n")
		a.Enc("add", "key.bin")
		a.commitPush("bin2")
		b.Write("key.bin", "\x00\x01C\n")
		b.Git("pull", "-q")
		b.Enc("update")
		if b.Read("key.bin.incoming") != "\x00\x01B\n" {
			t.Fatal("no .incoming for a binary conflict")
		}
	})

	t.Run("L3 exit codes", func(t *testing.T) {
		w, a, _ := team(t)
		if r := a.TryEnc("add", "nope.env"); r.Code != 1 {
			t.Fatalf("missing file: exit %d", r.Code)
		}
		if r := a.TryEnc("frobnicate"); r.Code != 2 {
			t.Fatalf("unknown command: exit %d", r.Code)
		}
		c := w.clone("carol")
		c.Write(".env", "mine\n")
		if r := c.TryEnc("update", ".env"); r.Code != 4 {
			t.Fatalf("no key: exit %d", r.Code)
		}
	})

	t.Run("L4 unclear blocks still guard commits", func(t *testing.T) {
		_, a, _ := team(t)
		a.Write(".gitignore", a.Read(".gitignore")+"# git-enc: team\n/token.txt\n")
		a.Write("token.txt", "T=1\n")
		a.Git("add", "-f", "token.txt")
		if r := a.TryGit("commit", "-q", "-m", "x"); r.Code == 0 {
			t.Fatal("plaintext in an unterminated block was committed")
		}
	})

	t.Run("L5 a key others can read says so", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("no unix permissions")
		}
		_, a, _ := team(t)
		os.Chmod(filepath.Join(a.home, "keys", "team"), 0o644)
		st := a.Status()
		if !strings.Contains(st.Secrets[0].Message, "chmod 600") {
			t.Fatalf("message: %q", st.Secrets[0].Message)
		}
		if r := a.TryEnc("key", "show", "team"); !strings.Contains(r.Err, "chmod 600") {
			t.Fatalf("key show: %s", r.Err)
		}
	})
}

// A broad rule outside the block (".env*", common in real projects) hides
// .env.enc; a `!.env.enc` line after it fixes that, and add must accept it.
func TestNegationAfterBroadRule(t *testing.T) {
	w := newWorld(t)
	a := w.clone("alice")
	a.Enc("key", "new", "team")
	a.Write(".gitignore", ".env*\n")
	a.Write(".env", "K=1\n")
	r := a.TryEnc("add", "--key", "team", ".env")
	if r.Code != 3 || !strings.Contains(r.Err, "add `!.env.enc` after it") {
		t.Fatalf("broad rule: exit %d %s", r.Code, r.Err)
	}
	a.Write(".gitignore", ".env*\n!.env.enc\n")
	a.Enc("add", "--key", "team", ".env")
	a.expectState(".env", "clean")
	if out := a.Git("status", "--porcelain"); strings.Contains(out, " .env\n") || !strings.Contains(out, ".env.enc") {
		t.Fatalf("status:\n%s", out)
	}
}
