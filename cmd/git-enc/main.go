// Command git-enc keeps secrets in git, encrypted. Run it as `git enc`.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/shreeve/git-enc/internal/engine"
	"github.com/shreeve/git-enc/internal/fsx"
	"github.com/shreeve/git-enc/internal/keys"
)

// version is set at release time with -ldflags "-X main.version=…"; a
// `go install …@vX.Y.Z` build reads it from the module instead.
var version = ""

func versionString() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return strings.TrimPrefix(bi.Main.Version, "v")
	}
	return "dev"
}

// protocol is the version of the `status --json` contract.
const protocol = 1

// Exit codes.
const (
	exitOK        = 0
	exitError     = 1
	exitUsage     = 2
	exitAttention = 3 // something needs `git enc add`, `update` or `merge`
	exitNoKey     = 4 // a key is missing
)

const usage = `git enc — encrypted secrets in git, declared in .gitignore

Declare secrets in .gitignore (git ignores the plaintext; git enc commits
an encrypted F.enc beside each one):

    # git-enc: team 3f9a1c2e
    .env
    config/secrets.yml
    # git-enc: end

Everyday commands:
    git enc status             which secrets you edited, which changed in git
                               (--json for tools, --exit-code as for check)
    git enc add FILE… | --all  encrypt your edits and stage the .enc files
    git enc update [FILE…]     bring your copies up to date (never loses edits)
    git enc diff [FILE…]       show your edits against the committed version
    git enc merge [FILE…]      resolve a git merge/rebase conflict on a secret

Setup:
    git enc init               set up this clone (hooks; decrypts what you're missing)
    git enc key new NAME       create a key; share it once, out of band
    git enc key add NAME       import a key someone shared (reads stdin)
    git enc key show NAME      print a key (e.g. | pbcopy)
    git enc key list           your keys
    git enc rekey OLD NEW      move every block from key OLD to key NEW and
                               re-encrypt its secrets (when someone leaves)
    git enc rekey              re-encrypt secrets whose block's key changed by
                               hand (a line moved to another block)

Other:
    git enc check              quiet check for scripts: exit 3 if anything needs doing
    git enc cat FILE           decrypt a .enc or a backup to stdout
    git enc version [--json]

Exit codes: 0 ok, 1 error, 2 usage, 3 needs attention, 4 missing key.
`

func main() {
	// An interrupted write must not leave plaintext in a temporary file.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-sig
		fsx.Cleanup()
		os.Exit(130)
	}()
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	var err error
	code := exitOK
	switch cmd {
	case "help", "-h", "--help":
		fmt.Print(usage)
	case "version", "--version":
		code, err = cmdVersion(rest)
	case "status":
		code, err = cmdStatus(rest)
	case "check":
		code, err = cmdCheck(rest)
	case "add":
		code, err = cmdAdd(rest)
	case "update":
		code, err = cmdUpdate(rest)
	case "diff":
		code, err = cmdDiff(rest)
	case "merge":
		code, err = cmdMerge(rest)
	case "init":
		code, err = cmdInit(rest)
	case "key":
		code, err = cmdKey(rest)
	case "cat":
		code, err = cmdCat(rest)
	case "rekey":
		code, err = cmdRekey(rest)
	case "hook":
		return cmdHook(rest)
	default:
		fmt.Fprintf(os.Stderr, "git enc: unknown command %q (see `git enc help`)\n", cmd)
		return exitUsage
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "git enc:", err)
		return errorCode(err)
	}
	return code
}

// errorCode maps an error to the documented exit codes.
func errorCode(err error) int {
	var ue usageError
	var ref *engine.Refusal
	var ke *engine.KeyError
	switch {
	case errors.As(err, &ue):
		return exitUsage
	case errors.As(err, &ke):
		return exitNoKey
	case errors.As(err, &ref):
		return exitAttention
	}
	return exitError
}

type usageError struct{ msg string }

func (u usageError) Error() string { return u.msg }

func flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("git enc "+name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return usageError{err.Error()}
	}
	return nil
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// open opens the repository around the current directory.
func open() (*engine.Engine, error) {
	return engine.Open(".")
}

// closeEngine saves the engine's state: deferred with a command's named
// results, it turns a failed save into the command's error, since a lost
// save can make git-enc misjudge a secret later.
func closeEngine(e *engine.Engine, code *int, err *error) {
	if cerr := e.Close(); cerr != nil && *err == nil {
		*code, *err = exitError, fmt.Errorf("saving git-enc state: %w", cerr)
	}
}

// relPaths turns command-line paths (relative to the current directory)
// into repository-relative slash paths.
func relPaths(e *engine.Engine, args []string) ([]string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	if real, err := filepath.EvalSymlinks(cwd); err == nil {
		cwd = real
	}
	root := e.Repo.Root
	if real, err := filepath.EvalSymlinks(root); err == nil {
		root = real
	}
	var out []string
	for _, a := range args {
		p := a
		if !filepath.IsAbs(p) {
			p = filepath.Join(cwd, p)
		}
		if real, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
			p = filepath.Join(real, filepath.Base(p))
		}
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("%s is outside the repository", a)
		}
		rel = filepath.ToSlash(rel)
		rel = strings.TrimSuffix(rel, ".enc") // accept either name
		out = append(out, rel)
	}
	return out, nil
}

func printLines(lines []string) {
	for _, l := range lines {
		fmt.Println(l)
	}
}

func cmdVersion(args []string) (int, error) {
	fs := flags("version")
	asJSON := fs.Bool("json", false, "")
	if err := parse(fs, args); err != nil {
		return exitUsage, err
	}
	if *asJSON {
		out, _ := json.Marshal(map[string]any{"version": versionString(), "protocol": protocol})
		fmt.Println(string(out))
	} else {
		fmt.Println("git-enc", versionString())
	}
	return exitOK, nil
}

func cmdStatus(args []string) (code int, err error) {
	fs := flags("status")
	asJSON := fs.Bool("json", false, "")
	exitCode := fs.Bool("exit-code", false, "")
	if err := parse(fs, args); err != nil {
		return exitUsage, err
	}
	e, err := open()
	if err != nil {
		return exitError, err
	}
	defer closeEngine(e, &code, &err)
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(e.Report()); err != nil {
			return exitError, err
		}
	} else {
		printStatus(e)
	}
	if *exitCode {
		return attentionCode(e), nil
	}
	return exitOK, nil
}

func attentionCode(e *engine.Engine) int {
	attention, onlyKeys := e.NeedsAttention()
	switch {
	case onlyKeys:
		return exitNoKey
	case attention:
		return exitAttention
	}
	return exitOK
}

func printStatus(e *engine.Engine) {
	r := e.Report()
	if !r.Repo.Uses && len(r.Secrets) == 0 && len(r.Problems) == 0 {
		fmt.Println("no git-enc secrets here (start with `git enc key new NAME`, then `git enc add --key NAME FILE`)")
		return
	}
	for _, k := range r.Keys {
		if k.Available {
			fmt.Printf("key %s (%s): ok\n", k.Name, k.Fingerprint)
		} else {
			fmt.Printf("key %s (%s): not on this machine — `git enc key add %s`\n", k.Name, orUnknown(k.Fingerprint), k.Name)
		}
	}
	group := func(title string, states ...engine.Kind) {
		var rows []engine.ReportSecret
		for _, s := range r.Secrets {
			for _, st := range states {
				if s.State == st {
					rows = append(rows, s)
				}
			}
		}
		if len(rows) == 0 {
			return
		}
		fmt.Printf("\n%s\n", title)
		for _, s := range rows {
			line := fmt.Sprintf("  %-10s %s", string(s.State)+":", s.Path)
			if s.State != engine.Modified && s.State != engine.Outdated && s.State != engine.New && s.State != engine.Missing && s.Message != "" {
				line += "  — " + s.Message
			}
			fmt.Println(line)
		}
	}
	var staged []string
	for _, s := range r.Secrets {
		if s.State == engine.Clean && s.Staged {
			staged = append(staged, s.EncPath)
		}
	}
	if len(staged) > 0 {
		fmt.Println("\nStaged for commit:")
		for _, p := range staged {
			fmt.Println("  " + p)
		}
	}
	group("Edited here (git enc add <file>):", engine.Modified, engine.New)
	group("Changed in git (git enc update):", engine.Outdated, engine.Missing)
	group("Needs attention:", engine.Conflict, engine.Diverged, engine.Merging, engine.NoKey, engine.Corrupt, engine.Orphaned)
	if len(r.Problems) > 0 {
		fmt.Println("\nProblems:")
		for _, p := range r.Problems {
			switch {
			case p.Line > 0:
				fmt.Printf("  %s:%d: %s\n", p.Path, p.Line, p.Message)
			case p.Path != "":
				fmt.Printf("  %s: %s\n", p.Path, p.Message)
			default:
				fmt.Printf("  %s\n", p.Message)
			}
		}
	}
	if a, _ := e.NeedsAttention(); !a {
		n := len(r.Secrets)
		if n == 1 {
			fmt.Println("\n1 secret, clean")
		} else {
			fmt.Printf("\n%d secrets, all clean\n", n)
		}
	}
	for _, w := range e.Keys.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "fingerprint unknown"
	}
	return s
}

func cmdCheck(args []string) (code int, err error) {
	fs := flags("check")
	if err := parse(fs, args); err != nil {
		return exitUsage, err
	}
	e, err := open()
	if err != nil {
		return exitError, err
	}
	defer closeEngine(e, &code, &err)
	code = attentionCode(e)
	if code == exitOK {
		return exitOK, nil
	}
	counts := map[engine.Kind]int{}
	for _, s := range e.Secrets {
		if s.Kind != engine.Clean {
			counts[s.Kind]++
		}
	}
	var parts []string
	for _, k := range []engine.Kind{engine.Modified, engine.New, engine.Outdated, engine.Missing, engine.Conflict, engine.Diverged, engine.Merging, engine.NoKey, engine.Corrupt, engine.Orphaned} {
		if n := counts[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, k))
		}
	}
	if len(e.Problems) > 0 {
		parts = append(parts, fmt.Sprintf("%d problem(s) in .gitignore", len(e.Problems)))
	}
	fmt.Fprintf(os.Stderr, "git-enc: secrets need attention (%s) — run `git enc status`\n", strings.Join(parts, ", "))
	return code, nil
}

func cmdAdd(args []string) (code int, err error) {
	fs := flags("add")
	all := fs.Bool("all", false, "")
	fs.BoolVar(all, "A", false, "")
	force := fs.Bool("force", false, "")
	fs.BoolVar(force, "f", false, "")
	key := fs.String("key", "", "")
	if err := parse(fs, args); err != nil {
		return exitUsage, err
	}
	if !*all && fs.NArg() == 0 {
		return exitUsage, usageError{"name the files to add, or use --all"}
	}
	e, err := open()
	if err != nil {
		return exitError, err
	}
	defer closeEngine(e, &code, &err)
	paths, err := relPaths(e, fs.Args())
	if err != nil {
		return exitUsage, err
	}
	out, err := e.Add(paths, engine.AddOptions{All: *all, Force: *force, Key: *key})
	printLines(out)
	if err != nil {
		return errorCode(err), err
	}
	return exitOK, nil
}

func cmdUpdate(args []string) (code int, err error) {
	fs := flags("update")
	discard := fs.Bool("discard", false, "")
	if err := parse(fs, args); err != nil {
		return exitUsage, err
	}
	if *discard && fs.NArg() == 0 {
		return exitUsage, usageError{"--discard needs the files to discard edits in"}
	}
	e, err := open()
	if err != nil {
		return exitError, err
	}
	defer closeEngine(e, &code, &err)
	paths, err := relPaths(e, fs.Args())
	if err != nil {
		return exitUsage, err
	}
	out, err := e.Update(paths, engine.UpdateOptions{Discard: *discard})
	printLines(out)
	if err != nil {
		return errorCode(err), err
	}
	if len(e.Reminders()) > 0 {
		for _, s := range e.Secrets {
			if s.Kind == engine.NoKey {
				return exitNoKey, nil
			}
		}
	}
	return exitOK, nil
}

func cmdDiff(args []string) (code int, err error) {
	fs := flags("diff")
	if err := parse(fs, args); err != nil {
		return exitUsage, err
	}
	e, err := open()
	if err != nil {
		return exitError, err
	}
	defer closeEngine(e, &code, &err)
	paths, err := relPaths(e, fs.Args())
	if err != nil {
		return exitUsage, err
	}
	return exitOK, e.Diff(paths, isTTY(os.Stdout), os.Stdout)
}

func cmdMerge(args []string) (code int, err error) {
	fs := flags("merge")
	if err := parse(fs, args); err != nil {
		return exitUsage, err
	}
	e, err := open()
	if err != nil {
		return exitError, err
	}
	defer closeEngine(e, &code, &err)
	paths, err := relPaths(e, fs.Args())
	if err != nil {
		return exitUsage, err
	}
	out, err := e.Merge(paths)
	printLines(out)
	if err != nil {
		return errorCode(err), err
	}
	return exitOK, nil
}

func cmdInit(args []string) (code int, err error) {
	fs := flags("init")
	if err := parse(fs, args); err != nil {
		return exitUsage, err
	}
	e, err := open()
	if err != nil {
		return exitError, err
	}
	defer closeEngine(e, &code, &err)
	bin, err := binaryPath()
	if err != nil {
		return exitError, err
	}
	out, err := e.Init(bin)
	printLines(out)
	if err != nil {
		return exitError, err
	}
	return exitOK, nil
}

// binaryPath returns the path hooks should call: the one on PATH if it is
// this binary (a stable name like /opt/homebrew/bin/git-enc that survives
// upgrades), else this executable's own path.
func binaryPath() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	selfReal, err := filepath.EvalSymlinks(self)
	if err != nil {
		selfReal = self
	}
	if onPath, err := exec.LookPath("git-enc"); err == nil {
		if abs, err := filepath.Abs(onPath); err == nil {
			if real, err := filepath.EvalSymlinks(abs); err == nil && real == selfReal {
				return abs, nil
			}
		}
	}
	return selfReal, nil
}

func cmdKey(args []string) (int, error) {
	if len(args) == 0 {
		return exitUsage, usageError{"usage: git enc key new|add|show|list [NAME]"}
	}
	sub, rest := args[0], args[1:]
	name := ""
	if sub != "list" {
		if len(rest) != 1 {
			return exitUsage, usageError{fmt.Sprintf("usage: git enc key %s NAME", sub)}
		}
		name = rest[0]
	}
	switch sub {
	case "new":
		k, err := keys.Generate(name)
		if err != nil {
			return exitError, err
		}
		fmt.Printf("created key %s (fingerprint %s) in %s\n", k.Name, k.Fingerprint, k.File)
		fmt.Printf("share it once with your team, through a password manager:\n  git enc key show %s | pbcopy\n", k.Name)
	case "add":
		if isTTY(os.Stdin) {
			fmt.Fprintf(os.Stderr, "paste key %s, then press Ctrl-D:\n", name)
		}
		k, err := keys.Import(name, os.Stdin)
		if err != nil {
			return exitError, err
		}
		fmt.Printf("saved key %s (fingerprint %s) in %s\n", k.Name, k.Fingerprint, k.File)
		fmt.Println("next, in a repository that uses it: git enc update")
	case "show":
		st, err := keys.Load()
		if err != nil {
			return exitError, err
		}
		k := st.ByName(name)
		if k == nil {
			if why, ok := st.Skipped[name]; ok {
				return exitError, fmt.Errorf("%s", why)
			}
			return exitError, fmt.Errorf("no key named %s", name)
		}
		if isTTY(os.Stdout) {
			fmt.Fprintf(os.Stderr, "key %s (%s) — anyone with this can read every secret it protects:\n", k.Name, k.Fingerprint)
		}
		fmt.Println(k.Secret())
	case "list":
		st, err := keys.Load()
		if err != nil {
			return exitError, err
		}
		for _, w := range st.Warnings {
			fmt.Fprintln(os.Stderr, "warning:", w)
		}
		if len(st.Keys) == 0 {
			dir, _ := keys.Dir()
			fmt.Printf("no keys (they live in %s)\n", dir)
		}
		for _, k := range st.Keys {
			where := k.File
			if where == "" {
				where = "$GIT_ENC_KEY"
			}
			fmt.Printf("%-16s %s  %-12s %s\n", k.Name, k.Fingerprint, k.Kind, where)
		}
	default:
		return exitUsage, usageError{"usage: git enc key new|add|show|list [NAME]"}
	}
	return exitOK, nil
}

func cmdRekey(args []string) (code int, err error) {
	fs := flags("rekey")
	if err := parse(fs, args); err != nil {
		return exitUsage, err
	}
	var from, to string
	switch fs.NArg() {
	case 0:
	case 2:
		from, to = fs.Arg(0), fs.Arg(1)
	default:
		return exitUsage, usageError{"usage: git enc rekey [OLD NEW]"}
	}
	e, err := open()
	if err != nil {
		return exitError, err
	}
	defer closeEngine(e, &code, &err)
	out, err := e.Rekey(from, to)
	printLines(out)
	if err != nil {
		return errorCode(err), err
	}
	return exitOK, nil
}

func cmdCat(args []string) (int, error) {
	if len(args) != 1 {
		return exitUsage, usageError{"usage: git enc cat FILE"}
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return exitError, err
	}
	body, err := engine.Cat(data)
	if err != nil {
		return exitError, err
	}
	os.Stdout.Write(body)
	return exitOK, nil
}

// cmdHook runs a git hook. Hooks read without taking git-enc's lock, so
// they work while another git-enc runs. Only the pre-commit guard can stop
// a git operation: when plaintext is staged, or when it cannot check.
func cmdHook(args []string) int {
	if len(args) == 0 {
		return exitOK
	}
	if args[0] == "post-checkout" && len(args) == 4 && args[3] == "1" && engine.SameSecrets(".", args[1], args[2]) {
		return exitOK // a branch switch that changed no .enc and no .gitignore: nothing to remind
	}
	e, err := engine.OpenReadOnly(".")
	if err != nil {
		fmt.Fprintln(os.Stderr, "git-enc:", err)
		if args[0] == "pre-commit" {
			fmt.Fprintln(os.Stderr, "git-enc: cannot check this commit for plaintext secrets; fix the problem above (or commit with --no-verify if you are sure)")
			return exitError
		}
		return exitOK
	}
	out, stop := e.Hook(args[0])
	for _, l := range out {
		fmt.Fprintln(os.Stderr, l)
	}
	if stop {
		return exitError
	}
	return exitOK
}
