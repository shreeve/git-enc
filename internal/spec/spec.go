// Package spec reads the git-enc blocks in a repository's root .gitignore.
//
// A block declares which files are secrets and which key protects them:
//
//	# git-enc: team 3f9a1c2e
//	.env
//	config/secrets.yml
//	# git-enc: end
//
// Every line inside a block is an ordinary .gitignore pattern, so git ignores
// the plaintext whether or not git-enc is installed. The encrypted copy of a
// secret F is committed as F.enc.
package spec

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// Block is one `# git-enc:` block.
type Block struct {
	Key         string // key name
	Fingerprint string // short key fingerprint; "" if the header omits it
	Start, End  int    // 1-based line numbers of the two marker lines
	Patterns    []*Pattern
	// Lines holds every pattern line as written, including ones git-enc
	// refuses: git still ignores what they match, so the pre-commit guard
	// asks git about all of them.
	Lines []string
	// Unterminated blocks run to the end of the file; they are reported
	// as problems and never edited.
	Unterminated bool
}

// Pattern is one pattern line inside a block.
type Pattern struct {
	Line     int    // 1-based line number in .gitignore
	Raw      string // the line as written
	anchored bool   // matches the full path, not just a basename
	glob     string // path.Match glob
	lit      string // the unescaped path, if the pattern names one path
	fold     bool   // case-insensitive
}

// Spec is the parsed .gitignore.
type Spec struct {
	Lines  []string // the file's lines, for editing
	Blocks []*Block
	EOL    string // line ending used by the file
}

// Problem is a mistake in .gitignore that git-enc refuses to guess about.
type Problem struct {
	Line int
	Msg  string
}

func (p Problem) Error() string { return fmt.Sprintf(".gitignore:%d: %s", p.Line, p.Msg) }

var (
	markerRE = regexp.MustCompile(`^#\s*git-enc:\s*(.*?)\s*$`)
	keyRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	fprRE    = regexp.MustCompile(`^[0-9a-f]{8}$`)
)

// ValidKeyName reports whether name can name a key.
func ValidKeyName(name string) bool { return keyRE.MatchString(name) && name != "end" }

// Parse parses .gitignore contents. ignoreCase mirrors core.ignorecase.
func Parse(data []byte, ignoreCase bool) (*Spec, []Problem) {
	text := string(data)
	s := &Spec{EOL: "\n"}
	if strings.Contains(text, "\r\n") {
		s.EOL = "\r\n"
		text = strings.ReplaceAll(text, "\r\n", "\n")
	}
	if text != "" {
		s.Lines = strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	}
	var probs []Problem
	var cur *Block
	for i, line := range s.Lines {
		n := i + 1
		if m := markerRE.FindStringSubmatch(line); m != nil {
			f := strings.Fields(m[1])
			if len(f) == 1 && f[0] == "end" {
				if cur == nil {
					probs = append(probs, Problem{n, "`# git-enc: end` without a block to end"})
				} else {
					cur.End = n
					s.Blocks = append(s.Blocks, cur)
					cur = nil
				}
				continue
			}
			if cur != nil {
				probs = append(probs, Problem{n, fmt.Sprintf("new block starts before the block at line %d ends (add `# git-enc: end`)", cur.Start)})
				continue
			}
			if len(f) < 1 || len(f) > 2 || !ValidKeyName(f[0]) {
				probs = append(probs, Problem{n, "expected `# git-enc: <key-name> [fingerprint]` or `# git-enc: end`"})
				continue
			}
			b := &Block{Key: f[0], Start: n}
			if len(f) == 2 {
				if !fprRE.MatchString(f[1]) {
					probs = append(probs, Problem{n, fmt.Sprintf("%q is not a key fingerprint (8 lowercase hex digits)", f[1])})
					continue
				}
				b.Fingerprint = f[1]
			}
			cur = b
			continue
		}
		if cur == nil {
			continue
		}
		raw := line
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		cur.Lines = append(cur.Lines, raw)
		p, err := compile(raw, ignoreCase)
		if err != "" {
			probs = append(probs, Problem{n, err})
			continue
		}
		p.Line = n
		cur.Patterns = append(cur.Patterns, p)
	}
	if cur != nil {
		// Keep it, so its patterns still guard commits, but report it.
		cur.End = len(s.Lines) + 1
		cur.Unterminated = true
		s.Blocks = append(s.Blocks, cur)
		probs = append(probs, Problem{cur.Start, "block is never ended (add `# git-enc: end`)"})
	}
	return s, probs
}

// compile turns a gitignore pattern into a matcher, restricted to the forms
// git-enc can reason about exactly: file patterns with *, ? and [...].
func compile(raw string, fold bool) (*Pattern, string) {
	pat := TrimTrailingSpace(raw)
	switch {
	case strings.HasPrefix(pat, "!"):
		return nil, "negated patterns (`!`) are not allowed in a git-enc block"
	case strings.HasSuffix(pat, "/"):
		return nil, fmt.Sprintf("directory pattern %q would also hide the .enc files; list files instead (e.g. %q)", pat, strings.TrimSuffix(pat, "/")+"/*")
	case strings.Contains(pat, "[:"):
		return nil, "character classes like `[[:digit:]]` are not supported in a git-enc block; use `[0-9]` or list the paths"
	case strings.Contains(pat, "**"):
		return nil, "`**` is not supported in a git-enc block; list the paths or use one `*` per directory level"
	case strings.HasSuffix(pat, ".enc"):
		return nil, fmt.Sprintf("pattern %q names encrypted files; list the plaintext name instead", pat)
	case hasTrailingComment(pat):
		return nil, fmt.Sprintf("%q: .gitignore has no end-of-line comments, so this pattern would not match; put the comment on its own line", pat)
	case strings.HasSuffix(pat, "*") && !strings.HasSuffix(pat, `\*`):
		return nil, fmt.Sprintf("pattern %q also matches the .enc files; end it with the file extension (e.g. %q) or list the files", pat, pat+".yml")
	}
	p := &Pattern{Raw: raw, fold: fold}
	body := pat
	if strings.HasPrefix(body, "/") {
		p.anchored = true
		body = body[1:]
	}
	if strings.Contains(body, "/") {
		p.anchored = true
	}
	if body == "" {
		return nil, "empty pattern"
	}
	if lit, ok := unescape(body); ok && p.anchored {
		p.lit = lit
	}
	// gitignore's [!...] is path.Match's [^...]
	body = strings.ReplaceAll(body, "[!", "[^")
	if fold {
		body = strings.ToLower(body)
	}
	if _, err := path.Match(body, ""); err != nil {
		return nil, fmt.Sprintf("malformed pattern %q", pat)
	}
	p.glob = body
	return p, ""
}

// hasTrailingComment reports an unescaped whitespace-then-# sequence, which
// people write as a comment but git reads as part of the pattern.
func hasTrailingComment(pat string) bool {
	for i := 1; i < len(pat); i++ {
		if pat[i] == '#' && (pat[i-1] == ' ' || pat[i-1] == '\t') && (i < 2 || pat[i-2] != '\\') {
			return true
		}
	}
	return false
}

// TrimTrailingSpace drops trailing spaces the way git does in a
// .gitignore file: a space escaped with a backslash is kept.
func TrimTrailingSpace(s string) string {
	for strings.HasSuffix(s, " ") && !strings.HasSuffix(s, "\\ ") {
		s = s[:len(s)-1]
	}
	return s
}

// Match reports whether the pattern matches the repository-relative file
// path rel, as git would for a file.
func (p *Pattern) Match(rel string) bool {
	if p.fold {
		rel = strings.ToLower(rel)
	}
	if p.anchored {
		ok, _ := path.Match(p.glob, rel)
		return ok
	}
	ok, _ := path.Match(p.glob, path.Base(rel))
	return ok
}

// Literal returns the one path an anchored pattern without wildcards
// names, or "".
func (p *Pattern) Literal() string { return p.lit }

// unescape returns the path a wildcard-free pattern names.
func unescape(pat string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(pat); i++ {
		c := pat[i]
		switch c {
		case '*', '?', '[':
			return "", false
		case '\\':
			if i+1 < len(pat) {
				i++
				c = pat[i]
			}
		}
		b.WriteByte(c)
	}
	return b.String(), true
}

// Match returns the block and pattern that declare rel as a secret, or nil.
// A path matched by patterns in two different blocks is an error.
func (s *Spec) Match(rel string) (*Block, *Pattern, error) {
	var hb *Block
	var hp *Pattern
	for _, b := range s.Blocks {
		for _, p := range b.Patterns {
			if p.Match(rel) {
				if hb != nil && hb != b {
					return nil, nil, fmt.Errorf("%s is declared by two blocks (.gitignore lines %d and %d)", rel, hp.Line, p.Line)
				}
				if hb == nil {
					hb, hp = b, p
				}
			}
		}
	}
	return hb, hp, nil
}

// Anchored reports whether a pattern that names a path from the root
// (`/build/*.yml`, `config/app.yml`) matches rel, as opposed to only a
// pattern for any directory (`.env`).
func (s *Spec) Anchored(rel string) bool {
	for _, b := range s.Blocks {
		for _, p := range b.Patterns {
			if p.anchored && p.Match(rel) {
				return true
			}
		}
	}
	return false
}

// Block returns the first block for the named key.
func (s *Spec) Block(key string) *Block {
	for _, b := range s.Blocks {
		if b.Key == key {
			return b
		}
	}
	return nil
}

// Keys returns the key names used by blocks, in order, without duplicates.
func (s *Spec) Keys() []string {
	var names []string
	seen := map[string]bool{}
	for _, b := range s.Blocks {
		if !seen[b.Key] {
			seen[b.Key] = true
			names = append(names, b.Key)
		}
	}
	return names
}

// Bytes renders the (possibly edited) file.
func (s *Spec) Bytes() []byte {
	if len(s.Lines) == 0 {
		return nil
	}
	return []byte(strings.Join(s.Lines, s.EOL) + s.EOL)
}

// AddPath appends a literal, anchored pattern for rel to block b, just
// before its end marker, and sets the fingerprint if the header lacks it.
func (s *Spec) AddPath(b *Block, rel, fingerprint string) {
	s.insert(b.End-1, EscapePath(rel))
	if b.Fingerprint == "" && fingerprint != "" {
		b.Fingerprint = fingerprint
		s.Lines[b.Start-1] = Header(b.Key, fingerprint)
	}
}

// NewBlock appends a new block holding rel.
func (s *Spec) NewBlock(key, fingerprint, rel string) {
	if n := len(s.Lines); n > 0 && strings.TrimSpace(s.Lines[n-1]) != "" {
		s.Lines = append(s.Lines, "")
	}
	s.Lines = append(s.Lines, Header(key, fingerprint), EscapePath(rel), "# git-enc: end")
}

// Header renders a block's first line.
func Header(key, fingerprint string) string {
	if fingerprint == "" {
		return "# git-enc: " + key
	}
	return "# git-enc: " + key + " " + fingerprint
}

// insert puts line after the 1-based line `after`.
func (s *Spec) insert(after int, line string) {
	s.Lines = append(s.Lines, "")
	copy(s.Lines[after+1:], s.Lines[after:])
	s.Lines[after] = line
}

// EscapePath renders rel as an anchored gitignore pattern that matches
// exactly that path.
func EscapePath(rel string) string {
	var b strings.Builder
	b.WriteByte('/')
	for i, r := range rel {
		switch r {
		case '*', '?', '[', ']', '\\':
			b.WriteByte('\\')
		case ' ':
			if i == len(rel)-1 {
				b.WriteByte('\\')
			}
		}
		b.WriteRune(r)
	}
	return b.String()
}
