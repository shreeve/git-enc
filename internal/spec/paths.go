package spec

import (
	"fmt"
	"strings"
)

// CheckPath refuses secret paths that could make decrypting write
// somewhere dangerous: outside the worktree, into .git, or over a file git
// itself reads for configuration. rel is a repository-relative slash path.
func CheckPath(rel string) error {
	if rel == "" {
		return fmt.Errorf("empty path")
	}
	if strings.ContainsAny(rel, "\x00\n\r\\") {
		return fmt.Errorf("%q: paths may not contain NUL, newlines or backslashes", rel)
	}
	if strings.HasPrefix(rel, "/") {
		return fmt.Errorf("%q: absolute paths are not allowed", rel)
	}
	parts := strings.Split(rel, "/")
	for _, c := range parts {
		switch c {
		case "", ".", "..":
			return fmt.Errorf("%q: path components may not be empty, `.` or `..`", rel)
		}
		if strings.HasSuffix(c, ".") || strings.HasSuffix(c, " ") {
			return fmt.Errorf("%q: path components may not end in a dot or space", rel)
		}
		folded := strings.ToLower(stripIgnorable(c))
		if folded == ".git" || folded == "git~1" {
			return fmt.Errorf("%q: paths inside .git are not allowed", rel)
		}
	}
	switch strings.ToLower(parts[len(parts)-1]) {
	case ".gitignore", ".gitattributes", ".gitmodules":
		return fmt.Errorf("%q: git's own configuration files cannot be secrets", rel)
	}
	return nil
}

// stripIgnorable removes the code points HFS+ ignores when comparing names,
// so ".g‌it" is still seen as ".git".
func stripIgnorable(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 0x200c && r <= 0x200f, r >= 0x202a && r <= 0x202e,
			r >= 0x206a && r <= 0x206f, r == 0xfeff:
			return -1
		}
		return r
	}, s)
}
