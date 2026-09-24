// Package keys stores the age keys git-enc decrypts with.
//
// Each key is a file named after the key in the key directory
// (~/.config/git-enc/keys, or $GIT_ENC_KEYS_DIR), holding one age identity.
// A key is identified by its fingerprint, a short hash of its public half,
// which .gitignore records next to the key name; two different keys that
// happen to share a name are told apart by it. $GIT_ENC_KEY may hold more
// identities (one per line), for CI.
package keys

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"filippo.io/age"
	"github.com/shreeve/git-enc/internal/spec"
)

// Key is one usable identity.
type Key struct {
	Name        string // file name, or "env" for $GIT_ENC_KEY
	Fingerprint string
	File        string // "" for keys from the environment
	Kind        string // "post-quantum" or "x25519"
	Identity    age.Identity
	Recipient   age.Recipient
	secret      string
}

// Secret returns the key's secret string (for `git enc key show`).
func (k *Key) Secret() string { return k.secret }

// Dir returns the key directory.
func Dir() (string, error) {
	if d := os.Getenv("GIT_ENC_KEYS_DIR"); d != "" {
		return d, nil
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "git-enc", "keys"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "git-enc", "keys"), nil
}

// Fingerprint returns the short fingerprint of a public key string.
func Fingerprint(recipient string) string {
	sum := sha256.Sum256([]byte("git-enc key fingerprint\n" + recipient))
	return hex.EncodeToString(sum[:4])
}

// parse reads one identity from a key file's contents: the first line
// that is not blank or a comment.
func parse(name, file, data string) (*Key, error) {
	var line string
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if line != "" {
			return nil, fmt.Errorf("key %q: holds more than one key", name)
		}
		line = t
	}
	if line == "" {
		return nil, fmt.Errorf("key %q: no key found", name)
	}
	return fromString(name, file, line)
}

func fromString(name, file, s string) (*Key, error) {
	k := &Key{Name: name, File: file, secret: s}
	switch {
	case strings.HasPrefix(s, "AGE-SECRET-KEY-PQ-1"):
		id, err := age.ParseHybridIdentity(s)
		if err != nil {
			return nil, fmt.Errorf("key %q: %v", name, err)
		}
		r := id.Recipient()
		k.Identity, k.Recipient, k.Kind = id, r, "post-quantum"
		k.Fingerprint = Fingerprint(r.String())
	case strings.HasPrefix(s, "AGE-SECRET-KEY-1"):
		id, err := age.ParseX25519Identity(s)
		if err != nil {
			return nil, fmt.Errorf("key %q: %v", name, err)
		}
		r := id.Recipient()
		k.Identity, k.Recipient, k.Kind = id, r, "x25519"
		k.Fingerprint = Fingerprint(r.String())
	default:
		return nil, fmt.Errorf("key %q: not an age secret key (expected AGE-SECRET-KEY-PQ-1… or AGE-SECRET-KEY-1…)", name)
	}
	return k, nil
}

// Store is every key available to this user.
type Store struct {
	Keys     []*Key
	Warnings []string          // unreadable or unsafe key files, skipped
	Skipped  map[string]string // key name -> why its file was skipped
}

// Load reads the key directory and $GIT_ENC_KEY.
func Load() (*Store, error) {
	st := &Store{Skipped: map[string]string{}}
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, ".") || !spec.ValidKeyName(name) {
			continue
		}
		file := filepath.Join(dir, name)
		if err := checkPerm(file); err != nil {
			st.Warnings = append(st.Warnings, err.Error())
			st.Skipped[name] = err.Error()
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			st.Warnings = append(st.Warnings, err.Error())
			continue
		}
		k, err := parse(name, file, string(data))
		if err != nil {
			st.Warnings = append(st.Warnings, err.Error())
			st.Skipped[name] = err.Error()
			continue
		}
		st.Keys = append(st.Keys, k)
	}
	if env := os.Getenv("GIT_ENC_KEY"); env != "" {
		for _, line := range strings.Split(env, "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			k, err := fromString("env", "", t)
			if err != nil {
				st.Warnings = append(st.Warnings, "GIT_ENC_KEY: "+err.Error())
				continue
			}
			st.Keys = append(st.Keys, k)
		}
	}
	sort.SliceStable(st.Keys, func(i, j int) bool { return st.Keys[i].Name < st.Keys[j].Name })
	return st, nil
}

// ByFingerprint returns the key with fingerprint fp.
func (s *Store) ByFingerprint(fp string) *Key {
	for _, k := range s.Keys {
		if k.Fingerprint == fp {
			return k
		}
	}
	return nil
}

// ByName returns the stored key file with that name.
func (s *Store) ByName(name string) *Key {
	for _, k := range s.Keys {
		if k.Name == name && k.File != "" {
			return k
		}
	}
	return nil
}

// Identities returns every identity, for decrypting files whose key is not
// known in advance (backups, `git enc cat`).
func (s *Store) Identities() []age.Identity {
	ids := make([]age.Identity, len(s.Keys))
	for i, k := range s.Keys {
		ids[i] = k.Identity
	}
	return ids
}

// Generate creates a new post-quantum key named name.
func Generate(name string) (*Key, error) {
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		return nil, err
	}
	return save(name, id.String())
}

// Import saves a key read from r (never from the command line, which would
// leave it in shell history and process listings).
func Import(name string, r io.Reader) (*Key, error) {
	data, err := io.ReadAll(io.LimitReader(r, 64<<10))
	if err != nil {
		return nil, err
	}
	k, err := parse(name, "", string(data))
	if err != nil {
		return nil, err
	}
	return save(name, k.secret)
}

func save(name, secret string) (*Key, error) {
	if !spec.ValidKeyName(name) {
		return nil, fmt.Errorf("invalid key name %q (use letters, digits, `.`, `_`, `-`)", name)
	}
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	_ = os.Chmod(dir, 0o700)
	file := filepath.Join(dir, name)
	k, err := fromString(name, file, secret)
	if err != nil {
		return nil, err
	}
	if data, err := os.ReadFile(file); err == nil {
		if old, err := parse(name, file, string(data)); err == nil && old.Fingerprint == k.Fingerprint {
			return old, nil
		}
		return nil, fmt.Errorf("a different key named %q already exists (%s); choose another name", name, file)
	}
	content := fmt.Sprintf("# git-enc key %q, fingerprint %s\n# Keep this secret. Anyone with it can read every secret it protects.\n%s\n", name, k.Fingerprint, secret)
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		os.Remove(file)
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return k, nil
}

// checkPerm refuses key files others can read, as ssh does.
func checkPerm(file string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	fi, err := os.Stat(file)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("ignoring key %s: readable by other users (run: chmod 600 %s)", file, file)
	}
	return nil
}
