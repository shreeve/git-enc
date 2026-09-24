// Package state keeps git-enc's per-worktree memory of each secret.
//
// For every secret it records the base: the last committed version of the
// .enc that the local plaintext was known to equal. Comparing the plaintext
// and the .enc against the base tells an edit (plaintext moved) from an
// update (the .enc moved) from a conflict (both moved), which a plain
// "plaintext differs from .enc" check cannot.
//
// The base only ever points at a committed blob, so a plaintext equal to the
// base can always be recovered from git history; that is what makes it safe
// for `git enc update` to overwrite it.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/shreeve/git-enc/internal/fsx"
)

// Entry is what git-enc remembers about one secret.
type Entry struct {
	BaseBlob string `json:"base_blob,omitempty"` // committed .enc blob the plaintext last equalled
	BaseHash string `json:"base_hash,omitempty"` // sha256 of that version's plaintext
	// Pending is the blob `git enc add` last wrote; it becomes the base once
	// it is committed.
	Pending string `json:"pending,omitempty"`
	// Seen is a .enc blob the user has already been shown as F.incoming
	// (or merged into F), so adding F again is a deliberate resolution.
	Seen string `json:"seen,omitempty"`
	// Merge holds the unmerged stage blobs `git enc merge` resolved.
	Merge string `json:"merge,omitempty"`
}

// State is the whole state file.
type State struct {
	Version int               `json:"version"`
	Secrets map[string]*Entry `json:"secrets"`
	// Managed lists every plaintext path git-enc has handled in this
	// worktree, so it stays excluded from commits even after a block stops
	// listing it.
	Managed []string `json:"managed"`
	path    string
}

// Load reads the state file at path; a missing file is an empty state.
// A corrupt file is also treated as empty: every decision then falls back
// to git history, which is slower and more conservative but never unsafe.
func Load(path string) (*State, error) {
	s := &State{Version: 1, Secrets: map[string]*Entry{}, path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var loaded State
	if json.Unmarshal(data, &loaded) != nil || loaded.Version != 1 {
		return s, nil
	}
	if loaded.Secrets != nil {
		s.Secrets = loaded.Secrets
	}
	s.Managed = loaded.Managed
	return s, nil
}

// Get returns the entry for path, creating it.
func (s *State) Get(path string) *Entry {
	e := s.Secrets[path]
	if e == nil {
		e = &Entry{}
		s.Secrets[path] = e
	}
	return e
}

// Manage records that path is a git-enc plaintext.
func (s *State) Manage(path string) {
	for _, p := range s.Managed {
		if p == path {
			return
		}
	}
	s.Managed = append(s.Managed, path)
	sort.Strings(s.Managed)
}

// Save writes the state atomically.
func (s *State) Save() error {
	for k, e := range s.Secrets {
		if *e == (Entry{}) {
			delete(s.Secrets, k)
		}
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	return fsx.WriteAtomic(s.path, append(data, '\n'), 0o600)
}

// Cache maps .enc blob ids to the sha256 of their plaintext. Blobs never
// change, so entries never go stale, and the file can be deleted at any
// time. It is shared by all worktrees.
type Cache struct {
	Hashes map[string]string `json:"hashes"`
	path   string
	dirty  bool
}

// LoadCache reads the cache at path.
func LoadCache(path string) *Cache {
	c := &Cache{Hashes: map[string]string{}, path: path}
	if data, err := os.ReadFile(path); err == nil {
		var loaded Cache
		if json.Unmarshal(data, &loaded) == nil && loaded.Hashes != nil {
			c.Hashes = loaded.Hashes
		}
	}
	return c
}

// Put records a blob's plaintext hash.
func (c *Cache) Put(blob, hash string) {
	if c.Hashes[blob] != hash {
		c.Hashes[blob] = hash
		c.dirty = true
	}
}

// Save writes the cache if it changed; failures are ignored (it is a cache).
func (c *Cache) Save() {
	if !c.dirty {
		return
	}
	data, err := json.Marshal(c)
	if err != nil {
		return
	}
	if os.MkdirAll(filepath.Dir(c.path), 0o700) == nil {
		_ = fsx.WriteAtomic(c.path, data, 0o600)
	}
}

// Lock is an exclusive lock on a worktree's git-enc state.
type Lock struct{ path string }

// Acquire takes the lock at path, waiting up to five seconds. A lock older
// than a minute is left over from a crashed process and is broken.
func Acquire(path string) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			f.WriteString(strconv.Itoa(os.Getpid()) + "\n")
			f.Close()
			return &Lock{path}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if fi, err := os.Stat(path); err == nil && time.Since(fi.ModTime()) > time.Minute {
			os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("another git-enc is running (lock %s); if not, delete that file", path)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Release frees the lock.
func (l *Lock) Release() { os.Remove(l.path) }
