// Package fsx writes files safely: atomically, and never through a
// symlink or outside the worktree.
package fsx

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// TempPattern matches the temporary files WriteAtomic creates. They can
// hold plaintext for a moment, so git-enc keeps them out of commits.
const TempPattern = ".*.git-enc-tmp-*"

var (
	temps sync.Map   // path -> struct{}
	mu    sync.Mutex // held while writing plaintext to a temporary file; Cleanup takes it for good
)

// Hold is taken while writing plaintext into a tracked temporary file or
// directory, so an interrupt cannot remove the directory halfway and let
// the rest of the write land after it. It returns the release function.
func Hold() func() {
	mu.Lock()
	return mu.Unlock
}

// Track registers a file or directory to remove if the process is
// interrupted (a temporary copy of plaintext, a lock); the returned
// function unregisters it.
func Track(path string) (untrack func()) {
	temps.Store(path, struct{}{})
	return func() { temps.Delete(path) }
}

// Cleanup removes everything still tracked; it is called when the process
// is interrupted, which must exit right after: it waits for a write in
// progress, and no other write can start.
func Cleanup() {
	mu.Lock()
	temps.Range(func(k, _ any) bool {
		os.RemoveAll(k.(string))
		return true
	})
}

// TempDir creates a private temporary directory in parent for plaintext.
// The returned function removes it, as does Cleanup.
func TempDir(parent, pattern string) (string, func(), error) {
	defer Hold()() // created and tracked as one step
	dir, err := os.MkdirTemp(parent, pattern)
	if err != nil {
		return "", nil, err
	}
	untrack := Track(dir)
	return dir, func() {
		os.RemoveAll(dir)
		untrack()
	}, nil
}

// WriteAtomic writes data to path by writing a temporary file in the same
// directory, syncing it, and renaming it into place. A reader never sees a
// half-written file, and an interruption leaves the old file intact.
func WriteAtomic(path string, data []byte, perm os.FileMode) error {
	defer Hold()()
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".git-enc-tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer Track(name)()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(name)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// CheckInside verifies that using the repository-relative path rel under
// root cannot escape root: no existing component of the path may be a
// symlink, and the target, if it exists, must be a regular file.
func CheckInside(root, rel string) error {
	parts := strings.Split(rel, "/")
	cur := root
	for i, p := range parts {
		cur = filepath.Join(cur, p)
		fi, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to use %s: %s is a symlink", rel, strings.Join(parts[:i+1], "/"))
		}
		last := i == len(parts)-1
		if last && !fi.Mode().IsRegular() {
			return fmt.Errorf("refusing to use %s: not a regular file", rel)
		}
		if !last && !fi.IsDir() {
			return fmt.Errorf("refusing to use %s: %s is not a directory", rel, strings.Join(parts[:i+1], "/"))
		}
	}
	return nil
}

// WriteWorktree writes a file inside the worktree after CheckInside,
// creating parent directories. An existing file keeps its permissions;
// a new one is created with perm.
func WriteWorktree(root, rel string, data []byte, perm os.FileMode) error {
	if err := CheckInside(root, rel); err != nil {
		return err
	}
	abs := filepath.Join(root, filepath.FromSlash(rel))
	if fi, err := os.Lstat(abs); err == nil {
		perm = fi.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return err
	}
	if err := CheckInside(root, rel); err != nil { // re-check after MkdirAll
		return err
	}
	return WriteAtomic(abs, data, perm)
}

// ReadRegular reads a worktree file, refusing symlinks anywhere on its
// path (so a tracked symlinked directory cannot make git-enc read a file
// from outside the worktree) and anything that is not a regular file.
// It returns (nil, nil) if the file does not exist.
func ReadRegular(root, rel string) ([]byte, error) {
	if err := CheckInside(root, rel); err != nil {
		return nil, err
	}
	abs := filepath.Join(root, filepath.FromSlash(rel))
	fi, err := os.Lstat(abs)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", rel)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	if data == nil {
		data = []byte{}
	}
	return data, nil
}
