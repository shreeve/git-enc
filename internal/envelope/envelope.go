// Package envelope defines what is inside a .enc file.
//
// A .enc file is a standard age file, readable with `age -d`. The decrypted
// payload is:
//
//	git-enc 1 <length> <path>\n
//	<length bytes of the secret>
//	<zero padding>
//
// The header binds the ciphertext to its path, so a .enc copied over
// another secret's name is detected. The padding rounds the payload up to
// a size bucket, so the exact length of a secret is not visible: every
// payload under 256 bytes produces the same ciphertext size, and larger
// ones grow by at most about 12% (the Padmé scheme). age encrypts under a
// fresh random key every time, so equal secrets never produce equal files.
package envelope

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"strconv"
	"strings"

	"filippo.io/age"
)

const (
	magic   = "git-enc"
	version = 1
	minSize = 256
)

// ageHeader starts every binary age file.
const ageHeader = "age-encryption.org/v1\n"

// IsSealed reports whether data looks like a .enc file (an age file), as
// opposed to plaintext that ended up under a .enc name.
func IsSealed(data []byte) bool { return bytes.HasPrefix(data, []byte(ageHeader)) }

// ErrPath means the ciphertext belongs to a different path.
var ErrPath = errors.New("encrypted for a different path")

// Seal encrypts body for path to recipient.
func Seal(path string, body []byte, recipient age.Recipient) ([]byte, error) {
	if strings.ContainsAny(path, "\n\x00") {
		return nil, fmt.Errorf("invalid path %q", path)
	}
	header := fmt.Sprintf("%s %d %d %s\n", magic, version, len(body), path)
	n := len(header) + len(body)
	payload := make([]byte, Padded(n))
	copy(payload, header)
	copy(payload[len(header):], body)

	var out bytes.Buffer
	w, err := age.Encrypt(&out, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(payload); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Open decrypts a .enc file with any of the identities and returns the
// path it was sealed for and the secret. If wantPath is not empty and the
// sealed path differs, it returns ErrPath (with the sealed path).
func Open(data []byte, wantPath string, ids ...age.Identity) (string, []byte, error) {
	r, err := age.Decrypt(bytes.NewReader(data), ids...)
	if err != nil {
		return "", nil, err
	}
	payload, err := io.ReadAll(r)
	if err != nil {
		return "", nil, err
	}
	path, body, err := parse(payload)
	if err != nil {
		return "", nil, err
	}
	if wantPath != "" && path != wantPath {
		return path, nil, fmt.Errorf("%w: it was sealed for %q", ErrPath, path)
	}
	return path, body, nil
}

func parse(payload []byte) (string, []byte, error) {
	nl := bytes.IndexByte(payload, '\n')
	if nl < 0 || nl > 4096 {
		return "", nil, errors.New("not a git-enc payload (no header)")
	}
	f := strings.SplitN(string(payload[:nl]), " ", 4)
	if len(f) != 4 || f[0] != magic {
		return "", nil, errors.New("not a git-enc payload (bad header)")
	}
	if f[1] != strconv.Itoa(version) {
		return "", nil, fmt.Errorf("git-enc payload version %s is newer than this git-enc supports; upgrade git-enc", f[1])
	}
	n, err := strconv.Atoi(f[2])
	rest := payload[nl+1:]
	if err != nil || n < 0 || n > len(rest) {
		return "", nil, errors.New("corrupt git-enc payload (bad length)")
	}
	for _, c := range rest[n:] {
		if c != 0 {
			return "", nil, errors.New("corrupt git-enc payload (bad padding)")
		}
	}
	return f[3], rest[:n], nil
}

// Padded returns the padded payload size for n bytes: at least 256, then
// Padmé buckets, which leak O(log log n) bits of the length and waste at
// most ~12%.
func Padded(n int) int {
	if n <= minSize {
		return minSize
	}
	l := uint64(n)
	e := 63 - bits.LeadingZeros64(l)         // floor(log2 L)
	s := 64 - bits.LeadingZeros64(uint64(e)) // floor(log2 E) + 1
	last := e - s
	mask := uint64(1)<<uint(last) - 1
	return int((l + mask) &^ mask)
}
