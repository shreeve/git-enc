package envelope

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"filippo.io/age"
)

func key(t *testing.T) *age.HybridIdentity {
	t.Helper()
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRoundTrip(t *testing.T) {
	id := key(t)
	for _, body := range [][]byte{nil, []byte("API_KEY=one\n"), bytes.Repeat([]byte{0, 1, 2, '\n'}, 5000)} {
		data, err := Seal("config/a b.env", body, id.Recipient())
		if err != nil {
			t.Fatal(err)
		}
		path, got, err := Open(data, "config/a b.env", id)
		if err != nil || path != "config/a b.env" || !bytes.Equal(got, body) {
			t.Fatalf("round trip: %q %q %v", path, got, err)
		}
	}
}

func TestFreshEncryptionEveryTime(t *testing.T) {
	id := key(t)
	a, _ := Seal(".env", []byte("same"), id.Recipient())
	b, _ := Seal(".env", []byte("same"), id.Recipient())
	if bytes.Equal(a, b) {
		t.Fatal("equal secrets produced equal ciphertexts")
	}
}

func TestPaddingHidesLength(t *testing.T) {
	id := key(t)
	var sizes []int
	for _, s := range []string{"x", "PASSWORD=hunter2", strings.Repeat("y", 200)} {
		data, _ := Seal(".env", []byte(s), id.Recipient())
		sizes = append(sizes, len(data))
	}
	if sizes[0] != sizes[1] || sizes[1] != sizes[2] {
		t.Fatalf("short secrets differ in size: %v", sizes)
	}
	for n := 1; n < 1<<20; n = n*3 + 7 {
		p := Padded(n)
		if p < n || (n > minSize && float64(p) > float64(n)*1.125) {
			t.Fatalf("Padded(%d) = %d", n, p)
		}
	}
}

func TestPathBinding(t *testing.T) {
	id := key(t)
	data, _ := Seal("a.env", []byte("A"), id.Recipient())
	if _, _, err := Open(data, "b.env", id); !errors.Is(err, ErrPath) {
		t.Fatalf("swapped file accepted: %v", err)
	}
}

func TestWrongKey(t *testing.T) {
	data, _ := Seal(".env", []byte("x"), key(t).Recipient())
	var nm *age.NoIdentityMatchError
	if _, _, err := Open(data, ".env", key(t)); !errors.As(err, &nm) {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestParseRejects(t *testing.T) {
	for _, p := range []string{
		"", "hello", "git-enc 2 1 x\nA", "git-enc 1 5 x\nAB", "git-enc 1 1 x\nAB",
		"git-enc 1 -1 x\n", "nope 1 1 x\nA",
	} {
		if _, _, err := parse([]byte(p)); err == nil {
			t.Errorf("parse(%q) accepted", p)
		}
	}
	if path, body, err := parse([]byte("git-enc 1 1 a b\nA\x00\x00")); err != nil || path != "a b" || string(body) != "A" {
		t.Fatalf("parse valid: %q %q %v", path, body, err)
	}
}
