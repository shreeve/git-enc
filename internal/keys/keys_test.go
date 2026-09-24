package keys

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestGenerateImportLoad(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GIT_ENC_KEYS_DIR", dir)
	t.Setenv("GIT_ENC_KEY", "")
	k, err := Generate("team")
	if err != nil {
		t.Fatal(err)
	}
	if k.Kind != "post-quantum" || len(k.Fingerprint) != 8 {
		t.Fatalf("key = %+v", k)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(k.File)
		di, _ := os.Stat(dir)
		if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
			t.Fatalf("modes %v %v", fi.Mode(), di.Mode())
		}
	}
	// Importing the same key again is a no-op; a different one is refused.
	if _, err := Import("team", strings.NewReader(k.Secret())); err != nil {
		t.Fatalf("re-import: %v", err)
	}
	other, _ := Generate("other")
	if _, err := Import("team", strings.NewReader(other.Secret())); err == nil {
		t.Fatal("overwrote a different key with the same name")
	}
	st, err := Load()
	if err != nil || len(st.Keys) != 2 || st.ByFingerprint(k.Fingerprint).Name != "team" {
		t.Fatalf("load: %v %+v", err, st)
	}
}

func TestEnvKeysAndBadInput(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GIT_ENC_KEYS_DIR", dir)
	k, _ := Generate("team")
	os.Remove(k.File)
	t.Setenv("GIT_ENC_KEY", "# ci\n"+k.Secret()+"\n")
	st, _ := Load()
	if len(st.Keys) != 1 || st.ByFingerprint(k.Fingerprint) == nil || st.ByName("team") != nil {
		t.Fatalf("env key: %+v", st.Keys)
	}
	for _, bad := range []string{"", "hello", "AGE-SECRET-KEY-1NOTAKEY", k.Secret() + "\n" + k.Secret()} {
		if _, err := Import("x", strings.NewReader(bad)); err == nil {
			t.Errorf("imported %q", bad)
		}
	}
	if _, err := Generate("../escape"); err == nil {
		t.Fatal("accepted a key name with a path")
	}
}

func TestRefusesReadableKeys(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no unix permissions")
	}
	dir := t.TempDir()
	t.Setenv("GIT_ENC_KEYS_DIR", dir)
	t.Setenv("GIT_ENC_KEY", "")
	k, _ := Generate("team")
	os.Chmod(k.File, 0o644)
	st, _ := Load()
	if len(st.Keys) != 0 || len(st.Warnings) != 1 || !strings.Contains(st.Warnings[0], "chmod 600") {
		t.Fatalf("readable key used: %+v", st)
	}
}
