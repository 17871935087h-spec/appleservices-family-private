package credentialvault

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAccountBlobEncryptionScopeAndPrimaryPasswordIsolation(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("DPAPI requires Windows")
	}
	dir := t.TempDir()
	const id = "fixture@example.test"
	if err := Save(dir, id, "primary-fixture"); err != nil {
		t.Fatal(err)
	}
	plain := bytes.Repeat([]byte("session-fixture-no-real-secret-"), 100)
	if err := SaveBlob(dir, id, "app-password-session", plain); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "app-password-session.dpapi"))
	if err != nil || bytes.Contains(raw, []byte("session-fixture")) {
		t.Fatal("blob was not encrypted")
	}
	got, err := LoadBlob(dir, id, "app-password-session")
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("blob roundtrip failed")
	}
	clear(got)
	if password, err := Load(dir, id); err != nil || password != "primary-fixture" {
		t.Fatal("primary password was changed")
	}
	if _, err = LoadBlob(dir, "other@example.test", "app-password-session"); err == nil {
		t.Fatal("cross-account blob accepted")
	}
	if err = SaveBlob(dir, id, "credential", plain); err == nil {
		t.Fatal("reserved file name accepted")
	}
	if err = os.WriteFile(filepath.Join(dir, "app-password-result.dpapi"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadBlob(dir, id, "app-password-result"); err == nil {
		t.Fatal("cross-purpose blob accepted")
	}
}
