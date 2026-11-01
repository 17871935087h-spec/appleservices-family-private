//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Laky-64/appleservices/internal/credentialvault"
)

func TestSuccessfulPasswordLoginSavesCredentialAfterSessionPersistence(t *testing.T) {
	dir := newPasswordSaveTestDir(t)
	if err := os.WriteFile(filepath.Join(dir, "session.json"), []byte("native session fixture"), 0o600); err != nil {
		t.Fatal("native session fixture setup failed")
	}
	if err := saveCredentialAfterSuccessfulLogin(dir, "saved-user@example.test", "fixture-password", false); err != nil {
		t.Fatal("successful password login did not save its credential")
	}
	loaded, err := credentialvault.Load(dir, "SAVED-USER@example.test")
	if err != nil || loaded != "fixture-password" {
		t.Fatal("saved credential could not be loaded")
	}
}

func TestResumeSessionDoesNotOverwriteSavedPassword(t *testing.T) {
	dir := newPasswordSaveTestDir(t)
	if err := credentialvault.Save(dir, "saved-user@example.test", "existing-password"); err != nil {
		t.Fatal("credential fixture setup failed")
	}
	if err := saveCredentialAfterSuccessfulLogin(dir, "saved-user@example.test", "", true); err != nil {
		t.Fatal("passwordless resume should not attempt a credential save")
	}
	loaded, err := credentialvault.Load(dir, "saved-user@example.test")
	if err != nil || loaded != "existing-password" {
		t.Fatal("passwordless resume changed the saved credential")
	}
}

func TestCredentialSaveFailureIsVisibleWithoutChangingPersistedSession(t *testing.T) {
	dir := newPasswordSaveTestDir(t)
	sessionPath := filepath.Join(dir, "session.json")
	const sessionFixture = "persisted native session fixture"
	if err := os.WriteFile(sessionPath, []byte(sessionFixture), 0o600); err != nil {
		t.Fatal("native session fixture setup failed")
	}
	err := saveCredentialAfterSuccessfulLogin(dir, "", "fixture-password", false)
	if !errors.Is(err, credentialvault.ErrInvalidAppleID) || strings.Contains(err.Error(), "fixture-password") {
		t.Fatal("credential save failure was not safely identifiable")
	}
	savedSession, err := os.ReadFile(sessionPath)
	if err != nil || string(savedSession) != sessionFixture {
		t.Fatal("credential save failure changed the persisted native session")
	}
}

func newPasswordSaveTestDir(t *testing.T) string {
	t.Helper()
	root := `D:\DevData\appleservices-family-private-password-save-tests`
	if !strings.EqualFold(filepath.VolumeName(root), "D:") {
		t.Fatal("test output root is not on D")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal("D test output directory is unavailable")
	}
	dir, err := os.MkdirTemp(root, "account-")
	if err != nil {
		t.Fatal("D test account directory could not be created")
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || !strings.EqualFold(filepath.VolumeName(resolved), "D:") {
		t.Fatal("test account directory did not resolve to D")
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
