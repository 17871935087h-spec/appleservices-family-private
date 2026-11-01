//go:build windows

package credentialvault

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testAppleID  = "vault-user@example.test"
	testPassword = "fixture-password-never-log-this"
	testRoot     = `D:\DevData\appleservices-family-private-credentialvault-tests`
)

func TestCredentialVaultSaveLoadBindsNormalizedAppleIDAndKeepsCiphertext(t *testing.T) {
	dir := newCredentialVaultTestDir(t)
	if err := Save(dir, "  VAULT-USER@EXAMPLE.TEST  ", testPassword); err != nil {
		t.Fatal("credential save failed")
	}
	loaded, err := Load(dir, testAppleID)
	if err != nil || loaded != testPassword {
		t.Fatal("credential did not load for its normalized account")
	}
	wrong, err := Load(dir, "different-user@example.test")
	if !errors.Is(err, ErrDecryption) || wrong != "" {
		t.Fatal("credential was available for a different account")
	}
	for _, sensitive := range []string{testAppleID, "different-user@example.test", testPassword} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatal("decryption error exposed account data")
		}
	}
	replacementPassword := "replacement-fixture-password"
	if err := Save(dir, testAppleID, replacementPassword); err != nil {
		t.Fatal("credential could not be atomically replaced")
	}
	loaded, err = Load(dir, testAppleID)
	if err != nil || loaded != replacementPassword {
		t.Fatal("replaced credential could not be loaded")
	}

	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != fileName {
		t.Fatal("atomic credential save left unexpected files")
	}
	path := filepath.Join(dir, fileName)
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !strings.EqualFold(filepath.VolumeName(resolved), "D:") {
		t.Fatal("credential was not written to D")
	}
	data, err := os.ReadFile(path)
	if err != nil || bytes.Contains(data, []byte(testPassword)) || bytes.Contains(data, []byte(replacementPassword)) {
		t.Fatal("credential file contains plaintext password")
	}
}

func TestCredentialVaultRejectsInvalidSaveWithoutReplacingExistingCredential(t *testing.T) {
	dir := newCredentialVaultTestDir(t)
	boundaryPassword := strings.Repeat("x", maxPasswordBytes)
	if err := Save(dir, testAppleID, boundaryPassword); err != nil {
		t.Fatal("credential save failed")
	}
	invalidPasswords := []struct {
		value string
		want  error
	}{
		{value: "", want: ErrEmptyPassword},
		{value: strings.Repeat("x", maxPasswordBytes+1), want: ErrTooLarge},
		{value: "invalid\x00password", want: ErrInvalidPassword},
		{value: "invalid\rpassword", want: ErrInvalidPassword},
		{value: "invalid\npassword", want: ErrInvalidPassword},
	}
	for _, testCase := range invalidPasswords {
		if err := Save(dir, testAppleID, testCase.value); !errors.Is(err, testCase.want) {
			t.Fatal("invalid password was not rejected")
		}
	}
	loaded, err := Load(dir, testAppleID)
	if err != nil || loaded != boundaryPassword {
		t.Fatal("invalid save changed the prior credential")
	}
	if err := Save(dir, "not-an-account", "another-password"); !errors.Is(err, ErrInvalidAppleID) {
		t.Fatal("invalid account binding was not rejected")
	}
}

func TestCredentialVaultRejectsNonDAndResolvedOutOfDrivePaths(t *testing.T) {
	if err := Save(`C:\credentialvault-test-must-not-be-created`, testAppleID, testPassword); !errors.Is(err, ErrUnsafeAccountDir) {
		t.Fatal("non-D account directory was accepted")
	}
	base := newCredentialVaultTestDir(t)
	target := filepath.Join(os.Getenv("SystemRoot"), "Temp")
	if target == "Temp" {
		t.Skip("system directory is unavailable")
	}
	link := filepath.Join(base, "credentialvault-link-to-system")
	if err := createDirectoryJunction(link, target); err != nil {
		t.Skip("directory symlink creation is unavailable")
	}
	t.Cleanup(func() { _ = os.Remove(link) })
	if err := Save(link, testAppleID, testPassword); !errors.Is(err, ErrUnsafeAccountDir) {
		t.Fatal("account directory resolving outside D was accepted")
	}
}

func createDirectoryJunction(link, target string) error {
	return exec.Command("cmd.exe", "/c", "mklink", "/J", link, target).Run()
}

func TestCredentialVaultRejectsCredentialFileSymlink(t *testing.T) {
	dir := newCredentialVaultTestDir(t)
	target := filepath.Join(dir, "other-file")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatal("test fixture setup failed")
	}
	if err := os.Symlink(target, filepath.Join(dir, fileName)); err != nil {
		t.Skip("file symlink creation is unavailable")
	}
	if err := Save(dir, testAppleID, testPassword); !errors.Is(err, ErrUnsafeCredential) {
		t.Fatal("credential symlink was followed")
	}
	if _, err := Load(dir, testAppleID); !errors.Is(err, ErrUnsafeCredential) {
		t.Fatal("credential symlink was loaded")
	}
}

func TestCredentialVaultLoadRejectsOversizedFile(t *testing.T) {
	dir := newCredentialVaultTestDir(t)
	path := filepath.Join(dir, fileName)
	if err := os.WriteFile(path, make([]byte, maxCredentialFileLen+1), 0o600); err != nil {
		t.Fatal("oversized file fixture setup failed")
	}
	if _, err := Load(dir, testAppleID); !errors.Is(err, ErrTooLarge) {
		t.Fatal("oversized credential file was not rejected")
	}
}

func newCredentialVaultTestDir(t *testing.T) string {
	t.Helper()
	if !strings.EqualFold(filepath.VolumeName(testRoot), "D:") {
		t.Fatal("test output root is not on D")
	}
	if err := os.MkdirAll(testRoot, 0o700); err != nil {
		t.Fatal("D test output directory is unavailable")
	}
	dir, err := os.MkdirTemp(testRoot, "account-")
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
