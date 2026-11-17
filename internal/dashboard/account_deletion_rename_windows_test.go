//go:build windows

package dashboard

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRemoveDoesNotPublishDeletionWhenRegistryRenameFails(t *testing.T) {
	account := &Account{
		ID: "account-a", Name: "fixture", AppleID: "person@example.test",
		Dir: filepath.Join(t.TempDir(), "accounts", "account-a"),
	}
	server := newLifecycleAutomationTestServer(t, account)
	root := server.config.Dir
	registryFile := filepath.Join(root, "accounts.json")
	registryPath, err := syscall.UTF16PtrFromString(registryFile)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(
		registryPath, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if handle != syscall.InvalidHandle {
			_ = syscall.CloseHandle(handle)
		}
	}()

	removed := server.removeAccount(t.Context(), account.ID)
	if removed.OK {
		t.Fatal("account removal succeeded despite the locked registry rename")
	}
	if err := syscall.CloseHandle(handle); err != nil {
		t.Fatal(err)
	}
	handle = syscall.InvalidHandle

	registry, err := readRegistryDocument(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Accounts) != 1 || registry.Accounts[0].ID != account.ID || registry.DeletionSequence != 0 || len(registry.DeletionEvents) != 0 {
		t.Fatalf("failed atomic rename published a partial deletion: %#v", registry)
	}
	if _, err := os.Stat(registryFile + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("failed rename left a deletion temp file: %v", err)
	}
}
