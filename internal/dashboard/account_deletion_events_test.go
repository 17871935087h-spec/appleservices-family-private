package dashboard

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemovePersistsRedactedDeletionAndRegistrySavesKeepLedger(t *testing.T) {
	account := &Account{
		ID: "account-a", Name: "fixture", AppleID: "  Person@Example.Test  ",
		Dir: filepath.Join(t.TempDir(), "accounts", "account-a"),
	}
	server := newLifecycleAutomationTestServer(t, account)
	root := server.config.Dir

	removed := server.removeAccount(t.Context(), account.ID)
	if !removed.OK {
		t.Fatalf("removeAccount failed: %#v", removed)
	}
	registry, err := readRegistryDocument(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Accounts) != 0 || registry.DeletionSequence != 1 || len(registry.DeletionEvents) != 1 {
		t.Fatalf("registry removal and event were not committed together: %#v", registry)
	}
	hash := sha256.Sum256([]byte("person@example.test"))
	wantHash := hex.EncodeToString(hash[:])
	event := registry.DeletionEvents[0]
	if event.Sequence != 1 || event.AccountID != account.ID || event.AppleIDSHA256 != wantHash {
		t.Fatalf("deletion event = %#v, want account id and normalized Apple ID hash", event)
	}
	data, err := os.ReadFile(registryPath(root))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "Person@Example.Test") || strings.Contains(string(data), "person@example.test") {
		t.Fatal("removed Apple ID was retained in the deletion event registry")
	}

	if err := saveRegistry(root, []*registryEntry{{ID: "account-b", AppleID: "next@example.test"}}); err != nil {
		t.Fatalf("save registry after adding another account: %v", err)
	}
	registry, err = readRegistryDocument(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Accounts) != 1 || registry.Accounts[0].ID != "account-b" || registry.DeletionSequence != 1 || len(registry.DeletionEvents) != 1 || registry.DeletionEvents[0] != event {
		t.Fatalf("subsequent registry save dropped the deletion ledger: %#v", registry)
	}
}

func TestRemoveDoesNotPublishDeletionWhenRegistryWriteFails(t *testing.T) {
	account := &Account{
		ID: "account-a", Name: "fixture", AppleID: "person@example.test",
		Dir: filepath.Join(t.TempDir(), "accounts", "account-a"),
	}
	server := newLifecycleAutomationTestServer(t, account)
	root := server.config.Dir
	if err := os.Mkdir(registryPath(root)+".tmp", 0700); err != nil {
		t.Fatal(err)
	}

	removed := server.removeAccount(t.Context(), account.ID)
	if removed.OK {
		t.Fatal("account removal succeeded even though the atomic registry write failed")
	}
	registry, err := readRegistryDocument(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Accounts) != 1 || registry.Accounts[0].ID != account.ID || registry.DeletionSequence != 0 || len(registry.DeletionEvents) != 0 {
		t.Fatalf("failed registry write published a partial deletion: %#v", registry)
	}
}
