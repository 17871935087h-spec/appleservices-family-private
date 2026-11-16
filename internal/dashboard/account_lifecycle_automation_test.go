package dashboard

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Laky-64/appleservices/internal/control"
)

func newLifecycleAutomationTestServer(t *testing.T, accounts ...*Account) *Server {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	entries := make([]*registryEntry, 0, len(accounts))
	for _, account := range accounts {
		if err := os.MkdirAll(account.Dir, 0700); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, &registryEntry{ID: account.ID, Name: account.Name, AppleID: account.AppleID, Dir: account.Dir, CreatedAt: account.CreatedAt})
	}
	if err := saveRegistry(root, entries); err != nil {
		t.Fatal(err)
	}
	return &Server{
		config:   Config{Dir: root, Worker: filepath.Join(root, "missing-worker.exe")},
		accounts: append([]*Account(nil), accounts...),
	}
}

func waitForAccount(t *testing.T, server *Server, appleID string) *Account {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		server.accountsMu.Lock()
		for _, account := range server.accounts {
			if account.AppleID == appleID {
				server.accountsMu.Unlock()
				return account
			}
		}
		server.accountsMu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("account %q was not registered before the lifecycle wait ended", appleID)
	return nil
}

func TestRemoveKeepsAccountRegisteredDuringActivationPause(t *testing.T) {
	fixture := newICloudAutomationFixture(t)
	root := filepath.Join(t.TempDir(), "state")
	oldAccount := &Account{ID: "old-account", Name: "old", AppleID: "old@example.test", Dir: filepath.Join(root, "accounts", "old-account")}
	fixture.account = oldAccount
	server := newLifecycleAutomationTestServer(t, oldAccount)
	server.icloudAutomation = fixture.service

	activationStarted := make(chan struct{})
	activationCanceled := make(chan struct{})
	releaseActivation := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseActivation) }) }
	defer release()
	fixture.activate = func(ctx context.Context, _ *Account) control.Result {
		close(activationStarted)
		<-ctx.Done()
		close(activationCanceled)
		<-releaseActivation
		return control.Result{Stage: "activation-terms"}
	}
	fixture.service.schedule(context.Background(), oldAccount)
	select {
	case <-activationStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("activation runner did not start")
	}

	removeDone := make(chan control.Result, 1)
	go func() { removeDone <- server.removeAccount(context.Background(), oldAccount.ID) }()
	select {
	case <-activationCanceled:
	case <-time.After(5 * time.Second):
		release()
		t.Fatal("remove did not cancel the active automation task")
	}

	addDone := make(chan struct {
		result control.Result
		id     string
	}, 1)
	go func() {
		result, id := server.addAccount(context.Background(), credentials{AppleID: "new@example.test", Password: "test-only"})
		addDone <- struct {
			result control.Result
			id     string
		}{result: result, id: id}
	}()
	newAccount := waitForAccount(t, server, "new@example.test")
	if newAccount.ID == oldAccount.ID {
		t.Fatal("new account reused the account being removed")
	}

	release()
	select {
	case result := <-removeDone:
		if !result.OK {
			t.Fatalf("removeAccount failed: %#v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("removeAccount did not finish after the runner exited")
	}
	select {
	case result := <-addDone:
		if result.id != newAccount.ID {
			t.Fatalf("addAccount returned id %q, want %q (result %#v)", result.id, newAccount.ID, result.result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("addAccount did not leave the lifecycle lock")
	}

	entries, err := loadRegistry(server.config.Dir, server.config.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != newAccount.ID || entries[0].AppleID != newAccount.AppleID {
		t.Fatalf("remove overwrote the concurrently added account: %#v", entries)
	}
}

func TestStartAccountRejectsRemovedAccountPointerWithoutRuntimeArtifacts(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	account := &Account{ID: "gone-account", Name: "gone", AppleID: "gone@example.test", Dir: filepath.Join(root, "accounts", "gone-account")}
	server := newLifecycleAutomationTestServer(t, account)

	removed := server.removeAccount(context.Background(), account.ID)
	if !removed.OK {
		t.Fatalf("removeAccount failed: %#v", removed)
	}
	result := server.startAccount(context.Background(), account, credentials{AppleID: account.AppleID, Password: "test-only"})
	if result.OK || result.Stage != "account-removed" {
		t.Fatalf("stale account start was not rejected: %#v", result)
	}
	for _, name := range []string{"runtime.json", "stop-request.json", iCloudAutomationJournalFile} {
		if _, err := os.Stat(filepath.Join(account.Dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale account start created %s: err=%v", name, err)
		}
	}
	entries, err := loadRegistry(server.config.Dir, server.config.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("removed account reappeared in registry: %#v", entries)
	}
}
