package dashboard

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Laky-64/appleservices/internal/control"
)

type iCloudAutomationFixture struct {
	service *iCloudAutomationService
	account *Account

	status      Status
	gsaReady    bool
	accepted    bool
	termsReady  bool
	fingerprint string
	registered  bool

	activated atomic.Int32
	stopped   atomic.Int32
	resumed   atomic.Int32
	activate  func(context.Context, *Account) control.Result
	stop      func(context.Context, *Account) error
	resume    func(context.Context, *Account) control.Result
}

func newICloudAutomationFixture(t *testing.T) *iCloudAutomationFixture {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "account")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	f := &iCloudAutomationFixture{
		account:  &Account{ID: "01-account", Name: "owner", AppleID: "owner@example.test", Dir: dir},
		status:   Status{PID: 100, Running: true, Authenticated: true, PushConnected: true, State: "online"},
		gsaReady: true, registered: true, fingerprint: "fresh-session",
	}
	f.service = &iCloudAutomationService{
		entries:    make(map[string]*iCloudAutomationEntry),
		pollEvery:  time.Millisecond,
		stableFor:  0,
		workerWait: 5 * time.Millisecond,
		retryBase:  0,
	}
	f.service.deps = iCloudAutomationDependencies{
		accounts:      func() []*Account { return []*Account{f.account} },
		status:        func(*Account) Status { return f.status },
		gsaReady:      func(*Account) bool { return f.gsaReady },
		acceptedReady: func(*Account) bool { return f.accepted },
		termsReady:    func(*Account) bool { return f.termsReady },
		fingerprint:   func(*Account) string { return f.fingerprint },
		registered: func(account *Account) bool {
			return f.registered && account.ID == f.account.ID && account.Dir == f.account.Dir && strings.EqualFold(account.AppleID, f.account.AppleID)
		},
		activate: func(ctx context.Context, account *Account) control.Result {
			f.activated.Add(1)
			if f.activate != nil {
				return f.activate(ctx, account)
			}
			return control.Result{OK: true, Stage: "activation-completed"}
		},
		stop: func(ctx context.Context, account *Account) error {
			f.stopped.Add(1)
			if f.stop != nil {
				return f.stop(ctx, account)
			}
			return nil
		},
		resume: func(ctx context.Context, account *Account) control.Result {
			f.resumed.Add(1)
			if f.resume != nil {
				return f.resume(ctx, account)
			}
			return control.Result{OK: true}
		},
		now: time.Now,
	}
	return f
}

func (f *iCloudAutomationFixture) runOnce(t *testing.T) {
	t.Helper()
	f.service.schedule(context.Background(), f.account)
	entry := f.service.entryFor(f.account)
	entry.mu.Lock()
	done := entry.done
	entry.mu.Unlock()
	if done != nil {
		<-done
	}
}

func waitICloudAutomationEntry(t *testing.T, service *iCloudAutomationService, account *Account) {
	t.Helper()
	entry := service.entryFor(account)
	entry.mu.Lock()
	done := entry.done
	entry.mu.Unlock()
	if done != nil {
		<-done
	}
}

func (f *iCloudAutomationFixture) journal(t *testing.T) iCloudAutomationJournal {
	t.Helper()
	data, err := os.ReadFile(iCloudAutomationJournalPath(f.account))
	if err != nil {
		t.Fatal(err)
	}
	var journal iCloudAutomationJournal
	if err := json.Unmarshal(data, &journal); err != nil {
		t.Fatal(err)
	}
	return journal
}

func TestICloudAutomationSubmittedJournalPreventsReplay(t *testing.T) {
	f := newICloudAutomationFixture(t)
	if err := writeICloudAutomationJournal(f.account, iCloudAutomationJournal{Version: 1, Stage: "activating", Submitted: true, Attempts: 1}); err != nil {
		t.Fatal(err)
	}
	f.runOnce(t)
	if got := f.service.Status(f.account).Stage; got != "needs-review" {
		t.Fatalf("stage = %q, want needs-review", got)
	}
	if got := f.activated.Load(); got != 0 {
		t.Fatalf("activation replayed %d times", got)
	}
	if !f.journal(t).Submitted {
		t.Fatal("uncertain submitted marker was cleared")
	}
}

func TestICloudAutomationAcceptedOnlineCompletesWithoutRestart(t *testing.T) {
	f := newICloudAutomationFixture(t)
	f.accepted = true
	f.runOnce(t)
	status := f.service.Status(f.account)
	if status.Stage != "complete" {
		t.Fatalf("stage = %q, want complete", status.Stage)
	}
	if f.stopped.Load() != 0 || f.resumed.Load() != 0 {
		t.Fatalf("accepted online worker was restarted: stop=%d resume=%d", f.stopped.Load(), f.resumed.Load())
	}
}

func TestICloudAutomationResetAcceptedWaitsForThisManualLogin(t *testing.T) {
	f := newICloudAutomationFixture(t)
	f.accepted = true
	if err := f.service.Reset(context.Background(), f.account); err != nil {
		t.Fatal(err)
	}
	f.runOnce(t)
	if f.resumed.Load() != 0 || f.stopped.Load() != 0 {
		t.Fatal("Reset reused the old accepted worker before the manual login")
	}
	if got := f.service.Status(f.account).Stage; got != "waiting-login" {
		t.Fatalf("stage = %q before new login, want waiting-login", got)
	}
	f.status.PID = 200
	f.runOnce(t)
	if got := f.service.Status(f.account).Stage; got != "complete" {
		t.Fatalf("stage = %q after fresh online login, want complete", got)
	}
	if f.resumed.Load() != 0 || f.stopped.Load() != 0 {
		t.Fatal("already-accepted manual login was unnecessarily restarted")
	}
}

func TestICloudAutomationRecoversCheckpointSavedBeforeRestart(t *testing.T) {
	for _, stage := range []string{"activating", "activation-followup", "resume-pending"} {
		t.Run(stage, func(t *testing.T) {
			f := newICloudAutomationFixture(t)
			f.accepted = true
			if err := writeICloudAutomationJournal(f.account, iCloudAutomationJournal{
				Version: 1, Stage: stage, Submitted: true, RestartFromPID: f.status.PID,
			}); err != nil {
				t.Fatal(err)
			}
			f.stop = func(context.Context, *Account) error {
				f.status = Status{PID: 100, State: "stopped"}
				return nil
			}
			f.resume = func(context.Context, *Account) control.Result {
				f.status = Status{PID: 200, Running: true, Authenticated: true, PushConnected: true, State: "online"}
				return control.Result{OK: true}
			}
			f.runOnce(t)
			if got := f.service.Status(f.account).Stage; got != "complete" {
				t.Fatalf("stage = %q, want complete", got)
			}
			if f.stopped.Load() != 1 || f.resumed.Load() != 1 {
				t.Fatalf("recovery did not restart exactly once: stop=%d resume=%d", f.stopped.Load(), f.resumed.Load())
			}
		})
	}
}

func TestICloudAutomationResetWaitsForFreshManualLogin(t *testing.T) {
	f := newICloudAutomationFixture(t)
	f.status = Status{PID: 100, State: "stopped"}
	f.fingerprint = "old-session"
	if err := f.service.Reset(context.Background(), f.account); err != nil {
		t.Fatal(err)
	}
	f.runOnce(t)
	if f.activated.Load() != 0 {
		t.Fatal("old GSA session activated before manual login changed it")
	}
	if got := f.service.Status(f.account).Stage; got != "waiting-login" {
		t.Fatalf("stage = %q, want waiting-login", got)
	}

	f.fingerprint = "new-session"
	f.accepted = false
	f.activate = func(context.Context, *Account) control.Result {
		f.accepted = true
		return control.Result{OK: true, Stage: "activation-completed"}
	}
	f.resume = func(context.Context, *Account) control.Result {
		f.status = Status{PID: 200, Running: true, Authenticated: true, PushConnected: true, State: "online"}
		return control.Result{OK: true, Message: "start accepted"}
	}
	f.runOnce(t)
	if got := f.service.Status(f.account).Stage; got != "complete" {
		t.Fatalf("stage = %q, want complete", got)
	}
	if f.activated.Load() != 1 || f.resumed.Load() != 1 {
		t.Fatalf("fresh login flow counts: activate=%d resume=%d", f.activated.Load(), f.resumed.Load())
	}
}

func TestICloudAutomationResetAcceptsNewWorkerWithUnchangedSession(t *testing.T) {
	f := newICloudAutomationFixture(t)
	f.fingerprint = "same-session"
	f.status = Status{PID: 100, State: "stopped"}
	if err := f.service.Reset(context.Background(), f.account); err != nil {
		t.Fatal(err)
	}
	f.status = Status{PID: 200, Running: true, Authenticated: true, PushConnected: true, State: "online"}
	f.accepted = false
	f.activate = func(context.Context, *Account) control.Result {
		f.accepted = true
		return control.Result{OK: true, Stage: "activation-completed"}
	}
	f.runOnce(t)
	if got := f.activated.Load(); got != 1 {
		t.Fatalf("activation count = %d, want 1 after a new authenticated PID", got)
	}
}

func TestICloudAutomationPauseCancelsAndWaits(t *testing.T) {
	f := newICloudAutomationFixture(t)
	started := make(chan struct{})
	f.activate = func(ctx context.Context, _ *Account) control.Result {
		close(started)
		<-ctx.Done()
		return control.Result{Stage: "activation-delegate"}
	}
	f.service.schedule(context.Background(), f.account)
	<-started
	if err := f.service.Pause(context.Background(), f.account); err != nil {
		t.Fatal(err)
	}
	if got := f.service.Status(f.account).Stage; got != "paused" {
		t.Fatalf("stage = %q, want paused", got)
	}
	if got := f.resumed.Load(); got != 0 {
		t.Fatalf("paused workflow started %d replacement workers", got)
	}
	dataBefore, err := os.ReadFile(iCloudAutomationJournalPath(f.account))
	if err != nil {
		t.Fatal(err)
	}
	f.service.scan(context.Background())
	dataAfter, err := os.ReadFile(iCloudAutomationJournalPath(f.account))
	if err != nil {
		t.Fatal(err)
	}
	if string(dataBefore) != string(dataAfter) {
		t.Fatal("paused workflow wrote to its journal after Pause returned")
	}
}

func TestICloudAutomationRunsAtMostOneTaskPerAccount(t *testing.T) {
	f := newICloudAutomationFixture(t)
	started := make(chan struct{})
	release := make(chan struct{})
	f.activate = func(context.Context, *Account) control.Result {
		close(started)
		<-release
		return control.Result{Stage: "activation-terms"}
	}
	f.service.schedule(context.Background(), f.account)
	<-started
	f.service.schedule(context.Background(), f.account)
	if got := f.activated.Load(); got != 1 {
		t.Fatalf("concurrent scan started %d activation calls, want 1", got)
	}
	close(release)
	waitICloudAutomationEntry(t, f.service, f.account)
}

func TestICloudAutomationDoesNotReviveUnregisteredAccount(t *testing.T) {
	f := newICloudAutomationFixture(t)
	f.registered = false
	f.runOnce(t)
	if f.activated.Load() != 0 || f.stopped.Load() != 0 || f.resumed.Load() != 0 {
		t.Fatalf("unregistered account had side effects: activate=%d stop=%d resume=%d", f.activated.Load(), f.stopped.Load(), f.resumed.Load())
	}
}

func TestICloudAutomationRequiresLiveWorkerStatusAfterResume(t *testing.T) {
	f := newICloudAutomationFixture(t)
	f.activate = func(context.Context, *Account) control.Result {
		f.accepted = true
		return control.Result{OK: true, Stage: "activation-completed"}
	}
	f.stop = func(context.Context, *Account) error {
		f.status = Status{State: "stopped"}
		return nil
	}
	f.resume = func(context.Context, *Account) control.Result {
		return control.Result{OK: true, Message: "start accepted but worker not ready"}
	}
	f.runOnce(t)
	if got := f.service.Status(f.account).Stage; got != "resume-unconfirmed" {
		t.Fatalf("stage = %q, want resume-unconfirmed", got)
	}
	if f.resumed.Load() != 1 || f.service.Status(f.account).Stage == "complete" {
		t.Fatal("start return alone was treated as worker readiness")
	}
}

func TestICloudAutomationRetriesOnlyBoundedReadOnlyPreflight(t *testing.T) {
	f := newICloudAutomationFixture(t)
	f.activate = func(context.Context, *Account) control.Result {
		return control.Result{Stage: "activation-plan"}
	}
	for i := 0; i < iCloudAutomationMaxTries+1; i++ {
		f.runOnce(t)
	}
	if got := f.activated.Load(); got != iCloudAutomationMaxTries {
		t.Fatalf("read-only preflight attempted %d times, want %d", got, iCloudAutomationMaxTries)
	}
	if got := f.service.Status(f.account).Stage; got != "preflight-exhausted" {
		t.Fatalf("stage = %q, want preflight-exhausted", got)
	}
	journal := f.journal(t)
	if journal.Submitted || journal.Attempts != iCloudAutomationMaxTries {
		t.Fatalf("unexpected exhausted journal: %#v", journal)
	}
}

func TestICloudAutomationUsesTermsReceiptForBoundedFollowupOnly(t *testing.T) {
	f := newICloudAutomationFixture(t)
	f.termsReady = true
	f.activate = func(context.Context, *Account) control.Result {
		return control.Result{Stage: "activation-followup-retry"}
	}
	for i := 0; i < iCloudAutomationMaxTries; i++ {
		f.runOnce(t)
	}
	if got := f.activated.Load(); got != iCloudAutomationMaxTries {
		t.Fatalf("follow-up attempted %d times, want %d", got, iCloudAutomationMaxTries)
	}
	if got := f.service.Status(f.account).Stage; got != "needs-review" {
		t.Fatalf("stage = %q, want needs-review after the bounded follow-up retries", got)
	}
	if !f.journal(t).Submitted {
		t.Fatal("durable terms receipt lost the submitted marker")
	}
	if f.service.schedule(context.Background(), f.account); f.activated.Load() != iCloudAutomationMaxTries {
		t.Fatal("follow-up retried beyond the configured bound")
	}
}

func TestICloudAutomationResetPersistsOnlySafeFingerprintMetadata(t *testing.T) {
	f := newICloudAutomationFixture(t)
	if err := os.WriteFile(filepath.Join(f.account.Dir, "session.json"), []byte(`{"AppleID":"owner@example.test","DSID":"123","Tokens":{"private":"token-value"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	f.status = Status{PID: 321, State: "stopped"}
	if err := f.service.Reset(context.Background(), f.account); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(iCloudAutomationJournalPath(f.account))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, forbidden := range []string{"token-value", "password", "otp", "cookie", "token"} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Fatalf("journal contains sensitive marker %q: %s", forbidden, text)
		}
	}
	journal := f.journal(t)
	if !journal.AwaitFreshLogin || journal.BaselineFingerprint == "" || journal.BaselinePID != 321 {
		t.Fatalf("Reset did not preserve fresh-login baseline: %#v", journal)
	}
}

func TestICloudAutomationScanFindsAccountsAddedAfterStartup(t *testing.T) {
	f := newICloudAutomationFixture(t)
	f.gsaReady = false
	accounts := []*Account{f.account}
	f.service.deps.accounts = func() []*Account { return append([]*Account(nil), accounts...) }
	f.service.deps.registered = func(account *Account) bool {
		for _, current := range accounts {
			if current.ID == account.ID && filepath.Clean(current.Dir) == filepath.Clean(account.Dir) && strings.EqualFold(current.AppleID, account.AppleID) {
				return true
			}
		}
		return false
	}
	f.service.scan(context.Background())
	waitICloudAutomationEntry(t, f.service, f.account)

	newDir := filepath.Join(t.TempDir(), "new-account")
	if err := os.MkdirAll(newDir, 0700); err != nil {
		t.Fatal(err)
	}
	newAccount := &Account{ID: "02-account", Name: "second", AppleID: "second@example.test", Dir: newDir}
	accounts = append(accounts, newAccount)
	f.service.scan(context.Background())
	waitICloudAutomationEntry(t, f.service, newAccount)
	if _, err := os.Stat(iCloudAutomationJournalPath(newAccount)); err != nil {
		t.Fatalf("new account was not scanned: %v", err)
	}
}
