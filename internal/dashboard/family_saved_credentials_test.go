package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appleservices "github.com/Laky-64/appleservices"
	"github.com/Laky-64/appleservices/internal/control"
)

const (
	familySavedTestAccountID = "family-saved-test"
	familySavedTestAppleID   = "member@example.invalid"
	familySavedTestPassword  = "synthetic-family-password-only"
)

type familySavedCredentialFixture struct {
	server  *Server
	worker  *control.Server
	account *Account
	dir     string
}

func newFamilySavedCredentialFixture(t *testing.T) *familySavedCredentialFixture {
	t.Helper()

	dir := filepath.Join(t.TempDir(), "account")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{Dir: dir, Worker: executable, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.listener.Close() })
	account := &Account{ID: familySavedTestAccountID, Dir: dir, AppleID: familySavedTestAppleID}
	server.accounts = []*Account{account}

	worker, err := control.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	fixture := &familySavedCredentialFixture{server: server, worker: worker, account: account, dir: dir}
	fixture.writeRuntime(t, Status{PID: os.Getpid(), Running: true, Authenticated: true})
	return fixture
}

func (f *familySavedCredentialFixture) writeRuntime(t *testing.T, status Status) {
	t.Helper()
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "runtime.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func (f *familySavedCredentialFixture) writeCheckpoints(t *testing.T, gsaAppleID, acceptedAppleID, acceptedADSID string) {
	t.Helper()
	saved := appleservices.Session{
		AppleID: gsaAppleID,
		DSID:    "synthetic-gsa-dsid",
		Tokens:  map[string]string{"com.apple.gs.idms.pet": "synthetic-pet-token"},
	}
	accepted := acceptedICloudCheckpoint{
		Session: appleservices.Session{
			AppleID: acceptedAppleID,
			DSID:    "synthetic-icloud-dsid",
			Tokens:  map[string]string{"mmeAuthToken": "synthetic-mme-token"},
		},
		ADSID:       acceptedADSID,
		ServiceData: map[string]any{"verified": true},
	}
	for name, value := range map[string]any{"session.json": saved, "icloud-accepted.json": accepted} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *familySavedCredentialFixture) post(t *testing.T, body any) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, f.server.URL()+"/api/action?account="+familySavedTestAccountID, strings.NewReader(string(data))).WithContext(ctx)
	request.Header.Set("X-App-Token", f.server.token)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	f.server.ServeHTTP(recorder, request)
	return recorder
}

func (f *familySavedCredentialFixture) setLoader(loader func(string, string) (string, error)) {
	f.server.familyCredentialLoader = loader
}

func (f *familySavedCredentialFixture) assertNoCommand(t *testing.T) {
	t.Helper()
	select {
	case command := <-f.worker.Commands:
		t.Fatalf("unexpected worker command was sent: %#v", command.Action)
	default:
	}
}

func (f *familySavedCredentialFixture) assertNoCredentialPersisted(t *testing.T, credential string) {
	t.Helper()
	err := filepath.WalkDir(f.dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), credential) {
			t.Errorf("one-shot credential was persisted in %s", filepath.Base(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func familySavedReadinessAction() control.Action {
	return control.Action{Action: "family-add-readiness"}
}

func TestSavedFamilyCredentialReadinessFallbackIsReadOnly(t *testing.T) {
	f := newFamilySavedCredentialFixture(t)
	f.worker.SetFamilyAddOneShotCredentialReady(true)
	f.writeCheckpoints(t, familySavedTestAppleID, familySavedTestAppleID, "synthetic-gsa-dsid")
	loaderCalls := 0
	f.setLoader(func(dir, appleID string) (string, error) {
		loaderCalls++
		if dir != f.account.Dir || appleID != f.account.AppleID {
			t.Fatalf("credential loader received unexpected binding: dir=%q appleID=%q", dir, appleID)
		}
		return familySavedTestPassword, nil
	})

	recorder := f.post(t, familySavedReadinessAction())
	var result control.Result
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK || !result.OK || result.Stage != "family-add-ready" {
		t.Fatalf("saved credential fallback readiness failed: status=%d response=%s", recorder.Code, recorder.Body.String())
	}
	if loaderCalls != 1 {
		t.Fatalf("credential loader called %d times, want once", loaderCalls)
	}
	if strings.Contains(recorder.Body.String(), familySavedTestPassword) {
		t.Fatal("readiness response exposed the saved password")
	}
	f.assertNoCommand(t)
	f.assertNoCredentialPersisted(t, familySavedTestPassword)
}

func TestSavedFamilyCredentialActionLoadsBoundPasswordTransiently(t *testing.T) {
	f := newFamilySavedCredentialFixture(t)
	f.worker.SetFamilyAddOneShotCredentialReady(true)
	f.writeCheckpoints(t, familySavedTestAppleID, familySavedTestAppleID, "synthetic-gsa-dsid")
	loaderCalls := 0
	f.setLoader(func(dir, appleID string) (string, error) {
		loaderCalls++
		if dir != f.account.Dir || appleID != f.account.AppleID {
			t.Fatalf("credential loader received unexpected binding: dir=%q appleID=%q", dir, appleID)
		}
		return familySavedTestPassword, nil
	})

	received := make(chan control.Action, 1)
	go func() {
		command := <-f.worker.Commands
		received <- command.Action
		command.Reply <- control.Result{OK: true, Stage: "family-added", Message: "synthetic worker result"}
	}()
	recorder := f.post(t, control.Action{Action: "family-add-self", Code: "synthetic-organizer"})
	var result control.Result
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK || !result.OK || result.Stage != "family-added" {
		t.Fatalf("saved credential family add failed: status=%d response=%s", recorder.Code, recorder.Body.String())
	}
	command := <-received
	if command.TargetAppleID != f.account.AppleID || command.TargetPassword != familySavedTestPassword {
		t.Fatalf("worker did not receive the bound saved credential: %#v", command)
	}
	if loaderCalls != 1 {
		t.Fatalf("credential loader called %d times, want once", loaderCalls)
	}
	if strings.Contains(recorder.Body.String(), familySavedTestPassword) {
		t.Fatal("family-add response exposed the saved password")
	}
	f.assertNoCredentialPersisted(t, familySavedTestPassword)
}

func TestSavedFamilyCredentialStartupReadySkipsVaultAndPreservesWorkerPath(t *testing.T) {
	f := newFamilySavedCredentialFixture(t)
	f.worker.SetFamilyAddReady(true)
	loaderCalls := 0
	f.setLoader(func(string, string) (string, error) {
		loaderCalls++
		return "unexpected synthetic password", nil
	})

	readiness := f.post(t, familySavedReadinessAction())
	var ready control.Result
	if err := json.Unmarshal(readiness.Body.Bytes(), &ready); err != nil {
		t.Fatal(err)
	}
	if !ready.OK || ready.Stage != "family-add-ready" {
		t.Fatalf("startup-ready readiness changed: %s", readiness.Body.String())
	}
	f.assertNoCommand(t)

	received := make(chan control.Action, 1)
	go func() {
		command := <-f.worker.Commands
		received <- command.Action
		command.Reply <- control.Result{OK: true, Stage: "family-added"}
	}()
	response := f.post(t, control.Action{Action: "family-add-self", Code: "synthetic-organizer"})
	var result control.Result
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.Stage != "family-added" {
		t.Fatalf("startup-ready action path failed: %s", response.Body.String())
	}
	command := <-received
	if command.TargetAppleID != "" || command.TargetPassword != "" {
		t.Fatalf("startup-ready action unexpectedly received saved credentials: %#v", command)
	}
	if loaderCalls != 0 {
		t.Fatalf("startup-ready path read the vault %d times", loaderCalls)
	}
}

func TestSavedFamilyCredentialMissingOrInvalidPasswordIsRejectedWithoutMutation(t *testing.T) {
	for _, test := range []struct {
		name     string
		password string
		err      error
	}{
		{name: "missing vault value", err: errors.New("synthetic vault diagnostic: private-password-marker")},
		{name: "invalid vault value", password: "\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFamilySavedCredentialFixture(t)
			f.worker.SetFamilyAddOneShotCredentialReady(true)
			f.writeCheckpoints(t, familySavedTestAppleID, familySavedTestAppleID, "synthetic-gsa-dsid")
			loaderCalls := 0
			f.setLoader(func(string, string) (string, error) {
				loaderCalls++
				return test.password, test.err
			})

			recorder := f.post(t, control.Action{Action: "family-add-self", Code: "synthetic-organizer"})
			var result control.Result
			if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if recorder.Code != http.StatusOK || result.OK || result.Stage != "family-credential-required" {
				t.Fatalf("invalid saved credential was not safely rejected: status=%d response=%s", recorder.Code, recorder.Body.String())
			}
			if loaderCalls != 1 {
				t.Fatalf("credential loader called %d times, want once", loaderCalls)
			}
			if strings.Contains(recorder.Body.String(), "private-password-marker") || strings.Contains(recorder.Body.String(), familySavedTestPassword) {
				t.Fatalf("credential or raw vault error leaked: %s", recorder.Body.String())
			}
			f.assertNoCommand(t)
			f.assertNoCredentialPersisted(t, familySavedTestPassword)
		})
	}
}

func TestSavedFamilyCredentialPreconditionsRejectBeforeVault(t *testing.T) {
	cases := []struct {
		name          string
		status        Status
		oneShot       bool
		gsaAppleID    string
		acceptedID    string
		acceptedADSID string
	}{
		{name: "worker unauthenticated", status: Status{PID: os.Getpid(), Running: true, Authenticated: false}, oneShot: true, gsaAppleID: familySavedTestAppleID, acceptedID: familySavedTestAppleID, acceptedADSID: "synthetic-gsa-dsid"},
		{name: "verification required", status: Status{PID: os.Getpid(), Running: true, Authenticated: true, VerificationRequired: true}, oneShot: true, gsaAppleID: familySavedTestAppleID, acceptedID: familySavedTestAppleID, acceptedADSID: "synthetic-gsa-dsid"},
		{name: "worker stopped", status: Status{PID: os.Getpid(), Running: false, Authenticated: true}, oneShot: true, gsaAppleID: familySavedTestAppleID, acceptedID: familySavedTestAppleID, acceptedADSID: "synthetic-gsa-dsid"},
		{name: "missing one-shot capability", status: Status{PID: os.Getpid(), Running: true, Authenticated: true}, oneShot: false, gsaAppleID: familySavedTestAppleID, acceptedID: familySavedTestAppleID, acceptedADSID: "synthetic-gsa-dsid"},
		{name: "GSA checkpoint bound to another account", status: Status{PID: os.Getpid(), Running: true, Authenticated: true}, oneShot: true, gsaAppleID: "other@example.invalid", acceptedID: familySavedTestAppleID, acceptedADSID: "synthetic-gsa-dsid"},
		{name: "accepted checkpoint bound to another account", status: Status{PID: os.Getpid(), Running: true, Authenticated: true}, oneShot: true, gsaAppleID: familySavedTestAppleID, acceptedID: "other@example.invalid", acceptedADSID: "synthetic-gsa-dsid"},
		{name: "accepted checkpoint ADSID mismatch", status: Status{PID: os.Getpid(), Running: true, Authenticated: true}, oneShot: true, gsaAppleID: familySavedTestAppleID, acceptedID: familySavedTestAppleID, acceptedADSID: "other-synthetic-gsa-dsid"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newFamilySavedCredentialFixture(t)
			f.worker.SetFamilyAddOneShotCredentialReady(test.oneShot)
			f.writeRuntime(t, test.status)
			f.writeCheckpoints(t, test.gsaAppleID, test.acceptedID, test.acceptedADSID)
			loaderCalls := 0
			f.setLoader(func(string, string) (string, error) {
				loaderCalls++
				return familySavedTestPassword, nil
			})

			recorder := f.post(t, familySavedReadinessAction())
			var result control.Result
			if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if recorder.Code != http.StatusOK || result.OK || result.Stage != "family-worker-unready" {
				t.Fatalf("precondition was not rejected as worker-unready: status=%d response=%s", recorder.Code, recorder.Body.String())
			}
			if loaderCalls != 0 {
				t.Fatalf("credential loader was called %d times despite failed precondition", loaderCalls)
			}
			f.assertNoCommand(t)
		})
	}
}

func TestExplicitOneShotFamilyCredentialIsNotReplacedByVault(t *testing.T) {
	f := newFamilySavedCredentialFixture(t)
	f.worker.SetFamilyAddOneShotCredentialReady(true)
	f.writeCheckpoints(t, familySavedTestAppleID, familySavedTestAppleID, "synthetic-gsa-dsid")
	loaderCalls := 0
	f.setLoader(func(string, string) (string, error) {
		loaderCalls++
		return "different-synthetic-password", nil
	})

	const explicitPassword = "explicit-synthetic-one-shot-password"
	received := make(chan control.Action, 1)
	go func() {
		command := <-f.worker.Commands
		received <- command.Action
		command.Reply <- control.Result{OK: true, Stage: "family-added"}
	}()
	recorder := f.post(t, control.Action{
		Action:         "family-add-self",
		Code:           "synthetic-organizer",
		TargetAppleID:  familySavedTestAppleID,
		TargetPassword: explicitPassword,
	})
	var result control.Result
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.Stage != "family-added" {
		t.Fatalf("explicit one-shot credential request failed: %s", recorder.Body.String())
	}
	command := <-received
	if command.TargetAppleID != familySavedTestAppleID || command.TargetPassword != explicitPassword {
		t.Fatalf("explicit one-shot credential was changed: %#v", command)
	}
	if loaderCalls != 0 {
		t.Fatalf("vault loader was called %d times for explicit credentials", loaderCalls)
	}
	if strings.Contains(recorder.Body.String(), explicitPassword) {
		t.Fatal("explicit credential was echoed in the response")
	}
	f.assertNoCredentialPersisted(t, explicitPassword)
}
