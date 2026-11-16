package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	appleservices "github.com/Laky-64/appleservices"
	"github.com/Laky-64/appleservices/internal/control"
)

type automaticActivationFixture struct {
	server      *Server
	account     *Account
	accepts     int
	delegates   int
	plan        string
	termsStatus int
	failNAC     bool
}

func newAutomaticActivationFixture(t *testing.T) *automaticActivationFixture {
	t.Helper()
	root := t.TempDir()
	account := &Account{ID: "account-1", AppleID: "owner@example.test", Dir: filepath.Join(root, "account")}
	for _, dir := range []string{account.Dir, filepath.Join(root, ".cache", "mac-nac-runtime")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	session := appleservices.Session{AppleID: account.AppleID, DSID: "test-dsid", Tokens: map[string]string{"com.apple.gs.idms.pet": "fixture-pet"}}
	data, _ := json.Marshal(session)
	if err := os.WriteFile(filepath.Join(account.Dir, "session.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	f := &automaticActivationFixture{account: account, plan: "v1", termsStatus: 200}
	f.server = &Server{config: Config{MacPushSetup: filepath.Join(root, "tools", "setup.py"), Worker: filepath.Join(root, "bin", "trusted-device.exe"), Python: "fixture-python"}}
	f.server.activationStorage = func(context.Context, *Account, bool) control.Result { return control.Result{OK: true} }
	f.server.activationRunner = func(ctx context.Context, _, dir, appleID, executable string, args ...string) ([]byte, error) {
		if dir != account.Dir || appleID != account.AppleID {
			t.Fatal("activation crossed account binding")
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		arg := func(key string) string {
			i := slices.Index(args, key)
			if i < 0 || i+1 >= len(args) {
				return ""
			}
			return args[i+1]
		}
		if executable == "fixture-python" {
			if f.failNAC {
				return nil, errors.New("fixture NAC failure")
			}
			return []byte(`{"stage": "NACSign"}`), nil
		}
		if slices.Contains(args, "-accept-terms") {
			f.accepts++
			if arg("-expected-terms") != "US:"+f.plan+":media" {
				t.Fatal("acceptance was not bound to current plan")
			}
			if err := os.WriteFile(arg("-dump")+".update.json", []byte(`{"success":true}`), 0600); err != nil {
				t.Fatal(err)
			}
			metadata, _ := json.Marshal(map[string]int{"HTTP": f.termsStatus})
			if err := os.WriteFile(arg("-dump")+".update-meta.json", metadata, 0600); err != nil {
				t.Fatal(err)
			}
			return nil, nil
		}
		if slices.Contains(args, "-delegate-only") {
			f.delegates++
			checkpoint := acceptedICloudCheckpoint{Session: appleservices.Session{AppleID: account.AppleID, DSID: "icloud-test", Tokens: map[string]string{"mmeAuthToken": "fixture-mme"}}, ADSID: session.DSID, ServiceData: map[string]any{"fixture": true}}
			data, _ := json.Marshal(checkpoint)
			if err := os.WriteFile(arg("-icloud-checkpoint"), data, 0600); err != nil {
				t.Fatal(err)
			}
			return []byte("delegate accepted; mme-token-present=true\nquota accepted;"), nil
		}
		data, _ := json.Marshal(map[string]any{"terms-plan": true, "region": "US", "icloud-version": f.plan, "media-version": "media"})
		return data, nil
	}
	return f
}

func TestAutomaticActivationReadsCurrentPlanAndSavesAcceptedCheckpoint(t *testing.T) {
	f := newAutomaticActivationFixture(t)
	result := f.server.automaticActivationAction(context.Background(), f.account)
	if !result.OK || result.Stage != "activation-completed" || f.accepts != 1 || f.delegates != 1 || !acceptedCheckpointReady(f.account.Dir, f.account.AppleID) {
		t.Fatalf("activation failed: result=%+v accepts=%d delegates=%d", result, f.accepts, f.delegates)
	}
	data, err := os.ReadFile(filepath.Join(f.account.Dir, "icloud-activation-terms.json"))
	if err != nil || strings.Contains(string(data), "fixture-pet") || strings.Contains(string(data), f.account.AppleID) || strings.Contains(string(data), "test-dsid") {
		t.Fatal("receipt absent or leaked credentials/identifiers")
	}
	result = f.server.automaticActivationAction(context.Background(), f.account)
	if !result.OK || f.accepts != 1 || f.delegates != 1 {
		t.Fatal("completed activation resubmitted Apple writes")
	}
}

func TestAutomaticActivationResumesConfirmedTermsWithoutRepeatingUpdate(t *testing.T) {
	f := newAutomaticActivationFixture(t)
	f.failNAC = true
	result := f.server.automaticActivationAction(context.Background(), f.account)
	if result.Stage != "activation-followup-retry" || f.accepts != 1 || !confirmedActivationTermsReceiptReady(f.account) {
		t.Fatalf("terms acknowledgement lost: %+v", result)
	}
	f.failNAC = false
	result = f.server.automaticActivationAction(context.Background(), f.account)
	if !result.OK || f.accepts != 1 || f.delegates != 1 {
		t.Fatalf("confirmed terms were repeated or activation failed: %+v", result)
	}
}

func TestAutomaticActivationDoesNotTrustNon200TermsSuccess(t *testing.T) {
	f := newAutomaticActivationFixture(t)
	f.termsStatus = 403
	result := f.server.automaticActivationAction(context.Background(), f.account)
	if result.OK || result.Stage != "activation-terms" || f.delegates != 0 || confirmedActivationTermsReceiptReady(f.account) {
		t.Fatalf("non-200 acknowledgement authorized followup: %+v", result)
	}
}

func TestAutomaticActivationDoesNotSilentlyAcceptChangedTermsAfterReceipt(t *testing.T) {
	f := newAutomaticActivationFixture(t)
	f.failNAC = true
	f.server.automaticActivationAction(context.Background(), f.account)
	f.plan = "v2"
	result := f.server.automaticActivationAction(context.Background(), f.account)
	if result.OK || result.Stage != "activation-consent" || f.accepts != 1 {
		t.Fatalf("changed terms repeated mutation: %+v", result)
	}
	other := &Account{ID: f.account.ID, Dir: f.account.Dir, AppleID: "other@example.test"}
	if confirmedActivationTermsReceiptReady(other) {
		t.Fatal("terms receipt crossed account binding")
	}
}
