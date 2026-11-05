package dashboard

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrimaryMailAPIRequiresExplicitAccountAndPermanentConsent(t *testing.T) {
	s, err := New(Config{Dir: t.TempDir(), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer s.listener.Close()
	s.accounts = []*Account{{ID: "fixture-01", AppleID: "fixture@example.test", Dir: t.TempDir()}}
	calls := 0
	s.primaryMailRunner = func(_ context.Context, a *Account, in primaryMailInput) primaryMailState {
		calls++
		return primaryMailState{AccountID: a.ID, Stage: "not_open", CanCreate: true, Message: "raw_secret_fixture"}
	}
	for _, item := range []struct {
		path, body string
		status     int
	}{{"/api/primary-mail/status", `{}`, 400}, {"/api/primary-mail/create?account=fixture-01", `{"prefix":"fixture"}`, 200}, {"/api/primary-mail/create?account=fixture-01", `{"prefix":"bad@evil","confirm_permanent":true}`, 200}, {"/api/primary-mail/status?account=fixture-01", `{"allow_web_login":true}`, 400}, {"/api/primary-mail/status?account=fixture-01", `{"password":"secret"}`, 400}} {
		req := httptest.NewRequest("POST", s.URL()+item.path, strings.NewReader(item.body))
		req.Header.Set("X-App-Token", s.token)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != item.status {
			t.Fatalf("wrong status %d", rec.Code)
		}
	}
	if calls != 0 {
		t.Fatal("invalid request invoked helper")
	}
	req := httptest.NewRequest("POST", s.URL()+"/api/primary-mail/status?account=fixture-01", strings.NewReader(`{}`))
	req.Header.Set("X-App-Token", s.token)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != 200 || calls != 1 || strings.Contains(rec.Body.String(), "raw_secret_fixture") {
		t.Fatal("status projection failed")
	}
	var state primaryMailState
	if json.Unmarshal(rec.Body.Bytes(), &state) != nil || state.AccountID != "fixture-01" || !state.CanCreate {
		t.Fatal("state was lost")
	}
}
func TestPrimaryMailProjectionRejectsWrongAccountAndFalseVerified(t *testing.T) {
	for _, value := range []primaryMailState{{AccountID: "other", Stage: "verified", Email: "fixture@icloud.com"}, {AccountID: "fixture", Stage: "verified"}, {AccountID: "fixture", Stage: "verified", Email: "not-an-email"}} {
		got := sanitizePrimaryMail(value, "fixture")
		if got.Stage != "unavailable" || got.CanCreate {
			t.Fatal("invalid identity/success allowed")
		}
	}
	got := sanitizePrimaryMail(primaryMailState{AccountID: "fixture", Stage: "outcome_unknown", CanCreate: true, Message: "secret"}, "fixture")
	if got.CanCreate || strings.Contains(got.Message, "secret") {
		t.Fatal("unsafe retry or message")
	}
}
