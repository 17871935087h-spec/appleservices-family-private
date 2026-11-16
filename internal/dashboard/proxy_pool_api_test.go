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

	"github.com/Laky-64/appleservices/internal/control"
)

func proxyAPIFixture(t *testing.T) (*Server, string) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "pool.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"enabled":false,"nodes":[],"assignments":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APPLESERVICES_PROXY_POOL", path)
	executable, _ := os.Executable()
	s, err := New(Config{Dir: root, Worker: executable})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.listener.Close() })
	s.proxyPoolProbe = func(context.Context, string) (string, error) { return "192.0.2.20", nil }
	return s, path
}

func proxyAPIRequest(t *testing.T, s *Server, method, action, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, s.URL()+"/api/proxy-pool/"+action, strings.NewReader(body))
	r.Header.Set("X-App-Token", s.token)
	r.Header.Set("Origin", s.URL())
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestProxyPoolAPIStoresCredentialsWithoutReturningThem(t *testing.T) {
	s, path := proxyAPIFixture(t)
	response := proxyAPIRequest(t, s, "POST", "node", `{"id":"unit","url":"http://private-user:private-password@proxy.example:8080","enabled":true}`)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"ok":true`) {
		t.Fatalf("save failed: %s", response.Body.String())
	}
	for _, action := range []string{"status"} {
		response = proxyAPIRequest(t, s, "GET", action, "")
		if strings.Contains(response.Body.String(), "private-user") || strings.Contains(response.Body.String(), "private-password") || strings.Contains(response.Body.String(), "http://") {
			t.Fatal("credential URL reached read response")
		}
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "private-password") {
		t.Fatal("private configuration did not persist credentials")
	}
	if !strings.Contains(response.Body.String(), `"enabled":false`) {
		t.Fatal("saving a node activated production traffic")
	}
}

func TestProxyPoolAPIFailedProbeDoesNotOverwriteConfiguration(t *testing.T) {
	s, path := proxyAPIFixture(t)
	before, _ := os.ReadFile(path)
	s.proxyPoolProbe = func(context.Context, string) (string, error) {
		return "", errors.New("proxy exit check failed: secret-value")
	}
	response := proxyAPIRequest(t, s, "POST", "node", `{"id":"unit","url":"http://user:password@proxy.example:8080","enabled":true}`)
	after, _ := os.ReadFile(path)
	if string(before) != string(after) || strings.Contains(response.Body.String(), "secret-value") || !strings.Contains(response.Body.String(), `"ok":false`) {
		t.Fatal("failed probe overwrote config or leaked its error")
	}
}

func TestProxyPoolAPIRequiresExistingAuthentication(t *testing.T) {
	s, _ := proxyAPIFixture(t)
	for _, action := range []string{"status", "node", "settings", "remove", "apply"} {
		r := httptest.NewRequest("POST", s.URL()+"/api/proxy-pool/"+action, strings.NewReader(`{}`))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s bypassed authentication", action)
		}
	}
	response := proxyAPIRequest(t, s, "POST", "settings", `{"max_accounts_per_exit":1,"path":"elsewhere"}`)
	if response.Code != 400 {
		t.Fatal("unexpected input accepted")
	}
}

func TestProxyPoolApplyPreflightsCapacityBeforeStoppingAccounts(t *testing.T) {
	s, _ := proxyAPIFixture(t)
	proxyAPIRequest(t, s, "POST", "node", `{"id":"unit","url":"http://proxy.example:8080","enabled":true}`)
	s.accounts = []*Account{{ID: "one", Dir: filepath.Join(s.config.Dir, "one")}, {ID: "two", Dir: filepath.Join(s.config.Dir, "two")}}
	stops, resumes := 0, 0
	s.proxyPoolStop = func(context.Context, *Account) error { stops++; return nil }
	s.proxyPoolResume = func(context.Context, *Account) control.Result { resumes++; return control.Result{OK: true} }
	response := proxyAPIRequest(t, s, "POST", "apply", `{}`)
	if stops != 0 || resumes != 0 || !strings.Contains(response.Body.String(), `"ok":false`) {
		t.Fatal("insufficient capacity disturbed an account")
	}
	manager := s.proxyManager()
	snapshot, err := manager.Snapshot()
	if err != nil || snapshot.Enabled || len(snapshot.Assignments) != 0 {
		t.Fatal("failed preflight partially assigned or enabled pool")
	}
}

func TestProxyPoolApplyRestoresSavedAccountsAndReportsActualWorkerState(t *testing.T) {
	s, _ := proxyAPIFixture(t)
	proxyAPIRequest(t, s, "POST", "node", `{"id":"unit","url":"http://proxy.example:8080","enabled":true}`)
	account := &Account{ID: "one", Dir: filepath.Join(s.config.Dir, "one"), AppleID: "fixture@example.test"}
	s.accounts = []*Account{account}
	if err := os.MkdirAll(account.Dir, 0700); err != nil {
		t.Fatal(err)
	}
	writeStatus := func(status Status) {
		data, _ := json.Marshal(status)
		if err := os.WriteFile(filepath.Join(account.Dir, "runtime.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeStatus(Status{Running: true, PID: os.Getpid(), State: "online"})
	stops, resumes := 0, 0
	s.proxyPoolStop = func(context.Context, *Account) error { stops++; writeStatus(Status{State: "stopped"}); return nil }
	s.proxyPoolResume = func(context.Context, *Account) control.Result { resumes++; return control.Result{OK: true} }
	response := proxyAPIRequest(t, s, "POST", "apply", `{}`)
	var view proxyPoolView
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if !view.OK || !view.Enabled || stops != 1 || resumes != 1 {
		t.Fatalf("saved migration failed: stops=%d resumes=%d response=%s", stops, resumes, response.Body.String())
	}
	if len(view.Accounts) != 1 || view.Accounts[0].Applied {
		t.Fatal("queued restart falsely reported as applied")
	}
	writeStatus(Status{Running: true, PID: os.Getpid(), State: "online", ProxyNodeID: "unit", ProxyExitIP: "192.0.2.20"})
	if !s.proxySnapshot().Accounts[0].Applied {
		t.Fatal("matching live worker not marked applied")
	}
}

func TestProxyPoolFailedStopReportsAnyFailedRollback(t *testing.T) {
	s, _ := proxyAPIFixture(t)
	proxyAPIRequest(t, s, "POST", "node", `{"id":"unit","url":"http://proxy.example:8080","enabled":true}`)
	proxyAPIRequest(t, s, "POST", "settings", `{"max_accounts_per_exit":2}`)
	for _, id := range []string{"one", "two"} {
		a := &Account{ID: id, Dir: filepath.Join(s.config.Dir, id)}
		s.accounts = append(s.accounts, a)
		if err := os.MkdirAll(a.Dir, 0700); err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(Status{Running: true, PID: os.Getpid(), State: "online"})
		if err := os.WriteFile(filepath.Join(a.Dir, "runtime.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	s.proxyPoolStop = func(_ context.Context, a *Account) error {
		if a.ID == "two" {
			return errors.New("synthetic stop failure")
		}
		data, _ := json.Marshal(Status{State: "stopped"})
		return os.WriteFile(filepath.Join(a.Dir, "runtime.json"), data, 0600)
	}
	s.proxyPoolResume = func(context.Context, *Account) control.Result {
		return control.Result{Message: "synthetic resume failure"}
	}
	response := proxyAPIRequest(t, s, "POST", "apply", `{}`)
	var view proxyPoolView
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.OK || view.Enabled || len(view.Accounts) != 2 || view.Accounts[0].Message == "" || !strings.Contains(view.Message, "未能恢复") {
		t.Fatal("rollback failure was hidden or pool activated")
	}
}
