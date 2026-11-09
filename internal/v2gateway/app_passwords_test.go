package v2gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const appPasswordTestRequestID = "123e4567-e89b-12d3-a456-426614174000"

func TestAppPasswordsBindsAccountAndKeepsStatusReadOnly(t *testing.T) {
	statusCalls, createCalls := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = io.WriteString(w, `<meta name="app-token" content="`+testAppKey+`">`)
			return
		}
		if r.URL.Path == "/api/app-passwords/status" {
			statusCalls++
			if r.URL.Query().Get("account") != "org-01" || r.Header.Get("X-App-Token") != testAppKey || r.Header.Get("Cache-Control") != "no-store" {
				t.Error("dashboard request binding/auth lost")
			}
			body, _ := io.ReadAll(r.Body)
			if string(body) != "{}" {
				t.Errorf("status request had unexpected payload: %s", body)
			}
			_, _ = io.WriteString(w, `{"account_id":"org-01","stage":"ready","message":"raw-secret-fixture","can_create":true,"items":[{"id":"item-01","description":"mail client","created_at":"2026-11-01T10:00:00Z"}]}`)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/create") {
			createCalls++
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	g := newAppPasswordTestGateway(t, server)

	response := gatewayRequest(t, g, "/v1/app-passwords/status", `{"account_id":"org-01","apple_id":"ORGANIZER@example.test"}`)
	state := decodeGatewayResponse[appPasswordReply](t, response)
	if response.Code != http.StatusOK || statusCalls != 1 || createCalls != 0 || state.Stage != "ready" || !state.CanCreate || state.Message != appPasswordMessage("ready") || len(state.Items) != 1 {
		t.Fatalf("safe read projection failed: status=%d calls=%d state=%#v", response.Code, statusCalls, state)
	}
	if state.FailurePhase != nil || state.HTTPStatus != nil {
		t.Fatalf("legacy dashboard response should remain compatible without diagnostics: %#v", state)
	}
	if strings.Contains(response.Body.String(), "raw-secret-fixture") || strings.Contains(response.Body.String(), "password") {
		t.Fatalf("dashboard text or password crossed response boundary: %s", response.Body.String())
	}
	response = gatewayRequest(t, g, "/v1/app-passwords/status", `{"account_id":"org-01","apple_id":"other@example.test"}`)
	if response.Code != http.StatusNotFound || statusCalls != 1 {
		t.Fatal("mismatched account reached dashboard")
	}
}

func TestAppPasswordsPassesAllowlistedFailureDiagnosticsWithoutRawErrors(t *testing.T) {
	for _, test := range []struct {
		name, phase string
		status      int
	}{
		{name: "dashboard phase", phase: "trusted-code", status: 401},
		{name: "local phase with zero status", phase: "records_load", status: 0},
		{name: "lower HTTP boundary", phase: "bootstrap", status: 100},
		{name: "upper HTTP boundary", phase: "session_save", status: 599},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					_, _ = io.WriteString(w, `<meta name="app-token" content="`+testAppKey+`">`)
					return
				}
				body := `{"account_id":"org-01","stage":"verification_required","message":"raw authentication response and secret","can_create":false,"items":[],"failure_phase":"` + test.phase + `","http_status":` + strconv.Itoa(test.status) + `}`
				_, _ = io.WriteString(w, body)
			}))
			defer server.Close()
			g := newAppPasswordTestGateway(t, server)
			response := gatewayRequest(t, g, "/v1/app-passwords/status", `{"account_id":"org-01","apple_id":"organizer@example.test"}`)
			state := decodeGatewayResponse[appPasswordReply](t, response)
			if response.Code != http.StatusOK || state.Stage != "verification_required" ||
				state.FailurePhase == nil || *state.FailurePhase != test.phase ||
				state.HTTPStatus == nil || *state.HTTPStatus != test.status {
				t.Fatalf("allowlisted diagnostics were not preserved: status=%d state=%#v", response.Code, state)
			}
			if state.Message != appPasswordMessage(state.Stage) || strings.Contains(response.Body.String(), "raw authentication response and secret") {
				t.Fatalf("raw dashboard error crossed response boundary: %s", response.Body.String())
			}
		})
	}
}

func TestAppPasswordsRejectsInvalidFailureDiagnostics(t *testing.T) {
	for _, test := range []struct {
		name, diagnostics string
	}{
		{name: "unknown phase", diagnostics: `,"failure_phase":"raw-auth-error-secret","http_status":401`},
		{name: "empty phase", diagnostics: `,"failure_phase":"","http_status":401`},
		{name: "low HTTP status", diagnostics: `,"failure_phase":"oauth-validate","http_status":99`},
		{name: "high HTTP status", diagnostics: `,"failure_phase":"oauth-validate","http_status":600`},
		{name: "non-integer HTTP status", diagnostics: `,"failure_phase":"oauth-validate","http_status":"401"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					_, _ = io.WriteString(w, `<meta name="app-token" content="`+testAppKey+`">`)
					return
				}
				body := `{"account_id":"org-01","stage":"ready","message":"raw-auth-error-secret","can_create":true,"items":[]` + test.diagnostics + `}`
				_, _ = io.WriteString(w, body)
			}))
			defer server.Close()
			g := newAppPasswordTestGateway(t, server)
			response := gatewayRequest(t, g, "/v1/app-passwords/status", `{"account_id":"org-01","apple_id":"organizer@example.test"}`)
			state := decodeGatewayResponse[appPasswordReply](t, response)
			if response.Code != http.StatusOK || state.Stage != "unavailable" || state.FailurePhase != nil || state.HTTPStatus != nil {
				t.Fatalf("invalid diagnostics were not rejected safely: status=%d state=%#v", response.Code, state)
			}
			if strings.Contains(response.Body.String(), "raw-auth-error-secret") {
				t.Fatalf("raw diagnostic or error crossed response boundary: %s", response.Body.String())
			}
		})
	}
}

func TestAppPasswordsRejectsUnauthorizedAndWrongMethod(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
	}))
	defer server.Close()
	g := newAppPasswordTestGateway(t, server)
	request := httptest.NewRequest(http.MethodPost, "/v1/app-passwords/status", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer wrong")
	response := httptest.NewRecorder()
	g.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || calls != 0 {
		t.Fatalf("unauthorized request reached dashboard: status=%d calls=%d", response.Code, calls)
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/app-passwords/status", nil)
	request.Header.Set("Authorization", "Bearer "+testBearer)
	response = httptest.NewRecorder()
	g.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed || calls != 0 {
		t.Fatalf("wrong method reached dashboard: status=%d calls=%d", response.Code, calls)
	}
}

func TestAppPasswordsRejectsInvalidAndExtraInput(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			calls++
			return
		}
		_, _ = io.WriteString(w, `<meta name="app-token" content="`+testAppKey+`">`)
	}))
	defer server.Close()
	g := newAppPasswordTestGateway(t, server)
	base := `"account_id":"org-01","apple_id":"organizer@example.test"`
	requests := []struct{ action, body string }{
		{"status", `{` + base + `,"unexpected":true}`},
		{"status", `{` + base + `,"account_id":"org-01"}`},
		{"status", `{` + base + `,"password":"private"}`},
		{"connect", `{` + base + `,"allow_web_login":true}`},
		{"connect", `{` + base + `,"allow_web_login":false,"allow_device_verification":true}`},
		{"create", `{` + base + `,"description":"line\nfeed","request_id":"` + appPasswordTestRequestID + `","allow_password_challenge":false}`},
		{"create", `{` + base + `,"description":"` + strings.Repeat("界", 65) + `","request_id":"` + appPasswordTestRequestID + `","allow_password_challenge":false}`},
		{"create", `{` + base + `,"description":"label","request_id":"not-a-uuid","allow_password_challenge":false}`},
		{"create", `{` + base + `,"description":"label","request_id":"` + appPasswordTestRequestID + `"}`},
		{"result", `{` + base + `,"request_id":"not-a-uuid"}`},
		{"review", `{` + base + `,"request_id":"` + appPasswordTestRequestID + `","allow_web_login":true}`},
	}
	for _, test := range requests {
		response := gatewayRequest(t, g, "/v1/app-passwords/"+test.action, test.body)
		if response.Code != http.StatusBadRequest {
			t.Errorf("%s accepted invalid body: status=%d body=%s", test.action, response.Code, response.Body.String())
		}
	}
	if calls != 0 {
		t.Fatalf("invalid input reached dashboard %d times", calls)
	}
}

func TestAppPasswordsProjectsPasswordOnlyFromGeneratedCreateOrResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = io.WriteString(w, `<meta name="app-token" content="`+testAppKey+`">`)
			return
		}
		switch r.URL.Path {
		case "/api/app-passwords/create", "/api/app-passwords/result":
			_, _ = io.WriteString(w, `{"account_id":"org-01","stage":"generated","message":"raw-secret-fixture","can_create":false,"items":[{"id":"item-01","description":"mail client"}],"request_id":"`+appPasswordTestRequestID+`","password":"abcd-efgh-ijkl-mnop","description":"mail client"}`)
		case "/api/app-passwords/status":
			_, _ = io.WriteString(w, `{"account_id":"org-01","stage":"ready","message":"raw-secret-fixture","can_create":true,"items":[],"password":"must-not-cross"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	g := newAppPasswordTestGateway(t, server)
	base := `"account_id":"org-01","apple_id":"organizer@example.test"`
	for _, action := range []string{"create", "result"} {
		body := `{` + base + `,"description":"mail client","request_id":"` + appPasswordTestRequestID + `","allow_password_challenge":false}`
		if action == "result" {
			body = `{` + base + `,"request_id":"` + appPasswordTestRequestID + `"}`
		}
		response := gatewayRequest(t, g, "/v1/app-passwords/"+action, body)
		state := decodeGatewayResponse[appPasswordReply](t, response)
		if response.Code != http.StatusOK || state.Stage != "generated" || state.Password != "abcd-efgh-ijkl-mnop" || strings.Contains(response.Body.String(), "raw-secret-fixture") {
			t.Fatalf("generated password projection failed for %s: %#v", action, state)
		}
	}
	status := gatewayRequest(t, g, "/v1/app-passwords/status", `{`+base+`}`)
	state := decodeGatewayResponse[appPasswordReply](t, status)
	if state.Stage != "unavailable" || state.Password != "" || strings.Contains(status.Body.String(), "must-not-cross") {
		t.Fatal("status response accepted or leaked a password")
	}
}

func TestAppPasswordsAcceptsLocalizedAndNumericCreatedAtAndEmptyHistoryLabels(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = io.WriteString(w, `<meta name="app-token" content="`+testAppKey+`">`)
			return
		}
		_, _ = io.WriteString(w, `{"account_id":"org-01","stage":"ready","message":"private","can_create":true,"items":[{"id":"item-中文","description":"","created_at":"2026年11月9日"},{"id":"item-02","description":"旧标签","created_at":"1794200000"}]}`)
	}))
	defer server.Close()
	g := newAppPasswordTestGateway(t, server)
	response := gatewayRequest(t, g, "/v1/app-passwords/status", `{"account_id":"org-01","apple_id":"organizer@example.test"}`)
	state := decodeGatewayResponse[appPasswordReply](t, response)
	if response.Code != http.StatusOK || len(state.Items) != 2 || state.Items[0].Description != "" ||
		state.Items[0].CreatedAt != "2026年11月9日" || state.Items[1].CreatedAt != "1794200000" {
		t.Fatalf("localized history fields were not preserved safely: status=%d state=%#v", response.Code, state)
	}
}

func TestAppPasswordsCreateFailureIsUnknownOnce(t *testing.T) {
	rootCalls, createCalls := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			rootCalls++
			_, _ = io.WriteString(w, `<meta name="app-token" content="`+testAppKey+`">`)
			return
		}
		if r.URL.Path == "/api/app-passwords/create" {
			createCalls++
			http.Error(w, "private dashboard failure", http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	g := newAppPasswordTestGateway(t, server)
	body := `{"account_id":"org-01","apple_id":"organizer@example.test","description":"mail client","request_id":"` + appPasswordTestRequestID + `","allow_password_challenge":true}`
	response := gatewayRequest(t, g, "/v1/app-passwords/create", body)
	state := decodeGatewayResponse[appPasswordReply](t, response)
	if response.Code != http.StatusOK || state.Stage != "outcome_unknown" || state.RequestID != appPasswordTestRequestID || createCalls != 1 || rootCalls != 1 || strings.Contains(response.Body.String(), "private dashboard failure") {
		t.Fatalf("unknown create was not safely surfaced once: roots=%d creates=%d state=%#v", rootCalls, createCalls, state)
	}
}

func newAppPasswordTestGateway(t *testing.T, server *httptest.Server) *Gateway {
	t.Helper()
	gateway, err := New(Config{
		DashboardURL: server.URL, RegistryPath: testRegistry(t, registryFixture()),
		IntentDir: testRoot(t), BearerToken: testBearer, RequestTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gateway.Close)
	return gateway
}
