package v2gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestPrimaryMailGatewayBindsAccountAndProjectsResponse(t *testing.T) {
	registryPath := testRegistry(t, registryFixture())
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			io.WriteString(w, `<meta name="app-token" content="`+testAppKey+`">`)
			return
		}
		calls++
		if r.URL.Path != "/api/primary-mail/status" || r.URL.Query().Get("account") != "org-01" || r.Header.Get("X-App-Token") != testAppKey {
			t.Error("request binding/auth lost")
		}
		json.NewEncoder(w).Encode(primaryMailState{AccountID: "org-01", Stage: "verified", Email: "fixture@icloud.com", CanCreate: true, Message: "raw-secret-fixture"})
	}))
	defer server.Close()
	g, err := New(Config{RegistryPath: registryPath, IntentDir: testRoot(t), BearerToken: testBearer})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	address, _ := url.Parse(server.URL)
	g.dashboardURL = *address
	registry, err := loadRegistry(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	appleID := ""
	for _, account := range registry.Accounts {
		if account.ID == "org-01" {
			appleID = account.AppleID
		}
	}
	encoded, _ := json.Marshal(primaryMailRequest{AccountID: "org-01", AppleID: appleID})
	response := gatewayRequest(t, g, "/v1/primary-mail/status", string(encoded))
	if response.Code != 200 || calls != 1 || strings.Contains(response.Body.String(), "raw-secret-fixture") {
		t.Fatal("safe bridge projection failed")
	}
	state := decodeGatewayResponse[primaryMailState](t, response)
	if state.CanCreate || state.Email != "fixture@icloud.com" {
		t.Fatal("verified mailbox remained writable")
	}
	encoded, _ = json.Marshal(primaryMailRequest{AccountID: "org-01", AppleID: "other@example.test"})
	response = gatewayRequest(t, g, "/v1/primary-mail/status", string(encoded))
	if response.Code != 404 || calls != 1 {
		t.Fatal("mismatched account reached dashboard")
	}
}

func TestPrimaryMailGatewayDoesNotReplayUnknownCreate(t *testing.T) {
	registryPath := testRegistry(t, registryFixture())
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			io.WriteString(w, `<meta name="app-token" content="`+testAppKey+`">`)
			return
		}
		calls++
		http.Error(w, "secret fixture", 500)
	}))
	defer server.Close()
	g, err := New(Config{RegistryPath: registryPath, IntentDir: testRoot(t), BearerToken: testBearer})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	address, _ := url.Parse(server.URL)
	g.dashboardURL = *address
	registry, _ := loadRegistry(registryPath)
	appleID := ""
	for _, account := range registry.Accounts {
		if account.ID == "org-01" {
			appleID = account.AppleID
		}
	}
	input := primaryMailRequest{AccountID: "org-01", AppleID: appleID, Prefix: "fixture", ConfirmPermanent: true}
	encoded, _ := json.Marshal(input)
	response := gatewayRequest(t, g, "/v1/primary-mail/create", string(encoded))
	state := decodeGatewayResponse[primaryMailState](t, response)
	if response.Code != 200 || state.Stage != "outcome_unknown" || state.CanCreate || calls != 1 || strings.Contains(response.Body.String(), "secret fixture") {
		t.Fatal("unknown mutation replayed or leaked")
	}
	input.ConfirmPermanent = false
	encoded, _ = json.Marshal(input)
	if gatewayRequest(t, g, "/v1/primary-mail/create", string(encoded)).Code != 400 || calls != 1 {
		t.Fatal("unconfirmed creation reached dashboard")
	}
}
