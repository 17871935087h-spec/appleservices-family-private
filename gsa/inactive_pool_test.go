package gsa

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestInactiveManagementPoolPreservesExistingTransport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"enabled":false,"nodes":[],"assignments":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APPLESERVICES_PROXY_POOL", path)
	t.Setenv("APPLESERVICES_ACCOUNT_PROXY", "")
	t.Setenv("APPLESERVICES_SOCKS_PROXY", "")
	transport, err := AppleRootTransportForAccount("fixture-account")
	if err != nil {
		t.Fatal("inactive management pool blocked existing account transport")
	}
	defer transport.CloseIdleConnections()
	ordinary, ok := AppleRootTransport().(*http.Transport)
	if !ok {
		t.Fatal("inactive management pool returned blocked transport")
	}
	defer ordinary.CloseIdleConnections()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer origin.Close()
	for _, candidate := range []*http.Transport{ordinary, transport} {
		request, _ := http.NewRequest(http.MethodGet, origin.URL, nil)
		response, err := candidate.RoundTrip(request)
		if err != nil {
			t.Fatalf("inactive pool blocked existing route: %v", err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatal("unexpected local response")
		}
	}
}
