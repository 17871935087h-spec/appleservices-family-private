package aps

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/Laky-64/appleservices/internal/egresspool"
)

func TestAccountProxyURLUsesPersistedPoolRoute(t *testing.T) {
	root := t.TempDir()
	poolPath := filepath.Join(root, "proxy-pool.json")
	data, err := json.Marshal(map[string]any{
		"version": 1,
		"nodes": []map[string]any{
			{"id": "a", "url": "socks5://user:password@127.0.0.1:1081", "exit_ip": "203.0.113.21", "enabled": true},
			{"id": "b", "url": "http://127.0.0.1:1082", "exit_ip": "203.0.113.22", "enabled": true},
		},
		"assignments": map[string]string{"account-a": "a", "account-b": "b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(poolPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(egresspool.PoolEnv, poolPath)
	t.Setenv("APPLESERVICES_ACCOUNT_PROXY", "http://127.0.0.1:1099")
	for _, test := range []struct{ account, want string }{
		{"account-a", "socks5://user:password@127.0.0.1:1081"},
		{"account-b", "http://127.0.0.1:1082"},
	} {
		got, err := accountProxyURL(filepath.Join(root, test.account))
		if err != nil || got != test.want {
			t.Fatalf("account route = %q, err=%v; want %q", got, err, test.want)
		}
	}
}

func TestConfiguredPoolWithoutAccountRouteFailsClosed(t *testing.T) {
	t.Setenv(egresspool.PoolEnv, filepath.Join(t.TempDir(), "pool.json"))
	t.Setenv("APPLESERVICES_ACCOUNT_PROXY", "")
	if _, err := processProxyURL(); err == nil {
		t.Fatal("configured pool without an account route was accepted")
	}
}

func TestValidateStateDoesNotResolveProxyRoute(t *testing.T) {
	t.Setenv(egresspool.PoolEnv, filepath.Join(t.TempDir(), "missing-pool.json"))
	err := ValidateState(State{})
	if err == nil || err.Error() != "aps: a matching client push certificate and private key are required" {
		t.Fatalf("ValidateState error = %v; want credential validation error", err)
	}
}

func TestExplicitAccountProxyTakesPriorityAndSupportsConnect(t *testing.T) {
	var gotMethod, gotHost string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotHost = r.Method, r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(egresspool.PoolEnv, "")
	t.Setenv("APPLESERVICES_ACCOUNT_PROXY", proxyURL.String())
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1999")
	route, err := processProxyURL()
	if err != nil || route != server.URL {
		t.Fatalf("explicit route = %q, err=%v", route, err)
	}
	connection, err := dialCourierWithProxy(context.Background(), "courier.example:5223", route)
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	if gotMethod != http.MethodConnect || gotHost != "courier.example:5223" {
		t.Fatalf("proxy received %s %q", gotMethod, gotHost)
	}
}
