package aps

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestInactiveManagementPoolDoesNotBlockExistingAPSRoute(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"enabled":false,"nodes":[],"assignments":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APPLESERVICES_PROXY_POOL", path)
	t.Setenv("APPLESERVICES_ACCOUNT_PROXY", "")
	t.Setenv("APPLESERVICES_SOCKS_PROXY", "")
	if raw, err := accountProxyURL("fixture-account"); err != nil || raw != "" {
		t.Fatal("inactive management pool changed APS route")
	}
}

func TestProxyCheckUsesCourierTunnelWithoutAuthenticatingDevice(t *testing.T) {
	observed := make(chan string, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Header.Get("Proxy-Authorization") == "" {
			t.Error("courier probe did not authenticate explicit proxy tunnel")
		}
		observed <- r.Host
		w.WriteHeader(http.StatusForbidden)
	}))
	defer proxy.Close()
	if err := CheckProxy(context.Background(), "http://fixture:synthetic@"+proxy.Listener.Addr().String()); err == nil {
		t.Fatal("proxy rejection passed")
	}
	if host := <-observed; host != "1-courier.push.apple.com:5223" {
		t.Fatalf("unexpected probe target: %s", host)
	}
	if CheckProxy(context.Background(), "") == nil {
		t.Fatal("empty proxy can fall back to direct")
	}
}
