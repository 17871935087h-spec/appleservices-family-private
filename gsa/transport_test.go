package gsa

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"howett.net/plist"
)

func TestAppleTransportPreservesProxyAndCertificateVerification(t *testing.T) {
	transport := AppleRootTransport().(*http.Transport)
	if transport.Proxy == nil {
		t.Fatal("Apple requests bypass configured environment proxy")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("Apple certificate verification is not enabled")
	}
}

func TestAccountTransportUsesPersistedPoolRouteBeforeInheritedProxy(t *testing.T) {
	root := t.TempDir()
	firstDir := filepath.Join(root, "account-a")
	secondDir := filepath.Join(root, "account-b")
	poolPath := filepath.Join(root, "proxy-pool.json")
	pool := map[string]any{
		"version":                 1,
		"max_accounts_per_exit":   1,
		"nodes": []map[string]any{
			{"id": "node-a", "url": "http://127.0.0.1:18101", "exit_ip": "203.0.113.11", "enabled": true},
			{"id": "node-b", "url": "http://127.0.0.1:18102", "exit_ip": "203.0.113.12", "enabled": true},
		},
		"assignments": map[string]string{"account-a": "node-a", "account-b": "node-b"},
	}
	data, err := json.Marshal(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(poolPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APPLESERVICES_PROXY_POOL", poolPath)
	t.Setenv(AccountProxyEnv, "http://127.0.0.1:18199")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:18198")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:18198")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:18198")
	t.Setenv("APPLESERVICES_SOCKS_PROXY", "")

	for _, test := range []struct {
		dir  string
		want string
	}{{firstDir, "http://127.0.0.1:18101"}, {secondDir, "http://127.0.0.1:18102"}} {
		client, err := NewClientForAccount(headerProvider{}, test.dir)
		if err != nil {
			t.Fatal(err)
		}
		transport := client.transport.(*authenticationTransport).shared
		proxyURL, err := transport.Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "apple.example"}})
		if err != nil || proxyURL == nil || proxyURL.String() != test.want {
			t.Fatalf("account %q route = %v, err=%v; want %s", filepath.Base(test.dir), proxyURL, err, test.want)
		}
		client.transport.(*authenticationTransport).shared.CloseIdleConnections()
	}
}

func TestPoolConfiguredWithoutAppliedAccountRouteFailsClosed(t *testing.T) {
	t.Setenv("APPLESERVICES_PROXY_POOL", filepath.Join(t.TempDir(), "configured-pool.json"))
	t.Setenv(AccountProxyEnv, "")
	t.Setenv("APPLESERVICES_SOCKS_PROXY", "")
	transport := AppleRootTransport().(*http.Transport)
	if transport.Proxy != nil {
		t.Fatal("missing account route retained an environment proxy fallback")
	}
	if _, err := transport.DialContext(context.Background(), "tcp", "apple.example:443"); err == nil {
		t.Fatal("missing account route allowed a direct dial")
	}
}

func TestExplicitAccountProxySupportsAuthenticatedSOCKSURL(t *testing.T) {
	t.Setenv("APPLESERVICES_PROXY_POOL", "")
	t.Setenv(AccountProxyEnv, "socks5://user:secret@127.0.0.1:1080")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:18198")
	transport := AppleRootTransport().(*http.Transport)
	if transport.Proxy != nil || transport.DialContext == nil {
		t.Fatal("explicit SOCKS route was not installed ahead of the HTTP proxy")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("explicit route disabled Apple certificate verification")
	}
}

// Reproduce the reported edge behavior locally: one response per connection.
// The old pooled transport gets 429 on complete; the fixed transport succeeds
// on two connections while still carrying the cookie set by init.
func TestGSAUsesFreshConnectionButKeepsSessionCookies(t *testing.T) {
	type connectionKey struct{}
	var mu sync.Mutex
	counts := map[net.Conn]int{}
	response, err := plist.Marshal(map[string]any{"Response": map[string]any{"Status": map[string]any{"ec": int64(0)}}}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn := r.Context().Value(connectionKey{}).(net.Conn)
		mu.Lock()
		counts[conn]++
		count := counts[conn]
		mu.Unlock()
		if count > 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		var envelope map[string]any
		if _, err := plist.Unmarshal(data, &envelope); err != nil {
			t.Error(err)
			return
		}
		operation := envelope["Request"].(map[string]any)["o"]
		if operation == "init" {
			http.SetCookie(w, &http.Cookie{Name: "test-trust", Value: "test-cookie", Path: "/", Secure: true})
		} else {
			cookie, err := r.Cookie("test-trust")
			if err != nil || cookie.Value != "test-cookie" {
				t.Error("lost session cookie between new connections")
			}
			if r.ProtoMajor != 1 || !r.Close {
				t.Error("GSA request did not use a single-use HTTP/1 connection")
			}
		}
		w.Write(response)
	}))
	server.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, connectionKey{}, c)
	}
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	configure := func(transport *http.Transport) {
		transport.Proxy = nil
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, ServerName: server.Certificate().DNSNames[0]}
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		}
	}
	for _, fixed := range []bool{false, true} {
		name := "pooled-reproduction"
		if fixed {
			name = "fixed"
		}
		t.Run(name, func(t *testing.T) {
			c := NewClient(headerProvider{})
			transport := c.transport.(*authenticationTransport)
			configure(transport.shared)
			configure(transport.gsa)
			defer transport.shared.CloseIdleConnections()
			defer transport.gsa.CloseIdleConnections()
			if !fixed {
				c.transport = transport.shared
			}
			if _, err := c.doRequest(map[string]any{"o": "init"}); err != nil {
				t.Fatal(err)
			}
			_, err := c.doRequest(map[string]any{"o": "complete"})
			if fixed {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			// A pooled connection keeps answering 429, which is now treated as a
			// dropped request and resent until the attempts run out. The failure
			// must still surface rather than be mistaken for success.
			if err == nil {
				t.Fatal("a permanently rejected pooled connection was reported as success")
			}
		})
	}
}
