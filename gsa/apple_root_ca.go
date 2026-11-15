package gsa

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/Laky-64/appleservices/internal/egresspool"
	"golang.org/x/net/proxy"
)

const AccountProxyEnv = "APPLESERVICES_ACCOUNT_PROXY"

func AppleRootTransport() http.RoundTripper {
	if raw := strings.TrimSpace(os.Getenv(AccountProxyEnv)); raw != "" {
		transport, err := AppleRootTransportForProxy(raw)
		if err != nil {
			return blockedAppleTransport()
		}
		return transport
	}
	if strings.TrimSpace(os.Getenv(egresspool.PoolEnv)) != "" {
		// A worker that inherited a configured pool must have had its account
		// route installed before it creates a client. Never let a missing route
		// silently fall back to the machine's ordinary egress.
		return blockedAppleTransport()
	}
	if raw := strings.TrimSpace(os.Getenv("APPLESERVICES_SOCKS_PROXY")); raw != "" {
		transport, err := AppleRootTransportForProxy(legacySOCKSURL(raw))
		if err != nil {
			return blockedAppleTransport()
		}
		return transport
	}
	transport := newAppleRootTransport()
	transport.Proxy = http.ProxyFromEnvironment
	return transport
}

// AppleRootTransportForAccount resolves a stable route for one account. When a
// pool is configured, its assignment takes precedence over inherited process
// proxy variables and resolution failures are returned to the caller.
func AppleRootTransportForAccount(accountDir string) (*http.Transport, error) {
	if strings.TrimSpace(os.Getenv(egresspool.PoolEnv)) != "" {
		route, err := egresspool.Resolve(accountDir)
		if err != nil {
			return nil, err
		}
		if !route.Enabled || strings.TrimSpace(route.URL) == "" {
			return nil, errors.New("gsa: configured proxy pool returned no account route")
		}
		return AppleRootTransportForProxy(route.URL)
	}
	if raw := strings.TrimSpace(os.Getenv(AccountProxyEnv)); raw != "" {
		return AppleRootTransportForProxy(raw)
	}
	if raw := strings.TrimSpace(os.Getenv("APPLESERVICES_SOCKS_PROXY")); raw != "" {
		return AppleRootTransportForProxy(legacySOCKSURL(raw))
	}
	transport := newAppleRootTransport()
	transport.Proxy = http.ProxyFromEnvironment
	return transport, nil
}

// AppleRootTransportForProxy builds an Apple-root-verifying transport through
// one explicit HTTP, HTTPS, or SOCKS5 proxy URL.
func AppleRootTransportForProxy(raw string) (*http.Transport, error) {
	parsed, err := parseProxyURL(raw)
	if err != nil {
		return nil, err
	}
	transport := newAppleRootTransport()
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		transport.Proxy = http.ProxyURL(parsed)
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if parsed.User != nil {
			password, _ := parsed.User.Password()
			auth = &proxy.Auth{User: parsed.User.Username(), Password: password}
		}
		dialer, dialErr := proxy.SOCKS5("tcp", parsed.Host, auth, proxy.Direct)
		if dialErr != nil {
			return nil, errors.New("gsa: account SOCKS proxy is invalid")
		}
		transport.Proxy = nil
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			if contextual, ok := dialer.(interface {
				DialContext(context.Context, string, string) (net.Conn, error)
			}); ok {
				return contextual.DialContext(ctx, network, address)
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return dialer.Dial(network, address)
		}
	}
	return transport, nil
}

func newAppleRootTransport() *http.Transport {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	pool.AppendCertsFromPEM([]byte(AppleRootCAPEM))
	pool.AppendCertsFromPEM([]byte(AppleRootCAG3PEM))
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyFromEnvironment
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	transport.TLSClientConfig.RootCAs = pool
	return transport
}

func parseProxyURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed == nil || parsed.Host == "" || parsed.Fragment != "" || parsed.RawQuery != "" {
		return nil, errors.New("gsa: account proxy URL is invalid")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, errors.New("gsa: account proxy scheme is unsupported")
	}
	if parsed.Hostname() == "" {
		return nil, errors.New("gsa: account proxy URL is invalid")
	}
	return parsed, nil
}

func legacySOCKSURL(raw string) string {
	if strings.Contains(raw, "://") {
		return raw
	}
	return "socks5://" + raw
}

func blockedAppleTransport() *http.Transport {
	transport := newAppleRootTransport()
	transport.Proxy = nil
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("gsa: account proxy route is unavailable")
	}
	return transport
}

// Apple PKI: https://www.apple.com/certificateauthority/AppleRootCA-G3.cer
// DER SHA-256: 63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179.
// The NAC certificate endpoint chains to G3 rather than the legacy Apple root.
//
//go:embed apple_root_ca_g3.pem
var AppleRootCAG3PEM string

// applySOCKS5Proxy routes this transport through a SOCKS5 proxy named by
// APPLESERVICES_SOCKS_PROXY. Apple throttles the verification-code page by
// egress address, and Go's environment proxy support covers HTTP proxies only,
// so a SOCKS5 listener needs its own dialer.
func applySOCKS5Proxy(transport *http.Transport) {
	raw := strings.TrimSpace(os.Getenv("APPLESERVICES_SOCKS_PROXY"))
	if raw == "" {
		return
	}
	dialer, err := proxy.SOCKS5("tcp", raw, nil, proxy.Direct)
	if err != nil {
		return
	}
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if cd, ok := dialer.(interface {
			DialContext(context.Context, string, string) (net.Conn, error)
		}); ok {
			return cd.DialContext(ctx, network, addr)
		}
		return dialer.Dial(network, addr)
	}
}

const AppleRootCAPEM = `-----BEGIN CERTIFICATE-----
MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0
MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBw
bGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
FjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg+
+FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1
XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9w
tj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IW
q6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKM
aLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3
R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAE
ggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93
d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNl
IG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0
YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj
b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp
Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBc
NplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQP
y3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7
R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4Fg
xhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oP
IQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AX
UKqK1drk/NAJBzewdXUh
-----END CERTIFICATE-----
`
