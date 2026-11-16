package aps

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Laky-64/appleservices/gsa"
	"github.com/Laky-64/appleservices/internal/egresspool"
	"golang.org/x/net/proxy"
)

type bufferedConnection struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConnection) Read(data []byte) (int, error) { return c.reader.Read(data) }

func dialCourier(ctx context.Context, address string) (net.Conn, error) {
	proxyURL, err := processProxyURL()
	if err != nil {
		return nil, err
	}
	return dialCourierWithProxy(ctx, address, proxyURL)
}

func processProxyURL() (string, error) {
	if raw := strings.TrimSpace(os.Getenv("APPLESERVICES_ACCOUNT_PROXY")); raw != "" {
		return validateProxyURL(raw)
	}
	if strings.TrimSpace(os.Getenv(egresspool.PoolEnv)) != "" {
		snapshot, err := egresspool.Inspect()
		if err != nil || snapshot.Enabled {
			return "", errors.New("aps: proxy pool requires an applied account route")
		}
	}
	if raw := strings.TrimSpace(os.Getenv("APPLESERVICES_SOCKS_PROXY")); raw != "" {
		return validateProxyURL(legacySOCKSURL(raw))
	}
	return "", nil
}

func accountProxyURL(accountDir string) (string, error) {
	if strings.TrimSpace(os.Getenv(egresspool.PoolEnv)) != "" {
		route, err := egresspool.Resolve(accountDir)
		if err != nil {
			return "", err
		}
		if route.Enabled {
			if strings.TrimSpace(route.URL) == "" {
				return "", errors.New("aps: configured proxy pool returned no account route")
			}
			return validateProxyURL(route.URL)
		}
	}
	return processProxyURL()
}

// CheckProxy verifies the courier tunnel and server TLS identity, then closes
// without sending a device identity or authenticating an Apple account.
func CheckProxy(ctx context.Context, raw string) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("aps: explicit proxy is required")
	}
	proxyURL, err := validateProxyURL(raw)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	connection, err := dialCourierWithProxy(ctx, "1-courier.push.apple.com:5223", proxyURL)
	if err != nil {
		return errors.New("aps: proxy courier tunnel is unavailable")
	}
	defer connection.Close()
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	pool.AppendCertsFromPEM([]byte(gsa.AppleRootCAPEM))
	secure := tls.Client(connection, &tls.Config{RootCAs: pool, ServerName: "courier.push.apple.com", NextProtos: []string{"apns-security-v3"}, MinVersion: tls.VersionTLS12})
	if err := secure.HandshakeContext(ctx); err != nil {
		return errors.New("aps: proxy courier TLS check failed")
	}
	return nil
}

func legacySOCKSURL(raw string) string {
	if strings.Contains(raw, "://") {
		return raw
	}
	return "socks5://" + raw
}

func validateProxyURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed == nil || parsed.Host == "" || parsed.Hostname() == "" || parsed.Fragment != "" || parsed.RawQuery != "" {
		return "", errors.New("aps: proxy URL is invalid")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	switch parsed.Scheme {
	case "http", "https", "socks5", "socks5h":
		return parsed.String(), nil
	default:
		return "", errors.New("aps: proxy URL scheme is unsupported")
	}
}

func dialCourierWithProxy(ctx context.Context, address, explicitProxy string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 20 * time.Second}
	endpoint := &url.URL{Scheme: "https", Host: address}
	var proxyURL *url.URL
	if strings.TrimSpace(explicitProxy) != "" {
		parsed, err := url.Parse(explicitProxy)
		if err != nil {
			return nil, errors.New("aps: proxy URL is invalid")
		}
		proxyURL = parsed
	} else {
		var err error
		proxyURL, err = http.ProxyFromEnvironment(&http.Request{URL: endpoint})
		if err != nil {
			return nil, err
		}
	}
	if proxyURL == nil {
		return dialer.DialContext(ctx, "tcp", address)
	}
	scheme := strings.ToLower(proxyURL.Scheme)
	if scheme == "socks5" || scheme == "socks5h" {
		socksURL := *proxyURL
		socksURL.Scheme = "socks5"
		d, err := proxy.FromURL(&socksURL, dialer)
		if err != nil {
			return nil, err
		}
		cd, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("aps: proxy cannot dial with a context")
		}
		return cd.DialContext(ctx, "tcp", address)
	}
	if scheme != "http" && scheme != "https" {
		return nil, errors.New("aps: unsupported proxy scheme")
	}
	host := proxyURL.Host
	if proxyURL.Port() == "" {
		if scheme == "https" {
			host = net.JoinHostPort(proxyURL.Hostname(), "443")
		} else {
			host = net.JoinHostPort(proxyURL.Hostname(), "80")
		}
	}
	connection, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			connection.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	if scheme == "https" {
		secured := tls.Client(connection, &tls.Config{ServerName: proxyURL.Hostname(), MinVersion: tls.VersionTLS12})
		if err := secured.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		connection = secured
	}
	deadline := time.Now().Add(20 * time.Second)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	connection.SetDeadline(deadline)
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: address}, Host: address, Header: make(http.Header)}
	if proxyURL.User != nil {
		pass, _ := proxyURL.User.Password()
		request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username()+":"+pass)))
	}
	if err := request.Write(connection); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("aps: proxy rejected courier tunnel")
	}
	connection.SetDeadline(time.Time{})
	success = true
	return &bufferedConnection{connection, reader}, nil
}
