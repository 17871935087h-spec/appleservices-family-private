package gsa

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

type proxyObservation struct {
	method string
	host   string
	auth   string
	err    error
}

func TestAppleTransportHTTPConnectUsesProxyAuthAndVerifiesTLS(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer origin.Close()
	originURL, _ := url.Parse(origin.URL)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	observed := make(chan proxyObservation, 1)
	go serveHTTPConnectTunnel(listener, originURL.Host, observed)

	transport, err := AppleRootTransportForProxy("http://test-user:test-pass@" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
	_, requestErr := client.Get(origin.URL)
	if requestErr == nil || !strings.Contains(requestErr.Error(), "certificate signed by unknown authority") {
		t.Fatalf("TLS verification error = %v; expected an untrusted origin certificate", requestErr)
	}
	select {
	case result := <-observed:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.method != http.MethodConnect || result.host != originURL.Host || result.auth != "Basic dGVzdC11c2VyOnRlc3QtcGFzcw==" {
			t.Fatalf("CONNECT observed: method=%q host=%q auth=%q", result.method, result.host, result.auth)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("HTTP proxy did not receive CONNECT; request may have bypassed it")
	}
}

func serveHTTPConnectTunnel(listener net.Listener, wantHost string, observed chan<- proxyObservation) {
	conn, err := listener.Accept()
	if err != nil {
		observed <- proxyObservation{err: err}
		return
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		observed <- proxyObservation{err: err}
		return
	}
	defer request.Body.Close()
	result := proxyObservation{method: request.Method, host: request.Host, auth: request.Header.Get("Proxy-Authorization")}
	remote, err := net.Dial("tcp", wantHost)
	if err != nil {
		result.err = err
		observed <- result
		return
	}
	defer remote.Close()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		result.err = err
		observed <- result
		return
	}
	observed <- result
	go func() { _, _ = io.Copy(remote, reader); _ = remote.Close() }()
	_, _ = io.Copy(conn, remote)
}

func TestAppleTransportSOCKSAuthUsesProxyAndVerifiesTLS(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer origin.Close()
	originURL, _ := url.Parse(origin.URL)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	observed := make(chan proxyObservation, 1)
	go serveSOCKSTunnel(listener, observed)

	transport, err := AppleRootTransportForProxy("socks5://test-user:test-pass@" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
	_, requestErr := client.Get(origin.URL)
	if requestErr == nil || !strings.Contains(requestErr.Error(), "certificate signed by unknown authority") {
		t.Fatalf("TLS verification error = %v; expected an untrusted origin certificate", requestErr)
	}
	select {
	case result := <-observed:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.method != "SOCKS5 USERPASS" || result.host != originURL.Host {
			t.Fatalf("SOCKS observed: method=%q host=%q", result.method, result.host)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("SOCKS proxy did not receive the request; request may have bypassed it")
	}
}

func TestAppleTransportAuthenticatesAndCompletesTLSRequestThroughProxy(t *testing.T) {
	for _, scheme := range []string{"http", "socks5"} {
		t.Run(scheme, func(t *testing.T) {
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "proxy-success") }))
			defer origin.Close()
			originURL, _ := url.Parse(origin.URL)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			observed := make(chan proxyObservation, 1)
			if scheme == "http" {
				go serveHTTPConnectTunnel(listener, originURL.Host, observed)
			} else {
				go serveSOCKSTunnel(listener, observed)
			}
			transport, err := AppleRootTransportForProxy(scheme + "://test-user:test-pass@" + listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer transport.CloseIdleConnections()
			// Trust only the fixture's certificate in addition to normal roots;
			// certificate verification itself remains enabled.
			transport.TLSClientConfig.RootCAs.AddCert(origin.Certificate())
			client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
			response, err := client.Get(origin.URL)
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			if readErr != nil || string(body) != "proxy-success" {
				t.Fatal("proxied TLS response was not received")
			}
			select {
			case result := <-observed:
				if result.err != nil || result.host != originURL.Host {
					t.Fatal("proxy tunnel was not observed")
				}
			case <-time.After(4 * time.Second):
				t.Fatal("request bypassed proxy")
			}
		})
	}
}

func serveSOCKSTunnel(listener net.Listener, observed chan<- proxyObservation) {
	conn, err := listener.Accept()
	if err != nil {
		observed <- proxyObservation{err: err}
		return
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	var greeting [2]byte
	if _, err := io.ReadFull(reader, greeting[:]); err != nil || greeting[0] != 5 {
		observed <- proxyObservation{err: errors.New("invalid SOCKS greeting")}
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		observed <- proxyObservation{err: err}
		return
	}
	if _, err := conn.Write([]byte{5, 2}); err != nil {
		observed <- proxyObservation{err: err}
		return
	}
	var authHeader [2]byte
	if _, err := io.ReadFull(reader, authHeader[:]); err != nil || authHeader[0] != 1 {
		observed <- proxyObservation{err: errors.New("invalid SOCKS user/password frame")}
		return
	}
	username := make([]byte, int(authHeader[1]))
	if _, err := io.ReadFull(reader, username); err != nil {
		observed <- proxyObservation{err: err}
		return
	}
	var passwordLength [1]byte
	if _, err := io.ReadFull(reader, passwordLength[:]); err != nil {
		observed <- proxyObservation{err: err}
		return
	}
	password := make([]byte, int(passwordLength[0]))
	if _, err := io.ReadFull(reader, password); err != nil {
		observed <- proxyObservation{err: err}
		return
	}
	if string(username) != "test-user" || string(password) != "test-pass" {
		_, _ = conn.Write([]byte{1, 1})
		observed <- proxyObservation{err: errors.New("SOCKS credentials did not match")}
		return
	}
	if _, err := conn.Write([]byte{1, 0}); err != nil {
		observed <- proxyObservation{err: err}
		return
	}
	var requestHeader [4]byte
	if _, err := io.ReadFull(reader, requestHeader[:]); err != nil || requestHeader[0] != 5 || requestHeader[1] != 1 {
		observed <- proxyObservation{err: errors.New("invalid SOCKS connect frame")}
		return
	}
	host, err := readSOCKSHost(reader, requestHeader[3])
	if err != nil {
		observed <- proxyObservation{err: err}
		return
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(reader, portBytes[:]); err != nil {
		observed <- proxyObservation{err: err}
		return
	}
	port := strconv.Itoa(int(binary.BigEndian.Uint16(portBytes[:])))
	target := net.JoinHostPort(host, port)
	remote, err := net.Dial("tcp", target)
	if err != nil {
		observed <- proxyObservation{err: err}
		return
	}
	defer remote.Close()
	if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		observed <- proxyObservation{err: err}
		return
	}
	observed <- proxyObservation{method: "SOCKS5 USERPASS", host: target}
	go func() { _, _ = io.Copy(remote, reader); _ = remote.Close() }()
	_, _ = io.Copy(conn, remote)
}

func readSOCKSHost(reader io.Reader, addressType byte) (string, error) {
	switch addressType {
	case 1:
		address := make([]byte, 4)
		if _, err := io.ReadFull(reader, address); err != nil {
			return "", err
		}
		return net.IP(address).String(), nil
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return "", err
		}
		address := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, address); err != nil {
			return "", err
		}
		return string(address), nil
	case 4:
		address := make([]byte, 16)
		if _, err := io.ReadFull(reader, address); err != nil {
			return "", err
		}
		return net.IP(address).String(), nil
	default:
		return "", errors.New("unsupported SOCKS address type")
	}
}
