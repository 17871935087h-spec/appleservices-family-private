// account-http is a private-pipe transport for Python helpers. Its input and
// output may contain account credentials and must never be logged or persisted.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Laky-64/appleservices/gsa"
)

const maxInput = 256 << 10
const maxResponse = 4 << 20

type request struct {
	Method         string            `json:"method"`
	URL            string            `json:"url"`
	Body           []byte            `json:"body"`
	Headers        map[string]string `json:"headers"`
	ByteLimit      int               `json:"byte_limit"`
	TimeoutSeconds int               `json:"timeout_seconds"`
}

type response struct {
	Status     int      `json:"status"`
	Body       []byte   `json:"body"`
	SetCookies []string `json:"set_cookies"`
}

func readRequest(input io.Reader) (request, error) {
	var value request
	data, readErr := io.ReadAll(io.LimitReader(input, maxInput+1))
	if readErr != nil || len(data) > maxInput {
		return request{}, errors.New("invalid transport input")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return request{}, errors.New("invalid transport input")
	}
	u, err := url.Parse(value.URL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" ||
		(u.Port() != "" && u.Port() != "443") || !allowedHost(u.Hostname()) ||
		(value.Method != "GET" && value.Method != "POST") ||
		value.ByteLimit < 1 || value.ByteLimit > maxResponse ||
		value.TimeoutSeconds < 1 || value.TimeoutSeconds > 30 || len(value.Headers) > 100 {
		return request{}, errors.New("invalid transport input")
	}
	return value, nil
}

func allowedHost(host string) bool {
	host = strings.ToLower(host)
	return strings.HasSuffix(host, ".icloud.com") || strings.HasSuffix(host, ".icloud.com.cn")
}

func exchange(ctx context.Context, input request, transport http.RoundTripper) (response, error) {
	client := &http.Client{Transport: transport, Timeout: time.Duration(input.TimeoutSeconds) * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := http.NewRequestWithContext(ctx, input.Method, input.URL, bytes.NewReader(input.Body))
	if err != nil {
		return response{}, errors.New("account proxy transport failed")
	}
	for key, value := range input.Headers {
		r.Header.Set(key, value)
	}
	result, err := client.Do(r)
	if err != nil {
		return response{}, errors.New("account proxy transport failed")
	}
	defer result.Body.Close()
	body, err := io.ReadAll(io.LimitReader(result.Body, int64(input.ByteLimit)+1))
	if err != nil || len(body) > input.ByteLimit {
		return response{}, errors.New("account proxy transport failed")
	}
	cookies := result.Header.Values("Set-Cookie")
	if cookies == nil {
		cookies = []string{}
	}
	cookieBytes := 0
	for _, cookie := range cookies {
		cookieBytes += len(cookie)
	}
	if cookieBytes > 64<<10 || len(cookies) > 100 {
		return response{}, errors.New("account proxy transport failed")
	}
	return response{Status: result.StatusCode, Body: body, SetCookies: cookies}, nil
}

func run(input io.Reader, output io.Writer) error {
	value, err := readRequest(input)
	if err != nil {
		return err
	}
	raw := os.Getenv(gsa.AccountProxyEnv)
	if raw == "" {
		return errors.New("account proxy is required")
	}
	transport, err := gsa.AppleRootTransportForProxy(raw)
	if err != nil {
		return errors.New("account proxy is invalid")
	}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(value.TimeoutSeconds)*time.Second)
	defer cancel()
	result, err := exchange(ctx, value, transport)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(result)
}

func main() {
	if run(os.Stdin, os.Stdout) != nil {
		// The Python supervisor interprets a nonzero exit as a terminal transport
		// failure. Never include URLs, headers, cookies or proxy credentials.
		os.Exit(1)
	}
}
