package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func validInput() request {
	return request{Method: "GET", URL: "https://setup.icloud.com/setup/get_account_settings", ByteLimit: 1024, TimeoutSeconds: 15}
}

func TestPipeTransportPreservesStatusAndSeparateCookies(t *testing.T) {
	calls := 0
	input := validInput()
	input.Headers = map[string]string{"Authorization": "test-private-header"}
	result, err := exchange(context.Background(), input, transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("Authorization") != "test-private-header" {
			t.Fatal("authentication header was lost")
		}
		return &http.Response{StatusCode: 401, Header: http.Header{"Set-Cookie": []string{"a=1; Path=/", "b=2; Path=/"}}, Body: io.NopCloser(strings.NewReader("rejected")), Request: r}, nil
	}))
	if err != nil || result.Status != 401 || len(result.SetCookies) != 2 || calls != 1 {
		t.Fatal("response did not preserve rejection and cookies")
	}
}

func TestPipeTransportDoesNotRetryProxyFailureOrFollowRedirect(t *testing.T) {
	calls := 0
	_, err := exchange(context.Background(), validInput(), transportFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("credential-bearing upstream failure")
	}))
	if err == nil || calls != 1 || strings.Contains(err.Error(), "credential-bearing") {
		t.Fatal("proxy failure retried or exposed")
	}
	calls = 0
	result, err := exchange(context.Background(), validInput(), transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://other.example/"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	}))
	if err != nil || result.Status != 302 || calls != 1 {
		t.Fatal("transport followed a redirect")
	}
}

func TestPipeTransportRejectsUnboundedOrNonAppleRequests(t *testing.T) {
	for _, target := range []string{"http://setup.icloud.com/", "https://127.0.0.1/", "https://setup.icloud.com.evil.example/", "https://user:secret@setup.icloud.com/"} {
		input := validInput()
		input.URL = target
		encoded, _ := json.Marshal(input)
		if _, err := readRequest(strings.NewReader(string(encoded))); err == nil {
			t.Fatal("invalid destination accepted")
		}
	}
	input := validInput()
	input.ByteLimit = 1
	_, err := exchange(context.Background(), input, transportFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("too long")), Header: make(http.Header), Request: r}, nil
	}))
	if err == nil {
		t.Fatal("unbounded response accepted")
	}
}
