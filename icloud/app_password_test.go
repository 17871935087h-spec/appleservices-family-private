package icloud

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

type appPasswordRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip appPasswordRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func newAppPasswordTestClient(t *testing.T, handler http.Handler) (*AppleAccountClient, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client, err := NewAppleAccountClient("owner@example.test")
	if err != nil {
		t.Fatal("create test Apple Account client:", err)
	}
	client.apiBase = "https://appleid.apple.com"
	client.apiKey = "test-api-key"
	client.portalSCNT = "test-scnt"

	localClient := server.Client()
	client.http = &http.Client{
		Jar:     client.jar,
		Timeout: time.Second,
		Transport: appPasswordRoundTripper(func(request *http.Request) (*http.Response, error) {
			localURL, parseErr := url.Parse(server.URL)
			if parseErr != nil {
				return nil, parseErr
			}
			mapped := *request.URL
			mapped.Scheme = localURL.Scheme
			mapped.Host = localURL.Host
			clone := request.Clone(request.Context())
			clone.URL = &mapped
			clone.Host = localURL.Host
			return localClient.Do(clone)
		}),
	}
	return client, server
}

func writeAppPasswordJSON(writer http.ResponseWriter, status int, body string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write([]byte(body))
}

func requireAppPasswordError(t *testing.T, err error, stage string, status int) *AppPasswordError {
	t.Helper()
	if err == nil {
		t.Fatal("expected an app-password error")
	}
	var appError *AppPasswordError
	if !errors.As(err, &appError) {
		t.Fatalf("error type=%T, want *AppPasswordError", err)
	}
	if appError.Stage != stage || appError.HTTPStatus != status {
		t.Fatalf("error=%+v, want stage=%q status=%d", appError, stage, status)
	}
	return appError
}

func TestListAppPasswordsUsesOnlyAuthenticatedGET(t *testing.T) {
	requests := 0
	client, _ := newAppPasswordTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodGet || request.URL.Path != appPasswordEndpoint {
			http.Error(writer, "unexpected request", http.StatusBadRequest)
			return
		}
		if request.Header.Get("X-Apple-Api-Key") != "test-api-key" ||
			request.Header.Get("scnt") != "test-scnt" {
			http.Error(writer, "missing management session", http.StatusUnauthorized)
			return
		}
		writeAppPasswordJSON(writer, http.StatusOK,
			"{\"data\":{\"passwords\":[{\"id\":17,\"description\":\"Mail client\",\"localizedCreateDate\":\"Nov 9, 2026\"},{\"id\":\"18\",\"description\":\"\",\"createDatetime\":1794240000}]}}")
	}))

	entries, err := client.ListAppPasswords(context.Background())
	if err != nil {
		t.Fatal("list app-specific passwords:", err)
	}
	if requests != 1 || len(entries) != 2 {
		t.Fatalf("requests=%d entries=%+v", requests, entries)
	}
	if entries[0].ID != "17" || entries[0].Description != "Mail client" || entries[0].CreatedAt != "Nov 9, 2026" {
		t.Fatalf("first entry=%+v", entries[0])
	}
	if entries[1].ID != "18" || entries[1].CreatedAt != "1794240000" {
		t.Fatalf("second entry=%+v", entries[1])
	}
}

func TestCreateAppPasswordPostsDescriptionAndReturnsPassword(t *testing.T) {
	requests := 0
	client, _ := newAppPasswordTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodPost || request.URL.Path != appPasswordEndpoint {
			http.Error(writer, "unexpected request", http.StatusBadRequest)
			return
		}
		var payload map[string]json.RawMessage
		if json.NewDecoder(request.Body).Decode(&payload) != nil || len(payload) != 1 {
			http.Error(writer, "unexpected request payload", http.StatusBadRequest)
			return
		}
		var description string
		if json.Unmarshal(payload["description"], &description) != nil || description != "Desktop Mail" {
			http.Error(writer, "description missing", http.StatusBadRequest)
			return
		}
		writeAppPasswordJSON(writer, http.StatusOK,
			"{\"id\":12345,\"description\":\"Desktop Mail\",\"createDatetime\":\"2026-11-09T12:00:00Z\",\"password\":\"abcd-efgh-ijkl-mnop\"}")
	}))

	result, err := client.CreateAppPassword(context.Background(), " Desktop Mail ", "")
	if err != nil {
		t.Fatal("create app-specific password:", err)
	}
	if requests != 1 || result.ID != "12345" || result.Description != "Desktop Mail" ||
		result.CreatedAt != "2026-11-09T12:00:00Z" || result.Password != "abcd-efgh-ijkl-mnop" {
		t.Fatalf("requests=%d result=%+v", requests, result)
	}
}

func TestCreateAppPasswordNormalizesUnseparatedPassword(t *testing.T) {
	client, _ := newAppPasswordTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeAppPasswordJSON(writer, http.StatusOK,
			"{\"id\":\"pw-1\",\"description\":\"Mail\",\"password\":\"abcdefghijklmnop\"}")
	}))
	result, err := client.CreateAppPassword(context.Background(), "Mail", "")
	if err != nil {
		t.Fatal("create app-specific password:", err)
	}
	if result.Password != "abcd-efgh-ijkl-mnop" {
		t.Fatalf("password=%q, want canonical four groups", result.Password)
	}
}

func TestCreateAppPasswordRetriesOnceAfterKnownPasswordChallenge(t *testing.T) {
	var requests []string
	client, _ := newAppPasswordTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests = append(requests, request.Method+" "+request.URL.Path)
		switch request.URL.Path {
		case appPasswordEndpoint:
			if request.Method != http.MethodPost {
				http.Error(writer, "wrong method", http.StatusBadRequest)
				return
			}
			if len(requests) == 1 {
				writeAppPasswordJSON(writer, http.StatusUnavailableForLegalReasons,
					"{\"formattedAccountName\":\"o***@example.test\"}")
				return
			}
			writeAppPasswordJSON(writer, http.StatusOK,
				"{\"id\":\"pw-1\",\"description\":\"Mail\",\"password\":\"abcd-efgh-ijkl-mnop\"}")
		case "/authenticate/password":
			if request.Method != http.MethodPost {
				http.Error(writer, "wrong method", http.StatusBadRequest)
				return
			}
			var payload map[string]string
			if json.NewDecoder(request.Body).Decode(&payload) != nil || payload["password"] != "test-main-password" {
				http.Error(writer, "wrong challenge payload", http.StatusBadRequest)
				return
			}
			writer.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(writer, request)
		}
	}))

	result, err := client.CreateAppPassword(context.Background(), "Mail", "test-main-password")
	if err != nil {
		t.Fatal("create app-specific password after challenge:", err)
	}
	want := []string{
		"POST " + appPasswordEndpoint,
		"POST /authenticate/password",
		"POST " + appPasswordEndpoint,
	}
	if !reflect.DeepEqual(requests, want) {
		t.Fatalf("request sequence=%v, want %v", requests, want)
	}
	if result.Password != "abcd-efgh-ijkl-mnop" {
		t.Fatalf("password=%q", result.Password)
	}
}

func TestCreateAppPasswordDoesNotTreatOnDemandTokenAsPasswordChallenge(t *testing.T) {
	passwordRequests := 0
	client, _ := newAppPasswordTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/authenticate/password" {
			passwordRequests++
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		writeAppPasswordJSON(writer, http.StatusUnavailableForLegalReasons,
			"{\"formattedAccountName\":\"o***@example.test\",\"onDemand2FAToken\":\"test-token\"}")
	}))

	_, err := client.CreateAppPassword(context.Background(), "Mail", "test-main-password")
	requireAppPasswordError(t, err, "verification_required", http.StatusUnavailableForLegalReasons)
	if passwordRequests != 0 {
		t.Fatalf("password challenge endpoint called %d times", passwordRequests)
	}
}

func TestCreateAppPasswordRequiresKnownChallengeShape(t *testing.T) {
	passwordRequests := 0
	client, _ := newAppPasswordTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/authenticate/password" {
			passwordRequests++
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		writeAppPasswordJSON(writer, http.StatusUnavailableForLegalReasons, "{}")
	}))

	_, err := client.CreateAppPassword(context.Background(), "Mail", "test-main-password")
	requireAppPasswordError(t, err, "unavailable", http.StatusUnavailableForLegalReasons)
	if passwordRequests != 0 {
		t.Fatalf("unrecognized 451 challenge caused %d password requests", passwordRequests)
	}
}

func TestCreateAppPasswordEmptyChallengePasswordDoesNotReverify(t *testing.T) {
	passwordRequests := 0
	createRequests := 0
	client, _ := newAppPasswordTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case appPasswordEndpoint:
			createRequests++
			writeAppPasswordJSON(writer, http.StatusUnavailableForLegalReasons,
				"{\"formattedAccountName\":\"o***@example.test\"}")
		case "/authenticate/password":
			passwordRequests++
			writer.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(writer, request)
		}
	}))

	_, err := client.CreateAppPassword(context.Background(), "Mail", "")
	requireAppPasswordError(t, err, "password_required", http.StatusUnavailableForLegalReasons)
	if createRequests != 1 || passwordRequests != 0 {
		t.Fatalf("create requests=%d password requests=%d", createRequests, passwordRequests)
	}
}

func TestListAppPasswordsDoesNotReverifyOn451(t *testing.T) {
	requests := 0
	client, _ := newAppPasswordTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodGet {
			http.Error(writer, "list request must be GET", http.StatusBadRequest)
			return
		}
		writeAppPasswordJSON(writer, http.StatusUnavailableForLegalReasons,
			"{\"formattedAccountName\":\"o***@example.test\"}")
	}))

	_, err := client.ListAppPasswords(context.Background())
	requireAppPasswordError(t, err, "password_required", http.StatusUnavailableForLegalReasons)
	if requests != 1 {
		t.Fatalf("list requests=%d", requests)
	}
}

func TestCreateAppPasswordStopsAfterRejectedPasswordChallenge(t *testing.T) {
	createRequests := 0
	passwordRequests := 0
	client, _ := newAppPasswordTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case appPasswordEndpoint:
			createRequests++
			writeAppPasswordJSON(writer, http.StatusUnavailableForLegalReasons,
				"{\"formattedAccountName\":\"o***@example.test\"}")
		case "/authenticate/password":
			passwordRequests++
			writeAppPasswordJSON(writer, http.StatusConflict, "{\"serviceErrors\":[{\"code\":\"-20101\"}]}")
		default:
			http.NotFound(writer, request)
		}
	}))

	_, err := client.CreateAppPassword(context.Background(), "Mail", "wrong-test-password")
	appError := requireAppPasswordError(t, err, "risk_blocked", http.StatusConflict)
	if strings.Contains(appError.Error(), "20101") || strings.Contains(appError.Error(), "wrong-test-password") {
		t.Fatalf("safe error leaked response or password: %q", appError.Error())
	}
	if createRequests != 1 || passwordRequests != 1 {
		t.Fatalf("create requests=%d password requests=%d", createRequests, passwordRequests)
	}
}

func TestCreateAppPasswordTransportTimeoutIsUnknownAndNotRetried(t *testing.T) {
	requests := 0
	client, _ := newAppPasswordTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writer.WriteHeader(http.StatusOK)
	}))
	client.http.Transport = appPasswordRoundTripper(func(request *http.Request) (*http.Response, error) {
		requests++
		return nil, context.DeadlineExceeded
	})

	_, err := client.CreateAppPassword(context.Background(), "Mail", "")
	requireAppPasswordError(t, err, "outcome_unknown", 0)
	if requests != 1 {
		t.Fatalf("create request retried %d times", requests)
	}
}

func TestCreateAppPasswordRiskAndTermsResponsesStop(t *testing.T) {
	for _, test := range []struct {
		name   string
		body   string
		stage  string
		status int
	}{
		{name: "forbidden", body: "forbidden", stage: "risk_blocked", status: http.StatusForbidden},
		{name: "locked", body: "{\"accountStatus\":\"locked\"}", stage: "risk_blocked", status: http.StatusBadRequest},
		{name: "terms", body: "{\"termsRequired\":true}", stage: "terms_required", status: http.StatusBadRequest},
		{name: "captcha", body: "{\"captchaRequired\":true,\"formattedAccountName\":\"o***@example.test\"}", stage: "unavailable", status: http.StatusUnavailableForLegalReasons},
	} {
		t.Run(test.name, func(t *testing.T) {
			authRequests := 0
			client, _ := newAppPasswordTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/authenticate/password" {
					authRequests++
					writer.WriteHeader(http.StatusNoContent)
					return
				}
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			}))
			_, err := client.CreateAppPassword(context.Background(), "Mail", "test-main-password")
			requireAppPasswordError(t, err, test.stage, test.status)
			if authRequests != 0 {
				t.Fatalf("challenge endpoint called %d times", authRequests)
			}
		})
	}
}

func TestCreateAppPasswordMissingOrMalformedPasswordIsOutcomeUnknown(t *testing.T) {
	for _, body := range []string{
		"{\"id\":\"pw-1\",\"description\":\"Mail\"}",
		"{\"id\":\"pw-1\",\"description\":\"Mail\",\"password\":\"abcd-efgh-ijkl-mno1\"}",
	} {
		client, _ := newAppPasswordTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writeAppPasswordJSON(writer, http.StatusOK, body)
		}))
		_, err := client.CreateAppPassword(context.Background(), "Mail", "")
		requireAppPasswordError(t, err, "outcome_unknown", http.StatusOK)
	}
}

func TestCreateAppPasswordRejectsInvalidDescriptionWithoutNetwork(t *testing.T) {
	requests := 0
	client, _ := newAppPasswordTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writeAppPasswordJSON(writer, http.StatusOK,
			"{\"id\":\"pw-1\",\"description\":\"Mail\",\"password\":\"abcd-efgh-ijkl-mnop\"}")
	}))
	for _, description := range []string{
		"",
		strings.Repeat("a", 65),
		"Mail\nClient",
	} {
		_, err := client.CreateAppPassword(context.Background(), description, "")
		requireAppPasswordError(t, err, "invalid_request", 0)
	}
	if requests != 0 {
		t.Fatalf("invalid descriptions caused %d requests", requests)
	}
}

func TestListAppPasswordsBoundsProjectedFieldsAndEntryCount(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{
			name: "id",
			body: []byte("{\"passwords\":[{\"id\":\"" + strings.Repeat("i", 129) + "\"}]}"),
		},
		{
			name: "description",
			body: []byte("{\"passwords\":[{\"id\":\"1\",\"description\":\"" + strings.Repeat("d", 257) + "\"}]}"),
		},
		{
			name: "created date",
			body: []byte("{\"passwords\":[{\"id\":\"1\",\"createDatetime\":\"" + strings.Repeat("t", 129) + "\"}]}"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, _ := newAppPasswordTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(http.StatusOK)
				_, _ = writer.Write(test.body)
			}))
			_, err := client.ListAppPasswords(context.Background())
			requireAppPasswordError(t, err, "unavailable", http.StatusOK)
		})
	}

	items := make([]map[string]string, 129)
	for index := range items {
		items[index] = map[string]string{"id": "id"}
	}
	body, err := json.Marshal(map[string]any{"passwords": items})
	if err != nil {
		t.Fatal("marshal bounded-list test body:", err)
	}
	client, _ := newAppPasswordTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(body)
	}))
	_, err = client.ListAppPasswords(context.Background())
	requireAppPasswordError(t, err, "unavailable", http.StatusOK)
}

func TestAppPasswordSessionExportRestoreAndValidation(t *testing.T) {
	client, _ := newAppPasswordTestClient(t, http.NotFoundHandler())
	client.portalSCNT = "session-scnt"
	for _, scope := range []string{"https://appleid.apple.com", "https://account.apple.com", "https://idmsa.apple.com"} {
		parsed, _ := url.Parse(scope)
		client.jar.SetCookies(parsed, []*http.Cookie{{Name: "session", Value: "opaque-session", Path: "/", Secure: true}})
	}
	apiOrigin, _ := url.Parse("https://appleid.apple.com")
	client.jar.SetCookies(apiOrigin, []*http.Cookie{{Name: "account-session", Value: "account-path-session", Path: "/account", Secure: true}})
	exported, err := client.ExportAccountSession()
	if err != nil {
		t.Fatal("export session:", err)
	}
	if strings.Contains(strings.ToLower(string(exported)), "password") {
		t.Fatalf("session export included a password field: %s", exported)
	}

	restored, err := NewAppleAccountClient("owner@example.test")
	if err != nil {
		t.Fatal("new restore client:", err)
	}
	if err := restored.RestoreAccountSession(exported); err != nil {
		t.Fatal("restore session:", err)
	}
	if restored.apiBase != "https://appleid.apple.com" || restored.apiKey != "test-api-key" ||
		restored.portalSCNT != "session-scnt" || restored.sessionPath != "" {
		t.Fatalf("restored client state=%+v", restored)
	}
	parsedOrigin, _ := url.Parse("https://appleid.apple.com/account/manage/security/secondary-password")
	cookies := restored.jar.Cookies(parsedOrigin)
	if len(cookies) != 2 || cookies[0].Name != "account-session" && cookies[1].Name != "account-session" {
		t.Fatalf("restored cookies=%v", cookies)
	}

	originalAPIBase := restored.apiBase
	originalAPIKey := restored.apiKey
	originalSCNT := restored.portalSCNT
	assertRejectedWithoutMutation := func(name string, payload []byte, appleID string) {
		t.Helper()
		target, newErr := NewAppleAccountClient(appleID)
		if newErr != nil {
			t.Fatal(newErr)
		}
		target.apiBase = originalAPIBase
		target.apiKey = originalAPIKey
		target.portalSCNT = originalSCNT
		beforeJar := target.jar
		err := target.RestoreAccountSession(payload)
		requireAppPasswordError(t, err, "session_required", 0)
		if target.apiBase != originalAPIBase || target.apiKey != originalAPIKey ||
			target.portalSCNT != originalSCNT || target.jar != beforeJar {
			t.Fatalf("%s failure partially changed the client", name)
		}
	}

	assertRejectedWithoutMutation("cross-account", exported, "other@example.test")

	var saved savedAppleAccountSession
	if err := json.Unmarshal(exported, &saved); err != nil {
		t.Fatal("decode exported test session:", err)
	}
	saved.APIBase = "https://evil.example"
	externalAPI, _ := json.Marshal(saved)
	assertRejectedWithoutMutation("external api base", externalAPI, "owner@example.test")

	saved.APIBase = "https://appleid.apple.com"
	saved.Cookies[0].Scope = "https://sub.appleid.apple.com"
	externalCookie, _ := json.Marshal(saved)
	assertRejectedWithoutMutation("external cookie scope", externalCookie, "owner@example.test")

	saved.Cookies[0].Scope = "https://user@appleid.apple.com"
	userInfoCookie, _ := json.Marshal(saved)
	assertRejectedWithoutMutation("userinfo cookie scope", userInfoCookie, "owner@example.test")

	saved.Cookies[0].Scope = "https://appleid.apple.com:8443"
	portCookie, _ := json.Marshal(saved)
	assertRejectedWithoutMutation("non-443 cookie port", portCookie, "owner@example.test")

	saved.Cookies[0].Scope = "https://appleid.apple.com?query=1"
	queryCookie, _ := json.Marshal(saved)
	assertRejectedWithoutMutation("cookie query", queryCookie, "owner@example.test")

	withPassword := append(append([]byte(nil), exported[:len(exported)-1]...), []byte(",\"password\":\"not-accepted\"}")...)
	rejectPassword, rejectErr := NewAppleAccountClient("owner@example.test")
	if rejectErr != nil {
		t.Fatal(rejectErr)
	}
	requireAppPasswordError(t, rejectPassword.RestoreAccountSession(withPassword), "invalid_request", 0)

	oversized := make([]byte, maxAppleAccountSessionBytes+1)
	requireAppPasswordError(t, restored.RestoreAccountSession(oversized), "invalid_request", 0)
}

func TestAppPasswordSessionRejectsUnsafeAPIBaseVariants(t *testing.T) {
	client, _ := newAppPasswordTestClient(t, http.NotFoundHandler())
	for _, raw := range []string{
		"http://appleid.apple.com",
		"https://appleid.apple.com:8443",
		"https://user@appleid.apple.com",
		"https://appleid.apple.com/path",
		"https://appleid.apple.com?query=1",
		"https://appleid.apple.com#fragment",
		"https://sub.appleid.apple.com",
	} {
		client.apiBase = raw
		if _, err := client.ExportAccountSession(); err == nil {
			t.Fatalf("export accepted unsafe API base %q", raw)
		}
	}
}
