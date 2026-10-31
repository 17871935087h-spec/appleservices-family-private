package icloud

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestHideMyEmailLifecycleBindsCurrentAlias(t *testing.T) {
	var mu sync.Mutex
	active := true
	selectedForward := "primary@example.test"
	paths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("dsid") != "123" || r.URL.Query().Get("clientBuildNumber") != hmeBuildNumber {
			http.Error(w, `{"success":false}`, http.StatusBadRequest)
			return
		}
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2/hme/list":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"forwardToEmails": []string{"primary@example.test", "backup@example.test"}, "selectedForwardTo": selectedForward, "hmeEmails": []map[string]any{{"hme": "alias@icloud.com", "label": "shop", "note": "test", "isActive": active, "anonymousId": "private-id", "forwardToEmail": selectedForward}}}})
		case "/v1/hme/generate":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"hme": "candidate@icloud.com"}})
		case "/v1/hme/reserve", "/v1/hme/updateMetaData", "/v1/hme/reactivate", "/v1/hme/delete":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{}})
		case "/v1/hme/updateForwardTo":
			var request map[string]string
			if json.NewDecoder(r.Body).Decode(&request) != nil || request["forwardToEmail"] != "backup@example.test" {
				t.Fatal("forward target request was not bound to the selected address")
			}
			selectedForward = request["forwardToEmail"]
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{}})
		case "/v1/hme/deactivate":
			active = false
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	client := &HideMyEmailClient{
		appleID:     "member@example.test",
		sessionPath: filepath.Join(t.TempDir(), "hme-session.json"),
		http:        server.Client(),
		jar:         jar,
		session:     hmeSession{AppleID: "member@example.test", DSID: "123", ClientID: "client", ServiceURL: server.URL},
	}
	client.http.Jar = jar
	ctx := context.Background()
	info, err := client.List(ctx)
	if err != nil || info.ActiveCount != 1 || len(info.Aliases) != 1 || info.Aliases[0].anonymousID != "private-id" || info.SelectedForward != "primary@example.test" || len(info.ForwardToEmails) != 2 {
		t.Fatalf("unexpected list info=%#v err=%v", info, err)
	}
	candidate, err := client.Generate(ctx, "zh-cn")
	if err != nil || candidate != "candidate@icloud.com" {
		t.Fatalf("unexpected candidate=%q err=%v", candidate, err)
	}
	if err := client.Reserve(ctx, candidate, "label", "note"); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateForwardTo(ctx, "unverified@example.test"); err == nil {
		t.Fatal("unverified forwarding target was accepted")
	}
	if err := client.UpdateForwardTo(ctx, "backup@example.test"); err != nil {
		t.Fatal(err)
	}
	forwarded, err := client.List(ctx)
	if err != nil || forwarded.SelectedForward != "backup@example.test" || forwarded.Aliases[0].ForwardToEmail != "backup@example.test" {
		t.Fatalf("forwarding change was not verified: %#v err=%v", forwarded, err)
	}
	if err := client.Update(ctx, "alias@icloud.com", "updated", "updated note"); err != nil {
		t.Fatal(err)
	}
	if err := client.Delete(ctx, "alias@icloud.com"); err == nil {
		t.Fatal("active alias was deleted")
	}
	if err := client.SetActive(ctx, "alias@icloud.com", false); err != nil {
		t.Fatal(err)
	}
	if err := client.Delete(ctx, "alias@icloud.com"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) < 8 || paths[len(paths)-1] != "/v1/hme/delete" {
		t.Fatalf("unexpected request paths %v", paths)
	}
}

func TestHideMyEmailSafeAliasOmitsPrivateIdentifier(t *testing.T) {
	data, err := json.Marshal(HideMyEmailAlias{Email: "alias@icloud.com", anonymousID: "private-id"})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"email":"alias@icloud.com","active":false}` {
		t.Fatalf("private identifier leaked in %s", data)
	}
}

func TestValidateHMEWebCookiesExplainsRepairState(t *testing.T) {
	if err := validateHMEWebCookies([]*http.Cookie{{Name: "X-APPLE-WEBAUTH-TOKEN", Value: "token"}}); err != nil {
		t.Fatal(err)
	}
	err := validateHMEWebCookies([]*http.Cookie{{Name: "X-APPLE-WEBAUTH-REPAIR", Value: "repair"}})
	if !errors.Is(err, ErrHMEWebRepairRequired) {
		t.Fatalf("repair state was not explained: %v", err)
	}
}

func TestAcceptHMEWebTermsUsesAdvertisedVersion(t *testing.T) {
	var accepted int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/getTerms":
			if r.Method != http.MethodGet {
				t.Fatalf("getTerms method = %s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"iCloudTerms": map[string]any{"version": 634301}})
		case "/repairDone":
			if r.Method != http.MethodGet {
				t.Fatalf("repairDone method = %s", r.Method)
			}
			var body struct {
				Accepted int `json:"acceptedICloudTerms"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Fatal("repairDone body was not valid JSON")
			}
			accepted = body.Accepted
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	client := &HideMyEmailClient{http: server.Client(), jar: jar}
	if err := client.acceptHMEWebTerms(context.Background(), server.URL, "zh-cn"); err != nil {
		t.Fatal(err)
	}
	if accepted != 634301 {
		t.Fatalf("accepted terms version = %d", accepted)
	}
}

func TestAcceptPendingTermsRequiresRepairCookie(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	client := &HideMyEmailClient{setupBase: "https://setup.icloud.com/setup/ws/1", http: http.DefaultClient, jar: jar}
	if err := client.AcceptPendingTerms(context.Background()); !errors.Is(err, ErrHMEWebRepairSessionUnavailable) {
		t.Fatalf("missing repair session was not rejected: %v", err)
	}
}

func TestHMESetupFailureReportsStatusWithoutAuthenticatedData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "private-cookie=private-cookie-value")
		w.WriteHeader(http.StatusMisdirectedRequest)
		_, _ = w.Write([]byte(`{"token":"private-response-token"}`))
	}))
	defer server.Close()
	client := &HideMyEmailClient{http: server.Client()}
	data, err := client.hmeSetupRequest(context.Background(), http.MethodPost, server.URL+"/accountLogin?dsid=private-account", []byte(`{"dsWebAuthToken":"private-request-token"}`))
	var setup *HMEWebSetupError
	if !errors.As(err, &setup) || setup.HTTPStatus != http.StatusMisdirectedRequest || setup.FailureKind != "http" || data != nil {
		t.Fatalf("setup rejection lost its classification: %v", err)
	}
	for _, private := range []string{server.URL, "private-account", "private-response-token", "private-request-token", "private-cookie-value"} {
		if strings.Contains(err.Error(), private) {
			t.Fatal("setup diagnostic leaked authenticated data")
		}
	}
}

func TestHMEAccountLoginPreservesSetupFailure(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/accountLogin" {
			t.Errorf("unexpected setup request path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	client := &HideMyEmailClient{setupBase: server.URL, http: server.Client()}
	err := client.accountLogin(context.Background(), &hmeAuthState{sessionToken: "private-token", accountCountry: "USA"}, false)
	var setup *HMEWebSetupError
	if !errors.As(err, &setup) || setup.HTTPStatus != http.StatusUnauthorized || requests != 1 {
		t.Fatalf("accountLogin hid or retried the setup rejection: %v", err)
	}
	if !strings.Contains(err.Error(), "session establishment failed") || strings.Contains(err.Error(), "private-token") {
		t.Fatal("accountLogin diagnostic lost context or exposed the token")
	}
}

type hmeTimeoutTransport struct{}

func (hmeTimeoutTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, context.DeadlineExceeded
}

func TestHMESetupTimeoutOmitsRequestURL(t *testing.T) {
	client := &HideMyEmailClient{http: &http.Client{Transport: hmeTimeoutTransport{}}}
	_, err := client.hmeSetupRequest(context.Background(), http.MethodPost, "https://setup.example.test/accountLogin?token=private-token", nil)
	var setup *HMEWebSetupError
	if !errors.As(err, &setup) || setup.FailureKind != "timeout" || setup.HTTPStatus != 0 {
		t.Fatalf("setup timeout was not classified: %v", err)
	}
	if strings.Contains(err.Error(), "example.test") || strings.Contains(err.Error(), "private-token") {
		t.Fatal("transport diagnostic exposed the request URL")
	}
}

type hmeRoundTripFunc func(*http.Request) (*http.Response, error)

func (f hmeRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestHMESetupRegionalRedirectPreservesPostAndCookieJar(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	body := `{"dsWebAuthToken":"fixture-token"}`
	calls := 0
	client := &HideMyEmailClient{jar: jar}
	client.http = &http.Client{Jar: jar, Transport: hmeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		data, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || string(data) != body || r.Header.Get("Origin") != "https://www.icloud.com" {
			t.Fatal("regional redirect changed the authenticated request")
		}
		response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Request: r}
		if calls == 1 {
			response.StatusCode = http.StatusFound
			response.Header.Set("Location", "https://p123-setup.icloud.com/setup/ws/1/accountLogin")
			response.Header.Add("Set-Cookie", "setup-route=fixture; Domain=.icloud.com; Path=/; Secure")
		} else if calls == 2 {
			if r.URL.Hostname() != "p123-setup.icloud.com" {
				t.Fatal("redirect destination was ignored")
			}
			cookie, err := r.Cookie("setup-route")
			if err != nil || cookie.Value != "fixture" {
				t.Fatal("regional setup lost its account-bound cookies")
			}
		} else {
			t.Fatal("setup redirected more than once")
		}
		return response, nil
	})}
	data, err := client.hmeSetupRequest(context.Background(), http.MethodPost, "https://setup.icloud.com/setup/ws/1/accountLogin", []byte(body))
	if err != nil || string(data) != `{"ok":true}` || calls != 2 || client.setupBase != "https://p123-setup.icloud.com/setup/ws/1" {
		t.Fatalf("regional setup did not complete: %v", err)
	}
}

func TestHMESetupRedirectTargetRejectsCredentialForwarding(t *testing.T) {
	current, _ := url.Parse("https://setup.icloud.com/setup/ws/1/accountLogin")
	for _, target := range []string{
		"https://setup.icloud.com.cn/setup/ws/1/accountLogin",
		"https://p42-setup.icloud.com/setup/ws/1/accountLogin",
		"/setup/ws/1/accountLogin?region=cn",
	} {
		if _, err := hmeSetupRedirectTarget(current, target); err != nil {
			t.Fatalf("valid setup route was rejected: %v", err)
		}
	}
	for _, target := range []string{
		"http://setup.icloud.com/setup/ws/1/accountLogin",
		"https://setup.icloud.com.evil.test/setup/ws/1/accountLogin",
		"https://arbitrary.icloud.com/setup/ws/1/accountLogin",
		"https://setup.icloud.com:8443/setup/ws/1/accountLogin",
		"https://user:secret@setup.icloud.com/setup/ws/1/accountLogin",
		"https://setup.icloud.com/setup/ws/1/repairDone",
		"https://www.icloud.com/",
		"",
	} {
		if _, err := hmeSetupRedirectTarget(current, target); err == nil {
			t.Fatal("unrecognized redirect accepted authenticated setup data")
		}
	}
}

func TestHMESetupRedirectLimitAndExternalLocationDoNotLeak(t *testing.T) {
	for _, test := range []struct {
		location, kind string
		requests       int
	}{
		{"https://external.example.test/path?token=private-token", "unrecognized-redirect", 1},
		{"https://setup.icloud.com/setup/ws/1/accountLogin?route=loop", "redirect-limit", 2},
	} {
		calls := 0
		client := &HideMyEmailClient{http: &http.Client{Transport: hmeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{test.location}}, Body: io.NopCloser(strings.NewReader("private-response-body")), Request: r}, nil
		})}}
		_, err := client.hmeSetupRequest(context.Background(), http.MethodPost, "https://setup.icloud.com/setup/ws/1/accountLogin", []byte("private-request"))
		var setup *HMEWebSetupError
		if !errors.As(err, &setup) || setup.FailureKind != test.kind || setup.HTTPStatus != http.StatusFound || calls != test.requests {
			t.Fatalf("redirect was not bounded: %v, requests=%d", err, calls)
		}
		if strings.Contains(err.Error(), "private-") || strings.Contains(err.Error(), "external.example.test") {
			t.Fatal("redirect diagnostic leaked authenticated data")
		}
	}
}

func TestHMEAccountLoginRedirectKeepsFinalRegionAndRequiresTermsConsent(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	calls := 0
	client := &HideMyEmailClient{setupBase: "https://setup.icloud.com/setup/ws/1", jar: jar}
	client.http = &http.Client{Jar: jar, Transport: hmeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/setup/ws/1/accountLogin" {
			t.Fatal("redirect attempted a terms mutation or changed the setup method")
		}
		response := &http.Response{StatusCode: http.StatusFound, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}
		switch calls {
		case 1:
			response.Header.Set("Location", "https://setup.icloud.com.cn/setup/ws/1/accountLogin")
		case 2:
			response.Header.Set("Location", "https://p42-setup.icloud.com.cn/setup/ws/1/accountLogin")
		case 3:
			response.StatusCode = http.StatusOK
			response.Body = io.NopCloser(strings.NewReader(`{"dsInfo":{"dsid":"fixture"},"termsUpdateNeeded":true}`))
		default:
			t.Fatal("terms were accepted without a separate user action")
		}
		return response, nil
	})}
	err := client.accountLogin(context.Background(), &hmeAuthState{sessionToken: "fixture", accountCountry: "USA"}, false)
	if !errors.Is(err, ErrHMEWebRepairRequired) || calls != 3 || client.setupBase != "https://p42-setup.icloud.com.cn/setup/ws/1" {
		t.Fatalf("redirect lost its final region or accepted terms implicitly: %v", err)
	}
}
