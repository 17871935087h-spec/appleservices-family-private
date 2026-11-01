package v2gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const fakeVaultPassword = "fake-vault-password-for-tests-only"

func newCredentialTestGateway(t *testing.T, accounts []accountEntry, loader credentialLoader) (*Gateway, []accountEntry) {
	t.Helper()
	root := testRoot(t)
	for index := range accounts {
		accountDir := filepath.Join(root, "worker-"+accounts[index].ID)
		if err := os.MkdirAll(accountDir, 0700); err != nil {
			t.Fatal(err)
		}
		accounts[index].Dir = accountDir
	}
	registryData, err := json.Marshal(accountRegistry{Accounts: accounts})
	if err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(root, "accounts.json")
	if err := os.WriteFile(registryPath, registryData, 0600); err != nil {
		t.Fatal(err)
	}
	gateway, err := New(Config{
		ListenAddr:   DefaultListenAddr,
		DashboardURL: DefaultDashboard,
		RegistryPath: registryPath,
		IntentDir:    filepath.Join(root, "journal"),
		BearerToken:  testBearer,
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway.credentialLoader = loader
	t.Cleanup(gateway.Close)
	return gateway, accounts
}

func sendCredentialRequest(t *testing.T, gateway *Gateway, body string, authorization bool, origin, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, credentialEndpointPath, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if authorization {
		request.Header.Set("Authorization", "Bearer "+testBearer)
	}
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	if cookie != "" {
		request.Header.Set("Cookie", cookie)
	}
	response := httptest.NewRecorder()
	gateway.ServeHTTP(response, request)
	return response
}

func credentialRequestBody(t *testing.T, accountID, appleID string) string {
	t.Helper()
	data, err := json.Marshal(accountCredentialRequest{AccountID: accountID, AppleID: appleID})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestCredentialEndpointReturnsPasswordWithoutAccountIdentity(t *testing.T) {
	const accountID = "worker-01"
	const appleID = "Worker01@example.test"
	loaderCalls := 0
	var loadedDir, loadedAppleID string
	gateway, accounts := newCredentialTestGateway(t, []accountEntry{{ID: accountID, AppleID: appleID}}, func(accountDir, normalizedAppleID string) (string, error) {
		loaderCalls++
		loadedDir, loadedAppleID = accountDir, normalizedAppleID
		return fakeVaultPassword, nil
	})
	response := sendCredentialRequest(t, gateway, credentialRequestBody(t, accountID, strings.ToLower(appleID)), true, "", "")
	if response.Code != http.StatusOK {
		t.Fatalf("expected successful credential response, got %d", response.Code)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("credential response was cacheable: %q", response.Header().Get("Cache-Control"))
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &fields); err != nil {
		t.Fatalf("invalid response JSON: %v", err)
	}
	if len(fields) != 2 || fields["ok"] == nil || fields["password"] == nil {
		t.Fatalf("response contained unexpected fields: %#v", fields)
	}
	var reply accountCredentialReply
	if err := json.Unmarshal(response.Body.Bytes(), &reply); err != nil || !reply.OK || reply.Password != fakeVaultPassword {
		t.Fatalf("credential response did not contain the fake test password: %#v err=%v", reply, err)
	}
	if strings.Contains(response.Body.String(), accountID) || strings.Contains(strings.ToLower(response.Body.String()), strings.ToLower(appleID)) {
		t.Fatal("credential response leaked the account identity")
	}
	resolvedDir, err := filepath.EvalSymlinks(accounts[0].Dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaderCalls != 1 || loadedAppleID != strings.ToLower(appleID) || !sameCredentialPath(loadedDir, resolvedDir) {
		t.Fatalf("vault loader received an unexpected identity or directory: calls=%d", loaderCalls)
	}
}

func TestCredentialEndpointRejectsIdentityMismatchWithoutVaultRead(t *testing.T) {
	loaderCalls := 0
	gateway, _ := newCredentialTestGateway(t, []accountEntry{{ID: "worker-02", AppleID: "worker02@example.test"}}, func(string, string) (string, error) {
		loaderCalls++
		return fakeVaultPassword, nil
	})
	response := sendCredentialRequest(t, gateway, credentialRequestBody(t, "worker-02", "other@example.test"), true, "", "")
	if response.Code != http.StatusNotFound || loaderCalls != 0 {
		t.Fatalf("identity mismatch was not rejected before vault read: status=%d calls=%d", response.Code, loaderCalls)
	}
	if strings.Contains(response.Body.String(), "worker-02") || strings.Contains(response.Body.String(), "other@example.test") {
		t.Fatal("identity mismatch response leaked request identity")
	}
}

func TestCredentialEndpointRejectsDuplicateAppleIDWithoutVaultRead(t *testing.T) {
	loaderCalls := 0
	gateway, _ := newCredentialTestGateway(t, []accountEntry{
		{ID: "worker-03", AppleID: "duplicate@example.test"},
		{ID: "worker-04", AppleID: "Duplicate@Example.test"},
	}, func(string, string) (string, error) {
		loaderCalls++
		return fakeVaultPassword, nil
	})
	response := sendCredentialRequest(t, gateway, credentialRequestBody(t, "worker-03", "duplicate@example.test"), true, "", "")
	if response.Code != http.StatusNotFound || loaderCalls != 0 {
		t.Fatalf("duplicate AppleID was not rejected before vault read: status=%d calls=%d", response.Code, loaderCalls)
	}
	if strings.Contains(response.Body.String(), "duplicate@example.test") || strings.Contains(response.Body.String(), "worker-03") {
		t.Fatal("duplicate AppleID response leaked account identity")
	}
}

func TestCredentialEndpointRequiresAuthentication(t *testing.T) {
	loaderCalls := 0
	gateway, _ := newCredentialTestGateway(t, []accountEntry{{ID: "worker-05", AppleID: "worker05@example.test"}}, func(string, string) (string, error) {
		loaderCalls++
		return fakeVaultPassword, nil
	})
	response := sendCredentialRequest(t, gateway, credentialRequestBody(t, "worker-05", "worker05@example.test"), false, "", "")
	if response.Code != http.StatusUnauthorized || loaderCalls != 0 {
		t.Fatalf("unauthenticated request was not rejected before vault read: status=%d calls=%d", response.Code, loaderCalls)
	}
}

func TestCredentialEndpointRejectsOriginAndCookie(t *testing.T) {
	for _, test := range []struct {
		name   string
		origin string
		cookie string
	}{
		{name: "origin", origin: "http://example.test"},
		{name: "cookie", cookie: "session=fake"},
	} {
		t.Run(test.name, func(t *testing.T) {
			loaderCalls := 0
			gateway, _ := newCredentialTestGateway(t, []accountEntry{{ID: "worker-06", AppleID: "worker06@example.test"}}, func(string, string) (string, error) {
				loaderCalls++
				return fakeVaultPassword, nil
			})
			response := sendCredentialRequest(t, gateway, credentialRequestBody(t, "worker-06", "worker06@example.test"), true, test.origin, test.cookie)
			if response.Code != http.StatusForbidden || loaderCalls != 0 {
				t.Fatalf("browser-originated request was not rejected before vault read: status=%d calls=%d", response.Code, loaderCalls)
			}
		})
	}
}

func TestCredentialEndpointDoesNotLeakVaultError(t *testing.T) {
	const accountID = "worker-07"
	const appleID = "worker07@example.test"
	internalDetail := "private-vault-error-" + fakeVaultPassword + "-" + appleID
	gateway, _ := newCredentialTestGateway(t, []accountEntry{{ID: accountID, AppleID: appleID}}, func(string, string) (string, error) {
		return "", errors.New(internalDetail)
	})
	response := sendCredentialRequest(t, gateway, credentialRequestBody(t, accountID, appleID), true, "", "")
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected generic vault failure, got %d", response.Code)
	}
	for _, privateValue := range []string{internalDetail, fakeVaultPassword, accountID, appleID} {
		if strings.Contains(response.Body.String(), privateValue) {
			t.Fatal("vault error response leaked private details")
		}
	}
}

func TestCredentialEndpointRejectsDirectoryInRequest(t *testing.T) {
	loaderCalls := 0
	gateway, _ := newCredentialTestGateway(t, []accountEntry{{ID: "worker-08", AppleID: "worker08@example.test"}}, func(string, string) (string, error) {
		loaderCalls++
		return fakeVaultPassword, nil
	})
	requestBody := `{"account_id":"worker-08","apple_id":"worker08@example.test","account_dir":"D:\\private"}`
	response := sendCredentialRequest(t, gateway, requestBody, true, "", "")
	if response.Code != http.StatusBadRequest || loaderCalls != 0 {
		t.Fatalf("request-supplied directory was not rejected: status=%d calls=%d", response.Code, loaderCalls)
	}
	if runtime.GOOS == "windows" && strings.Contains(response.Body.String(), `D:\private`) {
		t.Fatal("request error echoed the supplied directory")
	}
}

func sameCredentialPath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}
