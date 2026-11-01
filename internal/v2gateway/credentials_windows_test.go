//go:build windows

package v2gateway

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Laky-64/appleservices/internal/credentialvault"
)

func TestCredentialEndpointWindowsVaultRoundTripAndIdentityIsolation(t *testing.T) {
	root := newCredentialWindowsTempRoot(t)
	accountDirA := filepath.Join(root, "account-a")
	accountDirB := filepath.Join(root, "account-b")
	for _, accountDir := range []string{accountDirA, accountDirB} {
		if err := os.MkdirAll(accountDir, 0700); err != nil {
			t.Fatal(err)
		}
	}

	const (
		accountIDA = "vault-test-a"
		accountIDB = "vault-test-b"
		appleIDA   = "vault-test-a@example.test"
		appleIDB   = "vault-test-b@example.test"
		passwordA  = "synthetic-test-password-a"
		passwordB  = "synthetic-test-password-b"
	)
	if err := credentialvault.Save(accountDirA, appleIDA, passwordA); err != nil {
		t.Fatalf("save synthetic test credential A: %v", err)
	}
	if err := credentialvault.Save(accountDirB, appleIDB, passwordB); err != nil {
		t.Fatalf("save synthetic test credential B: %v", err)
	}

	registryData, err := json.Marshal(accountRegistry{Accounts: []accountEntry{
		{ID: accountIDA, Name: "synthetic A", AppleID: appleIDA, Dir: accountDirA},
		{ID: accountIDB, Name: "synthetic B", AppleID: appleIDB, Dir: accountDirB},
	}})
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
		IntentDir:    filepath.Join(root, "intent-journal"),
		BearerToken:  testBearer,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gateway.Close)

	for _, expected := range []struct {
		accountID string
		appleID   string
		password  string
	}{
		{accountID: accountIDA, appleID: appleIDA, password: passwordA},
		{accountID: accountIDB, appleID: appleIDB, password: passwordB},
	} {
		body, err := json.Marshal(accountCredentialRequest{AccountID: expected.accountID, AppleID: expected.appleID})
		if err != nil {
			t.Fatal(err)
		}
		response := gatewayRequest(t, gateway, credentialEndpointPath, string(body))
		if response.Code != http.StatusOK {
			t.Fatalf("credential request returned status %d", response.Code)
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("credential response cache policy was %q", response.Header().Get("Cache-Control"))
		}
		var reply accountCredentialReply
		if err := json.Unmarshal(response.Body.Bytes(), &reply); err != nil || !reply.OK || reply.Password != expected.password {
			t.Fatalf("credential response did not match its synthetic account: err=%v", err)
		}
		if strings.Contains(response.Body.String(), expected.accountID) || strings.Contains(response.Body.String(), expected.appleID) {
			t.Fatal("credential response leaked the synthetic account identity")
		}
	}

	// The registry binding rejects cross-account requests before loading either vault.
	crossBody, err := json.Marshal(accountCredentialRequest{AccountID: accountIDA, AppleID: appleIDB})
	if err != nil {
		t.Fatal(err)
	}
	crossResponse := gatewayRequest(t, gateway, credentialEndpointPath, string(crossBody))
	if crossResponse.Code != http.StatusNotFound {
		t.Fatalf("cross-account request returned status %d", crossResponse.Code)
	}
	for _, privateValue := range []string{accountIDA, accountIDB, appleIDA, appleIDB, passwordA, passwordB} {
		if strings.Contains(crossResponse.Body.String(), privateValue) {
			t.Fatal("cross-account response leaked identity or credential data")
		}
	}

	// DPAPI entropy binds the saved ciphertext to its normalized AppleID as well.
	wrongPassword, wrongIdentityErr := credentialvault.Load(accountDirA, appleIDB)
	if wrongIdentityErr == nil || wrongPassword != "" {
		t.Fatal("vault loaded a credential with a different AppleID")
	}
}

func newCredentialWindowsTempRoot(t *testing.T) string {
	t.Helper()
	base := `D:\DevData\test-runs`
	if !strings.EqualFold(filepath.VolumeName(base), `D:`) {
		t.Fatal("credential end-to-end test root is not on D:")
	}
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatalf("create D-drive test root: %v", err)
	}
	root, err := os.MkdirTemp(base, "v2gateway-credential-e2e-")
	if err != nil {
		t.Fatalf("create D-drive account fixture: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || !strings.EqualFold(filepath.VolumeName(resolved), `D:`) {
		_ = os.Remove(root)
		t.Fatal("credential end-to-end fixture did not resolve to D:")
	}
	t.Cleanup(func() {
		resolved, err := filepath.EvalSymlinks(root)
		if err == nil && strings.EqualFold(filepath.VolumeName(resolved), `D:`) {
			_ = os.RemoveAll(root)
		}
	})
	return filepath.Clean(resolved)
}
