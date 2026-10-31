package v2gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testBearer = "0123456789abcdef0123456789abcdef"
	testAppKey = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	storage50  = int64(50 << 30)
)

type fakeDashboard struct {
	server          *httptest.Server
	mu              sync.Mutex
	calls           []dashboardActionCall
	root            int
	addReady        bool
	credentialReady bool
	handle          func(http.ResponseWriter, *http.Request, dashboardActionCall)
}

type dashboardActionCall struct {
	Account string
	Action  dashboardAction
}

func newFakeDashboard(t *testing.T, handler func(http.ResponseWriter, *http.Request, dashboardActionCall)) *fakeDashboard {
	t.Helper()
	fake := &fakeDashboard{handle: handler, addReady: true, credentialReady: true}
	fake.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			fake.mu.Lock()
			fake.root++
			fake.mu.Unlock()
			_, _ = io.WriteString(w, `<html><head><meta name="app-token" content="`+testAppKey+`"></head></html>`)
			return
		}
		if r.URL.Path != "/api/action" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-App-Token") != testAppKey || r.Header.Get("Cookie") != "" || r.Header.Get("Origin") != "" {
			http.Error(w, "private dashboard auth failure", http.StatusForbidden)
			return
		}
		var action dashboardAction
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&action) != nil {
			http.Error(w, "invalid action", http.StatusBadRequest)
			return
		}
		call := dashboardActionCall{Account: r.URL.Query().Get("account"), Action: action}
		fake.mu.Lock()
		fake.calls = append(fake.calls, call)
		addReady := fake.addReady
		fake.mu.Unlock()
		if action.Action == "family-add-readiness" {
			if addReady {
				writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-add-ready"})
			} else {
				writeDashboardResult(w, dashboardResult{OK: false, Stage: "family-worker-unready"})
			}
			return
		}
		if action.Action == "family-add-credential-readiness" {
			fake.mu.Lock()
			ready := fake.credentialReady
			fake.mu.Unlock()
			if ready {
				writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-add-credential-ready"})
			} else {
				writeDashboardResult(w, dashboardResult{OK: false, Stage: "family-worker-unready"})
			}
			return
		}
		fake.handle(w, r, call)
	}))
	t.Cleanup(fake.server.Close)
	return fake
}

func TestAddRejectsPasswordlessWorkerBeforeIntent(t *testing.T) {
	registryPath := testRegistry(t, registryFixture())
	fake := newFakeDashboard(t, func(http.ResponseWriter, *http.Request, dashboardActionCall) {
		t.Error("unready worker reached family reads or mutation")
	})
	fake.addReady = false
	intentDir := filepath.Join(testRoot(t), "unready-journal")
	g := testGateway(t, fake, registryPath, intentDir, 500*time.Millisecond)
	response := gatewayRequest(t, g, "/v1/family/add", `{"organizer_account_id":"org-01","target_account_id":"target-02","operation_id":"unready-001"}`)
	reply := decodeGatewayResponse[familyReply](t, response)
	if response.Code != http.StatusConflict || reply.OK || reply.Stage != "family-worker-unready" {
		t.Fatalf("unready worker was not rejected: %d %#v", response.Code, reply)
	}
	entries, err := os.ReadDir(intentDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("unready worker created an intent: entries=%d err=%v", len(entries), err)
	}
}

func (fake *fakeDashboard) snapshot() ([]dashboardActionCall, int) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([]dashboardActionCall(nil), fake.calls...), fake.root
}

func testRoot(t *testing.T) string {
	t.Helper()
	base := os.TempDir()
	if runtime.GOOS == "windows" && !strings.EqualFold(filepath.VolumeName(base), `D:`) {
		t.Fatal("test temporary root must be on D:")
	}
	root, err := os.MkdirTemp(base, "v2gateway-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

func testRegistry(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(testRoot(t), "accounts.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testGateway(t *testing.T, fake *fakeDashboard, registryPath, intentDir string, timeout time.Duration) *Gateway {
	t.Helper()
	if intentDir == "" {
		intentDir = filepath.Join(testRoot(t), "intent-journal")
	}
	gateway, err := New(Config{ListenAddr: DefaultListenAddr, DashboardURL: fake.server.URL, RegistryPath: registryPath, IntentDir: intentDir, BearerToken: testBearer, RequestTimeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gateway.Close)
	return gateway
}

func registryFixture() string {
	return `{"accounts":[{"id":"org-01","name":"organizer","apple_id":"Organizer@Example.test","dir":"D:\\service\\accounts\\org-01","created_at":"2026-01-01T00:00:00Z"},{"id":"target-02","name":"target","apple_id":"target@example.test","dir":"D:\\service\\accounts\\target-02"},{"id":"member-03","name":"member 3","apple_id":"member3@example.test","dir":"D:\\service\\accounts\\member-03"},{"id":"member-04","name":"member 4","apple_id":"member4@example.test","dir":"D:\\service\\accounts\\member-04"},{"id":"member-05","name":"member 5","apple_id":"member5@example.test","dir":"D:\\service\\accounts\\member-05"}]}`
}

func familyPoolFixture(members []familyPoolMember, unmapped, total int) *familyPoolProjection {
	return &familyPoolProjection{Members: members, UnmappedCount: unmapped, TotalCount: total}
}

func familyFixture(member, organizer bool, members, organizers, self int, eligibleKnown, eligible bool, storageKnown, participating, available, enabled bool, storageBytes int64) *dashboardFamily {
	return &dashboardFamily{Member: member, Eligible: eligible, EligibilityKnown: eligibleKnown, Members: members, Organizers: organizers, Self: self, Children: 0, Invitations: 0, Pending: 0, Organizer: organizer, OrganizerAccount: "private-local-organizer", OrganizerName: "private@example.test", StorageKnown: storageKnown, StorageParticipating: participating, StorageAvailable: available, StorageEnabled: enabled, StorageBytes: storageBytes, PurchaseSharingKnown: true, PurchaseSharingEnabled: false, LocationSharingKnown: true, LocationSharingEnabled: false}
}

func writeDashboardResult(w http.ResponseWriter, result dashboardResult) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func gatewayRequest(t *testing.T, g *Gateway, path string, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+testBearer)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	g.ServeHTTP(response, request)
	return response
}

func decodeGatewayResponse[T any](t *testing.T, response *httptest.ResponseRecorder) T {
	t.Helper()
	var result T
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestAuthorizationStrictJSONAndResolveDoesNotExposeIdentity(t *testing.T) {
	registryPath := testRegistry(t, registryFixture())
	fake := newFakeDashboard(t, func(w http.ResponseWriter, _ *http.Request, _ dashboardActionCall) {
		t.Error("resolve must not call dashboard")
	})
	g := testGateway(t, fake, registryPath, "", 200*time.Millisecond)

	unauthorized := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(`{"apple_id":"target@example.test"}`))
	unauthorized.Header.Set("Authorization", "Bearer wrong")
	unauthorized.Header.Set("Content-Type", "application/json")
	unauthorizedResponse := httptest.NewRecorder()
	g.ServeHTTP(unauthorizedResponse, unauthorized)
	if unauthorizedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorizedResponse.Code)
	}

	badJSON := gatewayRequest(t, g, "/v1/resolve", `{"apple_id":"target@example.test","password":"not-accepted"}`)
	if badJSON.Code != http.StatusBadRequest || strings.Contains(badJSON.Body.String(), "not-accepted") {
		t.Fatalf("unknown request field was not rejected safely: %d %s", badJSON.Code, badJSON.Body.String())
	}

	request := gatewayRequest(t, g, "/v1/resolve", `{"apple_id":" TARGET@EXAMPLE.TEST "}`)
	if request.Code != http.StatusOK {
		t.Fatalf("resolve status = %d: %s", request.Code, request.Body.String())
	}
	resolved := decodeGatewayResponse[resolveReply](t, request)
	if !resolved.OK || resolved.AccountID != "target-02" || strings.Contains(request.Body.String(), "target@example.test") {
		t.Fatalf("unexpected resolve response: %s", request.Body.String())
	}
	calls, roots := fake.snapshot()
	if len(calls) != 0 || roots != 0 {
		t.Fatalf("resolve unexpectedly called dashboard: calls=%d roots=%d", len(calls), roots)
	}
}

func TestResolveRejectsAmbiguousIdentityAndCredentialRegistry(t *testing.T) {
	ambiguous := `{"accounts":[{"id":"org-01","apple_id":"same@example.test","name":"a","dir":"D:\\a"},{"id":"target-02","apple_id":"SAME@example.test","name":"b","dir":"D:\\b"}]}`
	fake := newFakeDashboard(t, func(w http.ResponseWriter, _ *http.Request, _ dashboardActionCall) {})
	g := testGateway(t, fake, testRegistry(t, ambiguous), "", 200*time.Millisecond)
	response := gatewayRequest(t, g, "/v1/resolve", `{"apple_id":"same@example.test"}`)
	if response.Code != http.StatusConflict || strings.Contains(response.Body.String(), "same@example.test") {
		t.Fatalf("ambiguous Apple ID was not rejected safely: %d %s", response.Code, response.Body.String())
	}

	launcherFile := `[{"name":"primary","apple_id":"secret@example.test","password":"do-not-read"}]`
	other := testGateway(t, fake, testRegistry(t, launcherFile), filepath.Join(testRoot(t), "other-journal"), 200*time.Millisecond)
	badRegistry := gatewayRequest(t, other, "/v1/resolve", `{"apple_id":"secret@example.test"}`)
	if badRegistry.Code != http.StatusServiceUnavailable || strings.Contains(badRegistry.Body.String(), "do-not-read") || strings.Contains(badRegistry.Body.String(), "secret@example.test") {
		t.Fatalf("credential launcher file was not rejected safely: %d %s", badRegistry.Code, badRegistry.Body.String())
	}
}

func TestFamilyReadNormalizesStageAndRedactsDashboardDetails(t *testing.T) {
	registryPath := testRegistry(t, registryFixture())
	family := familyFixture(true, true, 2, 1, 1, true, true, true, true, true, true, storage50)
	fake := newFakeDashboard(t, func(w http.ResponseWriter, _ *http.Request, call dashboardActionCall) {
		if call.Account != "target-02" || call.Action.Action != "family-info-direct" || call.Action.Code != "" {
			t.Errorf("wrong read action: %#v", call)
		}
		writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-cache-warning", Message: json.RawMessage(`"secret@example.test raw-token-value"`), Family: family})
	})
	g := testGateway(t, fake, registryPath, "", 200*time.Millisecond)
	response := gatewayRequest(t, g, "/v1/family/read", `{"account_id":"target-02"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("read status = %d: %s", response.Code, response.Body.String())
	}
	read := decodeGatewayResponse[familyReply](t, response)
	if !read.OK || read.Stage != "family-read" || read.Message != safeReadMessage || read.Family == nil || !read.Family.Member || !read.Family.StorageEnabled {
		t.Fatalf("unexpected family response: %#v", read)
	}
	for _, secret := range []string{"secret@example.test", "raw-token-value", "private-local-organizer", "private@example.test", "storage_bytes"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatalf("family response leaked %q: %s", secret, response.Body.String())
		}
	}
}

func TestFamilyPoolReturnsOnlyExactOpaqueProjection(t *testing.T) {
	registryPath := testRegistry(t, registryFixture())
	projection := familyPoolFixture([]familyPoolMember{{AccountID: "org-01", Organizer: true}, {AccountID: "target-02", Child: true}}, 1, 3)
	fake := newFakeDashboard(t, func(w http.ResponseWriter, _ *http.Request, call dashboardActionCall) {
		if call.Account != "org-01" || call.Action.Action != "family-pool" || call.Action.Code != "" {
			t.Errorf("wrong family-pool action: %#v", call)
		}
		writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-pool", Message: json.RawMessage(`"Organizer@Example.test private-family-id private-dsid"`), FamilyPool: projection})
	})
	g := testGateway(t, fake, registryPath, "", 200*time.Millisecond)
	response := gatewayRequest(t, g, "/v1/family/pool", `{"account_id":"org-01"}`)
	pool := decodeGatewayResponse[familyPoolReply](t, response)
	if response.Code != http.StatusOK || !pool.OK || pool.Stage != "family-pool" || pool.Message != "家庭成员映射已确认" || pool.TotalCount != 3 || pool.UnmappedCount != 1 || len(pool.Members) != 2 || !pool.Members[0].Organizer || !pool.Members[1].Child {
		t.Fatalf("unexpected pool response: %d %#v", response.Code, pool)
	}
	for _, secret := range []string{"Organizer@Example.test", "target@example.test", "private-family-id", "private-dsid", "apple_id", "family_id"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatalf("pool response leaked %q: %s", secret, response.Body.String())
		}
	}
}

func TestFamilyAddRoutesOnceAndPersistsSafeResult(t *testing.T) {
	registryPath := testRegistry(t, registryFixture())
	orgBefore := familyFixture(true, true, 4, 1, 1, true, true, true, true, true, true, storage50)
	orgAfter := familyFixture(true, true, 5, 1, 1, true, true, true, true, true, true, storage50)
	targetBefore := familyFixture(false, false, 0, 0, 0, true, true, false, false, false, false, 0)
	targetAfter := familyFixture(true, false, 5, 1, 1, true, true, true, true, true, true, storage50)
	poolBefore := familyPoolFixture([]familyPoolMember{{AccountID: "org-01", Organizer: true}, {AccountID: "member-03"}, {AccountID: "member-04"}, {AccountID: "member-05"}}, 0, 4)
	poolAfter := familyPoolFixture([]familyPoolMember{{AccountID: "org-01", Organizer: true}, {AccountID: "target-02"}, {AccountID: "member-03"}, {AccountID: "member-04"}, {AccountID: "member-05"}}, 0, 5)
	var mu sync.Mutex
	reads := map[string]int{}
	mutations := 0
	poolReads := 0
	fake := newFakeDashboard(t, func(w http.ResponseWriter, _ *http.Request, call dashboardActionCall) {
		if call.Action.Action == "family-add-self" {
			mu.Lock()
			mutations++
			mu.Unlock()
			if call.Account != "target-02" || call.Action.Code != "org-01" {
				t.Errorf("add not routed through target worker: %#v", call)
			}
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-added", Family: targetAfter})
			return
		}
		if call.Action.Action == "family-pool" {
			mu.Lock()
			poolReads++
			count := poolReads
			mu.Unlock()
			if call.Account != "org-01" {
				t.Errorf("family-pool was not read through organizer: %#v", call)
			}
			projection := poolBefore
			if count > 1 {
				projection = poolAfter
			}
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-pool", FamilyPool: projection})
			return
		}
		if call.Action.Action != "family-info-direct" {
			t.Errorf("unexpected dashboard action: %#v", call)
		}
		mu.Lock()
		reads[call.Account]++
		count := reads[call.Account]
		mu.Unlock()
		if call.Account == "org-01" && count == 1 {
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: orgBefore})
		} else if call.Account == "org-01" {
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: orgAfter})
		} else if count == 1 {
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: targetBefore})
		} else {
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: targetAfter})
		}
	})
	intentDir := filepath.Join(testRoot(t), "add-journal")
	g := testGateway(t, fake, registryPath, intentDir, 500*time.Millisecond)
	body := `{"organizer_account_id":"org-01","target_account_id":"target-02","operation_id":"add-001"}`
	response := gatewayRequest(t, g, "/v1/family/add", body)
	if response.Code != http.StatusOK {
		t.Fatalf("add status = %d: %s", response.Code, response.Body.String())
	}
	added := decodeGatewayResponse[familyReply](t, response)
	if !added.OK || added.Stage != "family-added" || added.Message != safeAddedMessage || added.Family == nil || added.Family.Members != 5 {
		t.Fatalf("unexpected add response: %#v", added)
	}
	responseBody := response.Body.String()
	for _, secret := range []string{"Organizer@Example.test", "target@example.test", "private-local-organizer", "private@example.test", "storage_bytes"} {
		if strings.Contains(responseBody, secret) {
			t.Fatalf("add response leaked %q: %s", secret, responseBody)
		}
	}

	duplicate := gatewayRequest(t, g, "/v1/family/add", body)
	if duplicate.Code != http.StatusOK || !decodeGatewayResponse[familyReply](t, duplicate).OK {
		t.Fatalf("duplicate operation did not return saved result: %d %s", duplicate.Code, duplicate.Body.String())
	}
	mu.Lock()
	mutationCount := mutations
	mu.Unlock()
	if mutationCount != 1 {
		t.Fatalf("add mutation count = %d, want exactly one", mutationCount)
	}
	mu.Lock()
	poolReadCount := poolReads
	mu.Unlock()
	if poolReadCount != 2 {
		t.Fatalf("add pool read count = %d, want pre-write and readback", poolReadCount)
	}
	entries, err := os.ReadDir(intentDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("journal entries = %d, err=%v", len(entries), err)
	}
	data, err := os.ReadFile(filepath.Join(intentDir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"Organizer@Example.test", "target@example.test", testAppKey, testBearer, "123456"} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatalf("journal leaked %q", secret)
		}
	}
}

func TestFamilyAddWithCredentialRoutesOnceAndKeepsSecretOutOfResponsesAndJournal(t *testing.T) {
	registryPath := testRegistry(t, registryFixture())
	orgBefore := familyFixture(true, true, 1, 1, 1, true, true, true, true, true, true, storage50)
	orgAfter := familyFixture(true, true, 2, 1, 1, true, true, true, true, true, true, storage50)
	targetBefore := familyFixture(false, false, 0, 0, 0, true, true, false, false, false, false, 0)
	targetAfter := familyFixture(true, false, 2, 1, 1, true, true, true, true, true, true, storage50)
	poolBefore := familyPoolFixture([]familyPoolMember{{AccountID: "org-01", Organizer: true}}, 0, 1)
	poolAfter := familyPoolFixture([]familyPoolMember{{AccountID: "org-01", Organizer: true}, {AccountID: "target-02"}}, 0, 2)
	secret := `one-shot-private-"credential"`
	var mu sync.Mutex
	reads := map[string]int{}
	mutations, poolReads := 0, 0
	fake := newFakeDashboard(t, func(w http.ResponseWriter, _ *http.Request, call dashboardActionCall) {
		if call.Action.Action == "family-add-self" {
			mu.Lock()
			mutations++
			mu.Unlock()
			if call.Account != "target-02" || call.Action.Code != "org-01" || call.Action.TargetAppleID != "target@example.test" || call.Action.TargetPassword != secret {
				t.Errorf("one-shot add was not bound/routed correctly: %#v", call)
			}
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-added", Family: targetAfter})
			return
		}
		if call.Action.Action == "family-pool" {
			mu.Lock()
			poolReads++
			count := poolReads
			mu.Unlock()
			projection := poolBefore
			if count > 1 {
				projection = poolAfter
			}
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-pool", FamilyPool: projection})
			return
		}
		if call.Action.Action != "family-info-direct" || call.Action.TargetPassword != "" {
			t.Errorf("unexpected preflight action or secret forwarding: %#v", call)
		}
		mu.Lock()
		reads[call.Account]++
		count := reads[call.Account]
		mu.Unlock()
		if call.Account == "org-01" && count == 1 {
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: orgBefore})
		} else if call.Account == "org-01" {
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: orgAfter})
		} else if count == 1 {
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: targetBefore})
		} else {
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: targetAfter})
		}
	})
	intentDir := filepath.Join(testRoot(t), "credential-add-journal")
	g := testGateway(t, fake, registryPath, intentDir, 500*time.Millisecond)
	requestBody, _ := json.Marshal(familyAddCredentialRequest{OrganizerAccountID: "org-01", TargetAccountID: "target-02", OperationID: "credential-add-001", TargetAppleID: " TARGET@EXAMPLE.TEST ", TargetPassword: secret})
	request := string(requestBody)
	response := gatewayRequest(t, g, "/v1/family/add-with-credential", request)
	added := decodeGatewayResponse[familyReply](t, response)
	if response.Code != http.StatusOK || !added.OK || added.Stage != "family-added" {
		t.Fatalf("credential add failed: %d %#v", response.Code, added)
	}
	if strings.Contains(response.Body.String(), secret) {
		t.Fatal("gateway response leaked the target password")
	}
	duplicate := gatewayRequest(t, g, "/v1/family/add-with-credential", request)
	if duplicate.Code != http.StatusOK || !decodeGatewayResponse[familyReply](t, duplicate).OK {
		t.Fatalf("credential operation replay did not return the saved result: %d %s", duplicate.Code, duplicate.Body.String())
	}
	replayWithoutPassword, _ := json.Marshal(familyAddCredentialRequest{OrganizerAccountID: "org-01", TargetAccountID: "target-02", OperationID: "credential-add-001", TargetAppleID: "target@example.test"})
	passwordlessReplay := gatewayRequest(t, g, "/v1/family/add-with-credential", string(replayWithoutPassword))
	if passwordlessReplay.Code != http.StatusOK || !decodeGatewayResponse[familyReply](t, passwordlessReplay).OK {
		t.Fatalf("credential replay without password did not return saved result: %d %s", passwordlessReplay.Code, passwordlessReplay.Body.String())
	}
	mu.Lock()
	mutationCount := mutations
	mu.Unlock()
	if mutationCount != 1 {
		t.Fatalf("credential mutation count = %d, want exactly one", mutationCount)
	}
	entries, err := os.ReadDir(intentDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("credential journal entries = %d, err=%v", len(entries), err)
	}
	data, err := os.ReadFile(filepath.Join(intentDir, entries[0].Name()))
	if err != nil || bytes.Contains(data, []byte(secret)) {
		t.Fatalf("credential journal retained the password: err=%v", err)
	}
	calls, _ := fake.snapshot()
	for _, call := range calls {
		if call.Action.Action != "family-add-self" && call.Action.TargetPassword != "" {
			t.Fatalf("preflight action received the password: %#v", call)
		}
	}
}

func TestFamilyAddWithCredentialRejectsBindingAndCapabilityBeforeIntent(t *testing.T) {
	secret := "one-shot-private-secret"
	registryPath := testRegistry(t, registryFixture())
	fake := newFakeDashboard(t, func(w http.ResponseWriter, _ *http.Request, call dashboardActionCall) {
		if call.Action.Action == "family-add-self" {
			t.Error("rejected credential add reached mutation")
		}
	})
	fake.credentialReady = false
	intentDir := filepath.Join(testRoot(t), "credential-reject-journal")
	g := testGateway(t, fake, registryPath, intentDir, 500*time.Millisecond)
	body, _ := json.Marshal(familyAddCredentialRequest{OrganizerAccountID: "org-01", TargetAccountID: "target-02", OperationID: "credential-unready-001", TargetAppleID: "target@example.test", TargetPassword: secret})
	response := gatewayRequest(t, g, "/v1/family/add-with-credential", string(body))
	rejected := decodeGatewayResponse[familyReply](t, response)
	if response.Code != http.StatusConflict || rejected.Stage != "family-worker-unready" || strings.Contains(response.Body.String(), secret) {
		t.Fatalf("unsupported worker was not safely rejected: %d %s", response.Code, response.Body.String())
	}
	entries, err := os.ReadDir(intentDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("unready worker created intent: entries=%d err=%v", len(entries), err)
	}
	calls, _ := fake.snapshot()
	if len(calls) != 1 || calls[0].Action.Action != "family-add-credential-readiness" || calls[0].Action.TargetPassword != "" {
		t.Fatalf("secret was forwarded before capability readiness: %#v", calls)
	}

	fake.credentialReady = true
	body, _ = json.Marshal(familyAddCredentialRequest{OrganizerAccountID: "org-01", TargetAccountID: "target-02", OperationID: "credential-binding-001", TargetAppleID: "wrong@example.test", TargetPassword: secret})
	response = gatewayRequest(t, g, "/v1/family/add-with-credential", string(body))
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "account-binding-invalid") || strings.Contains(response.Body.String(), secret) {
		t.Fatalf("mismatched target identity was not safely rejected: %d %s", response.Code, response.Body.String())
	}
	entries, err = os.ReadDir(intentDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("mismatched target created intent: entries=%d err=%v", len(entries), err)
	}

	body, _ = json.Marshal(familyAddCredentialRequest{OrganizerAccountID: "org-01", TargetAccountID: "target-02", OperationID: "credential-missing-001", TargetAppleID: "target@example.test"})
	response = gatewayRequest(t, g, "/v1/family/add-with-credential", string(body))
	if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), secret) {
		t.Fatalf("missing credential was not rejected: %d %s", response.Code, response.Body.String())
	}
}

func TestFamilyRemoveRoutesToOrganizerAndAcceptsCacheWarningAfterDualReadback(t *testing.T) {
	registryPath := testRegistry(t, registryFixture())
	orgBefore := familyFixture(true, true, 2, 1, 1, true, true, true, true, true, true, storage50)
	orgAfter := familyFixture(true, true, 1, 1, 1, true, true, true, true, true, true, storage50)
	targetBefore := familyFixture(true, false, 2, 1, 1, true, true, true, true, true, true, storage50)
	targetAfter := familyFixture(false, false, 0, 0, 0, true, true, false, false, false, false, 0)
	poolBefore := familyPoolFixture([]familyPoolMember{{AccountID: "org-01", Organizer: true}, {AccountID: "target-02"}}, 0, 2)
	poolAfter := familyPoolFixture([]familyPoolMember{{AccountID: "org-01", Organizer: true}}, 0, 1)
	var mu sync.Mutex
	reads := map[string]int{}
	mutations := 0
	poolReads := 0
	fake := newFakeDashboard(t, func(w http.ResponseWriter, _ *http.Request, call dashboardActionCall) {
		if call.Action.Action == "family-remove-member" {
			mu.Lock()
			mutations++
			mu.Unlock()
			if call.Account != "org-01" || call.Action.Code != "target-02" {
				t.Errorf("remove not routed through organizer: %#v", call)
			}
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-remove-cache-warning", Family: orgAfter})
			return
		}
		if call.Action.Action == "family-pool" {
			mu.Lock()
			poolReads++
			count := poolReads
			mu.Unlock()
			if call.Account != "org-01" {
				t.Errorf("family-pool was not read through organizer: %#v", call)
			}
			projection := poolBefore
			if count > 1 {
				projection = poolAfter
			}
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-pool", FamilyPool: projection})
			return
		}
		if call.Action.Action != "family-info-direct" {
			t.Errorf("unexpected dashboard action: %#v", call)
		}
		mu.Lock()
		reads[call.Account]++
		count := reads[call.Account]
		mu.Unlock()
		if call.Account == "org-01" && count == 1 {
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: orgBefore})
		} else if call.Account == "org-01" {
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: orgAfter})
		} else if count == 1 {
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: targetBefore})
		} else {
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: targetAfter})
		}
	})
	g := testGateway(t, fake, registryPath, "", 500*time.Millisecond)
	response := gatewayRequest(t, g, "/v1/family/remove", `{"organizer_account_id":"org-01","target_account_id":"target-02","operation_id":"remove-001"}`)
	removed := decodeGatewayResponse[familyReply](t, response)
	if response.Code != http.StatusOK || !removed.OK || removed.Stage != "family-remove-cache-warning" || removed.Message != safeRemoveCacheMessage || removed.Family == nil || removed.Family.Members != 1 {
		t.Fatalf("unexpected remove response: %d %#v", response.Code, removed)
	}
	mu.Lock()
	mutationCount := mutations
	mu.Unlock()
	if mutationCount != 1 {
		t.Fatalf("remove mutation count = %d, want exactly one", mutationCount)
	}
	mu.Lock()
	poolReadCount := poolReads
	mu.Unlock()
	if poolReadCount != 2 {
		t.Fatalf("remove pool read count = %d, want pre-write and readback", poolReadCount)
	}
}

func TestDeviceCodeIsReturnedOnlyAndNeverJournaled(t *testing.T) {
	registryPath := testRegistry(t, registryFixture())
	intentDir := filepath.Join(testRoot(t), "code-journal")
	fake := newFakeDashboard(t, func(w http.ResponseWriter, _ *http.Request, call dashboardActionCall) {
		if call.Account != "target-02" || call.Action.Action != "code" || call.Action.Code != "" {
			t.Errorf("wrong device-code action: %#v", call)
		}
		writeDashboardResult(w, dashboardResult{OK: true, Code: "123456"})
	})
	g := testGateway(t, fake, registryPath, intentDir, 200*time.Millisecond)
	response := gatewayRequest(t, g, "/v1/device/code", `{"account_id":"target-02"}`)
	result := decodeGatewayResponse[codeReply](t, response)
	if response.Code != http.StatusOK || !result.OK || result.Code != "123456" {
		t.Fatalf("unexpected code response: %d %#v", response.Code, result)
	}
	entries, err := os.ReadDir(intentDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("device code created persistent files: entries=%d err=%v", len(entries), err)
	}
}

func TestFailedWriteIsNotRetriedAndRestartKeepsOrganizerBlocked(t *testing.T) {
	registryPath := testRegistry(t, registryFixture())
	orgState := familyFixture(true, true, 1, 1, 1, true, true, true, true, true, true, storage50)
	targetState := familyFixture(false, false, 0, 0, 0, true, true, false, false, false, false, 0)
	var mu sync.Mutex
	reads := map[string]int{}
	mutations := 0
	fake := newFakeDashboard(t, func(w http.ResponseWriter, _ *http.Request, call dashboardActionCall) {
		if call.Action.Action == "family-add-self" {
			mu.Lock()
			mutations++
			mu.Unlock()
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, "raw response secret@example.test bearer="+testBearer+" code=123456")
			return
		}
		if call.Action.Action == "family-pool" {
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-pool", FamilyPool: familyPoolFixture([]familyPoolMember{{AccountID: "org-01", Organizer: true}}, 0, 1)})
			return
		}
		mu.Lock()
		reads[call.Account]++
		count := reads[call.Account]
		mu.Unlock()
		if call.Account == "org-01" {
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: orgState})
		} else {
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: targetState})
		}
		_ = count
	})
	intentDir := filepath.Join(testRoot(t), "failure-journal")
	g := testGateway(t, fake, registryPath, intentDir, 300*time.Millisecond)
	request := `{"organizer_account_id":"org-01","target_account_id":"target-02","operation_id":"add-fail-001"}`
	response := gatewayRequest(t, g, "/v1/family/add", request)
	unknown := decodeGatewayResponse[familyReply](t, response)
	if !unknownIs(response.Code, unknown) {
		t.Fatalf("failed write did not become outcome_unknown: %d %#v", response.Code, unknown)
	}
	for _, secret := range []string{"secret@example.test", testBearer, testAppKey, "123456", "raw response"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatalf("failed write leaked %q: %s", secret, response.Body.String())
		}
	}
	mu.Lock()
	mutationCount := mutations
	mu.Unlock()
	if mutationCount != 1 {
		t.Fatalf("mutating dashboard request count = %d, want exactly one", mutationCount)
	}

	duplicate := gatewayRequest(t, g, "/v1/family/add", request)
	if duplicate.Code != http.StatusOK || decodeGatewayResponse[familyReply](t, duplicate).Stage != "outcome_unknown" {
		t.Fatalf("duplicate operation did not return its recorded unknown result: %d %s", duplicate.Code, duplicate.Body.String())
	}
	second := testGateway(t, fake, registryPath, intentDir, 300*time.Millisecond)
	secondWrite := gatewayRequest(t, second, "/v1/family/add", `{"organizer_account_id":"org-01","target_account_id":"target-02","operation_id":"add-fail-002"}`)
	blocked := decodeGatewayResponse[familyReply](t, secondWrite)
	if secondWrite.Code != http.StatusConflict || blocked.Stage != "outcome_unknown" {
		t.Fatalf("restart did not retain organizer block: %d %#v", secondWrite.Code, blocked)
	}
	mu.Lock()
	mutationCount = mutations
	mu.Unlock()
	if mutationCount != 1 {
		t.Fatalf("blocked retry reached dashboard mutation: count=%d", mutationCount)
	}
}

func TestMutationTimeoutIsUnknownAndBlocksAfterRestart(t *testing.T) {
	registryPath := testRegistry(t, registryFixture())
	orgState := familyFixture(true, true, 1, 1, 1, true, true, true, true, true, true, storage50)
	targetState := familyFixture(false, false, 0, 0, 0, true, true, false, false, false, false, 0)
	var mu sync.Mutex
	mutations := 0
	fake := newFakeDashboard(t, func(w http.ResponseWriter, r *http.Request, call dashboardActionCall) {
		if call.Action.Action == "family-add-self" {
			mu.Lock()
			mutations++
			mu.Unlock()
			<-r.Context().Done()
			return
		}
		if call.Action.Action == "family-pool" {
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-pool", FamilyPool: familyPoolFixture([]familyPoolMember{{AccountID: "org-01", Organizer: true}}, 0, 1)})
			return
		}
		if call.Account == "org-01" {
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: orgState})
		} else {
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: targetState})
		}
	})
	intentDir := filepath.Join(testRoot(t), "timeout-journal")
	g := testGateway(t, fake, registryPath, intentDir, 150*time.Millisecond)
	request := `{"organizer_account_id":"org-01","target_account_id":"target-02","operation_id":"add-timeout-001"}`
	response := gatewayRequest(t, g, "/v1/family/add", request)
	unknown := decodeGatewayResponse[familyReply](t, response)
	if !unknownIs(response.Code, unknown) {
		t.Fatalf("timed-out write did not become outcome_unknown: %d %#v", response.Code, unknown)
	}
	mu.Lock()
	mutationCount := mutations
	mu.Unlock()
	if mutationCount != 1 {
		t.Fatalf("timed-out mutation count = %d, want exactly one", mutationCount)
	}
	second := testGateway(t, fake, registryPath, intentDir, 150*time.Millisecond)
	blocked := gatewayRequest(t, second, "/v1/family/add", `{"organizer_account_id":"org-01","target_account_id":"target-02","operation_id":"add-timeout-002"}`)
	if blocked.Code != http.StatusConflict || decodeGatewayResponse[familyReply](t, blocked).Stage != "outcome_unknown" {
		t.Fatalf("restart did not retain timeout block: %d %s", blocked.Code, blocked.Body.String())
	}
	mu.Lock()
	mutationCount = mutations
	mu.Unlock()
	if mutationCount != 1 {
		t.Fatalf("blocked timeout retry reached dashboard: count=%d", mutationCount)
	}
}

func TestInterruptedIntentIsRecoveredAsUnknown(t *testing.T) {
	intentDir := filepath.Join(testRoot(t), "interrupted-journal")
	store, err := openJournal(intentDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.create(operationRecord{Version: journalVersion, OperationID: "interrupted-001", Action: "family-add", OrganizerAccountID: "org-01", TargetAccountID: "target-02", State: stateIntent}); err != nil {
		t.Fatal(err)
	}
	registryPath := testRegistry(t, registryFixture())
	fake := newFakeDashboard(t, func(w http.ResponseWriter, _ *http.Request, _ dashboardActionCall) {
		t.Error("unknown organizer must be blocked before dashboard reads")
	})
	g := testGateway(t, fake, registryPath, intentDir, 200*time.Millisecond)
	response := gatewayRequest(t, g, "/v1/family/remove", `{"organizer_account_id":"org-01","target_account_id":"target-02","operation_id":"interrupted-002"}`)
	blocked := decodeGatewayResponse[familyReply](t, response)
	if response.Code != http.StatusConflict || blocked.Stage != "outcome_unknown" || blocked.OK {
		t.Fatalf("interrupted intent did not block organizer: %d %#v", response.Code, blocked)
	}
	record, ok := g.journal.lookup("interrupted-001")
	if !ok || record.State != stateUnknown {
		t.Fatalf("interrupted journal state was not recovered: %#v", record)
	}
}

func unknownIs(status int, result familyReply) bool {
	return status == http.StatusOK && !result.OK && result.Stage == "outcome_unknown" && result.Message == safeUnknownMessage
}

func gatewayMemberRef(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, sha256.Size))
}

func familyRosterFixture(members []familyRosterMember, unidentified, total int) *familyRosterProjection {
	return &familyRosterProjection{Members: members, UnidentifiedCount: unidentified, TotalCount: total}
}

func organizerOnlyRegistryFixture() string {
	return `{"accounts":[{"id":"org-01","name":"organizer","apple_id":"Organizer@Example.test","dir":"D:\\service\\accounts\\org-01"}]}`
}

func TestFamilyRosterReturnsOnlyValidatedOpaqueMembersAndRequiresRegistry(t *testing.T) {
	ref := gatewayMemberRef(11)
	registryPath := testRegistry(t, organizerOnlyRegistryFixture())
	org := familyFixture(true, true, 3, 1, 1, true, true, true, true, true, true, storage50)
	projection := familyRosterFixture([]familyRosterMember{{Ref: ref, Label: "m***@example.test"}}, 1, 3)
	fake := newFakeDashboard(t, func(w http.ResponseWriter, _ *http.Request, call dashboardActionCall) {
		if call.Account != "org-01" {
			t.Errorf("roster read used a non-organizer account: %#v", call)
		}
		switch call.Action.Action {
		case "family-info-direct":
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: org})
		case "family-roster":
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-roster", FamilyRoster: projection})
		default:
			t.Errorf("unexpected dashboard action: %#v", call)
		}
	})
	g := testGateway(t, fake, registryPath, "", 500*time.Millisecond)
	response := gatewayRequest(t, g, "/v1/family/roster", `{"account_id":"org-01"}`)
	result := decodeGatewayResponse[familyRosterReply](t, response)
	if response.Code != http.StatusOK || !result.OK || result.Stage != "family-roster" || result.TotalCount != 3 || result.UnidentifiedCount != 1 || len(result.Members) != 1 || result.Members[0] != projection.Members[0] {
		t.Fatalf("unexpected roster response: %d %#v", response.Code, result)
	}
	for _, forbidden := range []string{"Organizer@Example.test", "target@example.test", "target-02", "account_id"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("roster response leaked %q: %s", forbidden, response.Body.String())
		}
	}

	callsBefore, _ := fake.snapshot()
	missing := gatewayRequest(t, g, "/v1/family/roster", `{"account_id":"target-02"}`)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("unregistered organizer status = %d, want 404", missing.Code)
	}
	callsAfter, _ := fake.snapshot()
	if len(callsAfter) != len(callsBefore) {
		t.Fatalf("unregistered account reached dashboard: before=%d after=%d", len(callsBefore), len(callsAfter))
	}
}

func TestFamilyRosterStrictlyValidatesRefsLabelsAndCounts(t *testing.T) {
	ref := gatewayMemberRef(12)
	valid := familyRosterFixture([]familyRosterMember{{Ref: ref, Label: "m***@example.test"}}, 0, 2)
	if !validFamilyRoster(valid) {
		t.Fatal("valid masked roster rejected")
	}
	invalid := []*familyRosterProjection{
		familyRosterFixture([]familyRosterMember{{Ref: ref, Label: "m***@example.test"}, {Ref: ref, Label: "n***@example.test"}}, 0, 3),
		familyRosterFixture([]familyRosterMember{{Ref: "not-a-reference", Label: "m***@example.test"}}, 0, 2),
		familyRosterFixture([]familyRosterMember{{Ref: ref, Label: "member@example.test"}}, 0, 2),
		familyRosterFixture([]familyRosterMember{{Ref: ref, Label: "m***@example.test"}}, 2, 2),
		familyRosterFixture([]familyRosterMember{{Ref: ref, Label: "m***@example.test"}}, 0, 1),
		familyRosterFixture(nil, 0, 1),
		familyRosterFixture([]familyRosterMember{}, -1, 1),
	}
	for index, roster := range invalid {
		if validFamilyRoster(roster) {
			t.Fatalf("unsafe roster %d was accepted: %#v", index, roster)
		}
	}
}

func TestFamilyRosterRejectsUnknownDashboardMemberFields(t *testing.T) {
	ref := gatewayMemberRef(20)
	registryPath := testRegistry(t, organizerOnlyRegistryFixture())
	org := familyFixture(true, true, 2, 1, 1, true, true, true, true, true, true, storage50)
	fake := newFakeDashboard(t, func(w http.ResponseWriter, _ *http.Request, call dashboardActionCall) {
		if call.Action.Action == "family-info-direct" {
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: org})
			return
		}
		if call.Action.Action != "family-roster" {
			t.Errorf("unexpected dashboard action: %#v", call)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true,"stage":"family-roster","family_roster":{"members":[{"ref":"`+ref+`","label":"m***@example.test","dsid":"private-dsid"}],"unidentified_count":0,"total_count":2}}`)
	})
	g := testGateway(t, fake, registryPath, "", 500*time.Millisecond)
	response := gatewayRequest(t, g, "/v1/family/roster", `{"account_id":"org-01"}`)
	if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), ref) || strings.Contains(response.Body.String(), "private-dsid") {
		t.Fatalf("unknown dashboard roster field was not safely rejected: %d %s", response.Code, response.Body.String())
	}
}

func TestFamilyRemoveByRefUsesOrganizerOnlyAndIsIdempotent(t *testing.T) {
	ref := gatewayMemberRef(13)
	registryPath := testRegistry(t, organizerOnlyRegistryFixture())
	intentDir := filepath.Join(testRoot(t), "remove-ref-journal")
	orgBefore := familyFixture(true, true, 2, 1, 1, true, true, true, true, true, true, storage50)
	orgAfter := familyFixture(true, true, 1, 1, 1, true, true, true, true, true, true, storage50)
	rosterBefore := familyRosterFixture([]familyRosterMember{{Ref: ref, Label: "t***@example.test"}}, 0, 2)
	rosterAfter := familyRosterFixture([]familyRosterMember{}, 0, 1)
	mutations := 0
	reads := map[string]int{}
	var mu sync.Mutex
	fake := newFakeDashboard(t, func(w http.ResponseWriter, _ *http.Request, call dashboardActionCall) {
		if call.Account != "org-01" {
			t.Errorf("family removal used a non-organizer account: %#v", call)
		}
		switch call.Action.Action {
		case "family-roster":
			mu.Lock()
			reads["roster"]++
			count := reads["roster"]
			mu.Unlock()
			projection := rosterBefore
			if count > 1 {
				projection = rosterAfter
			}
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-roster", FamilyRoster: projection})
		case "family-info-direct":
			mu.Lock()
			reads["family"]++
			count := reads["family"]
			mu.Unlock()
			family := orgBefore
			if count > 1 {
				family = orgAfter
			}
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: family})
		case "family-remove-ref":
			mutations++
			if call.Action.Code != ref {
				t.Errorf("remove did not forward the selected opaque ref: %#v", call)
			}
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-member-removed", Family: orgAfter})
		default:
			t.Errorf("unexpected dashboard action: %#v", call)
		}
	})
	g := testGateway(t, fake, registryPath, intentDir, 500*time.Millisecond)
	requestBody, _ := json.Marshal(familyRemoveRefRequest{OrganizerAccountID: "org-01", MemberRef: ref, OperationID: "remove-ref-001"})
	response := gatewayRequest(t, g, "/v1/family/remove-by-ref", string(requestBody))
	removed := decodeGatewayResponse[familyReply](t, response)
	if response.Code != http.StatusOK || !removed.OK || removed.Stage != "family-member-removed" || removed.Family == nil || removed.Family.Members != 1 {
		t.Fatalf("unexpected remove-by-ref response: %d %#v", response.Code, removed)
	}
	duplicate := gatewayRequest(t, g, "/v1/family/remove-by-ref", string(requestBody))
	if duplicate.Code != http.StatusOK || !decodeGatewayResponse[familyReply](t, duplicate).OK {
		t.Fatalf("operation replay did not return the saved result: %d %s", duplicate.Code, duplicate.Body.String())
	}
	wrongRef := gatewayMemberRef(14)
	conflictBody, _ := json.Marshal(familyRemoveRefRequest{OrganizerAccountID: "org-01", MemberRef: wrongRef, OperationID: "remove-ref-001"})
	conflict := gatewayRequest(t, g, "/v1/family/remove-by-ref", string(conflictBody))
	if conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), "operation-id-conflict") {
		t.Fatalf("operation id accepted a different member ref: %d %s", conflict.Code, conflict.Body.String())
	}
	calls, _ := fake.snapshot()
	if mutations != 1 || len(calls) != 5 {
		t.Fatalf("dashboard calls = %d, mutations = %d; want 5 calls and one submission", len(calls), mutations)
	}
	wantActions := []string{"family-roster", "family-info-direct", "family-remove-ref", "family-roster", "family-info-direct"}
	for index, want := range wantActions {
		if calls[index].Action.Action != want || calls[index].Account != "org-01" {
			t.Fatalf("dashboard call %d = %#v, want organizer action %s", index, calls[index], want)
		}
	}
	record, ok := g.journal.lookup("remove-ref-001")
	if !ok || record.Action != "family-remove-ref" || record.TargetAccountID != familyMemberRefHash(ref) || record.State != stateSucceeded {
		t.Fatalf("journal did not retain the hashed target identity: %#v", record)
	}
	entries, err := os.ReadDir(intentDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("remove-ref journal entries = %d, err=%v", len(entries), err)
	}
	journalBytes, err := os.ReadFile(filepath.Join(intentDir, entries[0].Name()))
	if err != nil || bytes.Contains(journalBytes, []byte(ref)) || bytes.Contains(journalBytes, []byte("target-02")) || bytes.Contains(journalBytes, []byte("target@example.test")) {
		t.Fatalf("journal retained raw target identity: err=%v", err)
	}
}

func TestFamilyRemoveByRefDoesNotRequireUnchangedStorageMetadata(t *testing.T) {
	ref := gatewayMemberRef(21)
	before := familyFixture(true, true, 2, 1, 1, true, true, true, true, true, true, storage50)
	after := familyFixture(true, true, 1, 1, 1, true, true, false, false, false, false, 0)
	beforeRoster := familyRosterFixture([]familyRosterMember{{Ref: ref, Label: "t***@example.test"}}, 0, 2)
	afterRoster := familyRosterFixture([]familyRosterMember{}, 0, 1)
	fake := newFakeDashboard(t, func(w http.ResponseWriter, _ *http.Request, call dashboardActionCall) {
		switch call.Action.Action {
		case "family-roster":
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-roster", FamilyRoster: afterRoster})
		case "family-info-direct":
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: after})
		default:
			t.Fatalf("unexpected dashboard action: %s", call.Action.Action)
		}
	})
	g := testGateway(t, fake, testRegistry(t, organizerOnlyRegistryFixture()), "", 500*time.Millisecond)
	result := dashboardResult{OK: true, Stage: "family-member-removed", Family: after}
	if verified := g.verifyRemovedByRef(context.Background(), "org-01", ref, before, beforeRoster, result); verified == nil || verified.Members != 1 {
		t.Fatal("the verified target disappearance must not depend on unrelated storage metadata")
	}
}

func TestFamilyRemoveByRefRequiresOrganizerRoleAndExactRosterIdentity(t *testing.T) {
	ref := gatewayMemberRef(15)
	registryPath := testRegistry(t, organizerOnlyRegistryFixture())
	wrongRole := familyFixture(true, false, 2, 1, 1, true, true, true, true, true, true, storage50)
	mutations := 0
	fake := newFakeDashboard(t, func(w http.ResponseWriter, _ *http.Request, call dashboardActionCall) {
		switch call.Action.Action {
		case "family-roster":
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-roster", FamilyRoster: familyRosterFixture([]familyRosterMember{{Ref: ref, Label: "c***@example.test"}}, 0, 2)})
		case "family-info-direct":
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: wrongRole})
		case "family-remove-ref":
			mutations++
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-member-removed", Family: wrongRole})
		default:
			t.Errorf("unexpected dashboard action: %#v", call)
		}
	})
	intentDir := filepath.Join(testRoot(t), "remove-ref-role-journal")
	g := testGateway(t, fake, registryPath, intentDir, 500*time.Millisecond)
	body, _ := json.Marshal(familyRemoveRefRequest{OrganizerAccountID: "org-01", MemberRef: ref, OperationID: "remove-ref-role-001"})
	response := gatewayRequest(t, g, "/v1/family/remove-by-ref", string(body))
	if response.Code != http.StatusConflict || decodeGatewayResponse[familyReply](t, response).Stage != "family-preflight" || mutations != 0 {
		t.Fatalf("non-organizer reached removal: status=%d body=%s mutations=%d", response.Code, response.Body.String(), mutations)
	}
	entries, err := os.ReadDir(intentDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed organizer precondition persisted intent: entries=%d err=%v", len(entries), err)
	}

	// A ref absent from the exact live organizer roster must not create an intent
	// or reach the dashboard write action.
	wrongRef := gatewayMemberRef(16)
	body, _ = json.Marshal(familyRemoveRefRequest{OrganizerAccountID: "org-01", MemberRef: wrongRef, OperationID: "remove-ref-absent-001"})
	response = gatewayRequest(t, g, "/v1/family/remove-by-ref", string(body))
	if response.Code != http.StatusConflict || decodeGatewayResponse[familyReply](t, response).Stage != "family-preflight" || mutations != 0 {
		t.Fatalf("absent ref reached removal: status=%d body=%s mutations=%d", response.Code, response.Body.String(), mutations)
	}
}

func TestFamilyRemoveByRefKnownNotSubmittedIsSafeAndIdempotent(t *testing.T) {
	ref := gatewayMemberRef(17)
	registryPath := testRegistry(t, organizerOnlyRegistryFixture())
	org := familyFixture(true, true, 2, 1, 1, true, true, true, true, true, true, storage50)
	projection := familyRosterFixture([]familyRosterMember{{Ref: ref, Label: "c***@example.test"}}, 0, 2)
	mutations := 0
	fake := newFakeDashboard(t, func(w http.ResponseWriter, _ *http.Request, call dashboardActionCall) {
		switch call.Action.Action {
		case "family-roster":
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-roster", FamilyRoster: projection})
		case "family-info-direct":
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: org})
		case "family-remove-ref":
			mutations++
			writeDashboardResult(w, dashboardResult{OK: false, Stage: "family-remove-preflight"})
		default:
			t.Errorf("unexpected dashboard action: %#v", call)
		}
	})
	intentDir := filepath.Join(testRoot(t), "remove-ref-not-submitted-journal")
	g := testGateway(t, fake, registryPath, intentDir, 500*time.Millisecond)
	requestFor := func(operationID string) string {
		data, _ := json.Marshal(familyRemoveRefRequest{OrganizerAccountID: "org-01", MemberRef: ref, OperationID: operationID})
		return string(data)
	}
	first := gatewayRequest(t, g, "/v1/family/remove-by-ref", requestFor("remove-ref-preflight-001"))
	firstReply := decodeGatewayResponse[familyReply](t, first)
	if first.Code != http.StatusConflict || firstReply.OK || firstReply.Stage != "family-remove-preflight" {
		t.Fatalf("known not-submitted result was not preserved: %d %#v", first.Code, firstReply)
	}
	record, ok := g.journal.lookup("remove-ref-preflight-001")
	if !ok || record.State != stateNotSubmitted || g.journal.isBlocked("org-01") {
		t.Fatalf("known not-submitted outcome incorrectly blocked organizer: record=%#v blocked=%v", record, g.journal.isBlocked("org-01"))
	}
	replay := gatewayRequest(t, g, "/v1/family/remove-by-ref", requestFor("remove-ref-preflight-001"))
	if replay.Code != http.StatusOK || decodeGatewayResponse[familyReply](t, replay).Stage != "family-remove-preflight" {
		t.Fatalf("known not-submitted result was not idempotent: %d %s", replay.Code, replay.Body.String())
	}
	second := gatewayRequest(t, g, "/v1/family/remove-by-ref", requestFor("remove-ref-preflight-002"))
	if second.Code != http.StatusConflict || decodeGatewayResponse[familyReply](t, second).Stage != "family-remove-preflight" || mutations != 2 {
		t.Fatalf("known not-submitted outcome blocked a new explicit operation: %d %s mutations=%d", second.Code, second.Body.String(), mutations)
	}
}

func TestFamilyRemoveByRefUnknownOutcomeBlocksAfterRestart(t *testing.T) {
	ref := gatewayMemberRef(18)
	registryPath := testRegistry(t, organizerOnlyRegistryFixture())
	intentDir := filepath.Join(testRoot(t), "remove-ref-unknown-journal")
	org := familyFixture(true, true, 2, 1, 1, true, true, true, true, true, true, storage50)
	projection := familyRosterFixture([]familyRosterMember{{Ref: ref, Label: "c***@example.test"}}, 0, 2)
	mutations := 0
	fake := newFakeDashboard(t, func(w http.ResponseWriter, _ *http.Request, call dashboardActionCall) {
		switch call.Action.Action {
		case "family-roster":
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-roster", FamilyRoster: projection})
		case "family-info-direct":
			writeDashboardResult(w, dashboardResult{OK: true, Stage: "family-info", Family: org})
		case "family-remove-ref":
			mutations++
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, "private target@example.test dsid=private-dsid")
		default:
			t.Errorf("unexpected dashboard action: %#v", call)
		}
	})
	g := testGateway(t, fake, registryPath, intentDir, 500*time.Millisecond)
	requestBody := `{"organizer_account_id":"org-01","member_ref":"` + ref + `","operation_id":"remove-ref-unknown-001"}`
	response := gatewayRequest(t, g, "/v1/family/remove-by-ref", requestBody)
	unknown := decodeGatewayResponse[familyReply](t, response)
	if !unknownIs(response.Code, unknown) {
		t.Fatalf("failed mutation was not outcome_unknown: %d %#v", response.Code, unknown)
	}
	for _, secret := range []string{ref, "target@example.test", "private-dsid"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatalf("unknown response leaked %q: %s", secret, response.Body.String())
		}
	}
	callsBeforeReplay, _ := fake.snapshot()
	replay := gatewayRequest(t, g, "/v1/family/remove-by-ref", requestBody)
	if replay.Code != http.StatusOK || decodeGatewayResponse[familyReply](t, replay).Stage != "outcome_unknown" {
		t.Fatalf("unknown operation replay was not stable: %d %s", replay.Code, replay.Body.String())
	}
	secondGateway := testGateway(t, fake, registryPath, intentDir, 500*time.Millisecond)
	blocked := gatewayRequest(t, secondGateway, "/v1/family/remove-by-ref", `{"organizer_account_id":"org-01","member_ref":"`+gatewayMemberRef(19)+`","operation_id":"remove-ref-unknown-002"}`)
	if blocked.Code != http.StatusConflict || decodeGatewayResponse[familyReply](t, blocked).Stage != "outcome_unknown" {
		t.Fatalf("restart did not retain organizer block: %d %s", blocked.Code, blocked.Body.String())
	}
	callsAfterRestartAttempt, _ := fake.snapshot()
	if mutations != 1 || len(callsAfterRestartAttempt) != len(callsBeforeReplay) {
		t.Fatalf("unknown result was retried: mutations=%d calls-before=%d calls-after=%d", mutations, len(callsBeforeReplay), len(callsAfterRestartAttempt))
	}
	record, ok := secondGateway.journal.lookup("remove-ref-unknown-001")
	if !ok || record.State != stateUnknown || record.TargetAccountID != familyMemberRefHash(ref) {
		t.Fatalf("restart did not retain opaque target hash and unknown state: %#v", record)
	}
}

func TestGatewayRejectsCookieOriginAndOversizedInput(t *testing.T) {
	registryPath := testRegistry(t, registryFixture())
	fake := newFakeDashboard(t, func(w http.ResponseWriter, _ *http.Request, _ dashboardActionCall) {})
	g := testGateway(t, fake, registryPath, "", 200*time.Millisecond)

	for _, header := range []struct{ name, value string }{{"Cookie", "session=private"}, {"Origin", "https://untrusted.example"}} {
		request := httptest.NewRequest(http.MethodPost, "/v1/family/read", strings.NewReader(`{"account_id":"org-01"}`))
		request.Header.Set("Authorization", "Bearer "+testBearer)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set(header.name, header.value)
		response := httptest.NewRecorder()
		g.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s request status = %d", header.name, response.Code)
		}
	}
	large := `{"account_id":"` + strings.Repeat("a", maxRequestBytes+1) + `"}`
	response := gatewayRequest(t, g, "/v1/family/read", large)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request status = %d", response.Code)
	}
}

func TestAccountsListReturnsOnlyAccountIDsAndNormalizedAppleIDs(t *testing.T) {
	registry := accountRegistry{Accounts: []accountEntry{
		{ID: "account-a", Name: "private-name", AppleID: " First@Example.invalid ", Dir: `D:\private\account-a`},
		{ID: "account-b", Name: "private-name-b", AppleID: "second@example.invalid", Dir: `D:\private\account-b`},
	}}
	data, err := json.Marshal(registry)
	if err != nil {
		t.Fatal("could not encode synthetic registry")
	}
	fake := newFakeDashboard(t, func(http.ResponseWriter, *http.Request, dashboardActionCall) {
		t.Error("account listing must not call the dashboard")
	})
	gateway := testGateway(t, fake, testRegistry(t, string(data)), "", time.Second)
	response := gatewayRequest(t, gateway, "/v1/accounts/list", `{}`)
	if response.Code != http.StatusOK {
		t.Fatal("account listing did not succeed")
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal("account listing response was not JSON")
	}
	if len(envelope) != 2 || string(envelope["ok"]) != "true" {
		t.Fatal("account listing response contained unexpected top-level fields")
	}
	var listed []map[string]json.RawMessage
	if err := json.Unmarshal(envelope["accounts"], &listed); err != nil || len(listed) != 2 {
		t.Fatal("account listing returned an incomplete account array")
	}
	wantIDs := []string{"account-a", "account-b"}
	wantAppleIDs := []string{"first@example.invalid", "second@example.invalid"}
	for i, account := range listed {
		if len(account) != 2 {
			t.Fatalf("account %d contained fields beyond the public projection", i)
		}
		var accountID, appleID string
		if json.Unmarshal(account["account_id"], &accountID) != nil || json.Unmarshal(account["apple_id"], &appleID) != nil {
			t.Fatalf("account %d omitted required public fields", i)
		}
		if accountID != wantIDs[i] || appleID != wantAppleIDs[i] {
			t.Fatalf("account %d did not match the normalized public projection", i)
		}
	}
}

func TestAccountsListRejectsDuplicateIDsAndAppleIDsWithoutPartialData(t *testing.T) {
	cases := []struct {
		name     string
		accounts []accountEntry
	}{
		{
			name: "duplicate account IDs",
			accounts: []accountEntry{
				{ID: "duplicate", AppleID: "first@example.invalid"},
				{ID: "duplicate", AppleID: "second@example.invalid"},
			},
		},
		{
			name: "duplicate normalized Apple IDs",
			accounts: []accountEntry{
				{ID: "account-a", AppleID: "First@Example.invalid"},
				{ID: "account-b", AppleID: " first@example.invalid "},
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			data, err := json.Marshal(accountRegistry{Accounts: test.accounts})
			if err != nil {
				t.Fatal("could not encode synthetic registry")
			}
			fake := newFakeDashboard(t, func(http.ResponseWriter, *http.Request, dashboardActionCall) {
				t.Error("account listing must not call the dashboard")
			})
			gateway := testGateway(t, fake, testRegistry(t, string(data)), "", time.Second)
			response := gatewayRequest(t, gateway, "/v1/accounts/list", `{}`)
			if response.Code == http.StatusOK {
				t.Fatal("ambiguous registry was accepted")
			}
			var reply map[string]json.RawMessage
			if json.Unmarshal(response.Body.Bytes(), &reply) != nil {
				t.Fatal("ambiguous registry response was not JSON")
			}
			if _, exists := reply["accounts"]; exists {
				t.Fatal("failed account listing returned a partial account array")
			}
			if bytes.Contains(response.Body.Bytes(), []byte("example.invalid")) {
				t.Fatal("failed account listing exposed registry identity data")
			}
		})
	}
}

func TestAccountsListUsesBearerPostNoOriginNoCookieJSONContract(t *testing.T) {
	registry := testRegistry(t, `{"accounts":[]}`)
	fake := newFakeDashboard(t, func(http.ResponseWriter, *http.Request, dashboardActionCall) {
		t.Error("account listing must not call the dashboard")
	})
	gateway := testGateway(t, fake, registry, "", time.Second)
	cases := []struct {
		name       string
		method     string
		authorized bool
		origin     string
		cookie     string
		body       string
		status     int
	}{
		{name: "missing bearer", method: http.MethodPost, body: `{}`, status: http.StatusUnauthorized},
		{name: "GET rejected", method: http.MethodGet, authorized: true, body: `{}`, status: http.StatusMethodNotAllowed},
		{name: "Origin rejected", method: http.MethodPost, authorized: true, origin: "https://untrusted.invalid", body: `{}`, status: http.StatusForbidden},
		{name: "cookie rejected", method: http.MethodPost, authorized: true, cookie: "session=private", body: `{}`, status: http.StatusForbidden},
		{name: "unknown JSON field rejected", method: http.MethodPost, authorized: true, body: `{"unexpected":true}`, status: http.StatusBadRequest},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "/v1/accounts/list", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			if test.authorized {
				request.Header.Set("Authorization", "Bearer "+testBearer)
			}
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if test.cookie != "" {
				request.Header.Set("Cookie", test.cookie)
			}
			response := httptest.NewRecorder()
			gateway.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("request was not rejected with the expected status (%d)", test.status)
			}
			var reply map[string]json.RawMessage
			if json.Unmarshal(response.Body.Bytes(), &reply) != nil {
				t.Fatal("rejected request response was not JSON")
			}
			if _, exists := reply["accounts"]; exists {
				t.Fatal("rejected request returned account data")
			}
		})
	}
}

func TestBearerComparisonAndConfigRequireLoopbackAndAbsolutePaths(t *testing.T) {
	if _, err := validateConfig(Config{ListenAddr: "0.0.0.0:18742", DashboardURL: DefaultDashboard, RegistryPath: `D:\registry\accounts.json`, IntentDir: `D:\journal`, BearerToken: testBearer}); err == nil {
		t.Fatal("non-loopback listener accepted")
	}
	if _, err := validateConfig(Config{ListenAddr: DefaultListenAddr, DashboardURL: DefaultDashboard, RegistryPath: `accounts.json`, IntentDir: `D:\journal`, BearerToken: testBearer}); err == nil {
		t.Fatal("relative registry path accepted")
	}
	if _, err := validateConfig(Config{ListenAddr: DefaultListenAddr, DashboardURL: "http://example.test:18741", RegistryPath: `D:\registry\accounts.json`, IntentDir: `D:\journal`, BearerToken: testBearer}); err == nil {
		t.Fatal("non-loopback dashboard accepted")
	}
}
