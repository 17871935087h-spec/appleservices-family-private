package v2gateway

import (
	"bytes"
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
	server *httptest.Server
	mu     sync.Mutex
	calls  []dashboardActionCall
	root   int
	handle func(http.ResponseWriter, *http.Request, dashboardActionCall)
}

type dashboardActionCall struct {
	Account string
	Action  dashboardAction
}

func newFakeDashboard(t *testing.T, handler func(http.ResponseWriter, *http.Request, dashboardActionCall)) *fakeDashboard {
	t.Helper()
	fake := &fakeDashboard{handle: handler}
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
		fake.mu.Unlock()
		fake.handle(w, r, call)
	}))
	t.Cleanup(fake.server.Close)
	return fake
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
		if call.Account != "target-02" || call.Action.Action != "family-info" || call.Action.Code != "" {
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
		if call.Action.Action != "family-info" {
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
		if call.Action.Action != "family-info" {
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
