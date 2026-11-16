package egresspool

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDisabledEmptyPoolAndEnvironmentCleanup(t *testing.T) {
	poolPath := filepath.Join(t.TempDir(), "pool.json")
	writeConfig(t, poolPath, config{Version: 1, Enabled: boolPointer(false), Nodes: []node{}, MaxAccountsPerExit: 1, Assignments: map[string]string{}})
	t.Setenv(PoolEnv, poolPath)

	route, err := Resolve("")
	if err != nil || route.Enabled {
		t.Fatalf("disabled pool Resolve = %s, %v", route, err)
	}
	snapshot, err := (Manager{Path: poolPath}).Snapshot()
	if err != nil || snapshot.Enabled || len(snapshot.Nodes) != 0 || len(snapshot.Assignments) != 0 {
		t.Fatalf("disabled empty snapshot = %#v, %v", snapshot, err)
	}

	base := []string{PoolEnv + "=" + poolPath, "APPLESERVICES_ACCOUNT_PROXY=http://stale.example:8080", "HTTP_PROXY=http://machine.example:3128", "A=1"}
	child, err := Environment(base, "")
	if err != nil {
		t.Fatal(err)
	}
	values := envMap(child)
	if _, ok := values[PoolEnv]; ok {
		t.Fatal("explicitly inactive pool remained in child environment")
	}
	if _, ok := values["APPLESERVICES_ACCOUNT_PROXY"]; ok {
		t.Fatal("stale account route remained in inactive child environment")
	}
	if values["HTTP_PROXY"] != "http://machine.example:3128" || values["A"] != "1" {
		t.Fatalf("inactive environment changed unrelated proxy settings: %#v", values)
	}
	if len(base) != 4 || !strings.HasPrefix(base[0], PoolEnv+"=") {
		t.Fatal("Environment mutated the input slice")
	}

	t.Setenv("APPLESERVICES_ACCOUNT_PROXY", "http://stale.example:8080")
	t.Setenv("HTTP_PROXY", "http://machine.example:3128")
	if err := Apply(""); err != nil {
		t.Fatal(err)
	}
	if os.Getenv(PoolEnv) != "" || os.Getenv("APPLESERVICES_ACCOUNT_PROXY") != "" {
		t.Fatal("Apply did not clear inactive pool routing markers")
	}
	if os.Getenv("HTTP_PROXY") != "http://machine.example:3128" {
		t.Fatal("Apply changed the unrelated process proxy")
	}
}

func TestMissingManagerPoolIsAnEmptyDisabledSnapshot(t *testing.T) {
	manager := Manager{Path: filepath.Join(t.TempDir(), "not-created.json")}
	snapshot, err := manager.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Enabled || snapshot.MaxAccountsPerExit != 1 || len(snapshot.Nodes) != 0 || len(snapshot.Assignments) != 0 {
		t.Fatalf("missing file snapshot = %#v", snapshot)
	}
	if _, err := os.Stat(manager.Path); !os.IsNotExist(err) {
		t.Fatal("Snapshot created a pool file")
	}
}

func TestLegacyPoolWithoutEnabledOrCheckedAtStillResolves(t *testing.T) {
	poolPath := filepath.Join(t.TempDir(), "legacy.json")
	legacy := `{"version":1,"nodes":[{"id":"old","url":"http://proxy.example.invalid:8080","exit_ip":"192.0.2.88","enabled":true}],"assignments":{}}`
	if err := os.WriteFile(poolPath, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(PoolEnv, poolPath)
	route, err := Resolve("/accounts/legacy")
	if err != nil || !route.Enabled || route.NodeID != "old" {
		t.Fatalf("legacy Resolve = %s, %v", route, err)
	}
	snapshot, err := (Manager{Path: poolPath}).Snapshot()
	if err != nil || !snapshot.Enabled || snapshot.Nodes[0].CheckedAt != nil || snapshot.Nodes[0].Endpoint != "proxy.example.invalid:8080" {
		t.Fatalf("legacy summary = %#v, %v", snapshot, err)
	}
	if err := (Manager{Path: poolPath}).SetEnabled(true); err == nil {
		t.Fatal("activation accepted an unmeasured legacy node")
	}
}

func TestManagerUpsertUsesMeasuredIPAndReturnsSanitizedSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool.json")
	var manager Manager
	probeCalls := 0
	manager = Manager{Path: path}
	manager.Probe = func(ctx context.Context, proxyURL string) (string, error) {
		probeCalls++
		if proxyURL != "https://user:secret@proxy.example.invalid:443" {
			t.Errorf("probe URL = %q", proxyURL)
		}
		// Upsert must release the cross-process lock before invoking a prober.
		view, err := manager.Snapshot()
		wantEnabled, wantNodes := probeCalls > 1, probeCalls-1
		if err != nil || view.Enabled != wantEnabled || len(view.Nodes) != wantNodes {
			t.Errorf("snapshot during probe = %#v, %v", view, err)
		}
		return "198.51.100.31", nil
	}

	if err := manager.Upsert(context.Background(), "edge-a", "https://user:secret@proxy.example.invalid", true); err != nil {
		t.Fatal(err)
	}
	if probeCalls != 1 {
		t.Fatalf("probe calls = %d, want 1", probeCalls)
	}
	snapshot, err := manager.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Enabled || len(snapshot.Nodes) != 1 || snapshot.Nodes[0].ExitIP != "198.51.100.31" || snapshot.Nodes[0].CheckedAt == nil {
		t.Fatalf("upsert snapshot = %#v", snapshot)
	}
	if snapshot.Nodes[0].Scheme != "https" || snapshot.Nodes[0].Endpoint != "proxy.example.invalid:443" {
		t.Fatalf("unsanitized or incomplete endpoint metadata: %#v", snapshot.Nodes[0])
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "user:") {
		t.Fatalf("snapshot leaked proxy credentials: %s", encoded)
	}
	if err := manager.SetEnabled(true); err != nil {
		t.Fatalf("tested node could not activate: %v", err)
	}
	if err := manager.Upsert(context.Background(), "edge-a", "", true); err != nil {
		t.Fatalf("empty URL did not reuse and retest the existing URL: %v", err)
	}
	if probeCalls != 2 {
		t.Fatalf("probe calls after recheck = %d, want 2", probeCalls)
	}
	stored, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(stored), "user:secret@proxy.example.invalid") {
		t.Fatal("the pool did not persist the configured proxy URL")
	}
}

func TestAssignedNodeURLExitAndDeletionAreImmutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool.json")
	measured := "192.0.2.101"
	probeCalls := 0
	manager := Manager{Path: path, Probe: func(context.Context, string) (string, error) {
		probeCalls++
		return measured, nil
	}}
	if err := manager.Upsert(context.Background(), "bound", "http://proxy-one.example.invalid:8080", true); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	if err := manager.PrepareAccounts([]string{`C:\accounts\Alice`}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Upsert(context.Background(), "bound", "http://proxy-two.example.invalid:8080", true); err == nil {
		t.Fatal("assigned node URL change was accepted")
	}
	if probeCalls != 1 {
		t.Fatal("assigned node URL change should be refused before probing")
	}
	measured = "192.0.2.102"
	if err := manager.Upsert(context.Background(), "bound", "", true); err == nil {
		t.Fatal("assigned node exit IP change was accepted")
	}
	if err := manager.Delete("bound"); err == nil {
		t.Fatal("assigned node deletion was accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatal("refused operation changed the pool file")
	}
}

func TestPrepareAccountsIsAtomicWhenCapacityIsFull(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool.json")
	manager := Manager{Path: path, Probe: func(context.Context, string) (string, error) { return "192.0.2.111", nil }}
	if err := manager.Upsert(context.Background(), "only", "http://only.example.invalid:8080", true); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.PrepareAccounts([]string{"/accounts/alice", "/accounts/bob"}); err == nil {
		t.Fatal("over-capacity preparation unexpectedly succeeded")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatal("failed preparation partially persisted assignments")
	}
	snapshot, err := manager.Snapshot()
	if err != nil || len(snapshot.Assignments) != 0 {
		t.Fatalf("failed preparation left assignments: %#v, %v", snapshot.Assignments, err)
	}
}

func TestPrepareAccountsSerializesConcurrentAccountsByExit(t *testing.T) {
	const accounts = 8
	path := filepath.Join(t.TempDir(), "pool.json")
	nodes := make([]node, accounts)
	for i := range nodes {
		nodes[i] = checkedNode(fmt.Sprintf("node-%02d", i), fmt.Sprintf("http://proxy-%02d.example.invalid:8080", i), fmt.Sprintf("203.0.113.%d", i+1), true)
	}
	cfg := config{Enabled: boolPointer(false), Version: 1, Nodes: nodes, MaxAccountsPerExit: 1, Assignments: map[string]string{}}
	writeConfig(t, path, cfg)
	manager := Manager{Path: path}

	var wg sync.WaitGroup
	errs := make(chan error, accounts)
	for i := 0; i < accounts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- manager.PrepareAccounts([]string{fmt.Sprintf("/accounts/account-%02d", i)})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	snapshot, err := manager.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Enabled || len(snapshot.Assignments) != accounts {
		t.Fatalf("preparation changed activation or assignment count: enabled=%t assignments=%d", snapshot.Enabled, len(snapshot.Assignments))
	}
	seen := make(map[string]bool, accounts)
	for _, assignment := range snapshot.Assignments {
		if seen[assignment.ExitIP] {
			t.Errorf("accounts share exit %s", assignment.ExitIP)
		}
		seen[assignment.ExitIP] = true
	}
}

func TestSetMaxAndMalformedConfigFailWithoutOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool.json")
	cfg := config{
		Enabled:            boolPointer(false),
		Version:            1,
		Nodes:              []node{checkedNode("one", "http://one.example.invalid:8080", "192.0.2.121", true), checkedNode("two", "http://two.example.invalid:8080", "192.0.2.121", true)},
		MaxAccountsPerExit: 2,
		Assignments:        map[string]string{"alice": "one", "bob": "two"},
	}
	writeConfig(t, path, cfg)
	manager := Manager{Path: path}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.SetMaxAccountsPerExit(1); err == nil {
		t.Fatal("capacity reduction below persisted load was accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatal("rejected capacity change modified the file")
	}

	badPath := filepath.Join(t.TempDir(), "bad.json")
	bad := []byte(`{"version":1,"url":"http://user:secret@proxy.example.invalid`)
	if err := os.WriteFile(badPath, bad, 0600); err != nil {
		t.Fatal(err)
	}
	badBefore, _ := os.ReadFile(badPath)
	probeCalls := 0
	badManager := Manager{Path: badPath, Probe: func(context.Context, string) (string, error) { probeCalls++; return "192.0.2.1", nil }}
	if err := badManager.Upsert(context.Background(), "new", "http://new.example.invalid:8080", true); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("bad config update did not fail safely: %v", err)
	}
	if err := badManager.SetMaxAccountsPerExit(2); err == nil {
		t.Fatal("bad config capacity update unexpectedly succeeded")
	}
	badAfter, _ := os.ReadFile(badPath)
	if probeCalls != 0 || string(badAfter) != string(badBefore) {
		t.Fatal("bad config was probed or overwritten")
	}
}

func TestProbeExitUsesFixedEndpointsAndRejectsMismatchRedirectAndLargeBody(t *testing.T) {
	t.Run("matching", func(t *testing.T) {
		calls := 0
		got, err := ProbeExit(context.Background(), roundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls++
			if request.URL.String() != exitIPProbeEndpoints[calls-1] {
				t.Errorf("unexpected probe destination %s", request.URL)
			}
			return httpResponse(request, 200, "198.51.100.230\n"), nil
		}))
		if err != nil || got != "198.51.100.230" || calls != 2 {
			t.Fatalf("probe = %q, %v, calls=%d", got, err, calls)
		}
	})
	t.Run("mismatch", func(t *testing.T) {
		calls := 0
		if _, err := ProbeExit(context.Background(), roundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls++
			ip := "198.51.100.1"
			if calls == 2 {
				ip = "198.51.100.2"
			}
			return httpResponse(request, 200, ip), nil
		})); err == nil || calls != 2 {
			t.Fatalf("mismatch accepted or endpoints retried: calls=%d err=%v", calls, err)
		}
	})
	t.Run("redirect", func(t *testing.T) {
		calls := 0
		if _, err := ProbeExit(context.Background(), roundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls++
			return httpResponse(request, http.StatusFound, "198.51.100.1"), nil
		})); err == nil || calls != 1 {
			t.Fatalf("redirect followed or accepted: calls=%d err=%v", calls, err)
		}
	})
	t.Run("large body", func(t *testing.T) {
		calls := 0
		if _, err := ProbeExit(context.Background(), roundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls++
			return httpResponse(request, http.StatusOK, strings.Repeat("1", maxProbeBodyBytes+1)), nil
		})); err == nil || calls != 1 {
			t.Fatalf("large response accepted or retried: calls=%d err=%v", calls, err)
		}
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func httpResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: request}
}

func checkedNode(id, proxyURL, exitIP string, enabled bool) node {
	checkedAt := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	return node{ID: id, URL: proxyURL, ExitIP: exitIP, Enabled: enabled, CheckedAt: &checkedAt}
}
