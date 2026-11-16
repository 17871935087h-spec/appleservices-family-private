package egresspool

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestResolvePinsAssignmentAcrossCalls(t *testing.T) {
	poolPath := writePool(t, testConfig(1,
		node{ID: "west", URL: "http://user:secret@proxy.example:8080", ExitIP: "192.0.2.11", Enabled: true},
		node{ID: "east", URL: "socks5h://other:password@proxy.example:1080", ExitIP: "192.0.2.12", Enabled: true},
	))
	t.Setenv(PoolEnv, poolPath)

	first, err := Resolve(`C:\accounts\Alice`)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Resolve(filepath.Join("/accounts", "ALICE"))
	if err != nil {
		t.Fatal(err)
	}
	if first.NodeID != second.NodeID || first.URL != second.URL || first.ExitIP != second.ExitIP {
		t.Fatalf("assignment changed across calls: first=%s second=%s", first, second)
	}
	if !first.Enabled {
		t.Fatal("configured route was not enabled")
	}

	data, err := os.ReadFile(poolPath)
	if err != nil {
		t.Fatal(err)
	}
	var stored config
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	if got := stored.Assignments["alice"]; got != first.NodeID {
		t.Fatalf("persisted assignment = %q, want %q", got, first.NodeID)
	}
}

func TestResolveDefaultsExitCapacityToOne(t *testing.T) {
	poolPath := writePool(t, testConfig(0,
		node{ID: "one", URL: "http://one.proxy.example", ExitIP: "192.0.2.31", Enabled: true},
		node{ID: "two", URL: "https://two.proxy.example", ExitIP: "192.0.2.32", Enabled: true},
	))
	t.Setenv(PoolEnv, poolPath)
	if _, err := Resolve("/accounts/one"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := Inspect()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.MaxAccountsPerExit != 1 {
		t.Fatalf("default max_accounts_per_exit = %d, want 1", snapshot.MaxAccountsPerExit)
	}
}

func TestResolveDeduplicatesCapacityByExitIP(t *testing.T) {
	poolPath := writePool(t, testConfig(1,
		node{ID: "edge-a", URL: "http://proxy-a.example:8080", ExitIP: "192.0.2.20", Enabled: true},
		node{ID: "edge-a-alt", URL: "https://proxy-a-alt.example:8443", ExitIP: "192.0.2.20", Enabled: true},
		node{ID: "edge-b", URL: "socks5://proxy-b.example:1080", ExitIP: "192.0.2.21", Enabled: true},
	))
	t.Setenv(PoolEnv, poolPath)

	first, err := Resolve("/accounts/one")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Resolve("/accounts/two")
	if err != nil {
		t.Fatal(err)
	}
	if first.ExitIP == second.ExitIP {
		t.Fatalf("accounts were assigned the same exit IP %s", first.ExitIP)
	}
	if second.NodeID != "edge-b" {
		t.Fatalf("second account assigned to node %q, want edge-b", second.NodeID)
	}
	if _, err := Resolve("/accounts/three"); err == nil {
		t.Fatal("expected exhaustion with two distinct exits at capacity one")
	}
}

func TestResolveConcurrentAllocationsAreSerialized(t *testing.T) {
	const accounts = 10
	nodes := make([]node, accounts)
	for i := range nodes {
		nodes[i] = node{
			ID:      fmt.Sprintf("node-%02d", i),
			URL:     fmt.Sprintf("http://proxy-%02d.example:8080", i),
			ExitIP:  fmt.Sprintf("198.51.100.%d", i+1),
			Enabled: true,
		}
	}
	poolPath := writePool(t, testConfig(1, nodes...))
	t.Setenv(PoolEnv, poolPath)

	var wg sync.WaitGroup
	errs := make(chan error, accounts)
	routes := make(chan Route, accounts)
	for i := 0; i < accounts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			route, err := Resolve(fmt.Sprintf("/accounts/account-%02d", i))
			if err != nil {
				errs <- err
				return
			}
			routes <- route
		}(i)
	}
	wg.Wait()
	close(errs)
	close(routes)
	for err := range errs {
		t.Errorf("Resolve: %v", err)
	}
	seen := make(map[string]bool, accounts)
	for route := range routes {
		if seen[route.ExitIP] {
			t.Errorf("duplicate exit IP assignment %q", route.ExitIP)
		}
		seen[route.ExitIP] = true
	}
	if len(seen) != accounts {
		t.Fatalf("received %d unique routes, want %d", len(seen), accounts)
	}
	snapshot, err := Inspect()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Assignments) != accounts {
		t.Fatalf("persisted %d assignments, want %d", len(snapshot.Assignments), accounts)
	}
}

func TestResolveSerializesAcrossProcesses(t *testing.T) {
	const accounts = 8
	nodes := make([]node, accounts)
	for i := range nodes {
		nodes[i] = node{
			ID:      fmt.Sprintf("proc-node-%02d", i),
			URL:     fmt.Sprintf("http://proc-proxy-%02d.example:8080", i),
			ExitIP:  fmt.Sprintf("203.0.113.%d", i+10),
			Enabled: true,
		}
	}
	poolPath := writePool(t, testConfig(1, nodes...))
	t.Setenv(PoolEnv, poolPath)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	commands := make([]*exec.Cmd, accounts)
	for i := range commands {
		cmd := exec.Command(executable, "-test.run=^TestEgressPoolProcessHelper$")
		cmd.Env = append(os.Environ(),
			"EGRESSPOOL_PROCESS_HELPER=1",
			fmt.Sprintf("EGRESSPOOL_PROCESS_ACCOUNT=/accounts/process-%02d", i),
		)
		commands[i] = cmd
	}
	var wg sync.WaitGroup
	errs := make(chan error, accounts)
	for _, cmd := range commands {
		wg.Add(1)
		go func(cmd *exec.Cmd) {
			defer wg.Done()
			if output, err := cmd.CombinedOutput(); err != nil {
				errs <- fmt.Errorf("child process: %w: %s", err, strings.TrimSpace(string(output)))
			}
		}(cmd)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	snapshot, err := Inspect()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Assignments) != accounts {
		t.Fatalf("persisted %d cross-process assignments, want %d", len(snapshot.Assignments), accounts)
	}
	seen := make(map[string]bool, accounts)
	for _, assignment := range snapshot.Assignments {
		if seen[assignment.ExitIP] {
			t.Errorf("cross-process allocations shared exit %s", assignment.ExitIP)
		}
		seen[assignment.ExitIP] = true
	}
}

func TestEgressPoolProcessHelper(t *testing.T) {
	if os.Getenv("EGRESSPOOL_PROCESS_HELPER") != "1" {
		return
	}
	route, err := Resolve(os.Getenv("EGRESSPOOL_PROCESS_ACCOUNT"))
	if err != nil {
		t.Fatal(err)
	}
	if !route.Enabled || route.NodeID == "" || route.URL == "" {
		t.Fatal("child process did not receive an enabled route")
	}
}

func TestResolveFailsClosedForCorruptPoolAndMissingNode(t *testing.T) {
	secret := "never-print-this-password"
	poolPath := filepath.Join(t.TempDir(), "pool.json")
	if err := os.WriteFile(poolPath, []byte(`{"version":1,"nodes":[{"url":"http://u:`+secret+`@proxy.example`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(PoolEnv, poolPath)
	if _, err := Resolve("/accounts/alice"); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("corrupt config should fail without exposing credentials: %v", err)
	}

	writeConfig(t, poolPath, testConfig(1,
		node{ID: "present", URL: "http://proxy.example:8080", ExitIP: "203.0.113.9", Enabled: true},
	))
	data, err := os.ReadFile(poolPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Assignments = map[string]string{"alice": "removed-node"}
	writeConfig(t, poolPath, cfg)
	if _, err := Resolve("/accounts/alice"); err == nil {
		t.Fatal("missing assigned node must fail closed")
	}
}

func TestResolveFailsClosedForAssignedDisabledNodeAndOversizedPool(t *testing.T) {
	poolPath := writePool(t, testConfig(1,
		node{ID: "disabled", URL: "http://proxy.example.invalid:8080", ExitIP: "192.0.2.77", Enabled: false},
	))
	data, err := os.ReadFile(poolPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Assignments = map[string]string{"alice": "disabled"}
	writeConfig(t, poolPath, cfg)
	t.Setenv(PoolEnv, poolPath)
	if _, err := Resolve("/accounts/alice"); err == nil {
		t.Fatal("persisted assignment to a disabled node must fail closed")
	}

	poolPath = filepath.Join(t.TempDir(), "oversized.json")
	oversized := bytes.Repeat([]byte{'x'}, maxConfigBytes+1)
	copy(oversized, `{"version":1,"secret":"oversized-proxy-secret`)
	if err := os.WriteFile(poolPath, oversized, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(PoolEnv, poolPath)
	if _, err := Resolve("/accounts/alice"); err == nil || strings.Contains(err.Error(), "oversized-proxy-secret") {
		t.Fatalf("oversized config should fail without echoing contents: %v", err)
	}
}

func TestEnvironmentReplacesProxyVariablesAndPreservesLoopbackBypass(t *testing.T) {
	poolPath := writePool(t, testConfig(1,
		node{ID: "node", URL: "socks5h://user:secret@proxy.example:1080", ExitIP: "203.0.113.44", Enabled: true},
	))
	t.Setenv(PoolEnv, poolPath)
	base := []string{
		"Path=C:\\bin",
		"http_proxy=http://old.example",
		"HTTPS_PROXY=http://old.example",
		"all_proxy=socks5://old.example",
		"No_Proxy=*",
		"APPLESERVICES_SOCKS_PROXY=socks5://old.example",
		"store_proxy=old",
		"APPLESERVICES_STORE_PROXY=old",
		"APPLESERVICES_ACCOUNT_PROXY=http://old.example",
		"OTHER=value",
	}
	got, err := Environment(base, "/accounts/alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(base) != 10 || base[1] != "http_proxy=http://old.example" {
		t.Fatal("Environment mutated its input")
	}
	values := envMap(got)
	for _, removed := range []string{"http_proxy", "all_proxy", "No_Proxy", "APPLESERVICES_SOCKS_PROXY", "store_proxy", "APPLESERVICES_STORE_PROXY"} {
		if _, exists := values[removed]; exists {
			t.Errorf("old proxy key %q remains", removed)
		}
	}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "APPLESERVICES_ACCOUNT_PROXY"} {
		if values[key] != "socks5h://user:secret@proxy.example:1080" {
			t.Errorf("%s = %q", key, values[key])
		}
	}
	if values["NO_PROXY"] != "localhost,127.0.0.1,::1" || values["Path"] != `C:\bin` || values["OTHER"] != "value" {
		t.Fatalf("unexpected environment values: %#v", values)
	}
}

func TestApplyInstallsOnlyTheSelectedAccountProxy(t *testing.T) {
	poolPath := writePool(t, testConfig(1,
		node{ID: "node", URL: "https://user:pass@proxy.example.invalid", ExitIP: "203.0.113.45", Enabled: true},
	))
	t.Setenv(PoolEnv, poolPath)
	for _, key := range []string{"http_proxy", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "APPLESERVICES_SOCKS_PROXY", "STORE_PROXY", "APPLESERVICES_STORE_PROXY", "APPLESERVICES_ACCOUNT_PROXY"} {
		t.Setenv(key, "http://old-proxy.example.invalid")
	}
	if err := Apply("/accounts/alice"); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "APPLESERVICES_ACCOUNT_PROXY"} {
		if got := os.Getenv(key); got != "https://user:pass@proxy.example.invalid:443" {
			t.Errorf("%s = %q", key, got)
		}
	}
	if got := os.Getenv("NO_PROXY"); got != "localhost,127.0.0.1,::1" {
		t.Errorf("NO_PROXY = %q", got)
	}
	for _, key := range []string{"APPLESERVICES_SOCKS_PROXY", "STORE_PROXY", "APPLESERVICES_STORE_PROXY"} {
		if got := os.Getenv(key); got != "" {
			t.Errorf("legacy proxy key %s remains set", key)
		}
	}
}

func TestDisabledEnvironmentReturnsCopy(t *testing.T) {
	t.Setenv(PoolEnv, "")
	base := []string{"A=1", "B=2"}
	got, err := Environment(base, "")
	if err != nil {
		t.Fatal(err)
	}
	got[0] = "changed"
	if base[0] != "A=1" {
		t.Fatal("disabled Environment did not return an independent copy")
	}
}

func TestRouteFormattingAndJSONRedactURL(t *testing.T) {
	route := Route{Enabled: true, NodeID: "node", URL: "http://user:secret@proxy.example:8080", ExitIP: "192.0.2.1"}
	encoded, err := json.Marshal(route)
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{string(encoded), route.String(), fmt.Sprintf("%#v", route)} {
		if strings.Contains(rendered, "secret") || strings.Contains(rendered, "proxy.example") {
			t.Fatalf("route output leaked proxy URL: %s", rendered)
		}
	}
}

func TestInspectDoesNotExposeProxyURLs(t *testing.T) {
	poolPath := writePool(t, testConfig(1,
		node{ID: "node", URL: "http://user:secret@proxy.example:8080", ExitIP: "192.0.2.99", Enabled: true},
	))
	t.Setenv(PoolEnv, poolPath)
	if _, err := Resolve("/accounts/alice"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := Inspect()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "user:secret@") {
		t.Fatalf("inspection output leaked proxy URL: %s", encoded)
	}
	if !strings.Contains(string(encoded), "proxy.example:8080") {
		t.Fatal("inspection output omitted the sanitized endpoint")
	}
	if len(snapshot.Nodes) != 1 || len(snapshot.Assignments) != 1 || len(snapshot.Nodes[0].AssignedAccounts) != 1 {
		t.Fatalf("incomplete safe summary: %#v", snapshot)
	}
}

func TestResolveSupportsDefaultHTTPPortsAndRejectsUnsafeProxyURLs(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		wantURL    string
		wantErr    bool
		secretLeak string
	}{
		{name: "http default", url: "http://proxy.example", wantURL: "http://proxy.example:80"},
		{name: "https default", url: "https://user:pass@proxy.example/", wantURL: "https://user:pass@proxy.example:443/"},
		{name: "socks default", url: "socks5h://proxy.example", wantURL: "socks5h://proxy.example:1080"},
		{name: "path rejected", url: "http://user:topsecret@proxy.example/private", wantErr: true, secretLeak: "topsecret"},
		{name: "query rejected", url: "http://user:topsecret@proxy.example?token=abc", wantErr: true, secretLeak: "topsecret"},
		{name: "empty password rejected", url: "http://user:@proxy.example:8080", wantErr: true},
		{name: "empty username rejected", url: "http://:pass@proxy.example:8080", wantErr: true},
		{name: "missing password rejected", url: "http://user@proxy.example:8080", wantErr: true},
		{name: "invalid port rejected", url: "http://proxy.example:70000", wantErr: true},
		{name: "empty port rejected", url: "http://proxy.example:", wantErr: true},
		{name: "empty query rejected", url: "http://proxy.example?", wantErr: true},
		{name: "empty fragment rejected", url: "http://proxy.example#", wantErr: true},
		{name: "path slash accepted", url: "http://proxy.example:8080/", wantURL: "http://proxy.example:8080/"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			poolPath := writePool(t, testConfig(1,
				node{ID: "node", URL: test.url, ExitIP: "192.0.2.201", Enabled: true},
			))
			t.Setenv(PoolEnv, poolPath)
			route, err := Resolve("/accounts/url-case")
			if test.wantErr {
				if err == nil {
					t.Fatal("expected invalid URL to fail closed")
				}
				if test.secretLeak != "" && strings.Contains(err.Error(), test.secretLeak) {
					t.Fatal("error exposed URL credentials")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if route.URL != test.wantURL {
				t.Fatalf("route URL = %q, want %q", route.URL, test.wantURL)
			}
		})
	}
}

func TestResolveRejectsPreexistingExitOvercapacity(t *testing.T) {
	cfg := testConfig(1,
		node{ID: "one", URL: "http://one.example:8080", ExitIP: "192.0.2.220", Enabled: true},
		node{ID: "two", URL: "https://two.example:443", ExitIP: "192.0.2.220", Enabled: true},
	)
	cfg.Assignments = map[string]string{"alice": "one", "bob": "two"}
	poolPath := writePool(t, cfg)
	t.Setenv(PoolEnv, poolPath)
	if _, err := Resolve("/accounts/alice"); err == nil || !strings.Contains(err.Error(), "capacity") {
		t.Fatalf("over-capacity existing assignments should fail: %v", err)
	}
}

func testConfig(max int, nodes ...node) config {
	return config{Version: 1, Nodes: nodes, MaxAccountsPerExit: max}
}

func writePool(t *testing.T, cfg config) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pool.json")
	writeConfig(t, path, cfg)
	return path
}

func writeConfig(t *testing.T, path string, cfg config) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func envMap(entries []string) map[string]string {
	values := make(map[string]string, len(entries))
	for _, entry := range entries {
		key, value, _ := strings.Cut(entry, "=")
		values[key] = value
	}
	return values
}
