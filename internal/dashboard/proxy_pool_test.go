package dashboard

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Laky-64/appleservices/internal/control"
)

func TestInvalidProxyPoolStopsWorkerBeforeProvisioning(t *testing.T) {
	root := t.TempDir()
	t.Setenv("APPLESERVICES_PROXY_POOL", filepath.Join(root, "missing-pool.json"))
	provisions := 0
	s := &Server{config: Config{Worker: filepath.Join(root, "missing-worker.exe")}, provisionMacPush: func(context.Context, string) error { provisions++; return nil }}
	accountDir := filepath.Join(root, "01-account")
	result := s.startInMode(context.Background(), accountDir, credentials{AppleID: "owner@example.test", Password: "test-only", TwoFactor: "trusted-device"}, nil, false)
	if result.OK || result.Stage != "proxy-unavailable" || provisions != 0 {
		t.Fatalf("invalid pool did not stop before worker/provisioning: stage=%s provisions=%d", result.Stage, provisions)
	}
	if _, err := os.Stat(accountDir); !os.IsNotExist(err) {
		t.Fatal("failed route created account runtime data")
	}
}

func TestInvalidProxyPoolStopsActivationHelper(t *testing.T) {
	root := t.TempDir()
	t.Setenv("APPLESERVICES_PROXY_POOL", filepath.Join(root, "missing-pool.json"))
	_, err := runActivationCommand(context.Background(), root, filepath.Join(root, "01-account"), "owner@example.test", filepath.Join(root, "missing-helper.exe"))
	if err == nil || !strings.Contains(err.Error(), "proxy pool") {
		t.Fatal("activation helper bypassed proxy resolution")
	}
}

func TestAppPasswordFactoryRequiresAccountProxyRoute(t *testing.T) {
	root := t.TempDir()
	t.Setenv("APPLESERVICES_PROXY_POOL", filepath.Join(root, "missing-pool.json"))
	service := &appPasswordService{}
	_, err := service.clientForAccount(&Account{ID: "01-account", Dir: filepath.Join(root, "01-account"), AppleID: "owner@example.test"})
	if err == nil {
		t.Fatal("shared management client bypassed account route")
	}
}

func TestRunningLegacyWorkerCannotClaimPoolIsApplied(t *testing.T) {
	root := t.TempDir()
	accountDir := filepath.Join(root, "01-account")
	if err := os.MkdirAll(accountDir, 0700); err != nil {
		t.Fatal(err)
	}
	poolPath := filepath.Join(root, "pool.json")
	pool := `{"version":1,"nodes":[{"id":"node-a","url":"http://proxy.example:8080","exit_ip":"192.0.2.1","enabled":true}],"assignments":{"01-account":"node-a"}}`
	if err := os.WriteFile(poolPath, []byte(pool), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APPLESERVICES_PROXY_POOL", poolPath)
	controller, err := control.New(accountDir)
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	s := &Server{config: Config{Dir: root, Worker: filepath.Join(root, "missing-worker.exe")}}
	data, _ := json.Marshal(Status{PID: os.Getpid(), Running: true, Authenticated: true, State: "online"})
	if err := os.WriteFile(filepath.Join(accountDir, "runtime.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	result := s.startInMode(context.Background(), accountDir, credentials{AppleID: "owner@example.test"}, nil, true)
	if result.OK || result.Stage != "proxy-restart-required" {
		t.Fatalf("legacy direct worker accepted: %#v", result)
	}
	// Once the worker reports its assigned route, reconnecting does not require
	// another login or restart.
	data, _ = json.Marshal(Status{PID: os.Getpid(), Running: true, Authenticated: true, State: "online", ProxyNodeID: "node-a", ProxyExitIP: "192.0.2.1"})
	if err := os.WriteFile(filepath.Join(accountDir, "runtime.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	result = s.startInMode(context.Background(), accountDir, credentials{AppleID: "owner@example.test"}, nil, true)
	if !result.OK {
		t.Fatalf("existing account route was rejected: %#v", result)
	}
}
