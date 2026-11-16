package dashboard

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestListAccountsProjectsPushAndVerificationStatus(t *testing.T) {
	dir := t.TempDir()
	account := &Account{ID: "account-a", Name: "owner", AppleID: "owner@example.test", Dir: dir}
	status := Status{
		PID:                  os.Getpid(),
		Running:              true,
		PushConnected:        false,
		Authenticated:        true,
		VerificationRequired: true,
		State:                "refresh_failed",
	}
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "runtime.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	worker, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		config:   Config{Worker: worker},
		accounts: []*Account{account},
	}

	views := server.listAccounts(context.Background())
	if len(views) != 1 {
		t.Fatalf("account views = %d, want 1", len(views))
	}
	view := views[0]
	if view.State != "refresh_failed" || !view.Running || !view.Authenticated || view.PushConnected || !view.VerificationRequired {
		t.Fatalf("account view did not preserve worker readiness fields: %#v", view)
	}
	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["push_connected"] != false || fields["verification_required"] != true {
		t.Fatalf("account view JSON omitted readiness fields: %s", encoded)
	}
}
