package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Laky-64/appleservices"
)

func TestResolveFamilyAddPasswordUsesOnlyBoundOneShotOrExistingPassword(t *testing.T) {
	dir := t.TempDir()
	store := fileStore{dir: dir}
	saved := &appleservices.Session{AppleID: "target@example.test", DSID: "gsa-account", Tokens: map[string]string{"com.apple.gs.idms.pet": "pet"}}
	if err := store.SaveSession(saved); err != nil {
		t.Fatal(err)
	}
	checkpoint := map[string]any{
		"session":      appleservices.Session{AppleID: saved.AppleID, DSID: "icloud-account", Tokens: map[string]string{"mmeAuthToken": "mme"}},
		"adsid":        saved.DSID,
		"service-data": map[string]any{"verified": true},
	}
	data, _ := json.Marshal(checkpoint)
	if err := os.WriteFile(filepath.Join(dir, "icloud-accepted.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	secret := "one-shot-secret"
	got, oneShot, stage := resolveFamilyAddPassword("target@example.test", secret, "TARGET@example.test", dir, "startup-secret", true, false)
	if got != secret || !oneShot || stage != "" {
		t.Fatalf("bound one-shot credential rejected: got=%q oneShot=%v stage=%q", got, oneShot, stage)
	}
	got, oneShot, stage = resolveFamilyAddPassword("target@example.test", "", "target@example.test", dir, "startup-secret", true, false)
	if got != "" || !oneShot || stage != "family-binding" {
		t.Fatalf("missing one-shot password fell back to startup password: got=%q oneShot=%v stage=%q", got, oneShot, stage)
	}
	got, oneShot, stage = resolveFamilyAddPassword("", "", "target@example.test", dir, "", true, false)
	if got != "" || oneShot || stage != "family-worker-unready" {
		t.Fatalf("legacy passwordless action was not rejected: got=%q oneShot=%v stage=%q", got, oneShot, stage)
	}
	got, oneShot, stage = resolveFamilyAddPassword("other@example.test", secret, "target@example.test", dir, "startup-secret", true, false)
	if got != "" || !oneShot || stage != "family-binding" {
		t.Fatalf("cross-account credential was accepted: got=%q oneShot=%v stage=%q", got, oneShot, stage)
	}
}
