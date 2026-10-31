package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Laky-64/appleservices"
)

func TestVerifyFamilyAddSessionBindingRequiresStartupAndAcceptedIdentity(t *testing.T) {
	dir := t.TempDir()
	store := fileStore{dir: dir}
	saved := &appleservices.Session{AppleID: "target@example.test", DSID: "gsa-account", Tokens: map[string]string{"com.apple.gs.idms.pet": "pet"}}
	if err := store.SaveSession(saved); err != nil {
		t.Fatal(err)
	}
	checkpoint := map[string]any{
		"session":      appleservices.Session{AppleID: saved.AppleID, DSID: "icloud-account", Tokens: map[string]string{"mmeAuthToken": "mme", "cloudKitToken": "cloudkit"}},
		"adsid":        saved.DSID,
		"service-data": map[string]any{"quota": true},
	}
	writeCheckpoint := func() {
		t.Helper()
		data, err := json.Marshal(checkpoint)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "icloud-accepted.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeCheckpoint()
	if err := store.VerifyFamilyAddSessionBinding("TARGET@example.test"); err != nil {
		t.Fatalf("matching account binding rejected: %v", err)
	}
	if err := store.VerifyFamilyAddSessionBinding("other@example.test"); err == nil {
		t.Fatal("startup Apple ID mismatch was accepted")
	}
	checkpoint["adsid"] = "other-account"
	writeCheckpoint()
	if err := store.VerifyFamilyAddSessionBinding(saved.AppleID); err == nil {
		t.Fatal("accepted checkpoint ADSID mismatch was accepted")
	}
}

func TestLoadAcceptedICloudRequiresSameSavedAccount(t *testing.T) {
	dir := t.TempDir()
	store := fileStore{dir: dir}
	saved := &appleservices.Session{AppleID: "owner@example.test", DSID: "gsa-account", Tokens: map[string]string{"com.apple.gs.idms.pet": "pet"}}
	if err := store.SaveSession(saved); err != nil {
		t.Fatal(err)
	}
	checkpoint := map[string]any{
		"session":      appleservices.Session{AppleID: saved.AppleID, DSID: "icloud-account", Tokens: map[string]string{"mmeAuthToken": "mme", "cloudKitToken": "cloudkit"}},
		"adsid":        saved.DSID,
		"service-data": map[string]any{"quota": true},
	}
	data, _ := json.Marshal(checkpoint)
	if err := os.WriteFile(filepath.Join(dir, "icloud-accepted.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	accepted, err := store.LoadAcceptedICloud()
	if err != nil {
		t.Fatal(err)
	}
	if accepted.DSID != "icloud-account" || accepted.ADSID != saved.DSID || accepted.MMEAuthToken == "" || accepted.ServiceData == nil {
		t.Fatalf("unexpected restored checkpoint: %#v", accepted)
	}
	checkpoint["adsid"] = "other-account"
	data, _ = json.Marshal(checkpoint)
	if err := os.WriteFile(filepath.Join(dir, "icloud-accepted.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadAcceptedICloud(); err == nil {
		t.Fatal("cross-account accepted checkpoint was restored")
	}
}
