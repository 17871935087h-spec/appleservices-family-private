package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadPasswordBounds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		valid bool
	}{
		{"normal", "fixture-password\n", true},
		{"blank", " \n", false},
		{"nul", "fixture\x00password\n", false},
		{"oversize", strings.Repeat("x", 1025) + "\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			password, err := readPassword(strings.NewReader(tc.input))
			defer clear(password)
			if (err == nil) != tc.valid {
				t.Fatalf("input validation failed: %v", err)
			}
		})
	}
}

func TestSelectAccountRejectsAmbiguousOrEscapedRegistry(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("account vault is Windows only")
	}
	root := t.TempDir()
	if !strings.EqualFold(filepath.VolumeName(root), `D:`) {
		t.Fatal("test temporary directory must be on D:")
	}
	accountDir := filepath.Join(root, "accounts", "member-01")
	if err := os.MkdirAll(accountDir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "accounts.json")
	records := registry{}
	records.Accounts = append(records.Accounts, struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		AppleID   string `json:"apple_id"`
		Dir       string `json:"dir"`
		CreatedAt string `json:"created_at,omitempty"`
	}{ID: "member-01", AppleID: "member@example.invalid", Dir: accountDir})
	write := func() {
		t.Helper()
		data, err := json.Marshal(records)
		if err != nil || os.WriteFile(file, data, 0o600) != nil {
			t.Fatal("fixture registry could not be written")
		}
	}
	write()
	dir, id, err := selectAccount(file, "member-01")
	if err != nil || !strings.EqualFold(dir, accountDir) || id != "member@example.invalid" {
		t.Fatalf("valid binding rejected: %v", err)
	}
	records.Accounts = append(records.Accounts, records.Accounts[0])
	write()
	if _, _, err := selectAccount(file, "member-01"); err == nil {
		t.Fatal("duplicate registry identity accepted")
	}
	records.Accounts = records.Accounts[:1]
	records.Accounts[0].Dir = filepath.Dir(root)
	write()
	if _, _, err := selectAccount(file, "member-01"); err == nil {
		t.Fatal("directory outside the registry root was accepted")
	}
}
