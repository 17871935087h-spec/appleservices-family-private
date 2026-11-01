package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestResumedSessionChallengeIsSavedAndStops(t *testing.T) {
	dir := t.TempDir()
	status := runtimeStatus{PID: 123, Running: true}

	err := stopResumedSessionOnVerification(true, true, &status, dir)
	if !errors.Is(err, errVerificationRequired) {
		t.Fatalf("resume challenge error = %v, want %v", err, errVerificationRequired)
	}
	if status.State != "verification_required" || !status.VerificationRequired {
		t.Fatalf("in-memory status = %+v, want verification required", status)
	}

	data, err := os.ReadFile(filepath.Join(dir, "runtime.json"))
	if err != nil {
		t.Fatalf("read saved runtime status: %v", err)
	}
	var saved runtimeStatus
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatalf("decode saved runtime status: %v", err)
	}
	if saved.State != "verification_required" || !saved.VerificationRequired {
		t.Fatalf("saved status = %+v, want verification required", saved)
	}
}

func TestResumedSessionVerificationGuardDoesNotStopOtherLogins(t *testing.T) {
	for _, test := range []struct {
		name           string
		resumeSession  bool
		needsTwoFactor bool
	}{
		{name: "password login", needsTwoFactor: true},
		{name: "verified resume", resumeSession: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			status := runtimeStatus{}
			err := stopResumedSessionOnVerification(test.resumeSession, test.needsTwoFactor, &status, dir)
			if err != nil {
				t.Fatalf("guard error = %v, want nil", err)
			}
			if status.State == "verification_required" || status.VerificationRequired {
				t.Fatalf("guard changed status unexpectedly: %+v", status)
			}
			if _, err := os.Stat(filepath.Join(dir, "runtime.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("guard wrote runtime status for a non-resume challenge: stat error = %v", err)
			}
		})
	}
}
