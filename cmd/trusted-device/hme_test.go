package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Laky-64/appleservices/icloud"
	"github.com/Laky-64/appleservices/internal/control"
)

func TestHMESessionFailureRetainsSafeSetupStatus(t *testing.T) {
	err := fmt.Errorf("accountLogin: %w", &icloud.HMEWebSetupError{HTTPStatus: 421, FailureKind: "http"})
	result := hmeSessionFailure(err)
	if result.OK || result.Stage != "hme-session" || result.HTTPStatus != 421 || !strings.Contains(result.Message, "HTTP 421") {
		t.Fatalf("setup status was hidden from the dashboard: %#v", result)
	}
	result = hmeSessionFailure(icloud.ErrHMEWebRepairRequired)
	if result.OK || result.Stage != "hme-terms-required" || result.HTTPStatus != 0 {
		t.Fatal("terms repair was not distinguished from setup rejection")
	}
}

func TestReachableVerificationReconcilesAppliedAppleMutation(t *testing.T) {
	info := &icloud.HideMyEmailInfo{ForwardToEmails: []string{"primary@example.test", "new@example.test"}}
	if !reachableVerificationApplied(errors.New("account readback is stale"), info, "NEW@example.test") {
		t.Fatal("Apple-applied reachable email was not reconciled from HME candidates")
	}
	if reachableVerificationApplied(errors.New("verification rejected"), info, "missing@example.test") {
		t.Fatal("missing HME candidate was treated as a successful verification")
	}
}

func TestRequireHMEFamilyMemberRejectsOrganizerAndStaleCache(t *testing.T) {
	now := time.Now().UTC()
	write := func(dir string, checkedAt time.Time, family control.FamilyInfo) {
		record := hmeFamilyCache{Version: 1, AccountID: filepath.Base(dir), CheckedAt: checkedAt, Family: family}
		data, _ := json.Marshal(record)
		if err := os.WriteFile(filepath.Join(dir, "family-status.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	member := control.FamilyInfo{Member: true, Organizers: 1, Self: 1, StorageKnown: true, StorageParticipating: true, StorageAvailable: true, StorageEnabled: true, StorageBytes: 50 << 30}
	dir := filepath.Join(t.TempDir(), "01-primary")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	write(dir, now, member)
	if err := requireHMEFamilyMember(dir, now); err != nil {
		t.Fatal(err)
	}
	member.Organizer = true
	write(dir, now, member)
	if err := requireHMEFamilyMember(dir, now); err == nil {
		t.Fatal("organizer was accepted")
	}
	member.Organizer = false
	write(dir, now.Add(-16*time.Minute), member)
	if err := requireHMEFamilyMember(dir, now); err == nil {
		t.Fatal("stale family cache was accepted")
	}
}
