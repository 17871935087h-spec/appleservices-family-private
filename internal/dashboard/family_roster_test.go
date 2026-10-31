package dashboard

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appleservices "github.com/Laky-64/appleservices"
	"github.com/Laky-64/appleservices/internal/control"
)

func familyTestRef(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}

func familyRosterServerFixture(t *testing.T) (*Server, *Account) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "accounts", "organizer")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	saved := appleservices.Session{AppleID: "owner@example.test", DSID: "gsa-owner"}
	accepted := acceptedICloudCheckpoint{
		Session: appleservices.Session{AppleID: saved.AppleID, DSID: "mme-owner", Tokens: map[string]string{"mmeAuthToken": "token"}},
		ADSID:   saved.DSID, ServiceData: map[string]any{"ready": true},
	}
	for name, value := range map[string]any{"session.json": saved, "icloud-accepted.json": accepted} {
		data, _ := json.Marshal(value)
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	server, err := New(Config{Dir: root, Worker: filepath.Join(root, "bin", "worker.exe"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.listener.Close() })
	owner := &Account{ID: "organizer", Name: "owner", AppleID: saved.AppleID, Dir: dir}
	server.accounts = []*Account{owner}
	return server, owner
}

func familyRosterTargetFixture(t *testing.T, server *Server) *Account {
	t.Helper()
	root := filepath.Join(server.config.Dir, "accounts", "target")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	saved := appleservices.Session{AppleID: "target@example.test", DSID: "gsa-target"}
	accepted := acceptedICloudCheckpoint{
		Session: appleservices.Session{AppleID: saved.AppleID, DSID: "mme-target", Tokens: map[string]string{"mmeAuthToken": "target-token"}},
		ADSID:   saved.DSID, ServiceData: map[string]any{"ready": true},
	}
	for name, value := range map[string]any{"session.json": saved, "icloud-accepted.json": accepted} {
		data, _ := json.Marshal(value)
		if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	target := &Account{ID: "target", Name: "target", AppleID: saved.AppleID, Dir: root}
	server.accounts = append(server.accounts, target)
	return target
}

func familyRosterRequest(t *testing.T, server *Server, action control.Action) control.Result {
	t.Helper()
	body, err := json.Marshal(action)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, server.URL()+"/api/action?account=organizer", bytes.NewReader(body))
	request.Header.Set("X-App-Token", server.token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	var result control.Result
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid action response: %v", err)
	}
	if strings.Contains(response.Body.String(), "owner@example.test") || strings.Contains(response.Body.String(), "mme-owner") {
		t.Fatal("family action leaked organizer identity")
	}
	return result
}

func TestFamilyRosterRequiresOpaqueUniqueRefsAndMaskedLabels(t *testing.T) {
	valid := control.FamilyRosterProjection{
		Members:    []control.FamilyRosterMember{{Ref: familyTestRef(1), Label: "m***@example.test"}},
		TotalCount: 2,
	}
	data, _ := json.Marshal(valid)
	if _, err := parseFamilyRoster("FAMILY_ROSTER_JSON=" + string(data)); err != nil {
		t.Fatalf("valid roster rejected: %v", err)
	}
	invalid := []string{
		"FAMILY_ROSTER_JSON=" + string(data) + "\nFAMILY_ROSTER_JSON=" + string(data),
		"FAMILY_ROSTER_JSON={\"members\":[{\"ref\":\"" + familyTestRef(1) + "\",\"label\":\"member@example.test\"}],\"unidentified_count\":0,\"total_count\":2}",
		"FAMILY_ROSTER_JSON={\"members\":[{\"ref\":\"" + familyTestRef(1) + "\",\"label\":\"m***@example.test\",\"dsid\":\"123\"}],\"unidentified_count\":0,\"total_count\":2}",
		"FAMILY_ROSTER_JSON={\"members\":[{\"ref\":\"" + familyTestRef(1) + "\",\"label\":\"m***@example.test\"},{\"ref\":\"" + familyTestRef(1) + "\",\"label\":\"n***@example.test\"}],\"unidentified_count\":0,\"total_count\":3}",
		"FAMILY_ROSTER_JSON={\"members\":[],\"unidentified_count\":2,\"total_count\":1}",
	}
	for _, output := range invalid {
		if _, err := parseFamilyRoster(output); err == nil {
			t.Fatal("unsafe or ambiguous family roster accepted")
		}
	}
}

func TestOrganizerRosterAndRemovalNeedNoTargetAccount(t *testing.T) {
	server, owner := familyRosterServerFixture(t)
	ref := familyTestRef(7)
	calls := 0
	server.familyRosterReader = func(_ context.Context, _ string, dir, key string) (*control.FamilyRosterProjection, error) {
		if dir != owner.Dir || !validFamilyMemberRef(key) {
			t.Fatal("roster did not use the bound organizer and valid reference key")
		}
		return &control.FamilyRosterProjection{Members: []control.FamilyRosterMember{{Ref: ref, Label: "m***@example.test"}}, TotalCount: 2}, nil
	}
	server.familyRefRemover = func(_ context.Context, _ string, dir, key, selected string) (*control.FamilyInfo, string, error) {
		calls++
		if dir != owner.Dir || key != server.familyRosterKey || selected != ref {
			t.Fatal("removal was not bound to organizer and selected opaque reference")
		}
		return &control.FamilyInfo{Member: true, Organizer: true, Organizers: 1, Self: 1, Members: 1}, "confirmed", nil
	}
	roster := familyRosterRequest(t, server, control.Action{Action: "family-roster"})
	if !roster.OK || roster.FamilyRoster == nil || len(roster.FamilyRoster.Members) != 1 {
		t.Fatalf("organizer roster failed: %#v", roster)
	}
	removed := familyRosterRequest(t, server, control.Action{Action: "family-remove-ref", Code: ref})
	if !removed.OK || removed.Stage != "family-member-removed" || calls != 1 || len(server.accounts) != 1 {
		t.Fatalf("organizer-only removal failed: %#v, calls=%d", removed, calls)
	}
	if _, err := os.Stat(filepath.Join(owner.Dir, ".family-remove-pending")); !os.IsNotExist(err) {
		t.Fatal("confirmed removal left an intent marker")
	}
}

func TestUnknownOrganizerRemovalBlocksAnotherSubmission(t *testing.T) {
	server, _ := familyRosterServerFixture(t)
	calls := 0
	server.familyRefRemover = func(context.Context, string, string, string, string) (*control.FamilyInfo, string, error) {
		calls++
		return nil, "unknown", errors.New("private upstream error")
	}
	first := familyRosterRequest(t, server, control.Action{Action: "family-remove-ref", Code: familyTestRef(1)})
	second := familyRosterRequest(t, server, control.Action{Action: "family-remove-ref", Code: familyTestRef(2)})
	if first.OK || second.OK || first.Stage != "family-remove-unknown" || second.Stage != "family-remove-unknown" || calls != 1 {
		t.Fatalf("unknown removal was not blocked: first=%#v second=%#v calls=%d", first, second, calls)
	}
	if strings.Contains(first.Message, "private upstream error") {
		t.Fatal("upstream error leaked")
	}
	owner := server.accounts[0]
	if _, err := os.Stat(filepath.Join(owner.Dir, ".family-remove-pending")); err != nil {
		t.Fatal("unknown outcome did not preserve a durable intent")
	}
	restarted, err := New(Config{Dir: server.config.Dir, Worker: server.config.Worker, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restarted.listener.Close() })
	restarted.accounts = []*Account{owner}
	restarted.familyRefRemover = func(context.Context, string, string, string, string) (*control.FamilyInfo, string, error) {
		t.Fatal("a restarted dashboard retried an unconfirmed removal")
		return nil, "", nil
	}
	afterRestart := familyRosterRequest(t, restarted, control.Action{Action: "family-remove-ref", Code: familyTestRef(3)})
	if afterRestart.OK || afterRestart.Stage != "family-remove-unknown" {
		t.Fatalf("restart lost the uncertain outcome: %#v", afterRestart)
	}
}

func TestUnknownOpaqueRemovalBlocksLegacyFamilyRemoval(t *testing.T) {
	server, owner := familyRosterServerFixture(t)
	target := familyRosterTargetFixture(t, server)
	refCalls, legacyCalls := 0, 0
	server.familyRefRemover = func(context.Context, string, string, string, string) (*control.FamilyInfo, string, error) {
		refCalls++
		return nil, "unknown", errors.New("synthetic uncertain outcome")
	}
	server.familyPoolRemover = func(context.Context, *Account, *Account) (*control.FamilyInfo, *control.FamilyInfo, error) {
		legacyCalls++
		return nil, nil, errors.New("legacy runner must not run")
	}
	newResult := familyRosterRequest(t, server, control.Action{Action: "family-remove-ref", Code: familyTestRef(9)})
	legacyResult := server.removeFamilyMember(context.Background(), owner, target.ID)
	if newResult.OK || newResult.Stage != "family-remove-unknown" || legacyResult.OK || legacyResult.Stage != "family-remove-unknown" || refCalls != 1 || legacyCalls != 0 {
		t.Fatalf("legacy removal bypassed an unknown opaque removal: new=%#v legacy=%#v refCalls=%d legacyCalls=%d", newResult, legacyResult, refCalls, legacyCalls)
	}
	if _, err := os.Stat(filepath.Join(owner.Dir, ".family-remove-pending")); err != nil {
		t.Fatal("unknown opaque removal lost its durable intent")
	}
}

func TestLegacyRemovalHoldsMutexAgainstOpaqueRemoval(t *testing.T) {
	server, owner := familyRosterServerFixture(t)
	target := familyRosterTargetFixture(t, server)
	entered, release := make(chan struct{}), make(chan struct{})
	server.familyPoolRemover = func(ctx context.Context, _ *Account, _ *Account) (*control.FamilyInfo, *control.FamilyInfo, error) {
		close(entered)
		select {
		case <-release:
			return nil, nil, errors.New("synthetic interrupted legacy removal")
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
	refCalls := 0
	server.familyRefRemover = func(context.Context, string, string, string, string) (*control.FamilyInfo, string, error) {
		refCalls++
		return nil, "unknown", errors.New("opaque runner must not start while legacy removal is active")
	}
	legacyDone := make(chan control.Result, 1)
	go func() { legacyDone <- server.removeFamilyMember(context.Background(), owner, target.ID) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("legacy removal did not enter its serialized runner")
	}
	newStarted, newDone := make(chan struct{}), make(chan control.Result, 1)
	go func() {
		close(newStarted)
		newDone <- server.familyRemoveRefAction(context.Background(), owner, familyTestRef(10))
	}()
	<-newStarted
	select {
	case result := <-newDone:
		t.Fatalf("opaque removal bypassed the active legacy mutex: %#v", result)
	case <-time.After(75 * time.Millisecond):
	}
	close(release)
	legacyResult := <-legacyDone
	newResult := <-newDone
	if legacyResult.OK || legacyResult.Stage != "family-remove-unknown" || newResult.OK || newResult.Stage != "family-remove-unknown" || refCalls != 0 {
		t.Fatalf("legacy unknown state did not serialize and block opaque removal: legacy=%#v new=%#v refCalls=%d", legacyResult, newResult, refCalls)
	}
}

func TestLegacyUnknownRemovalMarkerBlocksOpaqueRemovalAfterRestart(t *testing.T) {
	server, owner := familyRosterServerFixture(t)
	target := familyRosterTargetFixture(t, server)
	legacyCalls := 0
	server.familyPoolRemover = func(context.Context, *Account, *Account) (*control.FamilyInfo, *control.FamilyInfo, error) {
		legacyCalls++
		return nil, nil, errors.New("synthetic interrupted legacy removal")
	}
	legacyResult := server.removeFamilyMember(context.Background(), owner, target.ID)
	if legacyResult.OK || legacyResult.Stage != "family-remove-unknown" || legacyCalls != 1 {
		t.Fatalf("legacy unknown outcome was not recorded: %#v calls=%d", legacyResult, legacyCalls)
	}
	if _, err := os.Stat(filepath.Join(owner.Dir, ".family-remove-pending")); err != nil {
		t.Fatal("legacy unknown outcome did not retain its durable intent")
	}

	restarted, err := New(Config{Dir: server.config.Dir, Worker: server.config.Worker, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restarted.listener.Close() })
	restarted.accounts = []*Account{owner, target}
	refCalls := 0
	restarted.familyRefRemover = func(context.Context, string, string, string, string) (*control.FamilyInfo, string, error) {
		refCalls++
		return nil, "confirmed", nil
	}
	result := familyRosterRequest(t, restarted, control.Action{Action: "family-remove-ref", Code: familyTestRef(11)})
	if result.OK || result.Stage != "family-remove-unknown" || refCalls != 0 {
		t.Fatalf("restart allowed an opaque removal despite the old pending intent: result=%#v calls=%d", result, refCalls)
	}
}

func TestNotSubmittedOrganizerRemovalDoesNotCreateUnknownBlock(t *testing.T) {
	server, _ := familyRosterServerFixture(t)
	calls := 0
	server.familyRefRemover = func(context.Context, string, string, string, string) (*control.FamilyInfo, string, error) {
		calls++
		return nil, "not_submitted", errors.New("preflight failed")
	}
	for i := 0; i < 2; i++ {
		result := familyRosterRequest(t, server, control.Action{Action: "family-remove-ref", Code: familyTestRef(byte(i + 1))})
		if result.OK || result.Stage != "family-remove-preflight" {
			t.Fatalf("unexpected preflight result: %#v", result)
		}
	}
	if calls != 2 {
		t.Fatalf("preflight failure incorrectly blocked future explicit requests: %d", calls)
	}
}

func TestFamilyRemoveOutcomeRejectsMissingOrDuplicateMarkers(t *testing.T) {
	for _, output := range []string{"", "FAMILY_REMOVE_OUTCOME=other", "FAMILY_REMOVE_OUTCOME=confirmed\nFAMILY_REMOVE_OUTCOME=not_submitted"} {
		if _, err := parseFamilyRemoveOutcome(output); err == nil {
			t.Fatal("invalid family removal outcome accepted")
		}
	}
	if got, err := parseFamilyRemoveOutcome("FAMILY_REMOVE_OUTCOME=confirmed"); err != nil || got != "confirmed" {
		t.Fatalf("valid family outcome rejected: %q %v", got, err)
	}
}
