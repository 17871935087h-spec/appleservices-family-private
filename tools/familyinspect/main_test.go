package main

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestSafeFamilyUIFormsOmitsValuesAndResolvesAppleAction(t *testing.T) {
	origin, _ := url.Parse("https://setup.icloud.com/setup/mac/family/setupFamilyUI")
	forms := safeFamilyUIForms(origin, []byte(`<html><form method="post" action="/setup/familykit/macos/addFamilyMember"><input type="hidden" name="familyId" value="private"><input name="email" value="private@example.test"><button type="submit" name="continue" value="private">Continue</button></form></html>`))
	if len(forms) != 1 || forms[0].Method != "POST" || forms[0].Host != "setup.icloud.com" || forms[0].Path != "/setup/familykit/macos/addFamilyMember" {
		t.Fatalf("unexpected safe form summary: %#v", forms)
	}
	want := []string{"hidden:familyId", "input:email", "submit:continue"}
	if !reflect.DeepEqual(forms[0].Fields, want) {
		t.Fatalf("values leaked or fields changed: %#v", forms[0].Fields)
	}
}

func TestSafeFamilyUIScriptsAndIdentifiers(t *testing.T) {
	origin, _ := url.Parse("https://setup.icloud.com/setup/mac/family/setupFamilyUI")
	scripts := safeFamilyUIScripts(origin, []byte(`<base href="/resource/current/family/"><script src="javascript-packed.js"></script><script src="https://evil.example/family.js"></script>`))
	if len(scripts) != 1 || scripts[0].Hostname() != "setup.icloud.com" || scripts[0].EscapedPath() != "/resource/current/family/javascript-packed.js" {
		t.Fatalf("unexpected safe scripts: %#v", scripts)
	}
	want := []string{"addFamilyMember", "finishSettingUpFamily"}
	if got := safeFamilyActionIdentifiers([]byte(`function addFamilyMember(secret){return finishSettingUpFamily(secret)}`)); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected safe identifiers: %#v", got)
	}
}

func TestSortedMapKeys(t *testing.T) {
	if got, want := sortedMapKeys(map[string]any{"z": 1, "a": 2}), []string{"a", "z"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected sorted keys: %#v", got)
	}
}

func TestNumericIDValueAcceptsAppleIntegerShapes(t *testing.T) {
	for _, value := range []any{"123", int(123), int64(123), uint64(123), float64(123)} {
		if got := numericIDValue(value); got != "123" {
			t.Fatalf("unexpected numeric ID %q for %T", got, value)
		}
	}
	for _, value := range []any{"", "12x", 0, -1, 1.5} {
		if got := numericIDValue(value); got != "" {
			t.Fatalf("invalid ID accepted: %q for %T", got, value)
		}
	}
}

func TestFamilyResponseErrorRecognizesHTTP200ErrorPayload(t *testing.T) {
	for _, payload := range []map[string]any{
		{"invalid-invite-code-title": "Invalid"},
		{"status-message": "invalid invitation"},
		{"success": false},
	} {
		if !familyResponseError(payload) {
			t.Fatalf("Apple error payload was accepted: %#v", payload)
		}
	}
	if familyResponseError(map[string]any{"success": true, "status-message": "success"}) {
		t.Fatal("success payload was rejected")
	}
}

func TestFindFamilyBoolMatchesOnlyRedactedSharingFlags(t *testing.T) {
	member := map[string]any{
		"member-apple-id":                "private@example.test",
		"shareMyPurchasesEnabledDefault": false,
		"nested": map[string]any{
			"location-sharing-enabled": true,
		},
	}
	purchase, purchaseKnown := findFamilyBool(member, func(key string) bool {
		return key == "sharemypurchasesenableddefault"
	})
	location, locationKnown := findFamilyBool(member, func(key string) bool {
		return key == "locationsharingenabled"
	})
	if !purchaseKnown || purchase || !locationKnown || !location {
		t.Fatalf("unexpected sharing flags purchase=%t/%t location=%t/%t", purchase, purchaseKnown, location, locationKnown)
	}
}

func TestFindFamilyIntegerAcceptsNestedStorageBytes(t *testing.T) {
	value := map[string]any{"storage": map[string]any{"storageInBytes": float64(53687091200)}}
	if got := findFamilyInteger(value, "storageInBytes"); got != 53687091200 {
		t.Fatalf("unexpected storage bytes %d", got)
	}
}

func TestSummarizeFamilyMembersAndAccountBinding(t *testing.T) {
	members := []any{
		map[string]any{"member-apple-id": "organizer@example.test", "member-is-organizer": true, "is-me": true, "member-dsid": "123"},
		map[string]any{"appleId": "member@example.test", "member-is-child-account": false, "member-dsid": float64(456)},
	}
	organizers, children, me, selfOrganizer, self := summarizeFamilyMembers(members)
	if organizers != 1 || children != 0 || me != 1 || !selfOrganizer || self == nil {
		t.Fatalf("unexpected family summary organizers=%d children=%d me=%d selfOrganizer=%t", organizers, children, me, selfOrganizer)
	}
	if got := familyMemberAppleID(members[1].(map[string]any)); got != "member@example.test" {
		t.Fatalf("unexpected member binding %q", got)
	}
}

func poolMemberFixture(appleID string, organizer, child, self bool) map[string]any {
	return map[string]any{
		"appleId":                 appleID,
		"member-is-organizer":     organizer,
		"member-is-child-account": child,
		"is-me":                   self,
		"member-dsid":             "private-dsid",
	}
}

func poolRegistryFixture() familyPoolRegistry {
	return familyPoolRegistry{Accounts: []familyPoolRegistryAccount{
		{ID: "01-organizer", AppleID: "organizer@example.test"},
		{ID: "02-member", AppleID: "member@example.test"},
		{ID: "03-child", AppleID: "child@example.test"},
	}}
}

func TestProjectFamilyPoolMapsCurrentRawMembersAndCountsExternal(t *testing.T) {
	members := []any{
		poolMemberFixture(" Organizer@Example.Test ", true, false, true),
		poolMemberFixture("member@example.test", false, false, false),
		poolMemberFixture("child@example.test", false, true, false),
		poolMemberFixture("external@example.test", false, false, false),
	}
	projection, err := projectFamilyPool(members, "organizer@example.test", poolRegistryFixture())
	if err != nil {
		t.Fatal(err)
	}
	if projection.TotalCount != 4 || projection.UnmappedCount != 1 || len(projection.Members) != 3 {
		t.Fatalf("unexpected pool counts: %#v", projection)
	}
	if projection.Members[0] != (familyPoolMember{AccountID: "01-organizer", Organizer: true}) || projection.Members[1] != (familyPoolMember{AccountID: "02-member"}) || projection.Members[2] != (familyPoolMember{AccountID: "03-child", Child: true}) {
		t.Fatalf("projection did not preserve raw order and roles: %#v", projection.Members)
	}
	encoded, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"organizer@example.test", "member@example.test", "external@example.test", "private-dsid", "family-id"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("projection leaked %q: %s", secret, encoded)
		}
	}
}

func TestProjectFamilyPoolDoesNotInferIdentityFromIsMeFlag(t *testing.T) {
	members := []any{
		map[string]any{"appleId": "organizer@example.test", "member-is-organizer": true, "member-is-child-account": false},
		map[string]any{"appleId": "member@example.test", "member-is-organizer": false, "member-is-child-account": false},
	}
	projection, err := projectFamilyPool(members, "organizer@example.test", poolRegistryFixture())
	if err != nil || projection.TotalCount != 2 || len(projection.Members) != 2 {
		t.Fatalf("exact session identity should be sufficient without is-me: %#v err=%v", projection, err)
	}
}

func TestProjectFamilyPoolFailsClosedOnMissingDuplicateAndDifferentFamily(t *testing.T) {
	valid := []any{poolMemberFixture("organizer@example.test", true, false, true), poolMemberFixture("member@example.test", false, false, false)}
	for _, test := range []struct {
		name     string
		members  []any
		current  string
		registry familyPoolRegistry
	}{
		{name: "missing Apple identity", members: []any{map[string]any{"member-is-organizer": true, "member-is-child-account": false, "is-me": true}}, current: "organizer@example.test", registry: poolRegistryFixture()},
		{name: "duplicate family identity", members: []any{valid[0], valid[1], poolMemberFixture("MEMBER@example.test", false, false, false)}, current: "organizer@example.test", registry: poolRegistryFixture()},
		{name: "conflicting identity aliases", members: []any{map[string]any{"appleId": "organizer@example.test", "member-apple-id": "other@example.test", "member-is-organizer": true, "member-is-child-account": false, "is-me": true}}, current: "organizer@example.test", registry: poolRegistryFixture()},
		{name: "missing child role", members: []any{map[string]any{"appleId": "organizer@example.test", "member-is-organizer": true, "is-me": true}}, current: "organizer@example.test", registry: poolRegistryFixture()},
		{name: "missing organizer role", members: []any{map[string]any{"appleId": "organizer@example.test", "member-is-child-account": false}, poolMemberFixture("member@example.test", false, false, false)}, current: "organizer@example.test", registry: poolRegistryFixture()},
		{name: "duplicate registry Apple ID", members: valid, current: "organizer@example.test", registry: familyPoolRegistry{Accounts: []familyPoolRegistryAccount{{ID: "01-organizer", AppleID: "organizer@example.test"}, {ID: "02-member", AppleID: "ORGANIZER@example.test"}}}},
		{name: "non-unique organizer", members: []any{valid[0], poolMemberFixture("member@example.test", true, false, false)}, current: "organizer@example.test", registry: poolRegistryFixture()},
		{name: "different family with same member count", members: []any{poolMemberFixture("other-organizer@example.test", true, false, false), poolMemberFixture("other-member@example.test", false, false, false)}, current: "organizer@example.test", registry: poolRegistryFixture()},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := projectFamilyPool(test.members, test.current, test.registry); err == nil {
				t.Fatal("unsafe or unbound family projection was accepted")
			}
		})
	}
}

func TestLoadFamilyPoolRegistryVerifiesCurrentFamilySessionBindings(t *testing.T) {
	if runtime.GOOS == "windows" && !strings.EqualFold(filepath.VolumeName(os.TempDir()), `D:`) {
		t.Fatal("test temporary directory must be on D:")
	}
	root := t.TempDir()
	accounts := []familyPoolRegistryAccount{
		{ID: "01-organizer", Name: "synthetic organizer", AppleID: "organizer@example.test", Dir: filepath.Join(root, "accounts", "01-organizer")},
		{ID: "02-member", Name: "synthetic member", AppleID: "member@example.test", Dir: filepath.Join(root, "accounts", "02-member")},
		{ID: "03-unrelated", Name: "synthetic unrelated", AppleID: "unrelated@example.test", Dir: filepath.Join(root, "accounts", "03-unrelated")},
	}
	members := []any{poolMemberFixture("organizer@example.test", true, false, true), poolMemberFixture("member@example.test", false, false, false)}
	for _, account := range accounts {
		if err := os.MkdirAll(account.Dir, 0700); err != nil {
			t.Fatal(err)
		}
		session, _ := json.Marshal(map[string]string{"appleId": account.AppleID, "DSID": "synthetic-private-dsid"})
		if err := os.WriteFile(filepath.Join(account.Dir, "session.json"), session, 0600); err != nil {
			t.Fatal(err)
		}
	}
	registryPath := filepath.Join(root, "accounts.json")
	writeRegistry := func(entries []familyPoolRegistryAccount) {
		t.Helper()
		data, err := json.Marshal(familyPoolRegistry{Accounts: entries})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(registryPath, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeRegistry(accounts)
	if _, err := loadFamilyPoolRegistry(registryPath, members); err != nil {
		t.Fatalf("valid synthetic registry rejected: %v", err)
	}
	if err := os.Remove(filepath.Join(accounts[2].Dir, "session.json")); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadFamilyPoolRegistry(registryPath, members)
	if err != nil {
		t.Fatalf("unrelated missing session blocked current family: %v", err)
	}
	projection, err := projectFamilyPool(members, "organizer@example.test", loaded)
	if err != nil || len(projection.Members) != 2 || projection.UnmappedCount != 0 {
		t.Fatalf("current members were not bound correctly: %#v err=%v", projection, err)
	}
	withUnrelated := append(append([]any(nil), members...), poolMemberFixture("unrelated@example.test", false, false, false))
	if _, err := loadFamilyPoolRegistry(registryPath, withUnrelated); err == nil {
		t.Fatal("current member with missing session was accepted")
	}

	mismatched := append([]familyPoolRegistryAccount(nil), accounts...)
	mismatchSession, _ := json.Marshal(map[string]string{"appleId": "wrong@example.test", "DSID": "synthetic-private-dsid"})
	if err := os.WriteFile(filepath.Join(accounts[1].Dir, "session.json"), mismatchSession, 0600); err != nil {
		t.Fatal(err)
	}
	writeRegistry(mismatched)
	if _, err := loadFamilyPoolRegistry(registryPath, members); err == nil {
		t.Fatal("registry/session Apple ID mismatch was accepted")
	}

	if err := os.Remove(filepath.Join(accounts[1].Dir, "session.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFamilyPoolRegistry(registryPath, members); err == nil {
		t.Fatal("missing registered session identity was accepted")
	}
	memberSession, _ := json.Marshal(map[string]string{"appleId": accounts[1].AppleID, "DSID": "synthetic-private-dsid"})
	if err := os.WriteFile(filepath.Join(accounts[1].Dir, "session.json"), memberSession, 0600); err != nil {
		t.Fatal(err)
	}

	duplicate := append([]familyPoolRegistryAccount(nil), accounts...)
	duplicate[1].AppleID = " ORGANIZER@example.test "
	writeRegistry(duplicate)
	if _, err := loadFamilyPoolRegistry(registryPath, members); err == nil {
		t.Fatal("duplicate normalized registry identity was accepted")
	}
	duplicate[1] = accounts[1]
	duplicate[2].AppleID = " MEMBER@example.test "
	writeRegistry(duplicate)
	if _, err := loadFamilyPoolRegistry(registryPath, members); err == nil {
		t.Fatal("duplicate identity on an unrelated account was accepted")
	}
}
