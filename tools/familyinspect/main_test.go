package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	appleservices "github.com/Laky-64/appleservices"
	"howett.net/plist"
)

func TestOrganizerFamilyReferenceUsesNumericICloudDSIDInsteadOfADSID(t *testing.T) {
	accepted := acceptedCheckpoint{ADSID: "synthetic-alternate-id", Session: appleservices.Session{DSID: "100"}}
	organizerDSID, err := organizerFamilyMemberDSID(accepted)
	if err != nil || organizerDSID != "100" {
		t.Fatalf("organizer family DSID = %q, err = %v", organizerDSID, err)
	}
	key := bytes.Repeat([]byte{1}, 32)
	members := []any{
		map[string]any{"appleId": "owner@example.test", "member-dsid": "100", "member-is-organizer": true, "member-is-child-account": false, "is-me": true},
		map[string]any{"appleId": "member@example.test", "member-dsid": "200", "member-is-organizer": false, "member-is-child-account": false, "is-me": false},
	}
	roster, _, err := projectFamilyReferenceRoster(members, organizerDSID, key)
	if err != nil || len(roster.Members) != 1 {
		t.Fatalf("organizer roster rejected numeric iCloud DSID: %v", err)
	}
	accepted.Session.DSID = "synthetic-not-numeric"
	if _, err := organizerFamilyMemberDSID(accepted); err == nil {
		t.Fatal("nonnumeric iCloud DSID must not be treated as a family member DSID")
	}
}

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

func refRosterMember(appleID, dsid string, organizer, child, self any) map[string]any {
	member := map[string]any{
		"appleId":                 appleID,
		"member-dsid":             dsid,
		"member-is-organizer":     organizer,
		"member-is-child-account": child,
	}
	if self != nil {
		member["is-me"] = self
	}
	return member
}

func TestConsumeFamilyReferenceInputsUnsetsEnvironmentAndRequiresUnpaddedValues(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	ref := bytes.Repeat([]byte{0x24}, 32)
	t.Setenv(familyRefKeyEnv, base64.RawURLEncoding.EncodeToString(key))
	t.Setenv(familyMemberRefEnv, base64.RawURLEncoding.EncodeToString(ref))
	inputs := consumeFamilyReferenceInputs()
	defer clearFamilyReferenceInputs(&inputs)
	if !inputs.KeyPresent || !inputs.KeyValid || !bytes.Equal(inputs.Key, key) || !inputs.RefPresent || !inputs.RefValid || !bytes.Equal(inputs.MemberRef, ref) {
		t.Fatal("valid family reference inputs were not decoded")
	}
	if _, exists := os.LookupEnv(familyRefKeyEnv); exists {
		t.Fatal("family reference key remained in the environment")
	}
	if _, exists := os.LookupEnv(familyMemberRefEnv); exists {
		t.Fatal("family member reference remained in the environment")
	}

	for _, value := range []string{
		base64.URLEncoding.EncodeToString(key),
		base64.RawURLEncoding.EncodeToString(key) + "=",
		base64.RawURLEncoding.EncodeToString(key[:31]),
	} {
		if _, ok := decodeFamilyReferenceValue(value); ok {
			t.Fatalf("invalid key encoding was accepted: %q", value)
		}
	}
}

func TestFamilyReferenceIsDomainSeparatedAndOpaque(t *testing.T) {
	key := bytes.Repeat([]byte{0x73}, 32)
	ref, err := familyMemberReference(key, "123456789")
	if err != nil {
		t.Fatal(err)
	}
	decoded, ok := decodeFamilyReferenceValue(ref)
	if !ok || len(decoded) != 32 {
		t.Fatalf("generated family reference is invalid: %q", ref)
	}
	other, err := familyMemberReference(key, "123456788")
	if err != nil || other == ref {
		t.Fatalf("distinct DSIDs produced the same reference: %q %q err=%v", ref, other, err)
	}
	if _, err := familyMemberReference(key[:31], "123456789"); err == nil {
		t.Fatal("short HMAC key was accepted")
	}
	if canonicalFamilyMemberDSID("000123") != "123" || canonicalFamilyMemberDSID("000") != "" || canonicalFamilyMemberDSID("12x") != "" {
		t.Fatal("family DSID canonicalization did not reject zero or nonnumeric IDs")
	}
}

func TestProjectFamilyReferenceRosterRedactsAndExcludesUnsafeMembers(t *testing.T) {
	key := bytes.Repeat([]byte{0x51}, 32)
	members := []any{
		refRosterMember("organizer@example.test", "100", true, false, true),
		refRosterMember("member@example.test", "200", false, false, false),
		refRosterMember("child@example.test", "300", false, true, false),
		map[string]any{"appleId": "unknown@example.test", "member-dsid": "400", "member-is-organizer": false},
		refRosterMember("dup-one@example.test", "500", false, false, false),
		refRosterMember("dup-two@example.test", "500", false, false, false),
	}
	projection, byRef, err := projectFamilyReferenceRoster(members, "100", key)
	if err != nil {
		t.Fatal(err)
	}
	if projection.TotalCount != 6 || projection.UnidentifiedCount != 3 || len(projection.Members) != 1 {
		t.Fatalf("unexpected roster projection: %#v", projection)
	}
	if projection.Members[0].Label != "m***r@example.test" || len(byRef) != 1 || byRef[projection.Members[0].Ref] != "200" {
		t.Fatalf("unexpected safe family candidate: %#v %#v", projection.Members, byRef)
	}
	encoded, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"organizer@example.test", "member@example.test", "unknown@example.test", "child@example.test", "100", "200", "500", "family-id", "token"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("roster projection leaked %q: %s", secret, encoded)
		}
	}
}

func TestMaskedFamilyAppleIDUsesLongAccountEdgesAndStricterShortMasking(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "ab123456cd@qq.com", want: "ab***cd@qq.com"},
		{input: "abc@qq.com", want: "a***c@qq.com"},
		{input: "ab@qq.com", want: "a***@qq.com"},
		{input: "a@qq.com", want: "a***@qq.com"},
	} {
		if got := maskedFamilyAppleID(test.input); got != test.want {
			t.Fatalf("unexpected masked Apple ID: got=%q want=%q", got, test.want)
		}
		if strings.Contains(test.want, test.input) {
			t.Fatalf("mask preserved the complete account: %q", test.want)
		}
	}
}

func TestFamilyRosterBlocksDuplicateMaskedLabels(t *testing.T) {
	key := bytes.Repeat([]byte{0x35}, 32)
	members := []any{
		refRosterMember("organizer@example.test", "100", true, false, true),
		refRosterMember("ab123456cd@qq.com", "200", false, false, false),
		refRosterMember("ab999999cd@qq.com", "300", false, false, false),
	}
	projection, byRef, err := projectFamilyReferenceRoster(members, "100", key)
	if err != nil {
		t.Fatal(err)
	}
	if len(projection.Members) != 0 || projection.UnidentifiedCount != 2 || len(byRef) != 0 {
		t.Fatalf("duplicate masked labels were not excluded: projection=%#v refs=%#v", projection, byRef)
	}
}

func TestProjectFamilyReferenceRosterFailsClosedOnAmbiguousOrganizer(t *testing.T) {
	key := bytes.Repeat([]byte{0x19}, 32)
	valid := []any{
		refRosterMember("organizer@example.test", "100", true, false, true),
		refRosterMember("member@example.test", "200", false, false, false),
	}
	for _, test := range []struct {
		name    string
		members []any
	}{
		{name: "missing current organizer child marker", members: []any{map[string]any{"appleId": "organizer@example.test", "member-dsid": "100", "member-is-organizer": true, "is-me": true}, valid[1]}},
		{name: "current organizer is not marked organizer", members: []any{refRosterMember("organizer@example.test", "100", false, false, true), valid[1]}},
		{name: "duplicate current DSID", members: []any{valid[0], valid[1], refRosterMember("other@example.test", "100", false, false, false)}},
		{name: "second organizer", members: []any{valid[0], refRosterMember("member@example.test", "200", true, false, false)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := projectFamilyReferenceRoster(test.members, "100", key); err == nil {
				t.Fatal("ambiguous current organizer was accepted")
			}
		})
	}
}

func TestProjectFamilyReferenceRosterCountsMissingOrWrongCandidateMarkers(t *testing.T) {
	key := bytes.Repeat([]byte{0x61}, 32)
	organizer := refRosterMember("organizer@example.test", "100", true, false, true)
	for _, candidate := range []map[string]any{
		{"appleId": "member@example.test", "member-dsid": "200", "member-is-child-account": false},
		{"appleId": "member@example.test", "member-dsid": "200", "member-is-organizer": false},
		{"appleId": "member@example.test", "member-dsid": "200", "member-is-organizer": false, "member-is-child-account": false, "is-me": "false"},
		{"member-dsid": "200", "member-is-organizer": false, "member-is-child-account": false},
	} {
		projection, _, err := projectFamilyReferenceRoster([]any{organizer, candidate}, "100", key)
		if err != nil {
			t.Fatal(err)
		}
		if len(projection.Members) != 0 || projection.UnidentifiedCount != 1 {
			t.Fatalf("unsafe candidate was not counted and excluded: %#v", projection)
		}
	}
}

func TestResolveFamilyMemberReferenceRequiresCurrentUniqueCandidate(t *testing.T) {
	key := bytes.Repeat([]byte{0x31}, 32)
	members := []any{
		refRosterMember("organizer@example.test", "100", true, false, true),
		refRosterMember("member@example.test", "200", false, false, false),
		refRosterMember("child@example.test", "300", false, true, false),
	}
	ref, err := familyMemberReference(key, "200")
	if err != nil {
		t.Fatal(err)
	}
	decoded, _ := decodeFamilyReferenceValue(ref)
	defer clearFamilyReferenceInputs(&familyReferenceInputs{MemberRef: decoded})
	if got, err := resolveFamilyMemberReference(members, "100", key, decoded); err != nil || got != "200" {
		t.Fatalf("current roster did not resolve the opaque reference: %q err=%v", got, err)
	}
	childRef, _ := familyMemberReference(key, "300")
	childBytes, _ := decodeFamilyReferenceValue(childRef)
	if _, err := resolveFamilyMemberReference(members, "100", key, childBytes); err == nil {
		t.Fatal("child reference resolved as a removable candidate")
	}
	missingRef, _ := familyMemberReference(key, "999")
	missingBytes, _ := decodeFamilyReferenceValue(missingRef)
	if _, err := resolveFamilyMemberReference(members, "100", key, missingBytes); err == nil {
		t.Fatal("reference for an absent member matched the current roster")
	}
}

func TestRemoveFamilyMemberReferenceSubmitsOnceAndConfirmsByOrganizerReadbackWithoutTargetSession(t *testing.T) {
	key := bytes.Repeat([]byte{0x72}, 32)
	initial := []any{
		refRosterMember("organizer@example.test", "100", true, false, true),
		refRosterMember("member@example.test", "200", false, false, false),
	}
	ref, err := familyMemberReference(key, "200")
	if err != nil {
		t.Fatal(err)
	}
	refBytes, _ := decodeFamilyReferenceValue(ref)
	removeCalls, readbackCalls := 0, 0
	verified, err := removeFamilyMemberReference(initial, "100", key, refBytes,
		func(dsid string) (bool, bool, error) {
			removeCalls++
			if dsid != "200" {
				t.Fatal("opaque reference resolved to an unexpected DSID")
			}
			return true, false, errors.New("synthetic transport outcome unknown")
		},
		func() ([]any, error) {
			readbackCalls++
			return []any{initial[0]}, nil
		}, func() {},
	)
	if err != nil || removeCalls != 1 || readbackCalls != 1 || len(verified) != 1 {
		t.Fatalf("confirmed removal failed or was repeated: verified=%#v remove=%d readback=%d err=%v", verified, removeCalls, readbackCalls, err)
	}
}

func TestRemoveFamilyMemberReferenceDoesNotSubmitForMissingOrIneligibleTarget(t *testing.T) {
	key := bytes.Repeat([]byte{0x28}, 32)
	initial := []any{
		refRosterMember("organizer@example.test", "100", true, false, true),
		refRosterMember("child@example.test", "300", false, true, false),
	}
	for _, targetDSID := range []string{"200", "300"} {
		ref, _ := familyMemberReference(key, targetDSID)
		refBytes, _ := decodeFamilyReferenceValue(ref)
		removeCalls, readbackCalls := 0, 0
		if _, err := removeFamilyMemberReference(initial, "100", key, refBytes,
			func(string) (bool, bool, error) { removeCalls++; return true, false, nil },
			func() ([]any, error) { readbackCalls++; return initial, nil }, func() {},
		); err == nil {
			t.Fatalf("missing or ineligible target %s was accepted", targetDSID)
		}
		if removeCalls != 0 || readbackCalls != 0 {
			t.Fatalf("preflight failure submitted or read back: remove=%d readback=%d", removeCalls, readbackCalls)
		}
	}
}

func TestRemoveFamilyMemberReferenceNeverReplaysUnknownMutation(t *testing.T) {
	key := bytes.Repeat([]byte{0x46}, 32)
	initial := []any{
		refRosterMember("organizer@example.test", "100", true, false, true),
		refRosterMember("member@example.test", "200", false, false, false),
	}
	ref, _ := familyMemberReference(key, "200")
	refBytes, _ := decodeFamilyReferenceValue(ref)
	removeCalls, readbackCalls := 0, 0
	_, err := removeFamilyMemberReference(initial, "100", key, refBytes,
		func(string) (bool, bool, error) { removeCalls++; return true, false, errors.New("synthetic timeout") },
		func() ([]any, error) { readbackCalls++; return initial, nil }, func() {},
	)
	if err == nil || removeCalls != 1 || readbackCalls != 4 {
		t.Fatalf("unknown result did not stop after bounded read-only checks: remove=%d readback=%d err=%v", removeCalls, readbackCalls, err)
	}
}

func TestRemoveFamilyMemberReferenceNeverConfirmsExplicitRejectEvenIfTargetDisappears(t *testing.T) {
	key := bytes.Repeat([]byte{0x41}, 32)
	initial := []any{
		refRosterMember("organizer@example.test", "100", true, false, true),
		refRosterMember("member@example.test", "200", false, false, false),
	}
	ref, _ := familyMemberReference(key, "200")
	refBytes, _ := decodeFamilyReferenceValue(ref)
	removeCalls, readbackCalls := 0, 0
	verified, err := removeFamilyMemberReference(initial, "100", key, refBytes,
		func(string) (bool, bool, error) {
			removeCalls++
			return true, true, errors.New("synthetic ec rejection")
		},
		func() ([]any, error) {
			readbackCalls++
			return []any{initial[0]}, nil
		}, func() {},
	)
	if err == nil || verified != nil || removeCalls != 1 || readbackCalls != 1 {
		t.Fatalf("explicit rejection was reported as confirmed: verified=%#v remove=%d readback=%d err=%v", verified, removeCalls, readbackCalls, err)
	}
}

func TestRemoveFamilyMemberReferenceRequiresRosterCountDecreaseByOne(t *testing.T) {
	key := bytes.Repeat([]byte{0x52}, 32)
	initial := []any{
		refRosterMember("organizer@example.test", "100", true, false, true),
		refRosterMember("member@example.test", "200", false, false, false),
	}
	ref, _ := familyMemberReference(key, "200")
	refBytes, _ := decodeFamilyReferenceValue(ref)
	removeCalls, readbackCalls := 0, 0
	concurrentRoster := []any{
		initial[0],
		refRosterMember("other@example.test", "300", false, false, false),
	}
	if _, err := removeFamilyMemberReference(initial, "100", key, refBytes,
		func(string) (bool, bool, error) { removeCalls++; return true, false, nil },
		func() ([]any, error) { readbackCalls++; return concurrentRoster, nil }, func() {},
	); err == nil || removeCalls != 1 || readbackCalls != 4 {
		t.Fatalf("concurrent member-count change was confirmed: remove=%d readback=%d err=%v", removeCalls, readbackCalls, err)
	}
}

func TestRemoveFamilyMemberReferenceRejectsPreSubmitAndAmbiguousReadback(t *testing.T) {
	key := bytes.Repeat([]byte{0x57}, 32)
	initial := []any{
		refRosterMember("organizer@example.test", "100", true, false, true),
		refRosterMember("member@example.test", "200", false, false, false),
	}
	ref, _ := familyMemberReference(key, "200")
	refBytes, _ := decodeFamilyReferenceValue(ref)
	removeCalls, readbackCalls := 0, 0
	if _, err := removeFamilyMemberReference(initial, "100", key, refBytes,
		func(string) (bool, bool, error) {
			removeCalls++
			return false, false, errors.New("synthetic pre-submit failure")
		},
		func() ([]any, error) { readbackCalls++; return []any{initial[0]}, nil }, func() {},
	); err == nil || removeCalls != 1 || readbackCalls != 0 {
		t.Fatalf("pre-submit error was treated as a submitted mutation: remove=%d readback=%d err=%v", removeCalls, readbackCalls, err)
	}
	ambiguous := []any{
		refRosterMember("organizer@example.test", "100", true, false, true),
		refRosterMember("other@example.test", "100", false, false, false),
	}
	if confirmed, err := verifyFamilyMemberReferenceRemoval(ambiguous, "100", "200", 3); err == nil || confirmed {
		t.Fatal("ambiguous readback incorrectly confirmed removal")
	}
}

func TestBuildAndPostFamilyMemberRemovalRequestUsesExistingFamilyKitProtocolOnce(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.Method != http.MethodPost || r.URL.Path != "/setup/family/removeFromFamily" {
			t.Errorf("unexpected removal route: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/x-plist" || r.Header.Get("Accept") != "application/json, text/plist, application/x-plist" {
			t.Errorf("unexpected content negotiation headers: %#v", r.Header)
		}
		if r.Header.Get("Authorization") != "Basic synthetic-organizer-auth" || r.Header.Get("X-MMe-LoggedIn-AppleID") != "organizer@example.test" || r.Header.Get("X-Apple-I-MD") != "synthetic-anisette" || r.Header.Get("X-Apple-Family-GS-Token") != "synthetic-family-gs" || r.Header.Get("User-Agent") != "synthetic-familykit-client" {
			t.Errorf("organizer authentication or anisette headers were not preserved: %#v", r.Header)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("could not read synthetic request body: %v", err)
		}
		var payload map[string]any
		if _, err := plist.Unmarshal(body, &payload); err != nil || len(payload) != 1 || payload["member-dsid"] != "987654321" {
			t.Errorf("unexpected removal plist body: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ec":0}`)
	}))
	defer server.Close()

	organizerRequest := func(endpoint string) (*http.Request, error) {
		request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", "Basic synthetic-organizer-auth")
		request.Header.Set("X-MMe-LoggedIn-AppleID", "organizer@example.test")
		request.Header.Set("X-Apple-I-MD", "synthetic-anisette")
		request.Header.Set("X-Apple-Family-GS-Token", "synthetic-family-gs")
		request.Header.Set("User-Agent", "synthetic-familykit-client")
		return request, nil
	}
	request, err := buildFamilyMemberRemovalRequest(server.URL+"/setup/family/removeFromFamily", "987654321", organizerRequest)
	if err != nil {
		t.Fatal(err)
	}
	removalOutcome := "not_submitted"
	submitted, explicitlyRejected, err := postFamilyMemberRemoval(server.Client(), request, func() { removalOutcome = "unknown" })
	if err != nil || !submitted || explicitlyRejected || removalOutcome != "unknown" || requestCount != 1 {
		t.Fatalf("synthetic FamilyKit removal did not submit exactly once: submitted=%t outcome=%s calls=%d err=%v", submitted, removalOutcome, requestCount, err)
	}
}

func TestPostFamilyMemberRemovalDoesNotFollowRedirectsOrReplay(t *testing.T) {
	firstCalls, redirectCalls := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/remove" {
			firstCalls++
			http.Redirect(w, r, "/redirect-target", http.StatusFound)
			return
		}
		if r.URL.Path == "/redirect-target" {
			redirectCalls++
		}
	}))
	defer server.Close()
	request, err := http.NewRequest(http.MethodPost, server.URL+"/remove", strings.NewReader(`{"dsid":"200"}`))
	if err != nil {
		t.Fatal(err)
	}
	submitted, explicitlyRejected, err := postFamilyMemberRemoval(server.Client(), request, nil)
	if err == nil || !submitted || !explicitlyRejected || firstCalls != 1 || redirectCalls != 0 {
		t.Fatalf("redirect was followed or mutation replayed: submitted=%t first=%d redirected=%d err=%v", submitted, firstCalls, redirectCalls, err)
	}
}

func TestPostFamilyMemberRemovalEmitsOnlyHTTPStatusForDiagnostics(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "synthetic-private-response")
	}))
	defer server.Close()
	request, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader("synthetic-private-body"))
	if err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previousStdout, previousFlag, previousDir := os.Stdout, familyRemovalOutcomeEnabled, familyRemovalDiagnosticDir
	diagnosticDir := t.TempDir()
	os.Stdout, familyRemovalOutcomeEnabled, familyRemovalDiagnosticDir = writer, true, diagnosticDir
	t.Cleanup(func() {
		os.Stdout, familyRemovalOutcomeEnabled, familyRemovalDiagnosticDir = previousStdout, previousFlag, previousDir
	})
	submitted, _, postErr := postFamilyMemberRemoval(server.Client(), request, nil)
	_ = writer.Close()
	os.Stdout, familyRemovalOutcomeEnabled, familyRemovalDiagnosticDir = previousStdout, previousFlag, previousDir
	output, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if !submitted || postErr == nil || readErr != nil || string(output) != "FAMILY_REMOVE_HTTP_STATUS=401\n" {
		t.Fatalf("unexpected safe diagnostic: submitted=%t postErr=%v readErr=%v output=%q", submitted, postErr, readErr, output)
	}
	logData, err := os.ReadFile(filepath.Join(diagnosticDir, ".family-remove-http-status.log"))
	if err != nil || !strings.HasSuffix(string(logData), " http=401\n") || strings.Contains(string(logData), "synthetic-private") {
		t.Fatalf("diagnostic file missing or contained unexpected data: %q, err=%v", logData, err)
	}
}

func TestFamilyMutationResponseRequiresExplicitSuccessfulEcOrStatus(t *testing.T) {
	for _, payload := range []map[string]any{
		{"ec": 0},
		{"nested": map[string]any{"status": "0"}},
		{"ec": 0, "Status": map[string]any{"synthetic-field": "synthetic-value"}},
	} {
		data, err := json.Marshal(payload)
		if err != nil || !familyMutationResponseConfirmed(data) {
			t.Fatalf("explicit zero family response code was rejected: %s err=%v", data, err)
		}
	}
	plistSuccess, err := plist.Marshal(map[string]any{"ec": int64(0)}, plist.XMLFormat)
	if err != nil || !familyMutationResponseConfirmed(plistSuccess) {
		t.Fatalf("plist ec=0 family response was rejected: err=%v", err)
	}
	plistFailure, err := plist.Marshal(map[string]any{"ec": int64(-1)}, plist.XMLFormat)
	if err != nil || familyMutationResponseConfirmed(plistFailure) {
		t.Fatalf("plist nonzero ec was treated as success: err=%v", err)
	}
	for _, data := range [][]byte{
		[]byte(`{"ec":7}`),
		[]byte(`{"ec":7,"Status":{"synthetic-field":"synthetic-value"}}`),
		[]byte(`{"ec":0,"Status":{"nested":{"ec":7}}}`),
		[]byte(`{"status":"rejected"}`),
		[]byte(`{"success":true}`),
		[]byte(`{}`),
		[]byte(""),
	} {
		if familyMutationResponseConfirmed(data) {
			t.Fatalf("response without explicit successful ec/status was accepted: %s", data)
		}
	}
}

func TestHTTP200WithNonzeroFamilyEcKeepsOutcomeUnknown(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/x-plist")
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>ec</key><integer>-1</integer></dict></plist>`)
	}))
	defer server.Close()
	key := bytes.Repeat([]byte{0x69}, 32)
	initial := []any{
		refRosterMember("organizer@example.test", "100", true, false, true),
		refRosterMember("member@example.test", "200", false, false, false),
	}
	reference, err := familyMemberReference(key, "200")
	if err != nil {
		t.Fatal(err)
	}
	referenceBytes, _ := decodeFamilyReferenceValue(reference)
	previousOutcome := familyRemovalOutcome
	t.Cleanup(func() { familyRemovalOutcome = previousOutcome })
	familyRemovalOutcome = "not_submitted"
	removeCalls, readbackCalls := 0, 0
	organizerRequest := func(endpoint string) (*http.Request, error) {
		return http.NewRequest(http.MethodPost, endpoint, nil)
	}
	verified, err := removeFamilyMemberReference(initial, "100", key, referenceBytes,
		func(dsid string) (bool, bool, error) {
			removeCalls++
			request, requestErr := buildFamilyMemberRemovalRequest(server.URL+"/remove", dsid, organizerRequest)
			if requestErr != nil {
				return false, false, requestErr
			}
			return postFamilyMemberRemoval(server.Client(), request, func() { familyRemovalOutcome = "unknown" })
		},
		func() ([]any, error) {
			readbackCalls++
			// Simulate a concurrent removal: the target is gone and the count fell
			// by one, but Apple's explicit nonzero ec must still prevent success.
			return []any{initial[0]}, nil
		}, func() {},
	)
	if err == nil || verified != nil || removeCalls != 1 || readbackCalls != 1 || familyRemovalOutcome != "unknown" || requestCount != 1 {
		t.Fatalf("HTTP 200 with nonzero plist ec was confirmed or repeated: verified=%#v outcome=%s http=%d remove=%d readback=%d err=%v", verified, familyRemovalOutcome, requestCount, removeCalls, readbackCalls, err)
	}
}
