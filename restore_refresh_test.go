package appleservices

import (
	"errors"
	"testing"

	"github.com/Laky-64/appleservices/gsa"
	"github.com/Laky-64/appleservices/icloud"
)

type restoredReauthBackend struct {
	result       *gsa.LoginResult
	loginErr     error
	loginCount   int
	loginAppleID string
	loginPass    string
	codeRequests int
	codeSubmits  int
	delegates    int
	deviceCalls  int
	deviceToken  string
	snapshotDSID string
	snapshot     map[string]string
}

func (b *restoredReauthBackend) Login(appleID, password string) (*gsa.LoginResult, error) {
	b.loginCount++
	b.loginAppleID, b.loginPass = appleID, password
	return b.result, b.loginErr
}
func (b *restoredReauthBackend) RequestTrustedDeviceCode(_, _ string) error {
	b.codeRequests++
	return nil
}
func (b *restoredReauthBackend) SubmitTrustedDeviceCode(_, _, _ string) error {
	b.codeSubmits++
	return nil
}
func (b *restoredReauthBackend) RequestSMSCode(_, _ string) error {
	b.codeRequests++
	return nil
}
func (b *restoredReauthBackend) SubmitSMSCode(_, _, _ string) error {
	b.codeSubmits++
	return nil
}
func (b *restoredReauthBackend) Snapshot(dsid string, tokens map[string]string) (gsa.Session, error) {
	b.snapshotDSID = dsid
	b.snapshot = make(map[string]string, len(tokens))
	for key, value := range tokens {
		b.snapshot[key] = value
	}
	return gsa.Session{DSID: dsid, Tokens: b.snapshot}, nil
}
func (b *restoredReauthBackend) AccountDevices(payload map[string]any) ([]gsa.AccountDevice, error) {
	b.deviceCalls++
	b.deviceToken = spdString(payload, "GsIdmsToken")
	if b.deviceToken == "" {
		return nil, errors.New("missing fresh identity")
	}
	return []gsa.AccountDevice{{ID: "device-1"}}, nil
}

type restoredReauthStore struct {
	memoryStore
	deviceSaves int
}

func (s *restoredReauthStore) SaveDevice(device *Device) error {
	s.deviceSaves++
	return s.memoryStore.SaveDevice(device)
}

func restoredReauthSessionPayload(adsid, identity string, twoFactor bool) *gsa.LoginResult {
	return &gsa.LoginResult{
		NeedsTwoFactor: twoFactor,
		SessionPayload: map[string]any{
			"adsid":       adsid,
			"GsIdmsToken": identity,
			"t": map[string]any{
				"com.apple.gs.idms.pet":     map[string]any{"token": "fresh-pet"},
				"com.apple.gs.idms.hb":      map[string]any{"token": "fresh-heartbeat"},
				"com.apple.gs.appleid.auth": map[string]any{"token": "fresh-account-token"},
			},
		},
	}
}

func restoredReauthAccepted() RestoredICloudSession {
	return RestoredICloudSession{
		DSID: "icloud-dsid", ADSID: "gsa-dsid", MMEAuthToken: "accepted-mme",
		CloudKitToken: "accepted-cloudkit", ServiceData: map[string]any{"quota": true},
	}
}

func restoredReauthOptions(backend *restoredReauthBackend) []Option {
	return []Option{
		WithAnisette(fakeAnisette{}),
		func(o *options) {
			o.newBackend = func(gsa.AnisetteProvider, *gsa.Session) loginBackend { return backend }
			o.fetchDelegate = func(map[string]string, string, string, string) (icloud.DelegateTokens, error) {
				backend.delegates++
				return icloud.DelegateTokens{}, errors.New("delegate must not run during restored reauthentication")
			}
		},
	}
}

func newRestoredReauthStore() *restoredReauthStore {
	return &restoredReauthStore{memoryStore: memoryStore{session: &Session{
		AppleID: "owner@example.test", DSID: "gsa-dsid",
		Tokens: map[string]string{
			"com.apple.gs.idms.pet":     "old-pet",
			"com.apple.gs.idms.hb":      "old-heartbeat",
			"com.apple.gs.appleid.auth": "old-account-token",
		},
		// Deliberately no DeviceIdentityToken: the password login must replenish it.
	}}}
}

func TestReauthenticateRestoredLoginUsesFreshGSAAndAcceptedICloudWithoutDelegate(t *testing.T) {
	store := newRestoredReauthStore()
	backend := &restoredReauthBackend{result: restoredReauthSessionPayload("gsa-dsid", "fresh-idms", false)}
	accepted := restoredReauthAccepted()

	login, err := ReauthenticateRestoredLogin(" OWNER@example.test ", "saved-password", store, accepted, restoredReauthOptions(backend)...)
	if err != nil {
		t.Fatal(err)
	}
	if backend.loginCount != 1 || backend.loginAppleID != "OWNER@example.test" || backend.loginPass != "saved-password" || login.creds.Password != "" {
		t.Fatalf("password-backed GSA login not performed once with the account-bound credentials: %#v", backend)
	}
	if backend.delegates != 0 || backend.codeRequests != 0 || backend.codeSubmits != 0 {
		t.Fatalf("unexpected delegate or verification-code operation: %#v", backend)
	}
	if store.saves != 0 || store.deviceSaves != 0 {
		t.Fatal("reauthentication checkpointed session/device before caller validation")
	}
	if login.fetchDelegate != nil {
		t.Fatal("restored reauthentication retained a delegate refresh path")
	}
	if login.client == nil || login.client.DSID != accepted.DSID || login.client.ADSID != accepted.ADSID ||
		login.client.MMEAuthToken != accepted.MMEAuthToken || login.client.serviceData["quota"] != true {
		t.Fatal("accepted iCloud client was not reused with its original account binding")
	}
	client, err := login.Client()
	if err != nil || client != login.client || backend.delegates != 0 {
		t.Fatal("Client did not return the accepted checkpoint without a new delegate")
	}
	if devices, err := login.AccountDevices(); err != nil || len(devices) != 1 || backend.deviceToken != "fresh-idms" {
		t.Fatalf("device query did not use the fresh GSA identity: devices=%#v err=%v", devices, err)
	}
	if store.saves != 0 {
		t.Fatal("device query persisted the session before caller validation")
	}
	if err := login.SaveSession(); err != nil {
		t.Fatal(err)
	}
	if store.saves != 1 || store.session.DeviceIdentityToken != "fresh-idms" ||
		store.session.Tokens["com.apple.gs.idms.pet"] != "fresh-pet" {
		t.Fatal("explicit post-validation save did not persist the refreshed GSA identity")
	}
	if backend.snapshotDSID != "gsa-dsid" || backend.snapshot["com.apple.gs.idms.hb"] != "fresh-heartbeat" {
		t.Fatal("saved session did not contain the fresh account-bound GSA tokens")
	}
}

func TestReauthenticateRestoredLoginReturnsUnpersistedTwoFactorPending(t *testing.T) {
	store := newRestoredReauthStore()
	backend := &restoredReauthBackend{result: restoredReauthSessionPayload("gsa-dsid", "pending-idms", true)}

	login, err := ReauthenticateRestoredLogin("owner@example.test", "saved-password", store, restoredReauthAccepted(), restoredReauthOptions(backend)...)
	if err != nil {
		t.Fatal(err)
	}
	if !login.NeedsTwoFactor() || login.client != nil {
		t.Fatal("two-factor result was not left pending without an iCloud client")
	}
	if backend.loginCount != 1 || backend.codeRequests != 0 || backend.codeSubmits != 0 || backend.delegates != 0 || login.creds.Password != "" {
		t.Fatalf("challenge caused another authentication action: %#v", backend)
	}
	if store.saves != 0 || store.deviceSaves != 0 {
		t.Fatal("pending challenge changed saved state")
	}
	if _, err := login.AccountDevices(); err == nil {
		t.Fatal("pending challenge exposed an authenticated device client")
	}
}

func TestReauthenticateRestoredLoginRejectsBadBindingsBeforeAttachingAcceptedClient(t *testing.T) {
	tests := []struct {
		name     string
		appleID  string
		session  *Session
		accepted RestoredICloudSession
		freshID  string
	}{
		{
			name: "saved Apple ID mismatch", appleID: "owner@example.test",
			session:  &Session{AppleID: "other@example.test", DSID: "gsa-dsid"},
			accepted: restoredReauthAccepted(), freshID: "gsa-dsid",
		},
		{
			name: "accepted ADSID mismatch", appleID: "owner@example.test",
			session:  &Session{AppleID: "owner@example.test", DSID: "gsa-dsid"},
			accepted: RestoredICloudSession{DSID: "icloud-dsid", ADSID: "other-gsa", MMEAuthToken: "mme", ServiceData: map[string]any{}},
			freshID:  "gsa-dsid",
		},
		{
			name: "fresh ADSID mismatch", appleID: "owner@example.test",
			session:  &Session{AppleID: "owner@example.test", DSID: "gsa-dsid"},
			accepted: restoredReauthAccepted(), freshID: "another-gsa",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &restoredReauthStore{memoryStore: memoryStore{session: test.session}}
			backend := &restoredReauthBackend{result: restoredReauthSessionPayload(test.freshID, "fresh-idms", false)}
			login, err := ReauthenticateRestoredLogin(test.appleID, "saved-password", store, test.accepted, restoredReauthOptions(backend)...)
			if err == nil {
				t.Fatal("invalid account binding was accepted")
			}
			if login != nil || backend.loginCount != 0 && test.name != "fresh ADSID mismatch" {
				t.Fatal("invalid preflight binding reached authentication or returned a login")
			}
			if store.saves != 0 || store.deviceSaves != 0 {
				t.Fatal("binding failure changed saved state")
			}
			if test.name == "fresh ADSID mismatch" && backend.loginCount != 1 {
				t.Fatal("fresh identity mismatch did not perform exactly one password handshake")
			}
		})
	}
}

func TestReauthenticateRestoredLoginRejectsIncompleteFreshSession(t *testing.T) {
	store := newRestoredReauthStore()
	backend := &restoredReauthBackend{result: &gsa.LoginResult{SessionPayload: map[string]any{
		"adsid": "gsa-dsid", "GsIdmsToken": "fresh-idms",
		"t": map[string]any{"com.apple.gs.idms.pet": map[string]any{"token": "fresh-pet"}},
	}}}
	login, err := ReauthenticateRestoredLogin("owner@example.test", "saved-password", store, restoredReauthAccepted(), restoredReauthOptions(backend)...)
	if err == nil || login != nil {
		t.Fatal("incomplete fresh GSA session was accepted")
	}
	if backend.loginCount != 1 || store.saves != 0 || store.deviceSaves != 0 {
		t.Fatal("incomplete refresh changed state or skipped its single login attempt")
	}
}

func TestReauthenticateRestoredLoginRequiresExplicitAnisetteProvider(t *testing.T) {
	store := newRestoredReauthStore()
	backend := &restoredReauthBackend{result: restoredReauthSessionPayload("gsa-dsid", "fresh-idms", false)}
	opts := []Option{func(o *options) {
		o.newBackend = func(gsa.AnisetteProvider, *gsa.Session) loginBackend { return backend }
	}}

	login, err := ReauthenticateRestoredLogin("owner@example.test", "saved-password", store, restoredReauthAccepted(), opts...)
	if err == nil || login != nil {
		t.Fatal("stateful store-backed anisette recovery was not rejected")
	}
	if backend.loginCount != 0 || store.saves != 0 || store.deviceSaves != 0 {
		t.Fatal("rejected anisette mode changed state or started authentication")
	}
}
