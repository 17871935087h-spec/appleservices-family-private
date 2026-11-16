package appleservices

import (
	"errors"
	"strings"
)

var errRestoredReauthenticationNeedsExplicitAnisette = errors.New("appleservices: restored-session reauthentication requires an explicit anisette provider")

// ReauthenticateRestoredLogin performs a fresh password-backed GSA login for
// an account whose previously accepted iCloud session is still available.
// It deliberately does not exchange a new iCloud delegate. The caller must
// verify the fresh GSA device-management credential and the accepted iCloud
// session with read-only checks before calling SaveSession.
//
// If Apple returns a two-factor challenge, the pending Login is returned with
// no iCloud Client attached. This method never requests or submits a code and
// does not checkpoint a session.
func ReauthenticateRestoredLogin(appleID, password string, store Store, accepted RestoredICloudSession, opts ...Option) (*Login, error) {
	appleID = strings.TrimSpace(appleID)
	if store == nil {
		return nil, errors.New("appleservices: store is required")
	}
	if appleID == "" || strings.TrimSpace(password) == "" {
		return nil, errors.New("appleservices: Apple ID and password are required")
	}
	if accepted.DSID == "" || accepted.ADSID == "" || accepted.MMEAuthToken == "" || accepted.ServiceData == nil {
		return nil, errors.New("appleservices: accepted iCloud session is incomplete")
	}

	login, saved, err := prepareLogin(Credentials{AppleID: appleID, Password: password}, store, true, opts...)
	if err != nil {
		return nil, err
	}
	// Do not retain the password on the returned Login or keep it available to
	// unrelated Store/validation flows after this one bounded GSA attempt.
	defer func() { login.creds.Password = "" }()
	if saved == nil || !strings.EqualFold(saved.AppleID, login.creds.AppleID) ||
		saved.DSID == "" || saved.DSID != accepted.ADSID {
		return nil, errors.New("appleservices: saved account session binding is invalid")
	}

	// authenticate persists a stateful anisette Device through Store before it
	// returns, including on a verification challenge. Recovery must keep the
	// prior local device state intact until its caller verifies the new GSA
	// identity, so require the caller to supply an explicit provider.
	if login.stateful != nil {
		return nil, errRestoredReauthenticationNeedsExplicitAnisette
	}
	if err := login.authenticate(); err != nil {
		return nil, err
	}
	if login.adsid == "" || login.adsid != accepted.ADSID {
		return nil, errors.New("appleservices: refreshed GSA account binding does not match accepted iCloud session")
	}
	if login.needsTwoFactor {
		return login, nil
	}

	payload := login.result.SessionPayload
	if spdString(payload, "GsIdmsToken") == "" ||
		spdToken(payload, "com.apple.gs.idms.pet") == "" ||
		spdToken(payload, "com.apple.gs.idms.hb") == "" ||
		spdToken(payload, "com.apple.gs.appleid.auth") == "" {
		return nil, errors.New("appleservices: refreshed GSA session is incomplete")
	}
	// StorageInfo may otherwise refresh incomplete accepted service data by
	// calling the GSA-to-iCloud delegate again. Keep recovery on the accepted
	// MME token and its read-only account-settings fallback only.
	login.fetchDelegate = nil

	login.client = &Client{
		DSID: accepted.DSID, ADSID: accepted.ADSID, MMEAuthToken: accepted.MMEAuthToken,
		StorageBuyToken: saved.Tokens["com.apple.gs.icloud.storage.buy"],
		CloudKitToken:   accepted.CloudKitToken, serviceData: accepted.ServiceData,
	}
	return login, nil
}
