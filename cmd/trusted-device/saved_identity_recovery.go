package main

import (
	"context"
	"errors"
	"time"

	"github.com/Laky-64/appleservices"
	"github.com/Laky-64/appleservices/gsa"
)

var errSavedIdentityRecoveryUnavailable = errors.New("saved account identity recovery is unavailable; reconnect in the dashboard")

type recoveredIdentityLogin interface {
	maintainedLogin
	StorageInfo(context.Context) (*appleservices.StorageInfo, error)
}

type savedIdentityRecoveryDependencies struct {
	accepted func() (appleservices.RestoredICloudSession, error)
	password func() (string, error)
	begin    func(appleservices.RestoredICloudSession, string) (recoveredIdentityLogin, error)
	now      func() time.Time
}

// This gate is account-local and lasts for the worker lifetime. Repeated UI
// refreshes cannot turn an expired identity into a password-login loop.
type savedIdentityRecovery struct {
	attempts int
	blocked  bool
	retryAt  time.Time
}

func deviceIdentityNeedsRecovery(err error) bool {
	var failure *gsa.DeviceRequestError
	return errors.Is(err, appleservices.ErrDeviceIdentityRefreshRequired) ||
		errors.As(err, &failure) && failure.HTTPStatus == 401
}

func (r *savedIdentityRecovery) recover(ctx context.Context, cause error, accountID string, deps savedIdentityRecoveryDependencies) (maintainedLogin, []appleservices.AccountDevice, error) {
	if !deviceIdentityNeedsRecovery(cause) {
		return nil, nil, cause
	}
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	now := deps.now()
	if r.blocked || r.attempts >= 3 || now.Before(r.retryAt) {
		return nil, nil, errSavedIdentityRecoveryUnavailable
	}
	r.attempts++
	r.retryAt = now.Add(time.Minute)
	accepted, err := deps.accepted()
	if err != nil || accountID == "" || accepted.ADSID != accountID {
		r.blocked = true
		return nil, nil, errSavedIdentityRecoveryUnavailable
	}
	password, err := deps.password()
	if err != nil || password == "" {
		r.blocked = true
		return nil, nil, errSavedIdentityRecoveryUnavailable
	}
	login, err := deps.begin(accepted, password)
	password = ""
	if err != nil {
		var rejection *gsa.AuthenticationError
		if errors.As(err, &rejection) {
			r.blocked = true
		}
		return nil, nil, err
	}
	if login == nil {
		return nil, nil, errSavedIdentityRecoveryUnavailable
	}
	// A fresh challenge is never requested, submitted, or treated as a
	// successful passwordless resume. Keep the old on-disk session intact.
	if login.NeedsTwoFactor() {
		r.blocked = true
		return nil, nil, errVerificationRequired
	}
	client, err := login.Client()
	if err != nil || client == nil || client.ADSID != accountID {
		r.blocked = true
		return nil, nil, errSavedIdentityRecoveryUnavailable
	}
	devices, err := login.AccountDevices()
	if err != nil {
		if deviceIdentityNeedsRecovery(err) {
			r.blocked = true
		}
		return nil, nil, err
	}
	quota, err := login.StorageInfo(ctx)
	if err != nil || quota == nil {
		return nil, nil, errSavedIdentityRecoveryUnavailable
	}
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	if err := login.SaveSession(); err != nil {
		return nil, nil, err
	}
	r.attempts = 0
	return login, devices, nil
}
