package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Laky-64/appleservices"
	"github.com/Laky-64/appleservices/gsa"
)

type fakeRecoveredIdentity struct {
	fakeMaintainedLogin
	quotaCalls int
	quotaErr   error
}

func (f *fakeRecoveredIdentity) StorageInfo(context.Context) (*appleservices.StorageInfo, error) {
	f.quotaCalls++
	return &appleservices.StorageInfo{}, f.quotaErr
}

func TestSavedIdentityRecoveryAdoptsOnlyVerifiedSameAccount(t *testing.T) {
	for _, test := range []struct {
		name                       string
		challenge                  bool
		account                    string
		listErr, quotaErr, saveErr error
		wantErr                    bool
		saves                      int
	}{
		{name: "success", account: "same", saves: 1},
		{name: "verification", account: "same", challenge: true, wantErr: true},
		{name: "wrong-account", account: "other", wantErr: true},
		{name: "device-refused", account: "same", listErr: &gsa.DeviceRequestError{HTTPStatus: 401}, wantErr: true},
		{name: "quota-refused", account: "same", quotaErr: errors.New("quota unavailable"), wantErr: true},
		{name: "save-failed", account: "same", saveErr: errors.New("save unavailable"), wantErr: true, saves: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			login := &fakeRecoveredIdentity{fakeMaintainedLogin: fakeMaintainedLogin{account: test.account, challenge: test.challenge, listErr: test.listErr, saveErr: test.saveErr}, quotaErr: test.quotaErr}
			gate := &savedIdentityRecovery{}
			deps := savedIdentityRecoveryDependencies{
				accepted: func() (appleservices.RestoredICloudSession, error) {
					return appleservices.RestoredICloudSession{ADSID: "same"}, nil
				},
				password: func() (string, error) { return "test-only", nil },
				begin: func(_ appleservices.RestoredICloudSession, password string) (recoveredIdentityLogin, error) {
					if password != "test-only" {
						t.Fatal("credential mismatch")
					}
					return login, nil
				},
				now: time.Now,
			}
			got, devices, err := gate.recover(context.Background(), &gsa.DeviceRequestError{HTTPStatus: 401}, "same", deps)
			if (err != nil) != test.wantErr || login.saved != test.saves {
				t.Fatalf("unexpected adoption: error=%v saves=%d", err, login.saved)
			}
			if test.wantErr && got != nil {
				t.Fatal("unverified login was adopted")
			}
			if !test.wantErr && (got != login || len(devices) != 1 || login.quotaCalls != 1) {
				t.Fatal("verified login was not adopted")
			}
			if test.challenge && (!errors.Is(err, errVerificationRequired) || login.clientCalls != 0 || login.quotaCalls != 0 || len(login.requestedCodes) != 0) {
				t.Fatal("challenge continued into service or verification actions")
			}
		})
	}
}

func TestSavedIdentityRecoveryDoesNotAuthenticateForTransientDeviceReads(t *testing.T) {
	gate := &savedIdentityRecovery{}
	deps := savedIdentityRecoveryDependencies{now: time.Now, accepted: func() (appleservices.RestoredICloudSession, error) {
		t.Fatal("transient read loaded credentials")
		return appleservices.RestoredICloudSession{}, nil
	}}
	cause := errors.New("transport failure")
	if got, _, err := gate.recover(context.Background(), cause, "same", deps); got != nil || err != cause {
		t.Fatal("transport error triggered authentication")
	}
}

func TestSavedIdentityRecoveryThrottlesCredentialAttempts(t *testing.T) {
	gate := &savedIdentityRecovery{}
	now := time.Now()
	calls := 0
	deps := savedIdentityRecoveryDependencies{
		accepted: func() (appleservices.RestoredICloudSession, error) {
			return appleservices.RestoredICloudSession{ADSID: "same"}, nil
		},
		password: func() (string, error) { return "test-only", nil },
		begin: func(appleservices.RestoredICloudSession, string) (recoveredIdentityLogin, error) {
			calls++
			return nil, errors.New("temporary auth transport failure")
		},
		now: func() time.Time { return now },
	}
	cause := &gsa.DeviceRequestError{HTTPStatus: 401}
	for i := 0; i < 4; i++ {
		gate.recover(context.Background(), cause, "same", deps)
	}
	if calls != 1 {
		t.Fatal("rapid refreshes repeated authentication")
	}
	for i := 0; i < 4; i++ {
		now = now.Add(time.Minute)
		gate.recover(context.Background(), cause, "same", deps)
	}
	if calls != 3 {
		t.Fatalf("credential retry bound = %d, want 3", calls)
	}
}
