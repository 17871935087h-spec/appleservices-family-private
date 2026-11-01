//go:build !windows

package credentialvault

import (
	"errors"
	"testing"
)

func TestCredentialVaultFailsClosedOutsideWindows(t *testing.T) {
	if err := Save("", "account@example.test", "fixture-password"); !errors.Is(err, ErrUnsupported) {
		t.Fatal("save did not report unsupported platform")
	}
	if _, err := Load("", "account@example.test"); !errors.Is(err, ErrUnsupported) {
		t.Fatal("load did not report unsupported platform")
	}
}
