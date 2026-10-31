package main

import (
	"strings"

	"github.com/Laky-64/appleservices/internal/control"
)

func resolveFamilyAddPassword(targetAppleID, targetPassword, startupAppleID, accountDir, startupPassword string, authenticated, verificationRequired bool) (string, bool, string) {
	hasOneShotCredential := targetAppleID != "" || targetPassword != ""
	if !hasOneShotCredential {
		if startupPassword == "" {
			return "", false, "family-worker-unready"
		}
		return startupPassword, false, ""
	}
	if !control.ValidOneShotFamilyPassword(targetPassword) || strings.TrimSpace(targetAppleID) == "" || !strings.EqualFold(strings.TrimSpace(targetAppleID), strings.TrimSpace(startupAppleID)) {
		return "", true, "family-binding"
	}
	if !authenticated || verificationRequired {
		return "", true, "family-worker-unready"
	}
	if err := (fileStore{dir: accountDir}).VerifyFamilyAddSessionBinding(startupAppleID); err != nil {
		return "", true, "family-binding"
	}
	return targetPassword, true, ""
}
