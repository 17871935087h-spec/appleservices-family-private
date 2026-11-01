package v2gateway

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	credentialEndpointPath     = "/v1/accounts/credential"
	safeCredentialUnavailable  = "凭据暂不可用"
	credentialUnavailableStage = "credential-unavailable"
)

type credentialLoader func(accountDir, appleID string) (string, error)

type accountCredentialRequest struct {
	AccountID string `json:"account_id"`
	AppleID   string `json:"apple_id"`
}

type accountCredentialReply struct {
	OK       bool   `json:"ok"`
	Password string `json:"password"`
}

func (g *Gateway) handleCredential(w http.ResponseWriter, r *http.Request) {
	var body accountCredentialRequest
	if !decodeRequest(w, r, &body) {
		return
	}
	requestedAppleID, valid := normalizeAppleID(body.AppleID)
	if !valid || !validAccountID(body.AccountID) {
		writeCredentialUnavailable(w, http.StatusNotFound)
		return
	}

	registry, err := loadRegistry(g.config.RegistryPath)
	if err != nil {
		writeCredentialUnavailable(w, http.StatusServiceUnavailable)
		return
	}
	entry, found := accountIDFromRegistry(registry, body.AccountID)
	registryAppleID, appleIDValid := normalizeAppleID(entry.AppleID)
	if !found || !appleIDValid || registryAppleID != requestedAppleID || !uniqueRegistryAppleID(registry, registryAppleID) {
		writeCredentialUnavailable(w, http.StatusNotFound)
		return
	}

	accountDir, err := validateCredentialAccountDir(entry.Dir)
	if err != nil || g.credentialLoader == nil {
		writeCredentialUnavailable(w, http.StatusServiceUnavailable)
		return
	}

	password, err := g.credentialLoader(accountDir, registryAppleID)
	if err != nil || password == "" {
		password = ""
		writeCredentialUnavailable(w, http.StatusServiceUnavailable)
		return
	}
	reply := accountCredentialReply{OK: true, Password: password}
	password = ""
	writeJSON(w, http.StatusOK, reply)
	reply.Password = ""
}

func writeCredentialUnavailable(w http.ResponseWriter, status int) {
	writeJSON(w, status, errorReply{OK: false, Stage: credentialUnavailableStage, Message: safeCredentialUnavailable})
}

func validateCredentialAccountDir(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("account directory unavailable")
	}
	cleanPath := filepath.Clean(path)
	if runtime.GOOS == "windows" && !strings.EqualFold(filepath.VolumeName(cleanPath), `D:`) {
		return "", errors.New("account directory unavailable")
	}
	resolved, err := filepath.EvalSymlinks(cleanPath)
	if err != nil || !filepath.IsAbs(resolved) {
		return "", errors.New("account directory unavailable")
	}
	if runtime.GOOS == "windows" && !strings.EqualFold(filepath.VolumeName(resolved), `D:`) {
		return "", errors.New("account directory unavailable")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errors.New("account directory unavailable")
	}
	return resolved, nil
}
