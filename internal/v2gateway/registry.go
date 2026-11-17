package v2gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	errAccountListInvalid   = errors.New("account registry is invalid")
	errAccountListAmbiguous = errors.New("account registry is ambiguous")
)

func loadRegistry(path string) (accountRegistry, error) {
	var result accountRegistry
	cleanPath := filepath.Clean(path)
	resolved, err := filepath.EvalSymlinks(cleanPath)
	if err != nil || !filepath.IsAbs(resolved) || (runtime.GOOS == "windows" && !strings.EqualFold(filepath.VolumeName(resolved), `D:`)) {
		return result, errors.New("account registry path is unavailable")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maxRegistryBytes {
		return result, errors.New("account registry is unavailable")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return result, errors.New("account registry is unavailable")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxRegistryBytes+1))
	if err != nil || len(data) > maxRegistryBytes {
		return result, errors.New("account registry is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(result.Accounts) > 500 || validateDeletionEvents(result) != nil {
		return accountRegistry{}, errors.New("account registry is invalid")
	}
	seenIDs := make(map[string]struct{}, len(result.Accounts))
	for _, account := range result.Accounts {
		if !validAccountID(account.ID) {
			return accountRegistry{}, errors.New("account registry is invalid")
		}
		if _, exists := seenIDs[account.ID]; exists {
			return accountRegistry{}, errors.New("account registry is ambiguous")
		}
		seenIDs[account.ID] = struct{}{}
		if _, valid := normalizeAppleID(account.AppleID); !valid {
			return accountRegistry{}, errors.New("account registry is invalid")
		}
	}
	return result, nil
}

func validateDeletionEvents(registry accountRegistry) error {
	if registry.DeletionSequence < 0 || int64(len(registry.DeletionEvents)) != registry.DeletionSequence {
		return errAccountListInvalid
	}
	for index, event := range registry.DeletionEvents {
		if event.Sequence != int64(index+1) || !validAccountID(event.AccountID) || !validSHA256Hex(event.AppleIDSHA256) {
			return errAccountListInvalid
		}
	}
	return nil
}

func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func accountListFromRegistry(registry accountRegistry) ([]accountListEntry, error) {
	if len(registry.Accounts) > 500 {
		return nil, errAccountListInvalid
	}
	accounts := make([]accountListEntry, 0, len(registry.Accounts))
	seenIDs := make(map[string]struct{}, len(registry.Accounts))
	seenAppleIDs := make(map[string]struct{}, len(registry.Accounts))
	for _, account := range registry.Accounts {
		if !validAccountID(account.ID) {
			return nil, errAccountListInvalid
		}
		if _, exists := seenIDs[account.ID]; exists {
			return nil, errAccountListAmbiguous
		}
		appleID, valid := normalizeAppleID(account.AppleID)
		if !valid {
			return nil, errAccountListInvalid
		}
		if _, exists := seenAppleIDs[appleID]; exists {
			return nil, errAccountListAmbiguous
		}
		seenIDs[account.ID] = struct{}{}
		seenAppleIDs[appleID] = struct{}{}
		accounts = append(accounts, accountListEntry{AccountID: account.ID, AppleID: appleID})
	}
	return accounts, nil
}

func validateIntentDirectory(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("intent directory must be absolute")
	}
	cleanPath := filepath.Clean(path)
	if runtime.GOOS == "windows" && !strings.EqualFold(filepath.VolumeName(cleanPath), `D:`) {
		return "", errors.New("intent directory must be on D:")
	}
	if err := os.MkdirAll(cleanPath, 0700); err != nil {
		return "", errors.New("intent directory is unavailable")
	}
	resolved, err := filepath.EvalSymlinks(cleanPath)
	if err != nil || !filepath.IsAbs(resolved) || (runtime.GOOS == "windows" && !strings.EqualFold(filepath.VolumeName(resolved), `D:`)) {
		return "", errors.New("intent directory is unavailable")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errors.New("intent directory is unavailable")
	}
	_ = os.Chmod(resolved, 0700)
	return resolved, nil
}
