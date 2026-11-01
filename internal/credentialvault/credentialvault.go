// Package credentialvault stores per-account passwords encrypted with the
// current Windows user's DPAPI key. It deliberately has no plaintext fallback.
package credentialvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	fileName             = "credential.dpapi"
	maxAppleIDBytes      = 254
	maxPasswordBytes     = 1024
	maxCiphertextBytes   = 128 << 10
	maxCredentialFileLen = 1 << 20
)

const fileHeader = "ASCV\x00\x01\x00\x00"

var (
	ErrUnsupported      = errors.New("credentialvault: unsupported platform")
	ErrInvalidAppleID   = errors.New("credentialvault: invalid account binding")
	ErrInvalidPassword  = errors.New("credentialvault: password is invalid")
	ErrEmptyPassword    = errors.New("credentialvault: password is empty")
	ErrTooLarge         = errors.New("credentialvault: credential exceeds size limit")
	ErrUnsafeAccountDir = errors.New("credentialvault: account directory is unsafe")
	ErrUnsafeCredential = errors.New("credentialvault: credential file is unsafe")
	ErrNotFound         = errors.New("credentialvault: credential is unavailable")
	ErrInvalidData      = errors.New("credentialvault: encrypted credential is invalid")
	ErrEncryption       = errors.New("credentialvault: encryption failed")
	ErrDecryption       = errors.New("credentialvault: decryption failed")
	ErrFileAccess       = errors.New("credentialvault: file operation failed")
)

// Save encrypts password for the normalized Apple ID and atomically replaces
// the credential file inside an existing account directory on D:.
func Save(accountDir, appleID, password string) error {
	if !platformSupported() {
		return ErrUnsupported
	}
	normalizedID, err := normalizeAppleID(appleID)
	if err != nil {
		return err
	}
	if password == "" || strings.TrimSpace(password) == "" {
		return ErrEmptyPassword
	}
	if len(password) > maxPasswordBytes {
		return ErrTooLarge
	}
	if !utf8.ValidString(password) {
		return ErrInvalidPassword
	}
	if strings.ContainsAny(password, "\x00\r\n") {
		return ErrInvalidPassword
	}
	dir, err := resolveAccountDirectory(accountDir)
	if err != nil {
		return err
	}

	plain := []byte(password)
	defer clear(plain)
	entropy := accountEntropy(normalizedID)
	ciphertext, err := protect(plain, entropy)
	if err != nil {
		return err
	}
	defer clear(ciphertext)
	if len(ciphertext) == 0 || len(ciphertext) > maxCiphertextBytes {
		return ErrTooLarge
	}

	payload := make([]byte, len(fileHeader)+4+len(ciphertext))
	defer clear(payload)
	copy(payload, fileHeader)
	binary.BigEndian.PutUint32(payload[len(fileHeader):], uint32(len(ciphertext)))
	copy(payload[len(fileHeader)+4:], ciphertext)

	target := filepath.Join(dir, fileName)
	if info, statErr := os.Lstat(target); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return ErrUnsafeCredential
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return ErrFileAccess
	}

	temp, err := os.CreateTemp(dir, ".credentialvault-*")
	if err != nil {
		return ErrFileAccess
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return ErrFileAccess
	}
	if _, err := temp.Write(payload); err != nil {
		_ = temp.Close()
		return ErrFileAccess
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return ErrFileAccess
	}
	if err := temp.Close(); err != nil {
		return ErrFileAccess
	}
	if err := os.Rename(tempPath, target); err != nil {
		return ErrFileAccess
	}
	return nil
}

// Load decrypts the credential for the normalized Apple ID. A credential
// copied from another account directory cannot be opened with a different ID.
func Load(accountDir, appleID string) (string, error) {
	if !platformSupported() {
		return "", ErrUnsupported
	}
	normalizedID, err := normalizeAppleID(appleID)
	if err != nil {
		return "", err
	}
	dir, err := resolveAccountDirectory(accountDir)
	if err != nil {
		return "", err
	}
	target := filepath.Join(dir, fileName)
	linkInfo, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", ErrFileAccess
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 || !linkInfo.Mode().IsRegular() {
		return "", ErrUnsafeCredential
	}
	file, err := os.Open(target)
	if err != nil {
		return "", ErrFileAccess
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		return "", ErrFileAccess
	}
	if !fileInfo.Mode().IsRegular() || !os.SameFile(linkInfo, fileInfo) {
		return "", ErrUnsafeCredential
	}
	if fileInfo.Size() > maxCredentialFileLen {
		return "", ErrTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCredentialFileLen+1))
	if err != nil {
		return "", ErrFileAccess
	}
	defer clear(data)
	if len(data) > maxCredentialFileLen {
		return "", ErrTooLarge
	}
	if len(data) < len(fileHeader)+4 || !bytes.Equal(data[:len(fileHeader)], []byte(fileHeader)) {
		return "", ErrInvalidData
	}
	ciphertextSize := binary.BigEndian.Uint32(data[len(fileHeader):])
	ciphertext := data[len(fileHeader)+4:]
	if ciphertextSize == 0 || ciphertextSize > maxCiphertextBytes || int(ciphertextSize) != len(ciphertext) {
		return "", ErrInvalidData
	}
	plain, err := unprotect(ciphertext, accountEntropy(normalizedID))
	if err != nil {
		return "", err
	}
	defer clear(plain)
	if len(plain) == 0 || len(plain) > maxPasswordBytes || !utf8.Valid(plain) {
		return "", ErrInvalidData
	}
	password := string(plain)
	if strings.TrimSpace(password) == "" || strings.ContainsAny(password, "\x00\r\n") {
		return "", ErrInvalidData
	}
	return password, nil
}

func normalizeAppleID(appleID string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(appleID))
	if normalized == "" || len(normalized) > maxAppleIDBytes || !utf8.ValidString(normalized) || strings.Count(normalized, "@") != 1 {
		return "", ErrInvalidAppleID
	}
	local, domain, found := strings.Cut(normalized, "@")
	if !found || local == "" || domain == "" {
		return "", ErrInvalidAppleID
	}
	for _, char := range normalized {
		if char <= 0x20 || char == 0x7f || char == '/' || char == '\\' {
			return "", ErrInvalidAppleID
		}
	}
	return normalized, nil
}

func accountEntropy(normalizedAppleID string) []byte {
	material := "github.com/Laky-64/appleservices/credentialvault/v1\x00" + normalizedAppleID
	result := sha256.Sum256([]byte(material))
	return result[:]
}
