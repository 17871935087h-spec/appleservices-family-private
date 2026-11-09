package credentialvault

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const blobHeader = "ASCB\x00\x01\x00\x00"
const maxBlobBytes = 2 << 20

func validBlobName(name string) bool {
	return name == "app-password-session" || name == "app-password-intent" || name == "app-password-result"
}

func blobEntropy(appleID, name string) []byte {
	sum := sha256.Sum256([]byte("appleservices/account-blob/v1\x00" + appleID + "\x00" + name))
	return sum[:]
}

// SaveBlob protects bounded account data using the service identity's DPAPI key.
// These named blobs cannot overwrite the saved primary password.
func SaveBlob(accountDir, appleID, name string, plain []byte) error {
	if !platformSupported() {
		return ErrUnsupported
	}
	id, err := normalizeAppleID(appleID)
	if err != nil {
		return err
	}
	if !validBlobName(name) || len(plain) == 0 || len(plain) > maxBlobBytes {
		return ErrInvalidData
	}
	dir, err := resolveAccountDirectory(accountDir)
	if err != nil {
		return err
	}
	ciphertext, err := protectAccountBlob(plain, blobEntropy(id, name), true)
	if err != nil {
		return err
	}
	defer clear(ciphertext)
	target := filepath.Join(dir, name+".dpapi")
	if info, statErr := os.Lstat(target); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return ErrUnsafeCredential
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return ErrFileAccess
	}
	file, err := os.CreateTemp(dir, ".account-blob-*")
	if err != nil {
		return ErrFileAccess
	}
	temp := file.Name()
	defer os.Remove(temp)
	defer file.Close()
	if file.Chmod(0600) != nil {
		return ErrFileAccess
	}
	if _, err = file.Write([]byte(blobHeader)); err != nil {
		return ErrFileAccess
	}
	if _, err = file.Write(ciphertext); err != nil {
		return ErrFileAccess
	}
	if file.Sync() != nil || file.Close() != nil {
		return ErrFileAccess
	}
	if os.Rename(temp, target) != nil {
		return ErrFileAccess
	}
	return nil
}

// LoadBlob returns sensitive bytes; callers must clear them after use.
func LoadBlob(accountDir, appleID, name string) ([]byte, error) {
	if !platformSupported() {
		return nil, ErrUnsupported
	}
	id, err := normalizeAppleID(appleID)
	if err != nil {
		return nil, err
	}
	if !validBlobName(name) {
		return nil, ErrInvalidData
	}
	dir, err := resolveAccountDirectory(accountDir)
	if err != nil {
		return nil, err
	}
	target := filepath.Join(dir, name+".dpapi")
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, ErrFileAccess
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrUnsafeCredential
	}
	if info.Size() > maxBlobBytes+65536 {
		return nil, ErrTooLarge
	}
	file, err := os.Open(target)
	if err != nil {
		return nil, ErrFileAccess
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrUnsafeCredential
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBlobBytes+65537))
	if err != nil {
		return nil, ErrFileAccess
	}
	defer clear(data)
	if len(data) <= len(blobHeader) || len(data) > maxBlobBytes+65536 || !bytes.Equal(data[:len(blobHeader)], []byte(blobHeader)) {
		return nil, ErrInvalidData
	}
	return protectAccountBlob(data[len(blobHeader):], blobEntropy(id, name), false)
}
