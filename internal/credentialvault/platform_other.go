//go:build !windows

package credentialvault

func platformSupported() bool { return false }

func resolveAccountDirectory(string) (string, error) {
	return "", ErrUnsupported
}

func protect([]byte, []byte) ([]byte, error) {
	return nil, ErrUnsupported
}

func unprotect([]byte, []byte) ([]byte, error) {
	return nil, ErrUnsupported
}
