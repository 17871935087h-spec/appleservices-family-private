//go:build !windows

package credentialvault

func protectAccountBlob([]byte, []byte, bool) ([]byte, error) { return nil, ErrUnsupported }
