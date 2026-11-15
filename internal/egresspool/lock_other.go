//go:build !windows && !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package egresspool

import (
	"os"
	"time"
)

// On unsupported systems a lock directory gives bounded cross-process
// exclusion. A stale directory fails closed after a crash until removed.
func acquireFileLock(path string, wait time.Duration) (*fileLock, error) {
	lockPath := path + ".d"
	deadline := time.Now().Add(wait)
	for {
		if err := os.Mkdir(lockPath, 0700); err == nil {
			return &fileLock{releaseFunc: func() error { return os.Remove(lockPath) }}, nil
		}
		if !time.Now().Before(deadline) {
			return nil, os.ErrExist
		}
		time.Sleep(25 * time.Millisecond)
	}
}
