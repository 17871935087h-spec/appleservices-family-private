//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package egresspool

import (
	"errors"
	"os"
	"syscall"
	"time"
)

func acquireFileLock(path string, wait time.Duration) (*fileLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &fileLock{releaseFunc: func() error {
				unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				closeErr := file.Close()
				if unlockErr != nil {
					return unlockErr
				}
				return closeErr
			}}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			return nil, err
		}
		if !time.Now().Before(deadline) {
			_ = file.Close()
			return nil, err
		}
		time.Sleep(25 * time.Millisecond)
	}
}
