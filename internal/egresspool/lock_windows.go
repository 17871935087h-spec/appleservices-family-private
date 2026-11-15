//go:build windows

package egresspool

import (
	"errors"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002
	lockFileBytes           = 1
	errorLockViolation      = syscall.Errno(33)
)

var (
	kernel32Lock     = syscall.NewLazyDLL("kernel32.dll")
	lockFileExProc   = kernel32Lock.NewProc("LockFileEx")
	unlockFileExProc = kernel32Lock.NewProc("UnlockFileEx")
)

func acquireFileLock(path string, wait time.Duration) (*fileLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	var overlapped syscall.Overlapped
	for {
		result, _, callErr := lockFileExProc.Call(
			file.Fd(),
			lockfileExclusiveLock|lockfileFailImmediately,
			0,
			lockFileBytes,
			0,
			uintptr(unsafe.Pointer(&overlapped)),
		)
		if result != 0 {
			return &fileLock{releaseFunc: func() error {
				result, _, callErr := unlockFileExProc.Call(file.Fd(), 0, lockFileBytes, 0, uintptr(unsafe.Pointer(&overlapped)))
				closeErr := file.Close()
				if result == 0 {
					if errno, ok := callErr.(syscall.Errno); ok && errno != 0 {
						return errno
					}
					return syscall.EINVAL
				}
				return closeErr
			}}, nil
		}
		if errno, ok := callErr.(syscall.Errno); !ok || errno != errorLockViolation {
			_ = file.Close()
			if callErr != nil {
				return nil, callErr
			}
			return nil, errors.New("LockFileEx failed")
		}
		if !time.Now().Before(deadline) {
			_ = file.Close()
			return nil, errors.New("file lock wait timed out")
		}
		time.Sleep(25 * time.Millisecond)
	}
}
