//go:build windows

package v2gateway

import (
	"context"
	"errors"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

const (
	fileNotifyChangeFileName  = 0x00000001
	fileNotifyChangeSize      = 0x00000008
	fileNotifyChangeLastWrite = 0x00000010
	waitObject0               = 0x00000000
	waitTimeout               = 0x00000102
	waitFailed                = 0xFFFFFFFF
)

var (
	kernel32                        = syscall.NewLazyDLL("kernel32.dll")
	findFirstChangeNotificationProc = kernel32.NewProc("FindFirstChangeNotificationW")
	findNextChangeNotificationProc  = kernel32.NewProc("FindNextChangeNotification")
	findCloseChangeNotificationProc = kernel32.NewProc("FindCloseChangeNotification")
	waitForSingleObjectProc         = kernel32.NewProc("WaitForSingleObject")
)

type registryWatcher struct {
	handle syscall.Handle
}

func newRegistryWatcher(directory string) (*registryWatcher, error) {
	directory, err := filepath.Abs(filepath.Clean(directory))
	if err != nil {
		return nil, err
	}
	path, err := syscall.UTF16PtrFromString(directory)
	if err != nil {
		return nil, err
	}
	handle, _, callErr := findFirstChangeNotificationProc.Call(
		uintptr(unsafe.Pointer(path)), 0,
		fileNotifyChangeFileName|fileNotifyChangeSize|fileNotifyChangeLastWrite,
	)
	if syscall.Handle(handle) == syscall.InvalidHandle {
		if callErr != syscall.Errno(0) {
			return nil, callErr
		}
		return nil, errors.New("registry change notification unavailable")
	}
	return &registryWatcher{handle: syscall.Handle(handle)}, nil
}

func (watcher *registryWatcher) Wait(ctx context.Context, timeout time.Duration) (bool, error) {
	if watcher == nil || watcher.handle == syscall.InvalidHandle {
		return false, errors.New("registry change notification unavailable")
	}
	deadline := time.Now().Add(timeout)
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false, nil
		}
		waitFor := 250 * time.Millisecond
		if remaining < waitFor {
			waitFor = remaining
		}
		milliseconds := uint32(waitFor.Milliseconds())
		if milliseconds == 0 {
			milliseconds = 1
		}
		result, _, callErr := waitForSingleObjectProc.Call(uintptr(watcher.handle), uintptr(milliseconds))
		switch uint32(result) {
		case waitObject0:
			next, _, nextErr := findNextChangeNotificationProc.Call(uintptr(watcher.handle))
			if next == 0 {
				if nextErr != syscall.Errno(0) {
					return false, nextErr
				}
				return false, errors.New("registry change notification reset failed")
			}
			return true, nil
		case waitTimeout:
			continue
		case waitFailed:
			if callErr != syscall.Errno(0) {
				return false, callErr
			}
			return false, errors.New("registry change notification wait failed")
		default:
			return false, errors.New("registry change notification returned an invalid status")
		}
	}
}

func (watcher *registryWatcher) Close() {
	if watcher == nil || watcher.handle == syscall.InvalidHandle {
		return
	}
	_, _, _ = findCloseChangeNotificationProc.Call(uintptr(watcher.handle))
	watcher.handle = syscall.InvalidHandle
}
