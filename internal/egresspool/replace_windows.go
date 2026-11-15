//go:build windows

package egresspool

import (
	"syscall"
	"unsafe"
)

const (
	movefileReplaceExisting = 0x00000001
	movefileWriteThrough    = 0x00000008
)

var moveFileExProc = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

func replaceFile(source, destination string) error {
	sourcePtr, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	destinationPtr, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	result, _, callErr := moveFileExProc.Call(
		uintptr(unsafe.Pointer(sourcePtr)),
		uintptr(unsafe.Pointer(destinationPtr)),
		movefileReplaceExisting|movefileWriteThrough,
	)
	if result != 0 {
		return nil
	}
	if errno, ok := callErr.(syscall.Errno); ok && errno != 0 {
		return errno
	}
	return syscall.EINVAL
}
