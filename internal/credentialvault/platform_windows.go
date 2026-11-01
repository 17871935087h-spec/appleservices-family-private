//go:build windows

package credentialvault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	fileReadAttributes      = 0x0080
	fileShareRead           = 0x00000001
	fileShareWrite          = 0x00000002
	fileShareDelete         = 0x00000004
	openExisting            = 3
	fileFlagBackupSemantics = 0x02000000
)

var getFinalPathNameByHandle = kernel32DLL.NewProc("GetFinalPathNameByHandleW")

func platformSupported() bool { return true }

func resolveAccountDirectory(accountDir string) (string, error) {
	accountDir = strings.TrimSpace(accountDir)
	if accountDir == "" {
		return "", ErrUnsafeAccountDir
	}
	absolute, err := filepath.Abs(accountDir)
	if err != nil || !strings.EqualFold(filepath.VolumeName(absolute), "D:") {
		return "", ErrUnsafeAccountDir
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", ErrUnsafeAccountDir
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", ErrUnsafeAccountDir
	}
	resolved, err = finalDirectoryPath(resolved)
	if err != nil || !strings.EqualFold(filepath.VolumeName(resolved), "D:") {
		return "", ErrUnsafeAccountDir
	}
	root := filepath.VolumeName(resolved) + string(filepath.Separator)
	relative, err := filepath.Rel(root, resolved)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", ErrUnsafeAccountDir
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() || errors.Is(err, os.ErrNotExist) {
		return "", ErrUnsafeAccountDir
	}
	return filepath.Clean(resolved), nil
}

func finalDirectoryPath(path string) (string, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", ErrUnsafeAccountDir
	}
	handle, err := syscall.CreateFile(pathPtr, fileReadAttributes,
		fileShareRead|fileShareWrite|fileShareDelete, nil, openExisting, fileFlagBackupSemantics, 0)
	if err != nil || handle == syscall.InvalidHandle {
		return "", ErrUnsafeAccountDir
	}
	defer syscall.CloseHandle(handle)

	buffer := make([]uint16, 32768)
	length, _, _ := getFinalPathNameByHandle.Call(
		uintptr(handle), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0,
	)
	if length == 0 || length >= uintptr(len(buffer)) {
		return "", ErrUnsafeAccountDir
	}
	finalPath := syscall.UTF16ToString(buffer[:int(length)])
	const extendedPathPrefix = `\\?\`
	if strings.HasPrefix(finalPath, extendedPathPrefix) {
		finalPath = finalPath[len(extendedPathPrefix):]
	}
	if !filepath.IsAbs(finalPath) {
		return "", ErrUnsafeAccountDir
	}
	return filepath.Clean(finalPath), nil
}
