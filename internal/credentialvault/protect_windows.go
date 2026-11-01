//go:build windows

package credentialvault

import (
	"runtime"
	"syscall"
	"unsafe"
)

const cryptProtectUIForbidden = 0x1

type dataBlob struct {
	cbData uint32
	pbData *byte
}

var (
	crypt32DLL         = syscall.NewLazyDLL("Crypt32.dll")
	cryptProtectData   = crypt32DLL.NewProc("CryptProtectData")
	cryptUnprotectData = crypt32DLL.NewProc("CryptUnprotectData")
	kernel32DLL        = syscall.NewLazyDLL("Kernel32.dll")
	localFree          = kernel32DLL.NewProc("LocalFree")
)

func protect(plain, entropy []byte) ([]byte, error) {
	input, ok := makeDataBlob(plain)
	if !ok {
		return nil, ErrEncryption
	}
	optionalEntropy, ok := makeDataBlob(entropy)
	if !ok {
		return nil, ErrEncryption
	}
	var output dataBlob
	result, _, _ := cryptProtectData.Call(
		uintptr(unsafe.Pointer(&input)),
		0,
		uintptr(unsafe.Pointer(&optionalEntropy)),
		0,
		0,
		cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&output)),
	)
	runtime.KeepAlive(plain)
	runtime.KeepAlive(entropy)
	if result == 0 || output.pbData == nil || output.cbData == 0 || output.cbData > maxCiphertextBytes {
		if output.pbData != nil {
			_, _, _ = localFree.Call(uintptr(unsafe.Pointer(output.pbData)))
		}
		return nil, ErrEncryption
	}
	defer func() { _, _, _ = localFree.Call(uintptr(unsafe.Pointer(output.pbData))) }()
	ciphertext := make([]byte, int(output.cbData))
	copy(ciphertext, unsafe.Slice(output.pbData, int(output.cbData)))
	return ciphertext, nil
}

func unprotect(ciphertext, entropy []byte) ([]byte, error) {
	input, ok := makeDataBlob(ciphertext)
	if !ok {
		return nil, ErrDecryption
	}
	optionalEntropy, ok := makeDataBlob(entropy)
	if !ok {
		return nil, ErrDecryption
	}
	var output dataBlob
	result, _, _ := cryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&input)),
		0,
		uintptr(unsafe.Pointer(&optionalEntropy)),
		0,
		0,
		cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&output)),
	)
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(entropy)
	if result == 0 || output.pbData == nil || output.cbData == 0 || output.cbData > maxPasswordBytes {
		if output.pbData != nil {
			_, _, _ = localFree.Call(uintptr(unsafe.Pointer(output.pbData)))
		}
		return nil, ErrDecryption
	}
	defer func() { _, _, _ = localFree.Call(uintptr(unsafe.Pointer(output.pbData))) }()
	plain := make([]byte, int(output.cbData))
	copy(plain, unsafe.Slice(output.pbData, int(output.cbData)))
	return plain, nil
}

func makeDataBlob(data []byte) (dataBlob, bool) {
	if len(data) == 0 || len(data) > maxCredentialFileLen {
		return dataBlob{}, false
	}
	return dataBlob{cbData: uint32(len(data)), pbData: &data[0]}, true
}
