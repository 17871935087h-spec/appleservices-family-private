//go:build windows

package credentialvault

import (
	"runtime"
	"unsafe"
)

func protectAccountBlob(data, entropy []byte, encrypt bool) ([]byte, error) {
	if len(data) == 0 || len(data) > maxBlobBytes+65536 || len(entropy) == 0 {
		return nil, ErrInvalidData
	}
	in := dataBlob{cbData: uint32(len(data)), pbData: &data[0]}
	ent := dataBlob{cbData: uint32(len(entropy)), pbData: &entropy[0]}
	var out dataBlob
	var result uintptr
	if encrypt {
		result, _, _ = cryptProtectData.Call(uintptr(unsafe.Pointer(&in)), 0, uintptr(unsafe.Pointer(&ent)), 0, 0, cryptProtectUIForbidden, uintptr(unsafe.Pointer(&out)))
	} else {
		result, _, _ = cryptUnprotectData.Call(uintptr(unsafe.Pointer(&in)), 0, uintptr(unsafe.Pointer(&ent)), 0, 0, cryptProtectUIForbidden, uintptr(unsafe.Pointer(&out)))
	}
	runtime.KeepAlive(data)
	runtime.KeepAlive(entropy)
	if out.pbData != nil {
		defer localFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	}
	limit := maxBlobBytes
	if encrypt {
		limit += 65536
	}
	if result == 0 || out.pbData == nil || out.cbData == 0 || int(out.cbData) > limit {
		if encrypt {
			return nil, ErrEncryption
		}
		return nil, ErrDecryption
	}
	copyOut := make([]byte, int(out.cbData))
	copy(copyOut, unsafe.Slice(out.pbData, int(out.cbData)))
	return copyOut, nil
}
