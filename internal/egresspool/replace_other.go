//go:build !windows

package egresspool

import "os"

func replaceFile(source, destination string) error {
	return os.Rename(source, destination)
}
