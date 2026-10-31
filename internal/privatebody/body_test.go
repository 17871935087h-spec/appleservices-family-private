package privatebody

import (
	"io"
	"sync"
	"testing"
)

func TestBodyClearsOwnedBytesOnClose(t *testing.T) {
	data := []byte("synthetic credential")
	body := New(data)
	buffer := make([]byte, 4)
	if n, err := body.Read(buffer); err != nil || n != len(buffer) {
		t.Fatal("body could not be read")
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	for _, value := range data {
		if value != 0 {
			t.Fatal("body buffer was not cleared")
		}
	}
	if _, err := body.Read(buffer); err != io.ErrClosedPipe {
		t.Fatal("closed body remained readable")
	}
}

func TestBodyAllowsConcurrentReadAndClose(t *testing.T) {
	body := New(make([]byte, 4096))
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		_, _ = io.Copy(io.Discard, body)
	}()
	go func() {
		defer workers.Done()
		_ = body.Close()
	}()
	workers.Wait()
}
