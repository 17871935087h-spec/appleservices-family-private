// Package privatebody owns a request body until HTTP transport is finished
// with it and clears its buffer on close.
package privatebody

import (
	"bytes"
	"io"
	"sync"
)

// Body takes ownership of data. Its Read and Close methods are safe to call
// concurrently, as required by net/http's request body contract.
type Body struct {
	mu     sync.Mutex
	data   []byte
	reader *bytes.Reader
}

func New(data []byte) *Body {
	return &Body{data: data, reader: bytes.NewReader(data)}
}

func (b *Body) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.reader == nil {
		return 0, io.ErrClosedPipe
	}
	return b.reader.Read(p)
}

func (b *Body) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	clear(b.data)
	b.data = nil
	b.reader = nil
	return nil
}
