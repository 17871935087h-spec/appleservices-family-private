package egresspool

type fileLock struct {
	releaseFunc func() error
}

func (l *fileLock) release() {
	if l != nil && l.releaseFunc != nil {
		_ = l.releaseFunc()
	}
}
