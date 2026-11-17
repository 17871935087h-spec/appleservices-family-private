//go:build !windows

package v2gateway

import (
	"context"
	"errors"
	"time"
)

type registryWatcher struct{}

func newRegistryWatcher(string) (*registryWatcher, error) {
	return nil, errors.New("registry change notifications require Windows")
}

func (*registryWatcher) Wait(context.Context, time.Duration) (bool, error) {
	return false, errors.New("registry change notifications require Windows")
}

func (*registryWatcher) Close() {}
