package icloud

import (
	"context"
	"net/http"
	"time"

	"github.com/Laky-64/appleservices/gsa"
)

type accountRouteContextKey struct{}

// WithAccountRoute binds subsequent iCloud HTTP calls to one account's
// resolved proxy route. It is safe to use concurrently for different accounts
// because it never changes process environment.
func WithAccountRoute(ctx context.Context, accountDir string) (context.Context, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	transport, err := gsa.AppleRootTransportForAccount(accountDir)
	if err != nil {
		return nil, err
	}
	return context.WithValue(ctx, accountRouteContextKey{}, transport), nil
}

// NewAppleHTTPClientForAccount creates a client with a route selected for one
// account. The caller owns the client and should close idle connections when
// finished.
func NewAppleHTTPClientForAccount(accountDir string, timeout time.Duration) (*http.Client, error) {
	ctx, err := WithAccountRoute(context.Background(), accountDir)
	if err != nil {
		return nil, err
	}
	return NewAppleHTTPClient(ctx, timeout), nil
}

// NewAppleHTTPClient constructs a request client using a route previously
// installed by WithAccountRoute, or the configured process route for a
// dedicated account worker.
func NewAppleHTTPClient(ctx context.Context, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	transport, _ := accountRouteTransport(ctx)
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func accountRouteTransport(ctx context.Context) (*http.Transport, bool) {
	if ctx != nil {
		if transport, ok := ctx.Value(accountRouteContextKey{}).(*http.Transport); ok && transport != nil {
			return transport, true
		}
	}
	return gsa.AppleRootTransport().(*http.Transport), false
}

func appleHTTPTransport(ctx context.Context) *http.Transport {
	transport, _ := accountRouteTransport(ctx)
	return transport
}

func appleHTTPClient(ctx context.Context, timeout time.Duration) *http.Client {
	return NewAppleHTTPClient(ctx, timeout)
}
