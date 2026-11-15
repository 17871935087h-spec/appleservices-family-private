package dashboard

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Laky-64/appleservices/internal/egresspool"
	"github.com/Laky-64/appleservices/nativeadi"
)

// ensureMacPushState establishes the account-private Mac APS certificate,
// key and token before the trusted-device worker starts. It never receives
// Apple account credentials and refuses to accept a partial result.
func (s *Server) ensureMacPushState(ctx context.Context, dir string) error {
	if macPushStateReady(dir) {
		return nil
	}
	if s.provisionMacPush == nil {
		return errors.New("Mac APS provisioner unavailable")
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		lastErr = s.provisionMacPush(ctx, dir)
		if macPushStateReady(dir) {
			return nil
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return errors.New("Mac APS provisioner returned incomplete state")
}

func macPushStateReady(dir string) bool {
	for _, path := range []string{
		filepath.Join(dir, "device.json"),
		filepath.Join(dir, "native-adi", "hw_info.plist"),
		filepath.Join(dir, "push.json"),
	} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return false
		}
	}
	return true
}

func (s *Server) runMacPushProvisioner(ctx context.Context, dir string) error {
	route, err := egresspool.Resolve(dir)
	if err != nil {
		return err
	}
	if route.Enabled {
		// The pinned native bootstrap owns its own sockets and has no verified
		// proxy option. Do not let it bypass an account's configured exit.
		return errors.New("proxy pool requires an existing account-private APS identity; native bootstrap cannot use the selected proxy")
	}
	if s.config.Python == "" || s.config.MacPushSetup == "" || s.config.Library == "" {
		return errors.New("Mac APS provisioner is not configured")
	}
	if _, err := os.Stat(s.config.MacPushSetup); err != nil {
		return errors.New("Mac APS provisioner is unavailable")
	}
	if err := nativeadi.ValidateLibrary(s.config.Library); err != nil {
		return err
	}
	command := exec.CommandContext(ctx, s.config.Python, s.config.MacPushSetup,
		"--profile", filepath.Join(dir, "native-adi"),
		"--device", filepath.Join(dir, "device.json"),
		"--library", s.config.Library,
		"--go-state-out", filepath.Join(dir, "push.json"))
	configureProcess(command)
	// The bootstrap has no reason to receive credentials or proxy overrides.
	// This also keeps a direct Apple APS path when the desktop environment has
	// unrelated proxy variables configured.
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		switch {
		case strings.EqualFold(key, "APPLESERVICES_APPLEID"),
			strings.EqualFold(key, "APPLESERVICES_PASSWORD"),
			strings.EqualFold(key, "APPLESERVICES_STORE_CODE"),
			strings.EqualFold(key, "HTTP_PROXY"),
			strings.EqualFold(key, "HTTPS_PROXY"),
			strings.EqualFold(key, "ALL_PROXY"),
			strings.EqualFold(key, "APPLESERVICES_SOCKS_PROXY"):
			continue
		}
		command.Env = append(command.Env, entry)
	}
	command.Env = append(command.Env, "NO_PROXY=*")
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		return errors.New("Mac APS bootstrap failed")
	}
	return nil
}
