// credential-import saves a user-supplied password for one registered device.
// The password is read from stdin or from an existing account-bound vault; it
// must never appear in arguments, environment variables, logs, or the registry.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/Laky-64/appleservices/internal/credentialvault"
)

type registry struct {
	Accounts []struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		AppleID   string `json:"apple_id"`
		Dir       string `json:"dir"`
		CreatedAt string `json:"created_at,omitempty"`
	} `json:"accounts"`
}

var validID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func main() {
	registryPath := flag.String("registry", "", "absolute D: account registry")
	accountID := flag.String("account", "", "one registered device account ID")
	sourceID := flag.String("source", "", "copy from another account's encrypted credential")
	verify := flag.Bool("verify", false, "verify that the selected encrypted credential can be read")
	flag.Parse()
	dir, appleID, err := selectAccount(*registryPath, *accountID)
	if err == nil && *verify {
		if *sourceID != "" {
			err = errors.New("verify cannot be combined with source")
		} else {
			var secret string
			secret, err = credentialvault.Load(dir, appleID)
			if secret == "" && err == nil {
				err = errors.New("credential unavailable")
			}
			secret = ""
		}
		if err == nil {
			_, _ = fmt.Fprintln(os.Stdout, "加密凭据可读取")
			return
		}
	}
	if err == nil {
		var password []byte
		if *sourceID != "" {
			var sourceDir, sourceAppleID, secret string
			if *sourceID == *accountID {
				err = errors.New("source and destination must differ")
			} else {
				sourceDir, sourceAppleID, err = selectAccount(*registryPath, *sourceID)
			}
			if err == nil {
				secret, err = credentialvault.Load(sourceDir, sourceAppleID)
				password = []byte(secret)
				secret = ""
			}
		} else {
			password, err = readPassword(os.Stdin)
		}
		if err == nil {
			err = credentialvault.Save(dir, appleID, string(password))
		}
		clear(password)
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "凭据未保存，请检查账号绑定和本机加密服务")
		os.Exit(1)
	}
	_, _ = fmt.Fprintln(os.Stdout, "凭据已加密保存")
}

func readPassword(source io.Reader) ([]byte, error) {
	reader := bufio.NewReader(io.LimitReader(source, 1027))
	password, err := reader.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, errors.New("credential input unavailable")
	}
	password = bytes.TrimSuffix(password, []byte{'\n'})
	password = bytes.TrimSuffix(password, []byte{'\r'})
	if len(password) == 0 || len(password) > 1024 || !utf8.Valid(password) || bytes.ContainsAny(password, "\x00\r\n") || len(bytes.TrimSpace(password)) == 0 {
		clear(password)
		return nil, errors.New("credential input invalid")
	}
	return password, nil
}

func selectAccount(path, id string) (string, string, error) {
	if !validID.MatchString(id) || !filepath.IsAbs(path) || !strings.EqualFold(filepath.VolumeName(path), `D:`) {
		return "", "", errors.New("invalid registry reference")
	}
	resolvedRegistry, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil || !strings.EqualFold(filepath.VolumeName(resolvedRegistry), `D:`) {
		return "", "", errors.New("invalid registry reference")
	}
	file, err := os.Open(resolvedRegistry)
	if err != nil {
		return "", "", errors.New("registry unavailable")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return "", "", errors.New("registry unavailable")
	}
	var records registry
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&records) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(records.Accounts) > 500 {
		return "", "", errors.New("registry invalid")
	}
	var dir, identity string
	seenIDs, seenIdentities := map[string]bool{}, map[string]bool{}
	for _, account := range records.Accounts {
		appleID := strings.ToLower(strings.TrimSpace(account.AppleID))
		if !validID.MatchString(account.ID) || appleID == "" || strings.Count(appleID, "@") != 1 || seenIDs[account.ID] || seenIdentities[appleID] {
			return "", "", errors.New("registry ambiguous")
		}
		seenIDs[account.ID], seenIdentities[appleID] = true, true
		if account.ID != id {
			continue
		}
		dir, err = filepath.EvalSymlinks(account.Dir)
		if err != nil || !filepath.IsAbs(dir) || !strings.EqualFold(filepath.VolumeName(dir), `D:`) {
			return "", "", errors.New("account directory unavailable")
		}
		rel, relErr := filepath.Rel(filepath.Dir(resolvedRegistry), dir)
		if relErr != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, `..`+string(filepath.Separator)) {
			return "", "", errors.New("account directory is outside registry")
		}
		identity = appleID
	}
	if dir == "" || identity == "" {
		return "", "", errors.New("account unavailable")
	}
	return dir, identity, nil
}
