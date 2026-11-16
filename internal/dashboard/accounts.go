package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// An account owns one device identity and one login session. Each lives in its
// own state directory so adding an account can never overwrite another one's
// session, which is what happened when every login reused a single directory.
//
//	<Root>/accounts.json           the registry
//	<Root>/accounts/01-primary/    one account's state
//	<Root>/accounts/02-second/
type Account struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	AppleID   string `json:"apple_id"`
	Dir       string `json:"dir"`
	CreatedAt string `json:"created_at,omitempty"`
	token     string // dashboard capability, never persisted here
	mu        sync.Mutex
	launching bool
	message   string
	pending   *credentials // credentials awaiting 2FA, if any
}

type AccountView struct {
	ID                     string                  `json:"id"`
	Name                   string                  `json:"name"`
	Account                string                  `json:"account"`
	State                  string                  `json:"state"`
	Running                bool                    `json:"running"`
	Authenticated          bool                    `json:"authenticated"`
	ICloudActivated        bool                    `json:"icloud_activated"`
	FamilyMember           bool                    `json:"family_member,omitempty"`
	FamilyOrganizer        bool                    `json:"family_organizer,omitempty"`
	FamilyOrganizerAccount string                  `json:"family_organizer_account,omitempty"`
	FamilyStale            bool                    `json:"family_stale"`
	FamilyCheckedAt        string                  `json:"family_checked_at,omitempty"`
	Message                string                  `json:"message,omitempty"`
	Automation             *ICloudAutomationStatus `json:"automation,omitempty"`
}

// registry is the on-disk account list.
type registry struct {
	Accounts []*registryEntry `json:"accounts"`
}

type registryEntry struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	AppleID   string `json:"apple_id"`
	Dir       string `json:"dir"`
	CreatedAt string `json:"created_at,omitempty"`
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func registryPath(root string) string { return filepath.Join(root, "accounts.json") }
func accountsDir(root string) string  { return filepath.Join(root, "accounts") }

// loadRegistry reads the account list, migrating a pre-existing single-account
// state directory into the first account the first time it runs, so an existing
// login is preserved rather than abandoned.
func loadRegistry(root, legacyDir string) ([]*registryEntry, error) {
	data, err := os.ReadFile(registryPath(root))
	if err == nil {
		var reg registry
		if json.Unmarshal(data, &reg) != nil {
			return nil, errors.New("账号列表文件损坏，请修复或删除 accounts.json")
		}
		valid := reg.Accounts[:0]
		for _, entry := range reg.Accounts {
			if entry == nil || !idPattern.MatchString(entry.ID) {
				continue
			}
			if entry.Dir == "" {
				entry.Dir = filepath.Join(accountsDir(root), entry.ID)
			}
			valid = append(valid, entry)
		}
		return valid, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	return migrateLegacy(root, legacyDir)
}

// migrateLegacy adopts an existing single-account state directory as the first
// account. The state files are moved into the new account directory rather than
// the directory itself, because the registry root and the legacy state dir are
// the same place and a directory cannot be moved into its own child.
func migrateLegacy(root, legacyDir string) ([]*registryEntry, error) {
	if legacyDir == "" {
		return nil, nil
	}
	legacyDir = filepath.Clean(legacyDir)
	if _, err := os.Stat(filepath.Join(legacyDir, "session.json")); err != nil {
		if _, err := os.Stat(filepath.Join(legacyDir, "device.json")); err != nil {
			return nil, nil // nothing worth migrating
		}
	}
	if _, err := os.Stat(filepath.Join(legacyDir, "runtime.json")); err == nil {
		// A worker may still hold this directory; refuse rather than move its
		// identity out from under a running process.
		return nil, errors.New("检测到旧版单账号目录仍在运行，请先停止后台再启动面板")
	}
	accountDir := filepath.Join(accountsDir(root), "01-primary")
	if err := os.MkdirAll(accountDir, 0700); err != nil {
		return nil, err
	}
	moved := false
	for _, name := range legacyStateFiles {
		source := filepath.Join(legacyDir, name)
		if _, err := os.Stat(source); err != nil {
			continue
		}
		target := filepath.Join(accountDir, name)
		if _, err := os.Stat(target); err == nil {
			continue // already migrated
		}
		if err := os.Rename(source, target); err != nil {
			return nil, fmt.Errorf("迁移 %s 失败: %w", name, err)
		}
		moved = true
	}
	if !moved {
		return nil, nil
	}
	entry := &registryEntry{ID: "01-primary", Dir: accountDir}
	entry.Name, entry.AppleID = legacyIdentity(accountDir)
	if entry.Name == "" {
		entry.Name = "primary"
	}
	if err := saveRegistry(root, []*registryEntry{entry}); err != nil {
		return nil, err
	}
	return []*registryEntry{entry}, nil
}

// legacyStateFiles are the per-account state carried over from the
// single-account layout. The account list itself stays at the root.
var legacyStateFiles = []string{
	"session.json", "device.json", "runtime.json", "control.json",
	"stop-request.json", "probe-urls.json", "daemon.out.log", "daemon.err.log",
	"native-adi", "icloud-modern-webview", "icloud-reset-backups",
	"family-status.json", "storage-status.json", "storage-plans.json",
}

// legacyIdentity recovers the migrated account's Apple ID from the session it
// already has, so duplicate-add detection and display work from the start.
func legacyIdentity(dir string) (name, appleID string) {
	var session struct {
		AppleID string `json:"appleId"`
	}
	data, err := os.ReadFile(filepath.Join(dir, "session.json"))
	if err != nil || json.Unmarshal(data, &session) != nil || session.AppleID == "" {
		return "", ""
	}
	return strings.SplitN(session.AppleID, "@", 2)[0], session.AppleID
}

func saveRegistry(root string, accounts []*registryEntry) error {
	reg := registry{Accounts: accounts}
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	temp := registryPath(root) + ".tmp"
	if err := os.WriteFile(temp, data, 0600); err != nil {
		return err
	}
	return os.Rename(temp, registryPath(root))
}

// newAccountDir allocates a fresh state directory. It never reuses an existing
// one, so an existing account's identity and session cannot be touched.
func newAccountDir(root string, entries []*registryEntry) (id, dir string, err error) {
	if err := os.MkdirAll(accountsDir(root), 0700); err != nil {
		return "", "", err
	}
	used := map[string]bool{}
	for _, entry := range entries {
		used[entry.ID] = true
	}
	for index := 1; index <= 999; index++ {
		candidate := fmt.Sprintf("%02d-account", index)
		if !used[candidate] {
			id = candidate
			break
		}
	}
	if id == "" {
		return "", "", errors.New("账号数量已达上限")
	}
	dir = filepath.Join(accountsDir(root), id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", err
	}
	return id, dir, nil
}
