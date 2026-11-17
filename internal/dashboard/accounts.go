package dashboard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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
	PushConnected          bool                    `json:"push_connected"`
	Authenticated          bool                    `json:"authenticated"`
	VerificationRequired   bool                    `json:"verification_required"`
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
	Accounts         []*registryEntry       `json:"accounts"`
	DeletionSequence int64                  `json:"deletion_sequence,omitempty"`
	DeletionEvents   []accountDeletionEvent `json:"deletion_events,omitempty"`
}

const maxRegistryBytes = 64 << 20

// accountDeletionEvent is a durable, redacted record of an account removed
// from the Windows account registry. It deliberately contains no Apple ID.
type accountDeletionEvent struct {
	Sequence      int64  `json:"sequence"`
	AccountID     string `json:"account_id"`
	AppleIDSHA256 string `json:"apple_id_sha256"`
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
	reg, err := readRegistryDocument(root)
	if err == nil {
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

func readRegistryDocument(root string) (registry, error) {
	var reg registry
	file, err := os.Open(registryPath(root))
	if err != nil {
		return reg, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maxRegistryBytes {
		return registry{}, errors.New("账号列表文件损坏，请修复或删除 accounts.json")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxRegistryBytes+1))
	if err != nil || len(data) > maxRegistryBytes || json.Unmarshal(data, &reg) != nil || validateDeletionEvents(reg) != nil {
		return registry{}, errors.New("账号列表文件损坏，请修复或删除 accounts.json")
	}
	return reg, nil
}

func validateDeletionEvents(reg registry) error {
	if reg.DeletionSequence < 0 || int64(len(reg.DeletionEvents)) != reg.DeletionSequence {
		return errors.New("invalid account deletion ledger")
	}
	for index, event := range reg.DeletionEvents {
		if event.Sequence != int64(index+1) || !idPattern.MatchString(event.AccountID) || !validSHA256Hex(event.AppleIDSHA256) {
			return errors.New("invalid account deletion ledger")
		}
	}
	return nil
}

func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func saveRegistry(root string, accounts []*registryEntry) error {
	reg, err := readRegistryDocument(root)
	if os.IsNotExist(err) {
		reg = registry{}
	} else if err != nil {
		return err
	}
	reg.Accounts = accounts
	return writeRegistryDocument(root, reg)
}

func saveRegistryWithDeletion(root string, accounts []*registryEntry, deleted *registryEntry) (accountDeletionEvent, error) {
	var empty accountDeletionEvent
	if deleted == nil || !idPattern.MatchString(deleted.ID) {
		return empty, errors.New("invalid deleted account")
	}
	reg, err := readRegistryDocument(root)
	if os.IsNotExist(err) {
		reg = registry{}
	} else if err != nil {
		return empty, err
	}
	if reg.DeletionSequence == math.MaxInt64 {
		return empty, errors.New("account deletion sequence exhausted")
	}
	normalizedAppleID := strings.ToLower(strings.TrimSpace(deleted.AppleID))
	appleIDHash := sha256.Sum256([]byte(normalizedAppleID))
	event := accountDeletionEvent{
		Sequence: reg.DeletionSequence + 1, AccountID: deleted.ID,
		AppleIDSHA256: hex.EncodeToString(appleIDHash[:]),
	}
	reg.Accounts = accounts
	reg.DeletionSequence = event.Sequence
	reg.DeletionEvents = append(reg.DeletionEvents, event)
	if err := writeRegistryDocument(root, reg); err != nil {
		return empty, err
	}
	return event, nil
}

func writeRegistryDocument(root string, reg registry) error {
	if err := validateDeletionEvents(reg); err != nil {
		return err
	}
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > maxRegistryBytes {
		return errors.New("账号列表文件超过大小限制")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	temp := registryPath(root) + ".tmp"
	file, err := os.OpenFile(temp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(temp)
		}
	}()
	n, writeErr := file.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(temp, registryPath(root)); err != nil {
		return err
	}
	renamed = true
	return nil
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
