package v2gateway

import (
	"errors"
	"net/url"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const (
	DefaultListenAddr         = "127.0.0.1:18742"
	DefaultDashboard          = "http://127.0.0.1:18741"
	maxRequestBytes           = 4096
	maxCredentialRequestBytes = 16 << 10
	maxRegistryBytes          = 256 << 10
	maxResponseBytes          = 1 << 20
)

var (
	accountIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	operationPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
	codePattern      = regexp.MustCompile(`^[0-9]{6}$`)
)

type Config struct {
	ListenAddr     string
	DashboardURL   string
	RegistryPath   string
	IntentDir      string
	BearerToken    string
	RequestTimeout time.Duration
}

type Family struct {
	Member               bool `json:"member"`
	Organizer            bool `json:"organizer"`
	Members              int  `json:"members"`
	Organizers           int  `json:"organizers"`
	Self                 int  `json:"self"`
	StorageKnown         bool `json:"storage_known"`
	StorageParticipating bool `json:"storage_participating"`
	StorageAvailable     bool `json:"storage_available"`
	StorageEnabled       bool `json:"storage_enabled"`
}

type familyReply struct {
	OK      bool    `json:"ok"`
	Stage   string  `json:"stage"`
	Message string  `json:"message"`
	Family  *Family `json:"family"`
}

type familyPoolMember struct {
	AccountID string `json:"account_id"`
	Organizer bool   `json:"organizer"`
	Child     bool   `json:"child"`
}

type familyPoolProjection struct {
	Members       []familyPoolMember `json:"members"`
	UnmappedCount int                `json:"unmapped_count"`
	TotalCount    int                `json:"total_count"`
}

type familyPoolReply struct {
	OK            bool               `json:"ok"`
	Stage         string             `json:"stage"`
	Message       string             `json:"message"`
	Members       []familyPoolMember `json:"members"`
	UnmappedCount int                `json:"unmapped_count"`
	TotalCount    int                `json:"total_count"`
}

type resolveRequest struct {
	AppleID string `json:"apple_id"`
}

type resolveReply struct {
	OK        bool   `json:"ok"`
	AccountID string `json:"account_id,omitempty"`
}

type accountRequest struct {
	AccountID string `json:"account_id"`
}

type mutationRequest struct {
	OrganizerAccountID string `json:"organizer_account_id"`
	TargetAccountID    string `json:"target_account_id"`
	OperationID        string `json:"operation_id"`
}

type familyAddCredentialRequest struct {
	OrganizerAccountID string `json:"organizer_account_id"`
	TargetAccountID    string `json:"target_account_id"`
	OperationID        string `json:"operation_id"`
	TargetAppleID      string `json:"target_apple_id"`
	TargetPassword     string `json:"target_password"`
}

type familyAddCredential struct {
	targetAppleID string
	password      string
}

func (c *familyAddCredential) clear() {
	if c != nil {
		c.targetAppleID, c.password = "", ""
	}
}

type codeReply struct {
	OK   bool   `json:"ok"`
	Code string `json:"code,omitempty"`
}

type errorReply struct {
	OK      bool   `json:"ok"`
	Stage   string `json:"stage,omitempty"`
	Message string `json:"message,omitempty"`
}

type accountEntry struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	AppleID   string `json:"apple_id"`
	Dir       string `json:"dir"`
	CreatedAt string `json:"created_at,omitempty"`
}

type accountRegistry struct {
	Accounts []accountEntry `json:"accounts"`
}

func defaultRequestTimeout(value time.Duration) time.Duration {
	if value <= 0 {
		return 125 * time.Second
	}
	return value
}

func validateConfig(cfg Config) (url.URL, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = DefaultListenAddr
	}
	host, port, err := splitListenAddr(cfg.ListenAddr)
	if err != nil || host != "127.0.0.1" || port == "" {
		return url.URL{}, errors.New("invalid loopback listener")
	}
	if cfg.DashboardURL == "" {
		cfg.DashboardURL = DefaultDashboard
	}
	dashboard, err := url.Parse(cfg.DashboardURL)
	if err != nil || dashboard.Scheme != "http" || dashboard.Hostname() != "127.0.0.1" || dashboard.Port() == "" || dashboard.User != nil || dashboard.Path != "" || dashboard.RawQuery != "" || dashboard.Fragment != "" {
		return url.URL{}, errors.New("invalid local dashboard URL")
	}
	if len([]byte(cfg.BearerToken)) < 32 || strings.ContainsAny(cfg.BearerToken, "\r\n") {
		return url.URL{}, errors.New("invalid bearer credential")
	}
	if !filepath.IsAbs(cfg.RegistryPath) || !strings.EqualFold(filepath.Base(cfg.RegistryPath), "accounts.json") {
		return url.URL{}, errors.New("invalid account registry path")
	}
	if !filepath.IsAbs(cfg.IntentDir) {
		return url.URL{}, errors.New("invalid intent directory")
	}
	if runtime.GOOS == "windows" {
		if !strings.EqualFold(filepath.VolumeName(cfg.RegistryPath), `D:`) || !strings.EqualFold(filepath.VolumeName(cfg.IntentDir), `D:`) {
			return url.URL{}, errors.New("local data paths must be on D:")
		}
	}
	return *dashboard, nil
}

// splitListenAddr deliberately accepts only a literal IPv4 loopback address.
func splitListenAddr(addr string) (string, string, error) {
	parts := strings.Split(addr, ":")
	if len(parts) != 2 || parts[0] != "127.0.0.1" || parts[1] == "" {
		return "", "", errors.New("listener must use 127.0.0.1")
	}
	for _, r := range parts[1] {
		if r < '0' || r > '9' {
			return "", "", errors.New("invalid listener port")
		}
	}
	return parts[0], parts[1], nil
}

func validAccountID(value string) bool { return accountIDPattern.MatchString(value) }

func validOperationID(value string) bool { return operationPattern.MatchString(value) }

func normalizeAppleID(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || len(value) > 254 || strings.Count(value, "@") != 1 {
		return "", false
	}
	for _, r := range value {
		if r <= 0x20 || r == 0x7f || r == '\\' || r == '/' {
			return "", false
		}
	}
	return value, true
}

func accountIDFromRegistry(reg accountRegistry, accountID string) (accountEntry, bool) {
	if !validAccountID(accountID) {
		return accountEntry{}, false
	}
	var found accountEntry
	count := 0
	for _, account := range reg.Accounts {
		if account.ID == accountID {
			found = account
			count++
		}
	}
	return found, count == 1
}
