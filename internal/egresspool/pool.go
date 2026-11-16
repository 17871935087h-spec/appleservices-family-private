// Package egresspool assigns account directories to persistent proxy nodes and
// manages sanitized pool metadata. Network probes are explicitly injected.
package egresspool

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const PoolEnv = "APPLESERVICES_PROXY_POOL"

const defaultLockWait = 5 * time.Second

const (
	maxConfigBytes    = 2 << 20
	maxNodes          = 2048
	maxAssignments    = 50000
	maxNodeIDBytes    = 128
	maxProxyURLBytes  = 4096
	maxAccountNameLen = 255
)

// Route is the selected route for one account. URL contains proxy credentials
// when configured and is intentionally excluded from automatic JSON output.
type Route struct {
	Enabled        bool   `json:"enabled"`
	NodeID         string `json:"node_id,omitempty"`
	URL            string `json:"-"`
	ExitIP         string `json:"exit_ip,omitempty"`
	inactiveByPool bool
}

func (r Route) String() string {
	return fmt.Sprintf("Route{Enabled:%t NodeID:%q URL:<redacted> ExitIP:%q}", r.Enabled, r.NodeID, r.ExitIP)
}

func (r Route) GoString() string { return r.String() }

type config struct {
	Enabled            *bool             `json:"enabled,omitempty"`
	Version            int               `json:"version"`
	Nodes              []node            `json:"nodes"`
	MaxAccountsPerExit int               `json:"max_accounts_per_exit,omitempty"`
	Assignments        map[string]string `json:"assignments"`
}

type node struct {
	ID        string     `json:"id"`
	URL       string     `json:"url"`
	ExitIP    string     `json:"exit_ip"`
	Enabled   bool       `json:"enabled"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`
}

// NodeSummary and Assignment are safe-to-display views that never include
// proxy URLs or credentials.
type NodeSummary struct {
	ID               string     `json:"id"`
	ExitIP           string     `json:"exit_ip"`
	Enabled          bool       `json:"enabled"`
	Scheme           string     `json:"scheme"`
	Endpoint         string     `json:"endpoint"`
	CheckedAt        *time.Time `json:"checked_at,omitempty"`
	AssignedAccounts []string   `json:"assigned_accounts"`
}

type Assignment struct {
	Account string `json:"account"`
	NodeID  string `json:"node_id"`
	ExitIP  string `json:"exit_ip"`
}

type Snapshot struct {
	Enabled            bool          `json:"enabled"`
	MaxAccountsPerExit int           `json:"max_accounts_per_exit"`
	Nodes              []NodeSummary `json:"nodes"`
	Assignments        []Assignment  `json:"assignments"`
}

// Resolve returns the persisted route for accountDir, allocating one if needed.
// An unset APPLESERVICES_PROXY_POOL disables routing. A configured but invalid
// or exhausted pool always returns an error; it never falls back to direct.
func Resolve(accountDir string) (Route, error) {
	poolPath := strings.TrimSpace(os.Getenv(PoolEnv))
	if poolPath == "" {
		return Route{Enabled: false}, nil
	}
	lock, err := acquireFileLock(poolPath+".lock", defaultLockWait)
	if err != nil {
		return Route{}, fmt.Errorf("proxy pool lock unavailable")
	}
	defer lock.release()

	cfg, err := loadConfig(poolPath)
	if err != nil {
		return Route{}, err
	}
	validated, err := validateConfig(&cfg)
	if err != nil {
		return Route{}, err
	}
	if !configEnabled(cfg) {
		return Route{Enabled: false, inactiveByPool: true}, nil
	}
	account, err := canonicalAccount(accountDir)
	if err != nil {
		return Route{}, err
	}
	loads := make(map[string]int)
	for _, assignedID := range cfg.Assignments {
		assigned := validated.byID[assignedID]
		if assigned == nil {
			return Route{}, fmt.Errorf("proxy pool assignment references an unavailable node")
		}
		loads[assigned.exitKey]++
	}
	for _, load := range loads {
		if load > cfg.MaxAccountsPerExit {
			return Route{}, fmt.Errorf("proxy pool assignments exceed exit capacity")
		}
	}
	if nodeID, ok := cfg.Assignments[account]; ok {
		selected := validated.byID[nodeID]
		if selected == nil {
			return Route{}, fmt.Errorf("proxy pool assignment references an unavailable node")
		}
		if !selected.source.Enabled {
			return Route{}, fmt.Errorf("assigned proxy node is disabled")
		}
		return selected.route(), nil
	}

	var selected *validatedNode
	for _, candidate := range validated.ordered {
		if !candidate.source.Enabled || loads[candidate.exitKey] >= cfg.MaxAccountsPerExit {
			continue
		}
		if selected == nil || loads[candidate.exitKey] < loads[selected.exitKey] {
			selected = candidate
		}
	}
	if selected == nil {
		return Route{}, fmt.Errorf("proxy pool has no enabled node with available exit capacity")
	}

	if cfg.Assignments == nil {
		cfg.Assignments = make(map[string]string)
	}
	cfg.Assignments[account] = selected.source.ID
	if err := saveConfig(poolPath, cfg); err != nil {
		return Route{}, fmt.Errorf("could not persist proxy pool assignment")
	}
	return selected.route(), nil
}

// Environment returns a copy of base with the selected account proxy
// environment installed. Existing proxy variables are removed case-insensitively.
func Environment(base []string, accountDir string) ([]string, error) {
	var result []string
	if base != nil {
		result = make([]string, len(base))
		copy(result, base)
	}
	route, err := Resolve(accountDir)
	if err != nil {
		return nil, err
	}
	if !route.Enabled {
		if route.inactiveByPool {
			result = withoutEnvironmentKeys(result, PoolEnv, "APPLESERVICES_ACCOUNT_PROXY")
		}
		return result, nil
	}
	result = withoutProxyEnvironment(result)
	return append(result,
		"HTTP_PROXY="+route.URL,
		"HTTPS_PROXY="+route.URL,
		"ALL_PROXY="+route.URL,
		"NO_PROXY=localhost,127.0.0.1,::1",
		"APPLESERVICES_ACCOUNT_PROXY="+route.URL,
	), nil
}

// Apply installs a route into the current process environment. Call once in a
// dedicated account helper before it performs network work; shared dashboards
// must use Environment to construct each worker's child environment instead.
func Apply(accountDir string) error {
	route, err := Resolve(accountDir)
	if err != nil {
		return err
	}
	if !route.Enabled {
		if route.inactiveByPool {
			if err := unsetEnvironmentKeys(PoolEnv, "APPLESERVICES_ACCOUNT_PROXY"); err != nil {
				return fmt.Errorf("could not clear inactive proxy environment")
			}
		}
		return nil
	}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if isProxyEnvironmentKey(key) {
			if err := os.Unsetenv(key); err != nil {
				return fmt.Errorf("could not clear prior proxy environment")
			}
		}
	}
	for _, pair := range [][2]string{
		{"HTTP_PROXY", route.URL},
		{"HTTPS_PROXY", route.URL},
		{"ALL_PROXY", route.URL},
		{"NO_PROXY", "localhost,127.0.0.1,::1"},
		{"APPLESERVICES_ACCOUNT_PROXY", route.URL},
	} {
		if err := os.Setenv(pair[0], pair[1]); err != nil {
			return fmt.Errorf("could not apply account proxy environment")
		}
	}
	return nil
}

// Inspect returns a sanitized summary of the configured pool. It never emits
// proxy URLs or credentials and does not perform network probes.
func Inspect() (Snapshot, error) {
	poolPath := strings.TrimSpace(os.Getenv(PoolEnv))
	if poolPath == "" {
		return Snapshot{}, errors.New("proxy pool is not configured")
	}
	lock, err := acquireFileLock(poolPath+".lock", defaultLockWait)
	if err != nil {
		return Snapshot{}, fmt.Errorf("proxy pool lock unavailable")
	}
	defer lock.release()
	cfg, err := loadConfig(poolPath)
	if err != nil {
		return Snapshot{}, err
	}
	validated, err := validateConfig(&cfg)
	if err != nil {
		return Snapshot{}, err
	}
	return snapshotFromConfig(cfg, validated), nil
}

func snapshotFromConfig(cfg config, validated validatedConfig) Snapshot {
	snapshot := Snapshot{
		Enabled:            configEnabled(cfg),
		MaxAccountsPerExit: cfg.MaxAccountsPerExit,
		Nodes:              make([]NodeSummary, 0, len(validated.ordered)),
		Assignments:        make([]Assignment, 0, len(cfg.Assignments)),
	}
	byID := make(map[string]int, len(validated.ordered))
	for _, item := range validated.ordered {
		parsed, _ := url.Parse(item.source.URL) // validateConfig already checked the URL.
		snapshot.Nodes = append(snapshot.Nodes, NodeSummary{ID: item.source.ID, ExitIP: item.source.ExitIP, Enabled: item.source.Enabled, Scheme: parsed.Scheme, Endpoint: parsed.Host, CheckedAt: item.source.CheckedAt, AssignedAccounts: []string{}})
		byID[item.source.ID] = len(snapshot.Nodes) - 1
	}
	for account, nodeID := range cfg.Assignments {
		item := validated.byID[nodeID]
		snapshot.Assignments = append(snapshot.Assignments, Assignment{Account: account, NodeID: nodeID, ExitIP: item.source.ExitIP})
		nodeIndex := byID[nodeID]
		snapshot.Nodes[nodeIndex].AssignedAccounts = append(snapshot.Nodes[nodeIndex].AssignedAccounts, account)
	}
	sort.Slice(snapshot.Assignments, func(i, j int) bool { return snapshot.Assignments[i].Account < snapshot.Assignments[j].Account })
	for i := range snapshot.Nodes {
		sort.Strings(snapshot.Nodes[i].AssignedAccounts)
	}
	return snapshot
}

type validatedNode struct {
	source  node
	exitKey string
}

func (n *validatedNode) route() Route {
	return Route{Enabled: true, NodeID: n.source.ID, URL: n.source.URL, ExitIP: n.source.ExitIP}
}

type validatedConfig struct {
	ordered []*validatedNode
	byID    map[string]*validatedNode
}

func loadConfig(path string) (config, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return config{}, fmt.Errorf("could not read proxy pool config: %w", os.ErrNotExist)
		}
		return config{}, fmt.Errorf("could not read proxy pool config")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil || len(data) > maxConfigBytes {
		return config{}, fmt.Errorf("proxy pool config exceeds size limit")
	}
	var cfg config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return config{}, fmt.Errorf("proxy pool config is invalid JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return config{}, fmt.Errorf("proxy pool config has trailing data")
	} else if err != io.EOF {
		return config{}, fmt.Errorf("proxy pool config is invalid JSON")
	}
	return cfg, nil
}

func validateConfig(cfg *config) (validatedConfig, error) {
	if cfg.Version != 1 {
		return validatedConfig{}, fmt.Errorf("proxy pool version must be 1")
	}
	if cfg.MaxAccountsPerExit == 0 {
		cfg.MaxAccountsPerExit = 1
	}
	if cfg.MaxAccountsPerExit < 1 || cfg.MaxAccountsPerExit > maxAssignments {
		return validatedConfig{}, fmt.Errorf("max_accounts_per_exit must be positive")
	}
	if len(cfg.Nodes) > maxNodes {
		return validatedConfig{}, fmt.Errorf("proxy pool has too many nodes")
	}
	if len(cfg.Assignments) > maxAssignments {
		return validatedConfig{}, fmt.Errorf("proxy pool has too many assignments")
	}
	if cfg.Nodes == nil {
		cfg.Nodes = []node{}
	}
	if cfg.Assignments == nil {
		cfg.Assignments = make(map[string]string)
	}
	validated := validatedConfig{ordered: make([]*validatedNode, 0, len(cfg.Nodes)), byID: make(map[string]*validatedNode, len(cfg.Nodes))}
	for index, item := range cfg.Nodes {
		if strings.TrimSpace(item.ID) == "" || strings.TrimSpace(item.ID) != item.ID || len(item.ID) > maxNodeIDBytes || hasControl(item.ID) {
			return validatedConfig{}, fmt.Errorf("proxy pool node %d has an invalid id", index)
		}
		if _, exists := validated.byID[item.ID]; exists {
			return validatedConfig{}, fmt.Errorf("proxy pool has duplicate node ids")
		}
		parsed, err := parseProxyURL(item.URL)
		if err != nil {
			return validatedConfig{}, fmt.Errorf("proxy pool node %d has an invalid URL", index)
		}
		item.URL = parsed.String()
		ip := net.ParseIP(strings.TrimSpace(item.ExitIP))
		if ip == nil {
			return validatedConfig{}, fmt.Errorf("proxy pool node %d has an invalid exit_ip", index)
		}
		if item.CheckedAt != nil && item.CheckedAt.IsZero() {
			return validatedConfig{}, fmt.Errorf("proxy pool node %d has invalid checked_at", index)
		}
		item.ExitIP = ip.String()
		entry := &validatedNode{source: item, exitKey: ip.String()}
		validated.ordered = append(validated.ordered, entry)
		validated.byID[item.ID] = entry
	}
	if len(validated.ordered) == 0 && configEnabled(*cfg) {
		return validatedConfig{}, fmt.Errorf("proxy pool has no nodes")
	}
	loads := make(map[string]int)
	for account, nodeID := range cfg.Assignments {
		if account == "" || len(account) > maxAccountNameLen || hasControl(account) || account != strings.ToLower(strings.TrimSpace(account)) || nodeID == "" {
			return validatedConfig{}, fmt.Errorf("proxy pool has an invalid assignment")
		}
		assigned, exists := validated.byID[nodeID]
		if !exists {
			return validatedConfig{}, fmt.Errorf("proxy pool assignment references an unavailable node")
		}
		loads[assigned.exitKey]++
		if loads[assigned.exitKey] > cfg.MaxAccountsPerExit {
			return validatedConfig{}, fmt.Errorf("proxy pool assignments exceed exit capacity")
		}
	}
	return validated, nil
}

func configEnabled(cfg config) bool {
	return cfg.Enabled == nil || *cfg.Enabled
}

func supportedScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "http", "https", "socks5", "socks5h":
		return true
	default:
		return false
	}
}

func parseProxyURL(raw string) (*url.URL, error) {
	if raw == "" || len(raw) > maxProxyURLBytes || hasControl(raw) {
		return nil, fmt.Errorf("invalid proxy URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || parsed.Opaque != "" || parsed.Host == "" || !supportedScheme(parsed.Scheme) {
		return nil, fmt.Errorf("invalid proxy URL")
	}
	if (parsed.Path != "" && parsed.Path != "/") || (parsed.RawPath != "" && parsed.RawPath != "/") || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(raw, "#") {
		return nil, fmt.Errorf("invalid proxy URL")
	}
	if parsed.Hostname() == "" {
		return nil, fmt.Errorf("invalid proxy URL")
	}
	if parsed.User != nil {
		username := parsed.User.Username()
		password, hasPassword := parsed.User.Password()
		if username == "" || !hasPassword || password == "" || hasControl(username) || hasControl(password) {
			return nil, fmt.Errorf("invalid proxy URL")
		}
	}
	port, hasPort, validPort := hostPort(parsed.Host)
	if !validPort {
		return nil, fmt.Errorf("invalid proxy URL")
	}
	if hasPort {
		parsedPort, err := strconv.Atoi(port)
		if err != nil || parsedPort < 1 || parsedPort > 65535 {
			return nil, fmt.Errorf("invalid proxy URL")
		}
	} else {
		defaultPort := ""
		switch strings.ToLower(parsed.Scheme) {
		case "http":
			defaultPort = "80"
		case "https":
			defaultPort = "443"
		case "socks5", "socks5h":
			defaultPort = "1080"
		}
		host := parsed.Hostname()
		if strings.Contains(host, "%") {
			host = strings.ReplaceAll(host, "%", "%25")
		}
		parsed.Host = net.JoinHostPort(host, defaultPort)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	return parsed, nil
}

// hostPort distinguishes a missing port from an explicit but empty port.
func hostPort(host string) (port string, hasPort bool, valid bool) {
	if strings.HasPrefix(host, "[") {
		end := strings.LastIndex(host, "]")
		if end < 0 {
			return "", false, false
		}
		suffix := host[end+1:]
		if suffix == "" {
			return "", false, true
		}
		if !strings.HasPrefix(suffix, ":") || len(suffix) == 1 {
			return "", false, false
		}
		return suffix[1:], true, true
	}
	if strings.Count(host, ":") > 1 {
		return "", false, false
	}
	if index := strings.LastIndexByte(host, ':'); index >= 0 {
		if index == len(host)-1 {
			return "", false, false
		}
		return host[index+1:], true, true
	}
	return "", false, true
}

func hasControl(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}

func canonicalAccount(accountDir string) (string, error) {
	accountDir = strings.TrimSpace(accountDir)
	if accountDir == "" {
		return "", fmt.Errorf("account directory is required when proxy pooling is enabled")
	}
	// Treat both separator styles alike so Windows paths stay canonical in
	// cross-platform tests and maintenance tools.
	portablePath := filepath.Clean(strings.ReplaceAll(accountDir, `\`, `/`))
	if portablePath == "/" || strings.HasSuffix(portablePath, ":") {
		return "", fmt.Errorf("account directory has no canonical basename")
	}
	account := filepath.Base(portablePath)
	account = strings.ToLower(strings.TrimSpace(account))
	if account == "" || account == "." || account == ".." || account == string(filepath.Separator) {
		return "", fmt.Errorf("account directory has no canonical basename")
	}
	if len(account) > maxAccountNameLen || hasControl(account) {
		return "", fmt.Errorf("account directory has an invalid canonical basename")
	}
	return account, nil
}

func withoutProxyEnvironment(base []string) []string {
	filtered := make([]string, 0, len(base)+5)
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		if !isProxyEnvironmentKey(key) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func withoutEnvironmentKeys(base []string, keys ...string) []string {
	filtered := make([]string, 0, len(base))
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		remove := false
		for _, candidate := range keys {
			if strings.EqualFold(key, candidate) {
				remove = true
				break
			}
		}
		if !remove {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func unsetEnvironmentKeys(keys ...string) error {
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		for _, candidate := range keys {
			if strings.EqualFold(key, candidate) {
				if err := os.Unsetenv(key); err != nil {
					return err
				}
				break
			}
		}
	}
	return nil
}

func isProxyEnvironmentKey(key string) bool {
	switch strings.ToUpper(key) {
	case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "APPLESERVICES_SOCKS_PROXY", "STORE_PROXY", "APPLESERVICES_STORE_PROXY", "APPLESERVICES_ACCOUNT_PROXY":
		return true
	default:
		return false
	}
}

func saveConfig(path string, cfg config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".egresspool-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return replaceFile(tmpPath, path)
}
