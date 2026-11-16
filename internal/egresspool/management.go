package egresspool

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	probeRequestTimeout = 8 * time.Second
	probeTotalTimeout   = 15 * time.Second
	maxProbeBodyBytes   = 256
)

var exitIPProbeEndpoints = [...]string{
	"https://api.ipify.org/",
	"https://checkip.amazonaws.com/",
}

// ProbeFunc must perform one bounded probe through proxyURL and return only
// the measured egress IP. Dashboard code can adapt the existing GSA transport
// without introducing an egresspool -> gsa import cycle.
type ProbeFunc func(ctx context.Context, proxyURL string) (string, error)

// Only these fixed probe categories may cross the management boundary. Raw
// network errors may embed proxy credentials and must never be returned.
var ErrExitProbe = errors.New("proxy exit check failed")
var ErrCourierProbe = errors.New("proxy courier check failed")

// Manager provides the management API over one application-selected pool path.
// The browser must never supply or override Path.
type Manager struct {
	Path  string
	Probe ProbeFunc
}

// ProbeExit queries two fixed HTTPS IP endpoints through transport. It follows
// no redirects, caps response size and duration, and requires matching results.
func ProbeExit(ctx context.Context, transport http.RoundTripper) (string, error) {
	if transport == nil {
		return "", errors.New("proxy probe transport is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, probeTotalTimeout)
	defer cancel()
	client := &http.Client{
		Transport: transport,
		Timeout:   probeRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ips := make([]string, 0, len(exitIPProbeEndpoints))
	for _, endpoint := range exitIPProbeEndpoints {
		ip, err := probeExitEndpoint(ctx, client, endpoint)
		if err != nil {
			return "", errors.New("proxy egress IP probe failed")
		}
		ips = append(ips, ip)
	}
	if ips[0] != ips[1] {
		return "", errors.New("proxy egress IP probe results disagree")
	}
	return ips[0], nil
}

func probeExitEndpoint(ctx context.Context, client *http.Client, endpoint string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("probe endpoint returned non-success status")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxProbeBodyBytes+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxProbeBodyBytes {
		return "", errors.New("probe response exceeds size limit")
	}
	ip := net.ParseIP(strings.TrimSpace(string(body)))
	if ip == nil {
		return "", errors.New("probe endpoint did not return an IP address")
	}
	return ip.String(), nil
}

// Snapshot returns a sanitized view. A missing file is treated as an empty,
// disabled pool so the settings page can render before the first node is added.
func (m Manager) Snapshot() (Snapshot, error) {
	_, err := m.configPath()
	if err != nil {
		return Snapshot{}, err
	}
	var snapshot Snapshot
	err = m.withLock(func(path string) error {
		cfg, err := loadConfig(path)
		if errors.Is(err, os.ErrNotExist) {
			cfg = newDisabledConfig()
		} else if err != nil {
			return err
		}
		validated, err := validateConfig(&cfg)
		if err != nil {
			return err
		}
		snapshot = snapshotFromConfig(cfg, validated)
		return nil
	})
	return snapshot, err
}

// Upsert probes outside the pool lock, then reloads and validates under lock
// before atomically saving the measured exit IP and timestamp. An empty URL
// reuses the existing URL for id. Exit IP is never accepted from the caller.
func (m Manager) Upsert(ctx context.Context, id, rawURL string, enabled bool) error {
	if !validNodeID(id) {
		return errors.New("proxy node id is invalid")
	}
	if m.Probe == nil {
		return errors.New("proxy node probe is not configured")
	}
	_, err := m.configPath()
	if err != nil {
		return err
	}

	var before node
	var existed bool
	var effectiveURL string
	err = m.withLock(func(path string) error {
		cfg, err := loadManagerConfig(path)
		if err != nil {
			return err
		}
		if _, err := validateConfig(&cfg); err != nil {
			return err
		}
		before, existed = findNode(cfg, id)
		if rawURL == "" {
			if !existed {
				return errors.New("proxy node does not exist")
			}
			effectiveURL = before.URL
		} else {
			effectiveURL = rawURL
		}
		if _, err := parseProxyURL(effectiveURL); err != nil {
			return errors.New("proxy node URL is invalid")
		}
		if existed && nodeHasAssignment(cfg, id) && before.URL != effectiveURL {
			return errors.New("an assigned proxy node URL cannot be changed")
		}
		return nil
	})
	if err != nil {
		return err
	}

	parsedURL, err := parseProxyURL(effectiveURL)
	if err != nil {
		return errors.New("proxy node URL is invalid")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	measured, probeErr := m.Probe(ctx, parsedURL.String())
	if probeErr != nil {
		if errors.Is(probeErr, ErrExitProbe) {
			return ErrExitProbe
		}
		if errors.Is(probeErr, ErrCourierProbe) {
			return ErrCourierProbe
		}
		return errors.New("proxy node probe failed")
	}
	ip := net.ParseIP(strings.TrimSpace(measured))
	if ip == nil {
		return errors.New("proxy node probe returned an invalid IP")
	}
	checkedAt := time.Now().UTC()

	return m.withLock(func(path string) error {
		cfg, err := loadManagerConfig(path)
		if err != nil {
			return err
		}
		if _, err := validateConfig(&cfg); err != nil {
			return err
		}
		current, currentlyExists := findNode(cfg, id)
		if currentlyExists != existed || currentlyExists && current.URL != before.URL {
			return errors.New("proxy pool changed while node was being probed")
		}
		assigned := nodeHasAssignment(cfg, id)
		if assigned && effectiveURL != current.URL {
			return errors.New("an assigned proxy node URL cannot be changed")
		}
		if assigned && ip.String() != current.ExitIP {
			return errors.New("an assigned proxy node exit IP cannot be changed")
		}

		updated := node{ID: id, URL: effectiveURL, ExitIP: ip.String(), Enabled: enabled, CheckedAt: &checkedAt}
		if currentlyExists {
			for index := range cfg.Nodes {
				if cfg.Nodes[index].ID == id {
					cfg.Nodes[index] = updated
					break
				}
			}
		} else {
			cfg.Nodes = append(cfg.Nodes, updated)
		}
		if cfg.Assignments == nil {
			cfg.Assignments = make(map[string]string)
		}
		if _, err := validateConfig(&cfg); err != nil {
			return err
		}
		if err := saveConfig(path, cfg); err != nil {
			return errors.New("could not save proxy node")
		}
		return nil
	})
}

// Delete removes an unassigned node. Assignments are never moved implicitly.
func (m Manager) Delete(id string) error {
	if !validNodeID(id) {
		return errors.New("proxy node id is invalid")
	}
	return m.withLock(func(path string) error {
		cfg, err := loadConfig(path)
		if err != nil {
			return err
		}
		if _, err := validateConfig(&cfg); err != nil {
			return err
		}
		index := nodeIndex(cfg, id)
		if index < 0 {
			return errors.New("proxy node does not exist")
		}
		if nodeHasAssignment(cfg, id) {
			return errors.New("an assigned proxy node cannot be deleted")
		}
		cfg.Nodes = append(cfg.Nodes[:index], cfg.Nodes[index+1:]...)
		if _, err := validateConfig(&cfg); err != nil {
			return err
		}
		if err := saveConfig(path, cfg); err != nil {
			return errors.New("could not delete proxy node")
		}
		return nil
	})
}

// SetMaxAccountsPerExit changes capacity only when every persisted assignment
// still fits under the limit.
func (m Manager) SetMaxAccountsPerExit(limit int) error {
	if limit < 1 || limit > maxAssignments {
		return errors.New("max_accounts_per_exit is out of range")
	}
	return m.withLock(func(path string) error {
		cfg, err := loadManagerConfig(path)
		if err != nil {
			return err
		}
		cfg.MaxAccountsPerExit = limit
		if _, err := validateConfig(&cfg); err != nil {
			return err
		}
		if err := saveConfig(path, cfg); err != nil {
			return errors.New("could not save proxy pool capacity")
		}
		return nil
	})
}

// SetEnabled(false) explicitly disables pool routing. Enabling requires at
// least one enabled, previously probed node and valid capacity for all current
// assignments. It never probes while holding the pool lock.
func (m Manager) SetEnabled(enabled bool) error {
	return m.withLock(func(path string) error {
		cfg, err := loadManagerConfig(path)
		if err != nil {
			return err
		}
		cfg.Enabled = boolPointer(enabled)
		validated, err := validateConfig(&cfg)
		if err != nil {
			return err
		}
		if enabled {
			if err := validateEnablement(cfg, validated); err != nil {
				return err
			}
		}
		if err := saveConfig(path, cfg); err != nil {
			return errors.New("could not save proxy pool state")
		}
		return nil
	})
}

// ValidateActivation performs the same read-only checks as SetEnabled(true)
// without changing the saved enabled flag. Call it before stopping workers or
// changing their route.
func (m Manager) ValidateActivation() error {
	return m.withLock(func(path string) error {
		cfg, err := loadConfig(path)
		if err != nil {
			return err
		}
		cfg.Enabled = boolPointer(true)
		validated, err := validateConfig(&cfg)
		if err != nil {
			return err
		}
		return validateEnablement(cfg, validated)
	})
}

// PrepareAccounts atomically fixes routes for all accountDirs without enabling
// the pool. On any invalid account or exhaustion it saves no assignments.
func (m Manager) PrepareAccounts(accountDirs []string) error {
	return m.withLock(func(path string) error {
		cfg, err := loadConfig(path)
		if err != nil {
			return err
		}
		validated, err := validateConfig(&cfg)
		if err != nil {
			return err
		}
		assignments := make(map[string]string, len(cfg.Assignments)+len(accountDirs))
		for account, nodeID := range cfg.Assignments {
			assignments[account] = nodeID
		}
		loads := make(map[string]int)
		for _, nodeID := range assignments {
			assigned := validated.byID[nodeID]
			if assigned == nil {
				return errors.New("proxy pool assignment references an unavailable node")
			}
			loads[assigned.exitKey]++
		}
		accounts := make([]string, 0, len(accountDirs))
		seen := make(map[string]bool, len(accountDirs))
		for _, dir := range accountDirs {
			account, err := canonicalAccount(dir)
			if err != nil {
				return err
			}
			if !seen[account] {
				seen[account] = true
				accounts = append(accounts, account)
			}
		}
		sort.Strings(accounts)
		for _, account := range accounts {
			if nodeID, exists := assignments[account]; exists {
				assigned := validated.byID[nodeID]
				if assigned == nil || !assigned.source.Enabled {
					return errors.New("an account has an unavailable assigned proxy node")
				}
				continue
			}
			var selected *validatedNode
			for _, candidate := range validated.ordered {
				if !candidate.source.Enabled || candidate.source.CheckedAt == nil || loads[candidate.exitKey] >= cfg.MaxAccountsPerExit {
					continue
				}
				if selected == nil || loads[candidate.exitKey] < loads[selected.exitKey] {
					selected = candidate
				}
			}
			if selected == nil {
				return errors.New("proxy pool has no tested node with available exit capacity")
			}
			assignments[account] = selected.source.ID
			loads[selected.exitKey]++
		}
		if equalAssignments(cfg.Assignments, assignments) {
			return nil
		}
		cfg.Assignments = assignments
		if _, err := validateConfig(&cfg); err != nil {
			return err
		}
		if err := saveConfig(path, cfg); err != nil {
			return errors.New("could not save account proxy assignments")
		}
		return nil
	})
}

func (m Manager) configPath() (string, error) {
	path := strings.TrimSpace(m.Path)
	if path == "" {
		return "", errors.New("proxy pool path is required")
	}
	return path, nil
}

func (m Manager) withLock(action func(string) error) error {
	path, err := m.configPath()
	if err != nil {
		return err
	}
	lock, err := acquireFileLock(path+".lock", defaultLockWait)
	if err != nil {
		return errors.New("proxy pool lock unavailable")
	}
	defer lock.release()
	return action(path)
}

func loadManagerConfig(path string) (config, error) {
	cfg, err := loadConfig(path)
	if errors.Is(err, os.ErrNotExist) {
		return newDisabledConfig(), nil
	}
	return cfg, err
}

func newDisabledConfig() config {
	return config{Enabled: boolPointer(false), Version: 1, Nodes: []node{}, MaxAccountsPerExit: 1, Assignments: map[string]string{}}
}

func boolPointer(value bool) *bool { return &value }

func validNodeID(id string) bool {
	return strings.TrimSpace(id) != "" && strings.TrimSpace(id) == id && len(id) <= maxNodeIDBytes && !hasControl(id)
}

func findNode(cfg config, id string) (node, bool) {
	index := nodeIndex(cfg, id)
	if index < 0 {
		return node{}, false
	}
	return cfg.Nodes[index], true
}

func nodeIndex(cfg config, id string) int {
	for index := range cfg.Nodes {
		if cfg.Nodes[index].ID == id {
			return index
		}
	}
	return -1
}

func nodeHasAssignment(cfg config, id string) bool {
	for _, assigned := range cfg.Assignments {
		if assigned == id {
			return true
		}
	}
	return false
}

func validateEnablement(cfg config, validated validatedConfig) error {
	usable := false
	for _, candidate := range validated.ordered {
		if candidate.source.Enabled && candidate.source.CheckedAt != nil {
			usable = true
			break
		}
	}
	if !usable {
		return errors.New("proxy pool needs an enabled, tested node")
	}
	for _, nodeID := range cfg.Assignments {
		assigned := validated.byID[nodeID]
		if assigned == nil || !assigned.source.Enabled || assigned.source.CheckedAt == nil {
			return errors.New("all assigned nodes must be enabled and tested before activation")
		}
	}
	return nil
}

func equalAssignments(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for account, nodeID := range left {
		if right[account] != nodeID {
			return false
		}
	}
	return true
}
