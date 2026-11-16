package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Laky-64/appleservices/aps"
	"github.com/Laky-64/appleservices/gsa"
	"github.com/Laky-64/appleservices/internal/control"
	"github.com/Laky-64/appleservices/internal/egresspool"
)

type proxyPoolAccount struct {
	AccountID string `json:"account_id"`
	NodeID    string `json:"node_id"`
	ExitIP    string `json:"exit_ip"`
	Applied   bool   `json:"applied"`
	Running   bool   `json:"running"`
	State     string `json:"state"`
	Message   string `json:"message,omitempty"`
}

type proxyPoolView struct {
	egresspool.Snapshot
	OK         bool               `json:"ok"`
	Configured bool               `json:"configured"`
	Applying   bool               `json:"applying"`
	Message    string             `json:"message"`
	Accounts   []proxyPoolAccount `json:"accounts"`
}

func (s *Server) proxyManager() egresspool.Manager {
	probe := s.proxyPoolProbe
	if probe == nil {
		probe = func(ctx context.Context, raw string) (string, error) {
			transport, err := gsa.AppleRootTransportForProxy(raw)
			if err != nil {
				return "", errors.New("proxy URL is invalid")
			}
			defer transport.CloseIdleConnections()
			exit, err := egresspool.ProbeExit(ctx, transport)
			if err != nil {
				return "", egresspool.ErrExitProbe
			}
			if err := aps.CheckProxy(ctx, raw); err != nil {
				return "", egresspool.ErrCourierProbe
			}
			return exit, nil
		}
	}
	return egresspool.Manager{Path: strings.TrimSpace(os.Getenv(egresspool.PoolEnv)), Probe: probe}
}

func (s *Server) proxyAccounts() []*Account {
	s.accountsMu.Lock()
	defer s.accountsMu.Unlock()
	return append([]*Account(nil), s.accounts...)
}

func (s *Server) proxySnapshot() proxyPoolView {
	result := proxyPoolView{OK: true, Accounts: []proxyPoolAccount{}, Applying: s.proxyPoolApplying.Load()}
	manager := s.proxyManager()
	result.Configured = manager.Path != ""
	if !result.Configured {
		result.Message = "服务器尚未设置独立代理池，请检查服务配置"
		return result
	}
	snapshot, err := manager.Snapshot()
	if err != nil {
		result.OK = false
		result.Message = "代理池配置读取失败，请检查服务器私有配置"
		return result
	}
	result.Snapshot = snapshot
	assignments := make(map[string]egresspool.Assignment, len(snapshot.Assignments))
	available := make(map[string]bool, len(snapshot.Nodes))
	for _, node := range snapshot.Nodes {
		available[node.ID] = node.Enabled
	}
	for _, assignment := range snapshot.Assignments {
		assignments[assignment.Account] = assignment
	}
	for _, account := range s.proxyAccounts() {
		status := s.accountStatus(account)
		assignment := assignments[strings.ToLower(filepath.Base(account.Dir))]
		state := status.State
		if state == "" {
			state = "stopped"
		}
		account.mu.Lock()
		message := account.message
		account.mu.Unlock()
		result.Accounts = append(result.Accounts, proxyPoolAccount{AccountID: account.ID, NodeID: assignment.NodeID, ExitIP: assignment.ExitIP, Running: status.Running, State: state,
			Message: message, Applied: snapshot.Enabled && available[assignment.NodeID] && assignment.NodeID != "" && status.Running && status.ProxyNodeID == assignment.NodeID && status.ProxyExitIP == assignment.ExitIP})
	}
	if snapshot.Enabled {
		result.Message = "代理池已启用；账号应用状态以实际运行的后台为准"
	} else {
		result.Message = "代理池尚未启用，当前账号出口保持原状"
	}
	return result
}

func proxyPoolError(err error) string {
	message := err.Error()
	switch {
	case strings.Contains(message, "courier"):
		return "代理无法通过 Apple 推送通道测试（TCP 5223），请检查节点和端口限制"
	case strings.Contains(message, "exit check") || strings.Contains(message, "probe"):
		return "代理出口测试未通过，请检查节点连接、认证及出口是否固定"
	case strings.Contains(message, "assigned") || strings.Contains(message, "assignment"):
		return "该节点已绑定账号，不能直接更换出口或删除；请保留原节点"
	case strings.Contains(message, "capacity") || strings.Contains(message, "enabled node"):
		return "不同出口数量或账号容量不足，请添加节点或调整每出口账号上限"
	case strings.Contains(message, "URL") || strings.Contains(message, "url"):
		return "代理地址格式不正确，请填写 HTTP、HTTPS 或 SOCKS5 代理地址"
	case strings.Contains(message, "max_accounts"):
		return "每出口账号上限必须是有效的正整数"
	case strings.Contains(message, "workers could not be stopped"):
		return "部分账号后台尚未停止，代理池保持原启用状态，请稍后重试"
	case strings.Contains(message, "worker recovery pending"):
		return "代理切换未完成，部分已停止账号未能恢复，请查看下方账号状态后处理"
	default:
		return "操作未完成，请检查节点配置后重试；原配置未被覆盖"
	}
}

func (s *Server) handleProxyPoolAPI(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/api/proxy-pool/") {
		return false
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/proxy-pool/status" {
		json.NewEncoder(w).Encode(s.proxySnapshot())
		return true
	}
	if r.Method != http.MethodPost {
		http.Error(w, `{"ok":false,"message":"请求方法不受支持"}`, 405)
		return true
	}
	if !s.proxyPoolMu.TryLock() {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "message": "代理池正在处理另一项操作，请稍候"})
		return true
	}
	defer s.proxyPoolMu.Unlock()
	manager := s.proxyManager()
	if manager.Path == "" {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "message": "服务器尚未设置独立代理池配置路径"})
		return true
	}
	var err error
	message := ""
	switch r.URL.Path {
	case "/api/proxy-pool/node":
		var input struct {
			ID      string `json:"id"`
			URL     string `json:"url"`
			Enabled bool   `json:"enabled"`
		}
		if !readJSON(w, r, &input) {
			return true
		}
		defer func() { input.URL = "" }()
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		err = manager.Upsert(ctx, strings.TrimSpace(input.ID), strings.TrimSpace(input.URL), input.Enabled)
		message = "节点已通过出口与推送通道测试并保存；请启用并应用到账号"
	case "/api/proxy-pool/remove":
		var input struct {
			ID string `json:"id"`
		}
		if !readJSON(w, r, &input) {
			return true
		}
		err = manager.Delete(input.ID)
		message = "节点已删除"
	case "/api/proxy-pool/settings":
		var input struct {
			Max int `json:"max_accounts_per_exit"`
		}
		if !readJSON(w, r, &input) {
			return true
		}
		err = manager.SetMaxAccountsPerExit(input.Max)
		message = "每出口账号上限已保存"
	case "/api/proxy-pool/apply":
		var input struct{}
		if !readJSON(w, r, &input) {
			return true
		}
		message, err = s.applyProxyPool(r.Context(), manager)
	default:
		http.NotFound(w, r)
		return true
	}
	if err != nil {
		result := s.proxySnapshot()
		result.OK = false
		result.Message = proxyPoolError(err)
		json.NewEncoder(w).Encode(result)
		return true
	}
	result := s.proxySnapshot()
	result.Message = message
	json.NewEncoder(w).Encode(result)
	return true
}

// Applying a pool never obtains credentials or starts a fresh login. Each
// account either resumes its own saved checkpoint or remains stopped.
func (s *Server) applyProxyPool(ctx context.Context, manager egresspool.Manager) (string, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute)
	defer cancel()
	s.proxyPoolApplying.Store(true)
	defer s.proxyPoolApplying.Store(false)
	accounts := s.proxyAccounts()
	dirs := make([]string, 0, len(accounts))
	for _, account := range accounts {
		dirs = append(dirs, account.Dir)
	}
	if err := manager.PrepareAccounts(dirs); err != nil {
		return "", err
	}
	if err := manager.ValidateActivation(); err != nil {
		return "", err
	}
	snapshot, err := manager.Snapshot()
	if err != nil {
		return "", err
	}
	assigned := make(map[string]egresspool.Assignment, len(snapshot.Assignments))
	for _, assignment := range snapshot.Assignments {
		assigned[assignment.Account] = assignment
	}
	stop := s.proxyPoolStop
	if stop == nil {
		stop = func(ctx context.Context, a *Account) error { return s.stopIn(ctx, a.Dir) }
	}
	resume := s.proxyPoolResume
	if resume == nil {
		resume = func(ctx context.Context, account *Account) control.Result {
			if !macPushStateReady(account.Dir) {
				return control.Result{Message: "账号缺少已有推送身份，请在账号页处理"}
			}
			return s.startSavedAccount(ctx, account)
		}
	}
	verificationRequired := make(map[string]bool, len(accounts))
	var stopped []*Account
	rollback := func() bool {
		restored := true
		for _, prior := range stopped {
			if verificationRequired[prior.ID] || !resume(ctx, prior).OK {
				s.setMessage(prior, "代理切换未完成；该账号未能恢复，请在账号页处理登录状态")
				restored = false
			}
		}
		return restored
	}
	for _, account := range accounts {
		status := s.accountStatus(account)
		verificationRequired[account.ID] = status.VerificationRequired
		binding := assigned[strings.ToLower(filepath.Base(account.Dir))]
		if status.Running && status.ProxyNodeID == binding.NodeID && status.ProxyExitIP == binding.ExitIP {
			continue
		}
		if !status.Running {
			continue
		}
		if err := stop(ctx, account); err != nil {
			// The pool is still in its prior activation state. Restore only those
			// stopped here, using that state's already-saved sessions.
			if !rollback() {
				return "", errors.New("proxy worker recovery pending")
			}
			return "", errors.New("proxy workers could not be stopped")
		}
		stopped = append(stopped, account)
	}
	if err := manager.SetEnabled(true); err != nil {
		if !rollback() {
			return "", errors.New("proxy worker recovery pending")
		}
		return "", err
	}
	for _, account := range accounts {
		if verificationRequired[account.ID] {
			s.setMessage(account, "代理已分配；该账号需要验证，请在账号页处理")
			continue
		}
		status := s.accountStatus(account)
		binding := assigned[strings.ToLower(filepath.Base(account.Dir))]
		if status.Running && status.ProxyNodeID == binding.NodeID && status.ProxyExitIP == binding.ExitIP {
			continue
		}
		result := resume(ctx, account)
		if !result.OK {
			s.setMessage(account, "代理已分配；已有会话未能恢复，请在账号页处理登录状态")
		}
	}
	return "代理池已启用并发起已有会话恢复；账号实际应用情况会自动更新，需要登录的账号保留待处理", nil
}
