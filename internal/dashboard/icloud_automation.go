package dashboard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Laky-64/appleservices/internal/control"
)

const (
	iCloudAutomationJournalFile = "icloud-automation.json"
	iCloudAutomationPollEvery   = 2 * time.Second
	iCloudAutomationStableFor   = 2 * time.Second
	iCloudAutomationWorkerWait  = 4 * time.Minute
	iCloudAutomationRetryBase   = 2 * time.Second
	iCloudAutomationMaxTries    = 3
)

// ICloudAutomationStatus is the safe, account-local progress shown by the
// dashboard. It deliberately has no account identifiers or session material.
type ICloudAutomationStatus struct {
	Enabled   bool      `json:"enabled"`
	Stage     string    `json:"stage"`
	Running   bool      `json:"running"`
	Message   string    `json:"message,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// iCloudAutomationJournal contains only workflow metadata. In particular, it
// must never grow fields for passwords, verification codes, cookies, or tokens.
type iCloudAutomationJournal struct {
	Version             int       `json:"version"`
	Stage               string    `json:"stage"`
	Paused              bool      `json:"paused,omitempty"`
	Submitted           bool      `json:"submitted,omitempty"`
	RestartPending      bool      `json:"restart_pending,omitempty"`
	RestartFromPID      int       `json:"restart_from_pid,omitempty"`
	RecoveryVersion     int       `json:"recovery_version,omitempty"`
	Attempts            int       `json:"attempts,omitempty"`
	FollowupAttempts    int       `json:"followup_attempts,omitempty"`
	RetryAt             time.Time `json:"retry_at,omitempty"`
	AwaitFreshLogin     bool      `json:"await_fresh_login,omitempty"`
	BaselineFingerprint string    `json:"baseline_fingerprint,omitempty"`
	BaselinePID         int       `json:"baseline_pid,omitempty"`
	Message             string    `json:"message,omitempty"`
	UpdatedAt           time.Time `json:"updated_at,omitempty"`
}

type iCloudAutomationDependencies struct {
	accounts      func() []*Account
	status        func(*Account) Status
	gsaReady      func(*Account) bool
	acceptedReady func(*Account) bool
	termsReady    func(*Account) bool
	fingerprint   func(*Account) string
	registered    func(*Account) bool
	activate      func(context.Context, *Account) control.Result
	stop          func(context.Context, *Account) error
	resume        func(context.Context, *Account) control.Result
	now           func() time.Time
}

type iCloudAutomationEntry struct {
	mu          sync.Mutex
	effectMu    sync.RWMutex
	loaded      bool
	loadErr     error
	journal     iCloudAutomationJournal
	active      bool
	cancel      context.CancelFunc
	done        chan struct{}
	generation  uint64
	stableSig   string
	stableSince time.Time
}

type iCloudAutomationService struct {
	server *Server

	mu      sync.Mutex
	entries map[string]*iCloudAutomationEntry
	deps    iCloudAutomationDependencies

	pollEvery  time.Duration
	stableFor  time.Duration
	workerWait time.Duration
	retryBase  time.Duration
	runSlots   chan struct{}
}

func newICloudAutomationService(server *Server) *iCloudAutomationService {
	service := &iCloudAutomationService{
		server:     server,
		entries:    make(map[string]*iCloudAutomationEntry),
		pollEvery:  iCloudAutomationPollEvery,
		stableFor:  iCloudAutomationStableFor,
		workerWait: iCloudAutomationWorkerWait,
		retryBase:  iCloudAutomationRetryBase,
		runSlots:   make(chan struct{}, 1),
	}
	service.deps = iCloudAutomationDependencies{
		accounts: func() []*Account {
			server.accountsMu.Lock()
			defer server.accountsMu.Unlock()
			return append([]*Account(nil), server.accounts...)
		},
		status:        server.accountStatus,
		gsaReady:      func(account *Account) bool { return verifiedGSACheckpointReady(account.Dir, account.AppleID) },
		acceptedReady: func(account *Account) bool { return acceptedCheckpointReady(account.Dir, account.AppleID) },
		termsReady:    confirmedActivationTermsReceiptReady,
		fingerprint:   gsaSessionFingerprint,
		registered: func(account *Account) bool {
			if account == nil {
				return false
			}
			server.accountsMu.Lock()
			defer server.accountsMu.Unlock()
			for _, current := range server.accounts {
				if current.ID == account.ID && filepath.Clean(current.Dir) == filepath.Clean(account.Dir) && strings.EqualFold(strings.TrimSpace(current.AppleID), strings.TrimSpace(account.AppleID)) {
					return true
				}
			}
			return false
		},
		activate: server.automaticActivationAction,
		stop: func(ctx context.Context, account *Account) error {
			return server.stopIn(ctx, account.Dir)
		},
		resume: server.startSavedAccount,
		now:    time.Now,
	}
	return service
}

func iCloudAutomationKey(account *Account) string {
	if account == nil {
		return ""
	}
	return account.ID + "\x00" + filepath.Clean(account.Dir)
}

func iCloudAutomationJournalPath(account *Account) string {
	return filepath.Join(account.Dir, iCloudAutomationJournalFile)
}

// gsaSessionFingerprint is only a comparison marker. The journal stores this
// digest instead of credentials or session contents so Reset can distinguish a
// fresh manual login from an old GSA checkpoint after a dashboard restart.
func gsaSessionFingerprint(account *Account) string {
	if account == nil {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(account.Dir, "session.json"))
	if err != nil || len(data) == 0 || len(data) > 2<<20 {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func loadICloudAutomationJournal(account *Account) (iCloudAutomationJournal, error) {
	journal := iCloudAutomationJournal{Version: 1, Stage: "waiting-login"}
	data, err := os.ReadFile(iCloudAutomationJournalPath(account))
	if os.IsNotExist(err) {
		return journal, nil
	}
	if err != nil {
		return journal, err
	}
	if len(data) == 0 || len(data) > 16<<10 || json.Unmarshal(data, &journal) != nil || journal.Version != 1 || journal.Attempts < 0 || journal.Attempts > 100 {
		return iCloudAutomationJournal{Version: 1, Stage: "needs-review", Submitted: true, Message: "自动激活记录无效，等待人工核对"}, errors.New("invalid iCloud automation journal")
	}
	if journal.Stage == "" {
		journal.Stage = "waiting-login"
	}
	return journal, nil
}

func writeICloudAutomationJournal(account *Account, journal iCloudAutomationJournal) error {
	data, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	path := iCloudAutomationJournalPath(account)
	temp := path + ".tmp"
	if err := os.WriteFile(temp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return err
	}
	return nil
}

func (service *iCloudAutomationService) entryFor(account *Account) *iCloudAutomationEntry {
	key := iCloudAutomationKey(account)
	if key == "" {
		return nil
	}
	service.mu.Lock()
	entry := service.entries[key]
	if entry == nil {
		entry = &iCloudAutomationEntry{}
		service.entries[key] = entry
	}
	service.mu.Unlock()

	entry.mu.Lock()
	if !entry.loaded {
		entry.journal, entry.loadErr = loadICloudAutomationJournal(account)
		entry.loaded = true
	}
	entry.mu.Unlock()
	return entry
}

func (service *iCloudAutomationService) Status(account *Account) *ICloudAutomationStatus {
	if account == nil {
		return &ICloudAutomationStatus{Stage: "unavailable"}
	}
	entry := service.entryFor(account)
	if entry == nil {
		return &ICloudAutomationStatus{Stage: "unavailable"}
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	status := &ICloudAutomationStatus{
		Enabled:   true,
		Stage:     entry.journal.Stage,
		Running:   entry.active,
		Message:   entry.journal.Message,
		UpdatedAt: entry.journal.UpdatedAt,
	}
	if entry.loadErr != nil {
		status.Stage = "needs-review"
		status.Message = "自动激活记录无效，等待人工核对"
	}
	if entry.journal.Paused {
		status.Stage = "paused"
	}
	return status
}

// Pause cancels an in-flight account workflow and waits until it can no longer
// update the journal or start a replacement worker.
func (service *iCloudAutomationService) Pause(ctx context.Context, account *Account) error {
	entry := service.entryFor(account)
	if entry == nil {
		return nil
	}
	entry.mu.Lock()
	entry.journal.Paused = true
	entry.journal.Stage = "paused"
	entry.journal.Message = "自动流程已暂停"
	entry.journal.UpdatedAt = service.deps.now().UTC()
	entry.generation++
	if entry.cancel != nil {
		entry.cancel()
	}
	done := entry.done
	saveErr := writeICloudAutomationJournal(account, entry.journal)
	entry.mu.Unlock()
	// Cancel before draining the external-operation gate. Any call that already
	// entered the gate observes cancellation; later calls fail the generation
	// check, so Pause returning is a hard no-more-effects boundary.
	entry.effectMu.Lock()
	entry.effectMu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return saveErr
}

// Reset clears a deliberate pause and waits for a valid manual login/checkpoint
// before scheduling any further work. An uncertain submitted marker is kept.
func (service *iCloudAutomationService) Reset(ctx context.Context, account *Account) error {
	if err := service.Pause(ctx, account); err != nil {
		return err
	}
	entry := service.entryFor(account)
	if entry == nil {
		return nil
	}
	accepted := service.deps.acceptedReady(account)
	termsReady := service.deps.termsReady != nil && service.deps.termsReady(account)
	baselineFingerprint := service.deps.fingerprint(account)
	baselineStatus := service.deps.status(account)
	entry.mu.Lock()
	entry.journal.Paused = false
	entry.journal.RetryAt = time.Time{}
	if !entry.journal.Submitted {
		entry.journal.Attempts = 0
		entry.journal.FollowupAttempts = 0
	}
	if entry.journal.Submitted {
		if !accepted && termsReady {
			entry.journal.Stage = "retry-wait"
			entry.journal.Message = "条款确认状态已保存，等待本轮手动登录后继续激活"
			entry.journal.AwaitFreshLogin = true
			entry.journal.BaselineFingerprint = baselineFingerprint
			entry.journal.BaselinePID = baselineStatus.PID
		} else if !accepted {
			entry.journal.Stage = "needs-review"
			entry.journal.Message = "提交结果待核对；请先确认 Apple 激活状态"
		} else {
			entry.journal.Stage = "waiting-login"
			entry.journal.Message = "iCloud 已验收，等待账号后台状态"
			entry.journal.AwaitFreshLogin = true
			entry.journal.BaselineFingerprint = baselineFingerprint
			entry.journal.BaselinePID = baselineStatus.PID
			entry.journal.RestartPending = false
			entry.journal.RestartFromPID = 0
		}
	} else if accepted {
		entry.journal.Stage = "waiting-login"
		entry.journal.Message = "iCloud 已验收，等待账号后台状态"
		entry.journal.AwaitFreshLogin = true
		entry.journal.BaselineFingerprint = baselineFingerprint
		entry.journal.BaselinePID = baselineStatus.PID
		entry.journal.RestartPending = false
		entry.journal.RestartFromPID = 0
	} else {
		entry.journal.Stage = "waiting-login"
		entry.journal.Message = "等待手动登录完成"
		entry.journal.AwaitFreshLogin = true
		entry.journal.BaselineFingerprint = baselineFingerprint
		entry.journal.BaselinePID = baselineStatus.PID
	}
	entry.stableSig = ""
	entry.stableSince = time.Time{}
	entry.journal.UpdatedAt = service.deps.now().UTC()
	err := writeICloudAutomationJournal(account, entry.journal)
	if err != nil {
		entry.journal.Paused = true
		entry.journal.Stage = "journal-error"
		entry.journal.Message = "无法保存手动登录重置状态"
	}
	entry.mu.Unlock()
	return err
}

func (service *iCloudAutomationService) Run(ctx context.Context) {
	if service.pollEvery <= 0 {
		service.pollEvery = iCloudAutomationPollEvery
	}
	ticker := time.NewTicker(service.pollEvery)
	defer ticker.Stop()
	defer service.cancelAndWait()
	service.scan(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			service.scan(ctx)
		}
	}
}

func (service *iCloudAutomationService) scan(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	for _, account := range service.deps.accounts() {
		if account != nil {
			service.schedule(ctx, account)
		}
	}
}

func (service *iCloudAutomationService) schedule(parent context.Context, account *Account) {
	entry := service.entryFor(account)
	if entry == nil {
		return
	}
	accepted := service.deps.acceptedReady(account)
	termsReady := service.deps.termsReady != nil && service.deps.termsReady(account)
	completedOnline := false
	if accepted {
		completedOnline = workerOnline(service.deps.status(account))
	}
	entry.mu.Lock()
	if entry.journal.Paused || entry.active || entry.loadErr != nil {
		entry.mu.Unlock()
		return
	}
	if entry.journal.Submitted && !accepted && !termsReady {
		if entry.journal.Stage != "needs-review" {
			entry.journal.Stage = "needs-review"
			entry.journal.Message = "提交结果待核对；未自动重复接受条款"
			entry.journal.UpdatedAt = service.deps.now().UTC()
			_ = writeICloudAutomationJournal(account, entry.journal)
		}
		entry.mu.Unlock()
		return
	}
	if !entry.journal.RetryAt.IsZero() && service.deps.now().Before(entry.journal.RetryAt) {
		entry.mu.Unlock()
		return
	}
	if (entry.journal.Stage == "resume-unconfirmed" && entry.journal.RecoveryVersion >= 1 && !completedOnline) || entry.journal.Stage == "verification-required" ||
		(!accepted && (entry.journal.Stage == "preflight-exhausted" || entry.journal.Stage == "complete" || entry.journal.Stage == "needs-review")) {
		entry.mu.Unlock()
		return
	}
	if accepted && entry.journal.Stage == "complete" && completedOnline {
		entry.mu.Unlock()
		return
	}
	entry.active = true
	entry.generation++
	generation := entry.generation
	runCtx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	entry.cancel, entry.done = cancel, done
	entry.mu.Unlock()

	go func() {
		defer func() {
			entry.mu.Lock()
			if entry.done == done {
				entry.active = false
				entry.cancel = nil
				entry.done = nil
			}
			entry.mu.Unlock()
			close(done)
		}()
		if service.runSlots != nil {
			select {
			case service.runSlots <- struct{}{}:
				defer func() { <-service.runSlots }()
			case <-runCtx.Done():
				return
			}
		}
		service.runAccount(runCtx, account, entry, generation)
	}()
}

func (service *iCloudAutomationService) runAccount(ctx context.Context, account *Account, entry *iCloudAutomationEntry, generation uint64) {
	if !service.canContinue(ctx, account, entry, generation) {
		return
	}
	entry.mu.Lock()
	journal := entry.journal
	loadErr := entry.loadErr
	entry.mu.Unlock()
	if loadErr != nil {
		return
	}

	accepted := service.deps.acceptedReady(account)
	termsReady := service.deps.termsReady != nil && service.deps.termsReady(account)
	if journal.Submitted && !accepted && !termsReady {
		service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
			value.Stage = "needs-review"
			value.Message = "提交结果待核对；未自动重复接受条款"
		})
		return
	}
	if accepted {
		status := service.deps.status(account)
		if accountLaunching(account) || workerTransitioning(status) {
			service.resetStable(entry, generation)
			service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
				value.Stage = "waiting-login"
				value.Message = "账号手动登录仍在进行"
			})
			return
		}
		entry.mu.Lock()
		awaitFreshLogin := entry.journal.AwaitFreshLogin
		entry.mu.Unlock()
		if awaitFreshLogin {
			if statusNeedsManualVerification(status) || !service.initialWorkerStable(entry, generation, status) || !service.freshLoginReady(account, entry, generation, status) {
				service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
					value.Stage = "waiting-login"
					value.Message = "等待本轮手动登录完成并稳定"
				})
				return
			}
			entry.mu.Lock()
			journal = entry.journal
			entry.mu.Unlock()
		}
		if statusNeedsManualVerification(status) {
			service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
				value.Stage = "verification-required"
				value.Message = "恢复会话需要手动账号验证"
			})
			return
		}
		if journal.RestartPending && status.PID > 0 && status.PID != journal.RestartFromPID && workerOnline(status) {
			service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
				value.Stage = "complete"
				value.Submitted = true
				value.RestartPending = false
				value.RestartFromPID = 0
				value.RetryAt = time.Time{}
				value.Message = "iCloud 已验收，账号后台登录与推送均在线"
			})
			return
		}
		forceRestart := journal.RestartPending || (journal.Submitted && (journal.Stage == "activating" || journal.Stage == "activation-followup" || journal.Stage == "resume-pending"))
		if forceRestart {
			service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
				value.RestartPending = true
				if value.RestartFromPID == 0 {
					value.RestartFromPID = status.PID
				}
				value.Stage = "resume-pending"
				value.Message = "iCloud 已验收，准备重启账号后台"
			})
			if workerTransitioning(status) {
				return
			}
			service.resumeAccepted(ctx, account, entry, generation, status, true)
			return
		}
		if workerOnline(status) {
			service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
				value.Stage = "complete"
				value.Submitted = true
				value.RestartPending = false
				value.RestartFromPID = 0
				value.RetryAt = time.Time{}
				value.Message = "iCloud 已验收，后台在线"
			})
			return
		}
		if workerTransitioning(status) {
			service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
				value.Stage = "waiting-worker"
				value.Message = "等待账号后台完成登录"
			})
			return
		}
		service.resumeAccepted(ctx, account, entry, generation, status, false)
		return
	}

	if !service.deps.gsaReady(account) {
		service.resetStable(entry, generation)
		service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
			value.Stage = "waiting-login"
			value.Message = "等待手动登录与账号验证完成"
		})
		return
	}
	status := service.deps.status(account)
	if accountLaunching(account) || workerTransitioning(status) {
		service.resetStable(entry, generation)
		service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
			value.Stage = "waiting-login"
			value.Message = "账号登录仍在进行，等待后台稳定"
		})
		return
	}
	if status.Running && (!status.Authenticated || status.VerificationRequired) {
		service.resetStable(entry, generation)
		service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
			value.Stage = "waiting-login"
			value.Message = "等待账号验证完成"
		})
		return
	}
	if !service.initialWorkerStable(entry, generation, status) {
		service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
			value.Stage = "settling-login"
			value.Message = "账号验证已完成，等待登录状态稳定"
		})
		return
	}
	if !service.freshLoginReady(account, entry, generation, status) {
		service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
			value.Stage = "waiting-login"
			value.Message = "等待本轮手动登录生成新的验证会话"
		})
		return
	}
	if !service.canContinue(ctx, account, entry, generation) {
		return
	}

	entry.mu.Lock()
	attempt := entry.journal.Attempts + 1
	followupAttempt := entry.journal.FollowupAttempts + 1
	entry.mu.Unlock()
	if attempt > iCloudAutomationMaxTries {
		service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
			value.Stage = "preflight-exhausted"
			value.Message = "激活前检查连续失败，等待人工处理"
		})
		return
	}
	if termsReady && followupAttempt > iCloudAutomationMaxTries {
		service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
			value.Stage = "needs-review"
			value.Message = "条款已确认后的激活步骤连续失败，等待人工处理"
		})
		return
	}
	if err := service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
		value.Submitted = true
		value.Attempts = attempt
		if termsReady {
			value.FollowupAttempts = followupAttempt
		}
		value.RestartFromPID = status.PID
		value.RetryAt = time.Time{}
		if termsReady {
			value.Stage = "activation-followup"
			value.Message = "条款已确认，正在继续完成 iCloud 服务激活"
		} else {
			value.Stage = "activating"
			value.Message = "正在检查并激活 iCloud 服务"
		}
	}); err != nil {
		return
	}
	if !service.canContinue(ctx, account, entry, generation) {
		return
	}
	var result control.Result
	if !service.withExternal(ctx, account, entry, generation, func() {
		result = service.deps.activate(ctx, account)
	}) {
		return
	}
	if ctx.Err() != nil || !service.canContinue(ctx, account, entry, generation) {
		return
	}
	if service.deps.acceptedReady(account) {
		service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
			value.Submitted = true
			value.Stage = "resume-pending"
			value.RestartPending = true
			value.RetryAt = time.Time{}
			value.Message = "iCloud 验收已保存，正在恢复账号后台"
		})
		// This worker predates the accepted checkpoint, so it must be restarted
		// even if it still reports authenticated and push-connected.
		service.resumeAccepted(ctx, account, entry, generation, service.deps.status(account), true)
		return
	}
	if result.Stage == "activation-followup-retry" && service.deps.termsReady != nil && service.deps.termsReady(account) {
		service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
			if value.FollowupAttempts == 0 {
				value.FollowupAttempts = 1
			}
			if value.FollowupAttempts >= iCloudAutomationMaxTries {
				value.Stage = "needs-review"
				value.RetryAt = time.Time{}
				value.Message = "条款已确认后的激活步骤连续失败，等待人工处理"
				return
			}
			value.Stage = "retry-wait"
			value.RetryAt = service.deps.now().Add(service.retryDelay(value.FollowupAttempts)).UTC()
			value.Message = "条款确认已持久保存，稍后继续完成服务激活"
		})
		return
	}
	if isKnownReadOnlyActivationFailure(result.Stage) {
		if result.Stage == "activation-busy" {
			attempt-- // launchMu contention did not submit an Apple operation.
		}
		service.schedulePreflightRetry(account, entry, generation, attempt, result.Stage)
		return
	}
	service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
		value.Stage = "needs-review"
		value.Submitted = true
		value.RetryAt = time.Time{}
		value.Message = "提交结果待核对；为避免重复接受条款，自动流程已停止"
	})
	_ = result // The journal stores only a bounded safe stage, never raw helper output.
}

func (service *iCloudAutomationService) resumeAccepted(ctx context.Context, account *Account, entry *iCloudAutomationEntry, generation uint64, status Status, forceRestart bool) {
	if !service.canContinue(ctx, account, entry, generation) {
		return
	}
	if statusNeedsManualVerification(status) {
		service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
			value.Stage = "verification-required"
			value.Message = "恢复会话需要手动账号验证"
		})
		return
	}
	if !forceRestart && workerOnline(status) {
		service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
			value.Stage = "complete"
			value.Submitted = true
			value.RetryAt = time.Time{}
			value.Message = "iCloud 已验收，后台在线"
		})
		return
	}
	if forceRestart && workerOnline(status) {
		entry.mu.Lock()
		restartFromPID := entry.journal.RestartFromPID
		entry.mu.Unlock()
		if restartFromPID > 0 && status.PID != restartFromPID {
			service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
				value.Stage = "complete"
				value.RestartPending = false
				value.RestartFromPID = 0
				value.RetryAt = time.Time{}
				value.Message = "iCloud 已验收，账号后台登录与推送均在线"
			})
			return
		}
	}
	if workerTransitioning(status) {
		service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
			value.Stage = "waiting-worker"
			value.Message = "等待账号后台完成登录"
		})
		return
	}
	if status.Running {
		var stopErr error
		if !service.withExternal(ctx, account, entry, generation, func() {
			stopErr = service.deps.stop(ctx, account)
		}) {
			return
		}
		if stopErr != nil {
			if ctx.Err() == nil {
				service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
					value.Stage = "resume-unconfirmed"
					value.Message = "旧账号后台未能停止，等待人工核对"
				})
			}
			return
		}
	}
	if !service.canContinue(ctx, account, entry, generation) {
		return
	}
	service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
		value.Stage = "resuming"
		value.RecoveryVersion = 1
		value.Message = "正在使用已保存会话恢复账号后台"
	})
	if !service.canContinue(ctx, account, entry, generation) {
		return
	}
	var result control.Result
	if !service.withExternal(ctx, account, entry, generation, func() {
		result = service.deps.resume(ctx, account)
	}) {
		return
	}
	if ctx.Err() != nil || !service.canContinue(ctx, account, entry, generation) {
		return
	}
	if !result.OK {
		if isWorkerStartBusy(result) {
			service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
				value.Stage = "resume-delayed"
				value.Message = "登录或其他操作占用后台启动，稍后重试"
				value.RetryAt = service.deps.now().Add(service.retryDelay(1)).UTC()
			})
			return
		}
		service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
			value.Stage = "resume-unconfirmed"
			value.Message = "已验收会话未能恢复，等待人工核对"
		})
		return
	}
	service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
		value.Stage = "waiting-worker"
		value.Message = "等待后台报告登录与推送连接已就绪"
	})
	deadline := service.deps.now().Add(service.workerWait)
	for service.deps.now().Before(deadline) {
		if !service.canContinue(ctx, account, entry, generation) {
			return
		}
		status = service.deps.status(account)
		if workerOnline(status) {
			service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
				value.Stage = "complete"
				value.Submitted = true
				value.RestartPending = false
				value.RestartFromPID = 0
				value.RetryAt = time.Time{}
				value.Message = "iCloud 已验收，账号后台登录与推送均在线"
			})
			return
		}
		if status.VerificationRequired || status.State == "verification_required" {
			service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
				value.Stage = "verification-required"
				value.Message = "恢复会话需要手动账号验证"
			})
			return
		}
		if !service.wait(ctx, service.pollEvery) {
			return
		}
	}
	service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
		value.Stage = "resume-unconfirmed"
		value.Message = "后台未确认登录与推送就绪，等待人工核对"
	})
}

func (service *iCloudAutomationService) initialWorkerStable(entry *iCloudAutomationEntry, generation uint64, status Status) bool {
	if !status.Running || !status.Authenticated {
		service.resetStable(entry, generation)
		// A persisted, account-bound GSA session can be activated after a clean
		// dashboard restart; there is no in-progress worker to race with.
		return !workerTransitioning(status) && status.State != "failed" && status.State != "refresh_failed"
	}
	if !status.PushConnected || (status.State != "online" && status.State != "device_query_failed") {
		service.resetStable(entry, generation)
		return false
	}
	signature := strings.Join([]string{intString(status.PID), status.State, boolString(status.Running), boolString(status.Authenticated), boolString(status.PushConnected), boolString(status.VerificationRequired)}, ":")
	now := service.deps.now()
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.generation != generation || entry.journal.Paused {
		return false
	}
	if entry.stableSig != signature {
		entry.stableSig = signature
		entry.stableSince = now
		return service.stableFor <= 0
	}
	return now.Sub(entry.stableSince) >= service.stableFor
}

func (service *iCloudAutomationService) freshLoginReady(account *Account, entry *iCloudAutomationEntry, generation uint64, status Status) bool {
	entry.mu.Lock()
	awaitFresh := entry.journal.AwaitFreshLogin
	baselineFingerprint := entry.journal.BaselineFingerprint
	baselinePID := entry.journal.BaselinePID
	entry.mu.Unlock()
	if !awaitFresh {
		return true
	}
	currentFingerprint := service.deps.fingerprint(account)
	fingerprintChanged := currentFingerprint != "" && currentFingerprint != baselineFingerprint
	newAuthenticatedWorker := status.Running && status.Authenticated && status.PID > 0 && status.PID != baselinePID
	if !(fingerprintChanged && !status.Running) && !newAuthenticatedWorker {
		return false
	}
	err := service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
		value.AwaitFreshLogin = false
		value.BaselineFingerprint = ""
		value.BaselinePID = 0
	})
	return err == nil
}

func (service *iCloudAutomationService) resetStable(entry *iCloudAutomationEntry, generation uint64) {
	entry.mu.Lock()
	if entry.generation == generation {
		entry.stableSig = ""
		entry.stableSince = time.Time{}
	}
	entry.mu.Unlock()
}

func (service *iCloudAutomationService) schedulePreflightRetry(account *Account, entry *iCloudAutomationEntry, generation uint64, attempts int, failedStage string) {
	if attempts >= iCloudAutomationMaxTries {
		service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
			value.Submitted = false
			value.Attempts = attempts
			value.Stage = "preflight-exhausted"
			value.RetryAt = time.Time{}
			value.Message = "激活前检查连续失败，自动流程暂停等待人工处理"
		})
		return
	}
	delay := service.retryDelay(attempts)
	service.update(account, entry, generation, func(value *iCloudAutomationJournal) {
		value.Submitted = false
		value.Attempts = attempts
		value.Stage = "retry-wait"
		value.RetryAt = service.deps.now().Add(delay).UTC()
		if failedStage == "activation-busy" {
			value.Message = "账号登录或激活操作占用中，稍后继续"
		} else {
			value.Message = "只读激活前检查未完成，稍后重试"
		}
	})
}

func (service *iCloudAutomationService) retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if service.retryBase <= 0 {
		return 0
	}
	delay := service.retryBase
	for i := 1; i < attempt && delay < 30*time.Second; i++ {
		delay *= 2
	}
	if delay > 30*time.Second {
		return 30 * time.Second
	}
	return delay
}

func (service *iCloudAutomationService) update(account *Account, entry *iCloudAutomationEntry, generation uint64, change func(*iCloudAutomationJournal)) error {
	if entry == nil || account == nil {
		return errors.New("automation account unavailable")
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.generation != generation || entry.journal.Paused {
		return context.Canceled
	}
	change(&entry.journal)
	entry.journal.Version = 1
	entry.journal.UpdatedAt = service.deps.now().UTC()
	if err := writeICloudAutomationJournal(account, entry.journal); err != nil {
		entry.journal.Stage = "journal-error"
		entry.journal.Message = "无法保存自动流程状态，已停止后续步骤"
		entry.journal.Paused = true
		entry.journal.UpdatedAt = service.deps.now().UTC()
		return err
	}
	return nil
}

func (service *iCloudAutomationService) canContinue(ctx context.Context, account *Account, entry *iCloudAutomationEntry, generation uint64) bool {
	if ctx.Err() != nil || account == nil || !service.deps.registered(account) {
		return false
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return entry.generation == generation && !entry.journal.Paused
}

// withExternal prevents a cancelled runner from starting a stop, activation,
// or resume after Pause has returned. Pause cancels first, then takes effectMu
// to drain any operation that had already passed this gate.
func (service *iCloudAutomationService) withExternal(ctx context.Context, account *Account, entry *iCloudAutomationEntry, generation uint64, operation func()) bool {
	entry.effectMu.RLock()
	defer entry.effectMu.RUnlock()
	if !service.canContinue(ctx, account, entry, generation) {
		return false
	}
	operation()
	return true
}

func (service *iCloudAutomationService) wait(ctx context.Context, duration time.Duration) bool {
	if duration <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (service *iCloudAutomationService) cancelAndWait() {
	service.mu.Lock()
	entries := make([]*iCloudAutomationEntry, 0, len(service.entries))
	for _, entry := range service.entries {
		entries = append(entries, entry)
	}
	service.mu.Unlock()
	for _, entry := range entries {
		entry.mu.Lock()
		if entry.cancel != nil {
			entry.cancel()
		}
		done := entry.done
		entry.mu.Unlock()
		if done != nil {
			<-done
		}
	}
}

func workerOnline(status Status) bool {
	return status.Running && status.Authenticated && status.PushConnected && !status.VerificationRequired && status.State == "online"
}

func workerTransitioning(status Status) bool {
	switch status.State {
	case "starting", "initializing", "signing_in", "awaiting_sms", "awaiting_device_code", "awaiting_existing_sms", "awaiting_pairing", "awaiting_account_validation", "verification_required":
		return true
	default:
		return status.Running && !status.Authenticated
	}
}

func statusNeedsManualVerification(status Status) bool {
	if status.VerificationRequired {
		return true
	}
	switch status.State {
	case "verification_required", "awaiting_sms", "awaiting_device_code", "awaiting_existing_sms", "awaiting_pairing", "awaiting_account_validation":
		return true
	default:
		return false
	}
}

func accountLaunching(account *Account) bool {
	if account == nil {
		return false
	}
	account.mu.Lock()
	defer account.mu.Unlock()
	return account.launching
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func isKnownReadOnlyActivationFailure(stage string) bool {
	switch stage {
	case "activation-busy", "activation-session", "activation-local", "activation-plan", "proxy-unavailable":
		return true
	default:
		return false
	}
}

func isWorkerStartBusy(result control.Result) bool {
	return result.Stage == "activation-busy" || result.Stage == "proxy-restart-required" || strings.Contains(result.Message, "正在启动，请稍等")
}
