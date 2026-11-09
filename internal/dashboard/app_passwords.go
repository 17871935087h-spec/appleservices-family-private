package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Laky-64/appleservices/icloud"
	"github.com/Laky-64/appleservices/internal/control"
	"github.com/Laky-64/appleservices/internal/credentialvault"
)

type appPasswordClient interface {
	ListAppPasswords(context.Context) ([]icloud.AppPasswordEntry, error)
	CreateAppPassword(context.Context, string, string) (*icloud.AppPasswordResult, error)
	Authenticate(context.Context, string, func(context.Context) (string, error)) error
	AuthenticationFailure() (string, int)
	ExportAccountSession() ([]byte, error)
	RestoreAccountSession([]byte) error
}

type appPasswordInput struct {
	Description             string `json:"description,omitempty"`
	RequestID               string `json:"request_id,omitempty"`
	AllowWebLogin           bool   `json:"allow_web_login,omitempty"`
	AllowDeviceVerification bool   `json:"allow_device_verification,omitempty"`
	AllowPasswordChallenge  bool   `json:"allow_password_challenge,omitempty"`
}

type appPasswordState struct {
	AccountID       string                    `json:"account_id"`
	Stage           string                    `json:"stage"`
	Message         string                    `json:"message"`
	CanCreate       bool                      `json:"can_create"`
	Items           []icloud.AppPasswordEntry `json:"items"`
	FailurePhase    string                    `json:"failure_phase,omitempty"`
	HTTPStatus      int                       `json:"http_status"`
	RequestID       string                    `json:"request_id,omitempty"`
	ResultAvailable bool                      `json:"result_available"`
	Password        string                    `json:"password,omitempty"`
	Description     string                    `json:"description,omitempty"`
}

type appPasswordIntent struct {
	RequestID   string `json:"request_id"`
	Description string `json:"description"`
	Stage       string `json:"stage"`
}

// The ledger retains completed IDs too: an old HTTP retry must never become a
// new Apple POST after a newer result has replaced the recoverable password.
type appPasswordLedger struct {
	AccountID string              `json:"account_id"`
	AppleID   string              `json:"apple_id"`
	Entries   []appPasswordIntent `json:"entries"`
}

type appPasswordSavedResult struct {
	AccountID   string `json:"account_id"`
	AppleID     string `json:"apple_id"`
	RequestID   string `json:"request_id"`
	Description string `json:"description"`
	Password    string `json:"password"`
}

type appPasswordService struct {
	locks        sync.Map
	newClient    func(string) (appPasswordClient, error)
	loadBlob     func(string, string, string) ([]byte, error)
	saveBlob     func(string, string, string, []byte) error
	loadPassword func(string, string) (string, error)
	deviceCode   func(context.Context, *Account) (string, error)
}

var appPasswordRequestID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var appPasswordSecret = regexp.MustCompile(`^[a-zA-Z]{4}(-[a-zA-Z]{4}){3}$`)

func validAppPasswordAuthenticationFailurePhase(value string) bool {
	switch value {
	case "bootstrap", "authorize", "federate", "srp-init", "srp-complete", "trusted-challenge", "trusted-code", "trust-session", "oauth-validate", "portal-token", "manage-data":
		return true
	default:
		return false
	}
}

func validAppPasswordLocalFailurePhase(value string) bool {
	switch value {
	case "client_init", "records_load", "session_load", "session_restore", "credential_load", "list", "session_save":
		return true
	default:
		return false
	}
}

func setAppPasswordFailure(state *appPasswordState, phase string, status int) {
	if state == nil {
		return
	}
	if validAppPasswordAuthenticationFailurePhase(phase) || validAppPasswordLocalFailurePhase(phase) {
		state.FailurePhase = phase
	} else {
		state.FailurePhase = ""
	}
	if status >= 100 && status <= 599 {
		state.HTTPStatus = status
	} else {
		state.HTTPStatus = 0
	}
}

func setAppPasswordLocalFailure(state *appPasswordState, phase string, err error) {
	status := 0
	var detail *icloud.AppPasswordError
	if errors.As(err, &detail) && detail != nil {
		status = detail.HTTPStatus
	}
	setAppPasswordFailure(state, phase, status)
}

func clearAppPasswordFailure(state *appPasswordState) {
	if state != nil {
		state.FailurePhase = ""
		state.HTTPStatus = 0
	}
}

func invalidAppPasswordSessionCache(err error) bool {
	var detail *icloud.AppPasswordError
	return errors.As(err, &detail) && detail != nil && detail.Stage == "invalid_request"
}

func validAppPasswordDescription(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || !utf8.ValidString(value) || utf8.RuneCountInString(value) > 64 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validAppPasswordInput(action string, in appPasswordInput) bool {
	switch action {
	case "status":
		return in == (appPasswordInput{})
	case "connect":
		return in.AllowWebLogin && in.AllowDeviceVerification && in.Description == "" && in.RequestID == "" && !in.AllowPasswordChallenge
	case "create":
		return validAppPasswordDescription(in.Description) && appPasswordRequestID.MatchString(in.RequestID) && !in.AllowWebLogin && !in.AllowDeviceVerification
	case "result", "review":
		return appPasswordRequestID.MatchString(in.RequestID) && in.Description == "" && !in.AllowWebLogin && !in.AllowDeviceVerification && !in.AllowPasswordChallenge
	}
	return false
}

func appPasswordMessage(stage string) string {
	switch stage {
	case "session_required":
		return "请先授权连接 Apple 账户管理会话"
	case "ready":
		return "专用密码列表已读取，可以生成新密码"
	case "generated":
		return "专用密码已生成，请复制到邮件客户端"
	case "password_required":
		return "Apple 要求复核主密码，请勾选允许复核后继续"
	case "verification_required":
		return "Apple 要求进一步验证，请先在官方设备处理"
	case "risk_blocked":
		return "Apple 拒绝了本次认证或请求，已停止"
	case "terms_required":
		return "Apple 要求确认条款，请先在官方页面处理"
	case "credential_required":
		return "未能读取此账号保存的密码，请先在账号面板重新连接"
	case "outcome_unknown":
		return "生成结果待核对，请读取列表并确认后再生成"
	case "busy":
		return "当前账号正在处理专用密码请求，请稍后读取状态"
	case "invalid_request":
		return "请求无效，或该请求编号已用于其他生成操作"
	default:
		return "专用密码服务暂不可用，请读取状态后检查连接"
	}
}

func newAppPasswordService(s *Server) *appPasswordService {
	service := &appPasswordService{newClient: func(id string) (appPasswordClient, error) { return icloud.NewAppleAccountClient(id) }, loadBlob: credentialvault.LoadBlob, saveBlob: credentialvault.SaveBlob, loadPassword: credentialvault.Load}
	service.deviceCode = func(ctx context.Context, account *Account) (string, error) {
		var result control.Result
		if err := s.callFor(ctx, account.Dir, "/action", control.Action{Action: "code"}, &result); err != nil || !result.OK || len(result.Code) != 6 {
			return "", errors.New("trusted device is unavailable")
		}
		for _, r := range result.Code {
			if r < '0' || r > '9' {
				return "", errors.New("trusted device is unavailable")
			}
		}
		return result.Code, nil
	}
	return service
}

func (s *Server) handleAppPasswordsAPI(w http.ResponseWriter, r *http.Request) bool {
	const prefix = "/api/app-passwords/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}
	action := strings.TrimPrefix(r.URL.Path, prefix)
	if action != "status" && action != "connect" && action != "create" && action != "result" && action != "review" {
		http.NotFound(w, r)
		return true
	}
	if r.Method != http.MethodPost {
		http.Error(w, `{"message":"POST required"}`, http.StatusMethodNotAllowed)
		return true
	}
	var input appPasswordInput
	if !readJSON(w, r, &input) {
		return true
	}
	accountID := r.URL.Query().Get("account")
	account := s.lookup(accountID)
	if accountID == "" || account == nil || !validAppPasswordInput(action, input) {
		http.Error(w, `{"message":"invalid request"}`, http.StatusBadRequest)
		return true
	}
	timeout := 90 * time.Second
	if action == "connect" {
		timeout = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	value := s.appPasswords.run(ctx, account, action, input)
	value.Message = appPasswordMessage(value.Stage)
	if value.Items == nil {
		value.Items = []icloud.AppPasswordEntry{}
	}
	// Only two explicit actions can ever return the recoverable secret.
	if (action != "create" && action != "result") || value.Stage != "generated" {
		value.Password = ""
	}
	_ = json.NewEncoder(w).Encode(value)
	return true
}

func (p *appPasswordService) loadJSON(account *Account, name string, out any) error {
	data, err := p.loadBlob(account.Dir, account.AppleID, name)
	if err != nil {
		return err
	}
	defer clear(data)
	if json.Unmarshal(data, out) != nil {
		return credentialvault.ErrInvalidData
	}
	return nil
}

func (p *appPasswordService) saveJSON(account *Account, name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	defer clear(data)
	return p.saveBlob(account.Dir, account.AppleID, name, data)
}

func (p *appPasswordService) readRecords(account *Account) (appPasswordLedger, *appPasswordSavedResult, error) {
	ledger := appPasswordLedger{AccountID: account.ID, AppleID: account.AppleID}
	err := p.loadJSON(account, "app-password-intent", &ledger)
	if err != nil && !errors.Is(err, credentialvault.ErrNotFound) {
		return ledger, nil, err
	}
	if ledger.AccountID != account.ID || !strings.EqualFold(ledger.AppleID, account.AppleID) || len(ledger.Entries) > 2048 {
		return ledger, nil, credentialvault.ErrInvalidData
	}
	seen := make(map[string]bool)
	for _, entry := range ledger.Entries {
		if !appPasswordRequestID.MatchString(entry.RequestID) || !validAppPasswordDescription(entry.Description) || seen[entry.RequestID] {
			return ledger, nil, credentialvault.ErrInvalidData
		}
		seen[entry.RequestID] = true
		switch entry.Stage {
		case "pending", "outcome_unknown", "password_required", "generated", "rejected", "reviewed":
		default:
			return ledger, nil, credentialvault.ErrInvalidData
		}
	}
	var result appPasswordSavedResult
	err = p.loadJSON(account, "app-password-result", &result)
	if errors.Is(err, credentialvault.ErrNotFound) {
		return ledger, nil, nil
	}
	if err != nil {
		return ledger, nil, err
	}
	if result.AccountID != account.ID || !strings.EqualFold(result.AppleID, account.AppleID) || !appPasswordRequestID.MatchString(result.RequestID) || !validAppPasswordDescription(result.Description) || !appPasswordSecret.MatchString(result.Password) || !seen[result.RequestID] {
		return ledger, nil, credentialvault.ErrInvalidData
	}
	for _, entry := range ledger.Entries {
		if entry.RequestID == result.RequestID && entry.Description != result.Description {
			return ledger, nil, credentialvault.ErrInvalidData
		}
	}
	return ledger, &result, nil
}

func appPasswordFailure(err error) string {
	var detail *icloud.AppPasswordError
	if errors.As(err, &detail) {
		switch detail.Stage {
		case "session_required", "password_required", "verification_required", "risk_blocked", "terms_required", "invalid_request", "outcome_unknown", "unavailable":
			return detail.Stage
		}
	}
	if errors.Is(err, icloud.ErrAccountManagementAuthenticationRequired) {
		return "session_required"
	}
	return "unavailable"
}

func (p *appPasswordService) saveSession(account *Account, client appPasswordClient) error {
	data, err := client.ExportAccountSession()
	if err != nil {
		return err
	}
	defer clear(data)
	return p.saveBlob(account.Dir, account.AppleID, "app-password-session", data)
}

func (p *appPasswordService) run(ctx context.Context, account *Account, action string, in appPasswordInput) appPasswordState {
	state := appPasswordState{AccountID: account.ID, Stage: "unavailable"}
	if !validAppPasswordInput(action, in) {
		state.Stage = "invalid_request"
		return state
	}
	lockValue, _ := p.locks.LoadOrStore(strings.ToLower(account.AppleID), &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)
	if !lock.TryLock() {
		state.Stage = "busy"
		return state
	}
	defer lock.Unlock()
	ledger, result, err := p.readRecords(account)
	if err != nil {
		setAppPasswordLocalFailure(&state, "records_load", err)
		return state
	}
	var current *appPasswordIntent
	var unresolved *appPasswordIntent
	reconciled := false
	for i := range ledger.Entries {
		entry := &ledger.Entries[i]
		if entry.RequestID == in.RequestID {
			current = entry
		}
		if entry.Stage == "pending" || entry.Stage == "outcome_unknown" {
			// Result is saved before the ledger's success marker. A restart
			// between the two writes can therefore still recover the result.
			if result == nil || result.RequestID != entry.RequestID {
				unresolved = entry
			} else {
				entry.Stage = "generated"
				reconciled = true
			}
		}
	}
	if result != nil {
		state.RequestID = result.RequestID
		state.ResultAvailable = true
	}
	if unresolved != nil {
		state.Stage = "outcome_unknown"
		state.RequestID = unresolved.RequestID
		state.ResultAvailable = false
	}
	if action == "result" {
		if result == nil || result.RequestID != in.RequestID {
			state.Stage = "invalid_request"
			return state
		}
		state.Stage = "generated"
		state.RequestID = result.RequestID
		state.Password = result.Password
		state.Description = result.Description
		return state
	}
	// Complete a crash-interrupted success marker before the last result can
	// be replaced. Otherwise that old pending intent would become uncertain
	// again as soon as a second password was generated.
	if reconciled && p.saveJSON(account, "app-password-intent", ledger) != nil {
		state.Stage = "unavailable"
		return state
	}
	if action == "review" {
		if unresolved == nil || unresolved.RequestID != in.RequestID {
			state.Stage = "invalid_request"
			return state
		}
	}
	if action == "create" {
		state.RequestID = in.RequestID
		state.ResultAvailable = false
		if current != nil {
			if current.Description != in.Description {
				state.Stage = "invalid_request"
				return state
			}
			if result != nil && result.RequestID == in.RequestID {
				state.Stage = "generated"
				state.ResultAvailable = true
				state.Password = result.Password
				state.Description = result.Description
				return state
			}
			if current.Stage != "password_required" {
				state.Stage = "outcome_unknown"
				if current.Stage == "reviewed" || current.Stage == "rejected" || current.Stage == "generated" {
					state.Stage = "invalid_request"
				}
				return state
			}
		}
		if unresolved != nil {
			state.Stage = "outcome_unknown"
			state.RequestID = unresolved.RequestID
			return state
		}
	}
	client, err := p.newClient(account.AppleID)
	if err != nil {
		setAppPasswordLocalFailure(&state, "client_init", err)
		return state
	}
	data, err := p.loadBlob(account.Dir, account.AppleID, "app-password-session")
	hasSession := err == nil
	if err != nil && !errors.Is(err, credentialvault.ErrNotFound) {
		setAppPasswordLocalFailure(&state, "session_load", err)
		return state
	}
	invalidSessionCache := false
	if hasSession {
		err = client.RestoreAccountSession(data)
		clear(data)
		if err != nil {
			if !invalidAppPasswordSessionCache(err) {
				setAppPasswordLocalFailure(&state, "session_restore", err)
				return state
			}
			invalidSessionCache = true
			setAppPasswordLocalFailure(&state, "session_restore", err)
			if action != "connect" {
				if state.Stage != "outcome_unknown" {
					state.Stage = "session_required"
				}
				return state
			}
			state.Stage = "session_required"
			// Restore may have partially initialized a client before rejecting a
			// malformed cache. Recreate it before the one authorized login attempt.
			client, err = p.newClient(account.AppleID)
			if err != nil {
				state.Stage = "unavailable"
				setAppPasswordLocalFailure(&state, "client_init", err)
				return state
			}
		}
	}
	var items []icloud.AppPasswordEntry
	stage := "session_required"
	if hasSession && !invalidSessionCache {
		items, err = client.ListAppPasswords(ctx)
		if err == nil {
			stage = "ready"
		} else {
			stage = appPasswordFailure(err)
			setAppPasswordLocalFailure(&state, "list", err)
		}
	}
	if action == "connect" && stage == "session_required" {
		if hasSession && !invalidSessionCache {
			if state.FailurePhase != "list" || state.HTTPStatus != http.StatusUnauthorized {
				state.Stage = "session_required"
				return state
			}
			// A confirmed expired session was restored into this client. Start
			// authorized authentication with a new cookie jar and no stale portal
			// SCNT/API key, while retaining the saved result and old cache until
			// authentication succeeds. Risk responses never enter this branch.
			client, err = p.newClient(account.AppleID)
			if err != nil {
				state.Stage = "unavailable"
				setAppPasswordLocalFailure(&state, "client_init", err)
				return state
			}
		}
		clearAppPasswordFailure(&state)
		password, passwordErr := p.loadPassword(account.Dir, account.AppleID)
		if passwordErr != nil {
			state.Stage = "credential_required"
			setAppPasswordLocalFailure(&state, "credential_load", passwordErr)
			return state
		}
		err = client.Authenticate(ctx, password, func(codeCtx context.Context) (string, error) { return p.deviceCode(codeCtx, account) })
		password = ""
		if err != nil {
			failure, status := client.AuthenticationFailure()
			phase := failure
			if !validAppPasswordAuthenticationFailurePhase(phase) {
				phase = ""
			}
			setAppPasswordFailure(&state, phase, status)
			state.Stage = "unavailable"
			if phase == "trusted-challenge" || phase == "trusted-code" || status == http.StatusConflict {
				state.Stage = "verification_required"
			} else if status == 401 || status == 403 || status == 423 || status == 429 {
				state.Stage = "risk_blocked"
			} else if status == 451 {
				state.Stage = "terms_required"
			}
			return state
		}
		// Persist the freshly established management session before any later
		// read can fail while decoding Apple's response. A successful list is
		// saved again below so any refreshed SCNT is retained as well.
		if err := p.saveSession(account, client); err != nil {
			state.Stage = "unavailable"
			setAppPasswordLocalFailure(&state, "session_save", err)
			return state
		}
		items, err = client.ListAppPasswords(ctx)
		if err == nil {
			stage = "ready"
		} else {
			stage = appPasswordFailure(err)
			setAppPasswordLocalFailure(&state, "list", err)
		}
		if err == nil {
			clearAppPasswordFailure(&state)
		}
	}
	if stage == "ready" {
		if err := p.saveSession(account, client); err != nil {
			setAppPasswordLocalFailure(&state, "session_save", err)
			if unresolved == nil {
				state.Stage = "unavailable"
			}
			return state
		}
	}
	state.Items = items
	if action == "review" {
		// A failed list is not evidence that the uncertain password is absent.
		// Review never logs in or sends another Apple mutation.
		if stage != "ready" {
			state.Stage = "outcome_unknown"
			return state
		}
		unresolved.Stage = "reviewed"
		if p.saveJSON(account, "app-password-intent", ledger) != nil {
			state.Stage = "outcome_unknown"
			return state
		}
		state.Stage = "ready"
		state.CanCreate = true
		state.RequestID = in.RequestID
		state.ResultAvailable = false
		return state
	}
	if unresolved != nil {
		state.Stage = "outcome_unknown"
		return state
	}
	state.Stage = stage
	state.CanCreate = stage == "ready"
	if action != "create" || stage != "ready" {
		return state
	}
	password := ""
	if in.AllowPasswordChallenge {
		password, err = p.loadPassword(account.Dir, account.AppleID)
		if err != nil {
			state.Stage = "credential_required"
			state.CanCreate = false
			setAppPasswordLocalFailure(&state, "credential_load", err)
			return state
		}
	}
	if current == nil {
		if len(ledger.Entries) >= 2048 {
			state.Stage = "unavailable"
			state.CanCreate = false
			return state
		}
		ledger.Entries = append(ledger.Entries, appPasswordIntent{RequestID: in.RequestID, Description: in.Description, Stage: "pending"})
		current = &ledger.Entries[len(ledger.Entries)-1]
	} else {
		current.Stage = "pending"
	}
	state.CanCreate = false
	if ctx.Err() != nil || p.saveJSON(account, "app-password-intent", ledger) != nil {
		state.Stage = "unavailable"
		return state
	}
	generated, err := client.CreateAppPassword(ctx, in.Description, password)
	password = ""
	if err != nil {
		stage = appPasswordFailure(err)
		current.Stage = "outcome_unknown"
		if stage == "password_required" {
			current.Stage = stage
		} else if stage == "session_required" || stage == "verification_required" || stage == "risk_blocked" || stage == "terms_required" || stage == "invalid_request" {
			current.Stage = "rejected"
		}
		if stage == "unavailable" {
			stage = "outcome_unknown"
		}
		if p.saveJSON(account, "app-password-intent", ledger) != nil {
			stage = "outcome_unknown"
		}
		state.Stage = stage
		state.CanCreate = stage == "password_required"
		if err := p.saveSession(account, client); err != nil {
			setAppPasswordLocalFailure(&state, "session_save", err)
		}
		return state
	}
	if generated == nil || !appPasswordSecret.MatchString(generated.Password) {
		state.Stage = "outcome_unknown"
		return state
	}
	saved := appPasswordSavedResult{AccountID: account.ID, AppleID: account.AppleID, RequestID: in.RequestID, Description: in.Description, Password: generated.Password}
	if p.saveJSON(account, "app-password-result", saved) != nil {
		state.Stage = "outcome_unknown"
		return state
	}
	current.Stage = "generated"
	_ = p.saveJSON(account, "app-password-intent", ledger)
	if err := p.saveSession(account, client); err != nil {
		setAppPasswordLocalFailure(&state, "session_save", err)
	}
	state.Stage = "generated"
	state.CanCreate = true
	state.ResultAvailable = true
	state.Password = generated.Password
	state.Description = in.Description
	return state
}
