package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"
)

// Primary-mail state never contains an Apple authentication response.
type primaryMailState struct {
	AccountID string `json:"account_id"`
	Stage     string `json:"stage"`
	Email     string `json:"email,omitempty"`
	Target    string `json:"target,omitempty"`
	Message   string `json:"message"`
	CanCreate bool   `json:"can_create"`
	CheckedAt string `json:"checked_at,omitempty"`
}
type primaryMailInput struct {
	Prefix           string `json:"prefix,omitempty"`
	AllowWebLogin    bool   `json:"allow_web_login,omitempty"`
	ConfirmPermanent bool   `json:"confirm_permanent,omitempty"`
}

var primaryMailPrefix = regexp.MustCompile(`^[a-z][a-z0-9._]{2,19}$`)
var primaryMailAddress = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+-]{1,63}@icloud\.com$`)

func primaryMailMessage(stage string) string {
	switch stage {
	case "verified":
		return "iCloud 主邮箱已开通，已回读确认"
	case "not_open":
		return "尚未开通 iCloud 主邮箱"
	case "web_login_required":
		return "需要授权使用已保存密码和受信任设备建立 iCloud 网页会话"
	case "verification_required":
		return "设备验证未完成，请在官方设备处理后读取状态"
	case "terms_required":
		return "Apple 要求确认条款，请先在官方页面处理"
	case "risk_blocked":
		return "Apple 拒绝了本次认证或请求，已停止"
	case "outcome_unknown":
		return "创建结果待核验，请读取状态，勿重复提交"
	case "busy":
		return "当前账号正在处理邮箱请求，请稍后读取状态"
	case "invalid_request":
		return "请填写有效前缀并确认永久邮箱地址"
	default:
		return "主邮箱状态未确认，请读取状态或检查服务配置"
	}
}

func sanitizePrimaryMail(value primaryMailState, account string) primaryMailState {
	if value.AccountID != account {
		return primaryMailState{AccountID: account, Stage: "unavailable", Message: primaryMailMessage("unavailable")}
	}
	switch value.Stage {
	case "unknown", "not_open", "verified", "outcome_unknown", "web_login_required", "verification_required", "terms_required", "risk_blocked", "unavailable", "busy", "invalid_request":
	default:
		value.Stage = "unavailable"
	}
	if value.Email != "" && !primaryMailAddress.MatchString(value.Email) {
		value.Email = ""
		value.Stage = "unavailable"
	}
	if value.Target != "" && !primaryMailAddress.MatchString(value.Target) {
		value.Target = ""
		value.Stage = "unavailable"
	}
	if value.Stage == "verified" && value.Email == "" {
		value.Stage = "unavailable"
	}
	value.CanCreate = value.CanCreate && (value.Stage == "not_open" || value.Stage == "web_login_required")
	if _, err := time.Parse(time.RFC3339Nano, value.CheckedAt); err != nil {
		value.CheckedAt = ""
	}
	value.Message = primaryMailMessage(value.Stage)
	return value
}

func (s *Server) handlePrimaryMailAPI(w http.ResponseWriter, r *http.Request) bool {
	action := ""
	switch r.URL.Path {
	case "/api/primary-mail/status":
		action = "status"
	case "/api/primary-mail/create":
		action = "create"
	default:
		return false
	}
	if r.Method != http.MethodPost {
		http.Error(w, `{"message":"POST required"}`, http.StatusMethodNotAllowed)
		return true
	}
	var input primaryMailInput
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF || (action == "status" && (input.Prefix != "" || input.AllowWebLogin || input.ConfirmPermanent)) {
		http.Error(w, `{"message":"invalid request"}`, http.StatusBadRequest)
		return true
	}
	accountID := r.URL.Query().Get("account")
	account := s.lookup(accountID)
	if accountID == "" || account == nil {
		http.Error(w, `{"message":"account required"}`, http.StatusBadRequest)
		return true
	}
	if action == "create" && (!input.ConfirmPermanent || (input.Prefix != "" && !primaryMailPrefix.MatchString(input.Prefix))) {
		_ = json.NewEncoder(w).Encode(primaryMailState{AccountID: account.ID, Stage: "invalid_request", Message: primaryMailMessage("invalid_request")})
		return true
	}
	timeout := 105 * time.Second
	if action == "create" {
		timeout = 7 * time.Minute
		// Login, one trusted-device verification and independent readback may
		// exceed the dashboard's ordinary four-minute response deadline.
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(8 * time.Minute))
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	var value primaryMailState
	if s.primaryMailRunner != nil {
		value = s.primaryMailRunner(ctx, account, input)
	} else {
		value = s.runPrimaryMail(ctx, account, action, input)
	}
	_ = json.NewEncoder(w).Encode(sanitizePrimaryMail(value, account.ID))
	return true
}

func (s *Server) runPrimaryMail(ctx context.Context, account *Account, action string, input primaryMailInput) primaryMailState {
	failure := primaryMailState{AccountID: account.ID, Stage: "unavailable"}
	executable, err := os.Executable()
	if err != nil {
		return failure
	}
	tools := filepath.Dir(executable)
	payload := struct {
		Action    string `json:"action"`
		Root      string `json:"root"`
		AccountID string `json:"account_id"`
		AppleID   string `json:"apple_id"`
		primaryMailInput
		Library      string `json:"library"`
		Python       string `json:"python"`
		LoginHelper  string `json:"login_helper"`
		NativeHelper string `json:"native_helper"`
		DashboardURL string `json:"dashboard_url"`
	}{action, s.config.Dir, account.ID, account.AppleID, input, s.config.Library, s.config.Python, filepath.Join(tools, "primary-mail-login.exe"), filepath.Join(tools, "primary-mail-native.exe"), s.URL()}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return failure
	}
	defer clear(encoded)
	command := exec.CommandContext(ctx, s.config.Python, "-B", "-I", filepath.Join(tools, "primary_mail.py"))
	configureProcess(command)
	command.Dir = tools
	command.Env = filteredActivationEnv("")
	command.Stdin = bytes.NewReader(encoded)
	command.Stderr = io.Discard
	var output bytes.Buffer
	command.Stdout = &output
	err = command.Run()
	if output.Len() > 16<<10 {
		return failure
	}
	var value primaryMailState
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		if err != nil && action == "create" {
			failure.Stage = "outcome_unknown"
		}
		return failure
	}
	return value
}
