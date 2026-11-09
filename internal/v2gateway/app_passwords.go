package v2gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const maxAppPasswordResponseBytes = 32 << 10

var appPasswordRequestIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var appPasswordValuePattern = regexp.MustCompile(`^[a-zA-Z]{4}(-[a-zA-Z]{4}){3}$`)

type appPasswordRequest struct {
	AccountID               string `json:"account_id"`
	AppleID                 string `json:"apple_id"`
	Description             string `json:"description"`
	RequestID               string `json:"request_id"`
	AllowPasswordChallenge  *bool  `json:"allow_password_challenge"`
	AllowWebLogin           *bool  `json:"allow_web_login"`
	AllowDeviceVerification *bool  `json:"allow_device_verification"`
}

type appPasswordItem struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at,omitempty"`
}

type appPasswordReply struct {
	AccountID       string            `json:"account_id"`
	Stage           string            `json:"stage"`
	Message         string            `json:"message"`
	CanCreate       bool              `json:"can_create"`
	Items           []appPasswordItem `json:"items"`
	RequestID       string            `json:"request_id,omitempty"`
	ResultAvailable bool              `json:"result_available,omitempty"`
	Password        string            `json:"password,omitempty"`
	Description     string            `json:"description,omitempty"`
	FailurePhase    *string           `json:"failure_phase,omitempty"`
	HTTPStatus      *int              `json:"http_status,omitempty"`
}

func (g *Gateway) handleAppPasswords(w http.ResponseWriter, r *http.Request) {
	action := strings.TrimPrefix(r.URL.Path, "/v1/app-passwords/")
	if action != "status" && action != "connect" && action != "create" && action != "result" && action != "review" {
		writeJSON(w, http.StatusNotFound, errorReply{OK: false, Stage: "not_found", Message: "接口不存在"})
		return
	}
	var input appPasswordRequest
	if !decodeAppPasswordRequest(w, r, action, &input) {
		return
	}
	if action == "create" {
		if !validAppPasswordInputDescription(input.Description) {
			writeAppPasswordReply(w, http.StatusBadRequest, unavailableAppPasswords(input.AccountID, "invalid_request", ""))
			return
		}
		input.Description = strings.TrimSpace(input.Description)
	}
	if !validAppPasswordRequest(input, action) {
		writeAppPasswordReply(w, http.StatusBadRequest, unavailableAppPasswords(input.AccountID, "invalid_request", ""))
		return
	}
	normalized, valid := normalizeAppleID(input.AppleID)
	if !valid {
		writeAppPasswordReply(w, http.StatusBadRequest, unavailableAppPasswords(input.AccountID, "invalid_request", ""))
		return
	}
	registry, err := loadRegistry(g.config.RegistryPath)
	if err != nil {
		writeAppPasswordReply(w, http.StatusServiceUnavailable, unavailableAppPasswords(input.AccountID, "unavailable", ""))
		return
	}
	listed, err := accountListFromRegistry(registry)
	if err != nil {
		writeAppPasswordReply(w, http.StatusConflict, unavailableAppPasswords(input.AccountID, "unavailable", ""))
		return
	}
	bound := false
	for _, account := range listed {
		if account.AccountID == input.AccountID && strings.EqualFold(account.AppleID, normalized) {
			bound = true
			break
		}
	}
	if !bound {
		writeAppPasswordReply(w, http.StatusNotFound, unavailableAppPasswords(input.AccountID, "unavailable", ""))
		return
	}

	reply, err := g.appPasswordsDashboard(r.Context(), input, action)
	if err != nil {
		stage, requestID := "unavailable", ""
		if action == "create" {
			stage, requestID = "outcome_unknown", input.RequestID
		}
		writeAppPasswordReply(w, http.StatusOK, unavailableAppPasswords(input.AccountID, stage, requestID))
		return
	}
	defer clearAppPasswordReply(&reply)
	writeAppPasswordReply(w, http.StatusOK, reply)
}

func decodeAppPasswordRequest(w http.ResponseWriter, r *http.Request, action string, target *appPasswordRequest) bool {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	defer clearGatewaySensitiveBytes(data)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorReply{OK: false, Stage: "invalid_request", Message: safeInvalidRequest})
		return false
	}
	fields, ok := appPasswordRequestFields(data)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorReply{OK: false, Stage: "invalid_request", Message: safeInvalidRequest})
		return false
	}
	allowed := map[string]bool{"account_id": true, "apple_id": true}
	switch action {
	case "connect":
		allowed["allow_web_login"], allowed["allow_device_verification"] = true, true
	case "create":
		allowed["description"], allowed["request_id"], allowed["allow_password_challenge"] = true, true, true
	case "result", "review":
		allowed["request_id"] = true
	}
	for field := range fields {
		if !allowed[field] {
			writeJSON(w, http.StatusBadRequest, errorReply{OK: false, Stage: "invalid_request", Message: safeInvalidRequest})
			return false
		}
	}
	if !fields["account_id"] || !fields["apple_id"] {
		writeJSON(w, http.StatusBadRequest, errorReply{OK: false, Stage: "invalid_request", Message: safeInvalidRequest})
		return false
	}
	switch action {
	case "connect":
		if !fields["allow_web_login"] || !fields["allow_device_verification"] {
			writeJSON(w, http.StatusBadRequest, errorReply{OK: false, Stage: "invalid_request", Message: safeInvalidRequest})
			return false
		}
	case "create":
		if !fields["description"] || !fields["request_id"] || !fields["allow_password_challenge"] {
			writeJSON(w, http.StatusBadRequest, errorReply{OK: false, Stage: "invalid_request", Message: safeInvalidRequest})
			return false
		}
	case "result", "review":
		if !fields["request_id"] {
			writeJSON(w, http.StatusBadRequest, errorReply{OK: false, Stage: "invalid_request", Message: safeInvalidRequest})
			return false
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, http.StatusBadRequest, errorReply{OK: false, Stage: "invalid_request", Message: safeInvalidRequest})
		return false
	}
	return true
}

func appPasswordRequestFields(data []byte) (map[string]bool, bool) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false
	}
	fields := make(map[string]bool)
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, false
		}
		name, ok := key.(string)
		if !ok || fields[name] {
			return nil, false
		}
		fields[name] = true
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return nil, false
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, false
	}
	return fields, true
}

func validAppPasswordRequest(input appPasswordRequest, action string) bool {
	if !validAccountID(input.AccountID) {
		return false
	}
	noConnect := input.AllowWebLogin == nil && input.AllowDeviceVerification == nil
	noCreate := input.Description == "" && input.AllowPasswordChallenge == nil
	noRequestID := input.RequestID == ""
	switch action {
	case "status":
		return noConnect && noCreate && noRequestID
	case "connect":
		return input.AllowWebLogin != nil && *input.AllowWebLogin && input.AllowDeviceVerification != nil && *input.AllowDeviceVerification && noCreate && noRequestID
	case "create":
		return noConnect && validAppPasswordDescription(input.Description) && validAppPasswordRequestID(input.RequestID) && input.AllowPasswordChallenge != nil
	case "result", "review":
		return noConnect && noCreate && validAppPasswordRequestID(input.RequestID)
	default:
		return false
	}
}

func validAppPasswordDescription(value string) bool {
	return utf8.ValidString(value) && strings.TrimSpace(value) != "" && utf8.RuneCountInString(value) <= 64 && !strings.ContainsFunc(value, unicode.IsControl)
}

func validAppPasswordInputDescription(value string) bool {
	return utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsControl) && validAppPasswordDescription(strings.TrimSpace(value))
}

func validAppPasswordRequestID(value string) bool {
	return appPasswordRequestIDPattern.MatchString(value)
}

func (g *Gateway) appPasswordsDashboard(ctx context.Context, input appPasswordRequest, action string) (appPasswordReply, error) {
	var result appPasswordReply
	token, err := g.dashboardToken(ctx)
	if err != nil {
		return result, err
	}
	var payload any
	switch action {
	case "connect":
		payload = struct {
			AllowWebLogin           bool `json:"allow_web_login"`
			AllowDeviceVerification bool `json:"allow_device_verification"`
		}{true, true}
	case "create":
		payload = struct {
			Description            string `json:"description"`
			RequestID              string `json:"request_id"`
			AllowPasswordChallenge bool   `json:"allow_password_challenge"`
		}{input.Description, input.RequestID, *input.AllowPasswordChallenge}
	case "result", "review":
		payload = struct {
			RequestID string `json:"request_id"`
		}{input.RequestID}
	default:
		payload = struct{}{}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return result, err
	}
	defer clearGatewaySensitiveBytes(body)
	endpoint := g.dashboardURL.ResolveReference(&url.URL{Path: "/api/app-passwords/" + action, RawQuery: "account=" + url.QueryEscape(input.AccountID)})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return result, err
	}
	request.Header.Set("X-App-Token", token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	client := *g.client
	if action == "create" {
		client.Timeout = 8 * time.Minute
		if transport, ok := client.Transport.(*http.Transport); ok {
			copy := transport.Clone()
			copy.ResponseHeaderTimeout = 8 * time.Minute
			client.Transport = copy
			defer copy.CloseIdleConnections()
		}
	}
	response, err := client.Do(request)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, io.ErrUnexpectedEOF
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxAppPasswordResponseBytes+1))
	if err != nil || len(data) > maxAppPasswordResponseBytes {
		clearGatewaySensitiveBytes(data)
		return result, io.ErrUnexpectedEOF
	}
	defer clearGatewaySensitiveBytes(data)
	fields, fieldsOK := appPasswordRequestFields(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if !fieldsOK || !fields["account_id"] || !fields["stage"] || !fields["message"] || !fields["can_create"] || !fields["items"] ||
		decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF || result.Items == nil ||
		!validAppPasswordResponse(result, input, action) ||
		(fields["password"] != (result.Stage == "generated" && (action == "create" || action == "result"))) {
		clearAppPasswordReply(&result)
		return appPasswordReply{}, io.ErrUnexpectedEOF
	}
	if action == "create" && result.Stage == "outcome_unknown" && result.RequestID == "" {
		result.RequestID = input.RequestID
	}
	result.Message = appPasswordMessage(result.Stage)
	result.CanCreate = result.CanCreate && appPasswordCanCreate(result.Stage)
	if result.Items == nil {
		result.Items = []appPasswordItem{}
	}
	if result.Stage != "generated" {
		result.Password = ""
		result.Description = ""
	}
	return result, nil
}

func validAppPasswordResponse(result appPasswordReply, input appPasswordRequest, action string) bool {
	if result.AccountID != input.AccountID || len(result.Items) > 128 {
		return false
	}
	if result.FailurePhase != nil && !validAppPasswordFailurePhase(*result.FailurePhase) {
		return false
	}
	if result.HTTPStatus != nil && !validAppPasswordHTTPStatus(*result.HTTPStatus) {
		return false
	}
	switch result.Stage {
	case "session_required", "ready", "generated", "password_required", "verification_required", "risk_blocked", "terms_required", "credential_required", "outcome_unknown", "busy", "invalid_request", "unavailable":
	default:
		return false
	}
	if result.RequestID != "" && !validAppPasswordRequestID(result.RequestID) {
		return false
	}
	if !appPasswordCanCreate(result.Stage) && result.CanCreate {
		return false
	}
	if result.ResultAvailable && result.RequestID == "" {
		return false
	}
	for _, item := range result.Items {
		if !validAppPasswordItemID(item.ID) || !validAppPasswordItemDescription(item.Description) {
			return false
		}
		if item.CreatedAt != "" {
			if !validAppPasswordCreatedAt(item.CreatedAt) {
				return false
			}
		}
	}
	if result.Description != "" && !validAppPasswordDescription(result.Description) {
		return false
	}
	if result.Password != "" && (action != "create" && action != "result" || result.Stage != "generated" || !appPasswordValuePattern.MatchString(result.Password)) {
		return false
	}
	if result.Stage == "generated" {
		if action != "create" && action != "result" || result.Password == "" || result.RequestID != input.RequestID {
			return false
		}
	} else if action == "create" && result.Stage == "outcome_unknown" && result.RequestID != "" && result.RequestID != input.RequestID {
		return false
	}
	if action == "create" && result.Stage != "outcome_unknown" && result.RequestID != input.RequestID {
		return false
	}
	if (action == "create" || action == "result" || action == "review") && result.RequestID != "" && result.RequestID != input.RequestID {
		return false
	}
	return true
}

func appPasswordCanCreate(stage string) bool {
	return stage == "ready" || stage == "password_required" || stage == "generated"
}

func validAppPasswordItemID(value string) bool {
	return utf8.ValidString(value) && value != "" && utf8.RuneCountInString(value) <= 128 && !strings.ContainsFunc(value, unicode.IsControl)
}

func validAppPasswordItemDescription(value string) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) <= 256 && !strings.ContainsFunc(value, unicode.IsControl)
}

func validAppPasswordCreatedAt(value string) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) <= 128 && !strings.ContainsFunc(value, unicode.IsControl)
}

func validAppPasswordFailurePhase(value string) bool {
	switch value {
	case "bootstrap", "authorize", "federate", "srp-init", "srp-complete",
		"trusted-challenge", "trusted-code", "trust-session", "oauth-validate",
		"portal-token", "manage-data", "client_init", "records_load", "session_load",
		"session_restore", "credential_load", "list", "session_save":
		return true
	default:
		return false
	}
}

func validAppPasswordHTTPStatus(value int) bool {
	return value == 0 || value >= 100 && value <= 599
}

func unavailableAppPasswords(accountID, stage, requestID string) appPasswordReply {
	return appPasswordReply{AccountID: accountID, Stage: stage, Message: appPasswordMessage(stage), Items: []appPasswordItem{}, RequestID: requestID}
}

func appPasswordMessage(stage string) string {
	switch stage {
	case "session_required":
		return "需要连接管理会话后继续"
	case "ready":
		return "管理会话已就绪"
	case "generated":
		return "App 专用密码已生成"
	case "password_required":
		return "当前步骤需要主密码复核"
	case "verification_required":
		return "需要受信任设备验证"
	case "risk_blocked":
		return "Apple 暂停了此操作"
	case "terms_required":
		return "需要先在 Apple 页面确认条款"
	case "credential_required":
		return "当前账号没有可用的已保存密码"
	case "outcome_unknown":
		return "新建结果待核对，请读取列表确认，勿重复提交"
	case "busy":
		return "当前账号仍在处理中"
	case "invalid_request":
		return safeInvalidRequest
	default:
		return "App 专用密码状态未确认"
	}
}

func writeAppPasswordReply(w http.ResponseWriter, status int, reply appPasswordReply) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(reply)
	clearAppPasswordReply(&reply)
}

func clearAppPasswordReply(reply *appPasswordReply) {
	if reply == nil {
		return
	}
	reply.Password = ""
	if reply.FailurePhase != nil {
		*reply.FailurePhase = ""
	}
	reply.FailurePhase = nil
	if reply.HTTPStatus != nil {
		*reply.HTTPStatus = 0
	}
	reply.HTTPStatus = nil
	for index := range reply.Items {
		reply.Items[index] = appPasswordItem{}
	}
	reply.Items = nil
}
