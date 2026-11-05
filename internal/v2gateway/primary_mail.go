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
)

type primaryMailRequest struct {
	AccountID        string `json:"account_id"`
	AppleID          string `json:"apple_id"`
	Prefix           string `json:"prefix,omitempty"`
	AllowWebLogin    bool   `json:"allow_web_login,omitempty"`
	ConfirmPermanent bool   `json:"confirm_permanent,omitempty"`
}
type primaryMailState struct {
	AccountID string `json:"account_id"`
	Stage     string `json:"stage"`
	Email     string `json:"email,omitempty"`
	Target    string `json:"target,omitempty"`
	Message   string `json:"message"`
	CanCreate bool   `json:"can_create"`
	CheckedAt string `json:"checked_at,omitempty"`
}

var mailPrefixPattern = regexp.MustCompile(`^[a-z][a-z0-9._]{2,19}$`)
var mailAddressPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+-]{1,63}@icloud\.com$`)

func (g *Gateway) handlePrimaryMail(w http.ResponseWriter, r *http.Request) {
	var body primaryMailRequest
	if !decodeRequest(w, r, &body) {
		return
	}
	create := r.URL.Path == "/v1/primary-mail/create"
	normalized, valid := normalizeAppleID(body.AppleID)
	if !validAccountID(body.AccountID) || !valid || (create && (!body.ConfirmPermanent || (body.Prefix != "" && !mailPrefixPattern.MatchString(body.Prefix)))) || (!create && (body.Prefix != "" || body.AllowWebLogin || body.ConfirmPermanent)) {
		writeJSON(w, http.StatusBadRequest, errorReply{Stage: "invalid_request", Message: safeInvalidRequest})
		return
	}
	registry, err := loadRegistry(g.config.RegistryPath)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errorReply{Stage: "unavailable", Message: safeServiceFailure})
		return
	}
	listed, err := accountListFromRegistry(registry)
	if err != nil {
		writeJSON(w, http.StatusConflict, errorReply{Stage: "account_ambiguous", Message: safeAccountAmbiguous})
		return
	}
	found := false
	for _, account := range listed {
		if account.AccountID == body.AccountID && strings.EqualFold(account.AppleID, normalized) {
			found = true
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, errorReply{Stage: "account_not_found", Message: safeAccountNotFound})
		return
	}
	action := "status"
	if create {
		action = "create"
	}
	value, err := g.primaryMailDashboard(r.Context(), body, action)
	if err != nil {
		stage := "unavailable"
		if create {
			stage = "outcome_unknown"
		}
		writeJSON(w, http.StatusOK, primaryMailState{AccountID: body.AccountID, Stage: stage, Message: "主邮箱状态未确认，请读取状态后继续"})
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (g *Gateway) primaryMailDashboard(ctx context.Context, input primaryMailRequest, action string) (primaryMailState, error) {
	var result primaryMailState
	token, err := g.dashboardToken(ctx)
	if err != nil {
		return result, err
	}
	payload, err := json.Marshal(struct {
		Prefix           string `json:"prefix,omitempty"`
		AllowWebLogin    bool   `json:"allow_web_login,omitempty"`
		ConfirmPermanent bool   `json:"confirm_permanent,omitempty"`
	}{input.Prefix, input.AllowWebLogin, input.ConfirmPermanent})
	if err != nil {
		return result, err
	}
	endpoint := g.dashboardURL.ResolveReference(&url.URL{Path: "/api/primary-mail/" + action, RawQuery: "account=" + url.QueryEscape(input.AccountID)})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(payload))
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
	if response.StatusCode != 200 {
		return result, io.ErrUnexpectedEOF
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 16<<10))
	if err != nil {
		return result, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF || result.AccountID != input.AccountID {
		return primaryMailState{}, io.ErrUnexpectedEOF
	}
	switch result.Stage {
	case "unknown", "not_open", "verified", "outcome_unknown", "web_login_required", "verification_required", "terms_required", "risk_blocked", "unavailable", "busy", "invalid_request":
	default:
		return primaryMailState{}, io.ErrUnexpectedEOF
	}
	if (result.Email != "" && !mailAddressPattern.MatchString(result.Email)) || (result.Target != "" && !mailAddressPattern.MatchString(result.Target)) || (result.Stage == "verified" && result.Email == "") {
		return primaryMailState{}, io.ErrUnexpectedEOF
	}
	result.CanCreate = result.CanCreate && (result.Stage == "not_open" || result.Stage == "web_login_required")
	result.Message = "主邮箱状态已读取"
	if result.Stage == "verified" {
		result.Message = "iCloud 主邮箱已开通，已回读确认"
	} else if result.Stage == "outcome_unknown" {
		result.Message = "创建结果待核验，请读取状态，勿重复提交"
	}
	return result, nil
}
