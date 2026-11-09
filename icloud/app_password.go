package icloud

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const maxAppleAccountSessionBytes = 2 << 20

const appPasswordEndpoint = "/account/manage/security/secondary-password"

type AppPasswordEntry struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at,omitempty"`
}

type AppPasswordResult struct {
	AppPasswordEntry
	Password string `json:"password"`
}

type AppPasswordError struct {
	Stage      string
	HTTPStatus int
}

func (e *AppPasswordError) Error() string {
	if e == nil {
		return "icloud: app-specific password operation failed"
	}
	switch e.Stage {
	case "session_required":
		return "icloud: Apple Account management session is required"
	case "password_required":
		return "icloud: Apple Account password confirmation is required"
	case "verification_required":
		return "icloud: Apple Account verification is required"
	case "risk_blocked":
		return "icloud: Apple Account blocked this operation"
	case "terms_required":
		return "icloud: Apple Account terms must be accepted"
	case "invalid_request":
		return "icloud: app-specific password request is invalid"
	case "outcome_unknown":
		return "icloud: app-specific password creation outcome is unknown"
	case "unavailable":
		return "icloud: app-specific password service is unavailable"
	default:
		return "icloud: app-specific password operation failed"
	}
}

func appPasswordError(stage string, status int) error {
	return &AppPasswordError{Stage: stage, HTTPStatus: status}
}

func (c *AppleAccountClient) ListAppPasswords(ctx context.Context) ([]AppPasswordEntry, error) {
	if ctx == nil {
		return nil, appPasswordError("invalid_request", 0)
	}
	if !c.appPasswordSessionReady() {
		return nil, appPasswordError("session_required", 0)
	}
	data, status, err := c.portalRequest(ctx, http.MethodGet, appPasswordEndpoint, nil, true)
	if err != nil {
		return nil, appPasswordError(appPasswordFailureStage(status, data, false), status)
	}
	if status != http.StatusOK {
		return nil, appPasswordError(appPasswordFailureStage(status, data, false), status)
	}
	entries, ok := decodeAppPasswordEntries(data)
	if !ok {
		return nil, appPasswordError("unavailable", status)
	}
	return entries, nil
}

func (c *AppleAccountClient) CreateAppPassword(ctx context.Context, description, challengePassword string) (*AppPasswordResult, error) {
	if !validAppPasswordDescription(description) || ctx == nil {
		return nil, appPasswordError("invalid_request", 0)
	}
	description = strings.TrimSpace(description)
	if !c.appPasswordSessionReady() {
		return nil, appPasswordError("session_required", 0)
	}

	payload := map[string]string{"description": description}
	data, status, err := c.portalRequest(ctx, http.MethodPost, appPasswordEndpoint, payload, true)
	if err != nil && status == http.StatusUnavailableForLegalReasons {
		stage := appPasswordChallengeStage(data)
		if stage != "password_required" {
			return nil, appPasswordError(stage, status)
		}
		if challengePassword == "" {
			return nil, appPasswordError("password_required", status)
		}

		challengeData, challengeStatus, challengeErr := c.portalRequest(
			ctx,
			http.MethodPost,
			"/authenticate/password",
			map[string]string{"password": challengePassword},
			true,
		)
		if challengeErr != nil || challengeStatus < 200 || challengeStatus >= 300 {
			stage := appPasswordPasswordChallengeFailureStage(challengeStatus, challengeData)
			return nil, appPasswordError(stage, challengeStatus)
		}

		data, status, err = c.portalRequest(ctx, http.MethodPost, appPasswordEndpoint, payload, true)
		if err != nil && status == http.StatusUnavailableForLegalReasons {
			stage := appPasswordChallengeStage(data)
			if stage == "password_required" {
				stage = "unavailable"
			}
			return nil, appPasswordError(stage, status)
		}
	}
	if err != nil {
		return nil, appPasswordError(appPasswordFailureStage(status, data, true), status)
	}
	if status != http.StatusOK {
		return nil, appPasswordError(appPasswordFailureStage(status, data, true), status)
	}

	result, found, ok := decodeAppPasswordResult(data, description)
	canonicalPassword, validPassword := canonicalAppSpecificPassword(result.Password)
	if !found || !ok || !validPassword {
		return nil, appPasswordError("outcome_unknown", status)
	}
	result.Password = canonicalPassword
	return &result, nil
}

func (c *AppleAccountClient) appPasswordSessionReady() bool {
	if c == nil || c.http == nil || c.jar == nil ||
		!validAccountSessionHeaderValue(c.apiKey) ||
		(c.portalSCNT != "" && !validAccountSessionHeaderValue(c.portalSCNT)) {
		return false
	}
	_, ok := appleAccountOrigin(c.apiBase)
	return ok
}

func appPasswordFailureStage(status int, body []byte, creating bool) string {
	if status == http.StatusUnavailableForLegalReasons {
		return appPasswordChallengeStage(body)
	}
	if status == http.StatusForbidden || appPasswordBodyHasRiskSignal(body) {
		return "risk_blocked"
	}
	if appPasswordBodyNeedsTerms(body) {
		return "terms_required"
	}
	if status == http.StatusUnauthorized {
		return "session_required"
	}
	if creating && (status == 0 || status >= 500) {
		return "outcome_unknown"
	}
	return "unavailable"
}

func appPasswordChallengeStage(body []byte) string {
	if appPasswordBodyHasRiskSignal(body) {
		return "risk_blocked"
	}
	if appPasswordBodyHasKey(body, "onDemand2FAToken") {
		return "verification_required"
	}
	if appPasswordBodyNeedsTerms(body) {
		return "terms_required"
	}
	if appPasswordBodyHasCaptchaMarker(body) {
		return "unavailable"
	}
	if appPasswordIsOrdinaryPasswordChallenge(body) {
		return "password_required"
	}
	return "unavailable"
}

func appPasswordPasswordChallengeFailureStage(status int, body []byte) string {
	if status == http.StatusForbidden || status == http.StatusConflict || appPasswordBodyHasRiskSignal(body) {
		return "risk_blocked"
	}
	if status == http.StatusUnavailableForLegalReasons && appPasswordBodyHasKey(body, "onDemand2FAToken") {
		return "verification_required"
	}
	if appPasswordBodyNeedsTerms(body) {
		return "terms_required"
	}
	if appPasswordBodyHasCaptchaMarker(body) {
		return "unavailable"
	}
	if status == http.StatusUnauthorized {
		return "session_required"
	}
	return "unavailable"
}

func appPasswordIsOrdinaryPasswordChallenge(body []byte) bool {
	if appPasswordBodyHasRiskSignal(body) ||
		appPasswordBodyHasKey(body, "onDemand2FAToken") ||
		appPasswordBodyNeedsTerms(body) ||
		appPasswordBodyHasCaptchaMarker(body) {
		return false
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(body, &object) != nil || object == nil {
		return false
	}
	formattedRaw, ok := appPasswordRawField(object, "formattedAccountName")
	if !ok {
		return false
	}
	formattedAccountName, ok := appPasswordJSONString(formattedRaw)
	return ok && strings.TrimSpace(formattedAccountName) != ""
}

func appPasswordBodyHasCaptchaMarker(body []byte) bool {
	var value any
	if json.Unmarshal(body, &value) != nil {
		return appPasswordTextHasCaptchaMarker(string(body))
	}
	var walk func(any) bool
	walk = func(current any) bool {
		switch item := current.(type) {
		case map[string]any:
			for key, nested := range item {
				normalizedKey := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", ""))
				if strings.Contains(normalizedKey, "captcha") || strings.Contains(normalizedKey, "humanverification") {
					return true
				}
				if walk(nested) {
					return true
				}
			}
		case []any:
			for _, nested := range item {
				if walk(nested) {
					return true
				}
			}
		case string:
			return appPasswordTextHasCaptchaMarker(item)
		}
		return false
	}
	return walk(value)
}

func appPasswordTextHasCaptchaMarker(text string) bool {
	lower := strings.ToLower(text)
	for _, marker := range []string{"captcha", "recaptcha", "hcaptcha", "turnstile", "verify you are human", "robot check"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func appPasswordBodyHasKey(body []byte, expected string) bool {
	var value any
	if json.Unmarshal(body, &value) != nil {
		return false
	}
	var walk func(any) bool
	walk = func(current any) bool {
		switch item := current.(type) {
		case map[string]any:
			for key, nested := range item {
				if strings.EqualFold(key, expected) {
					return true
				}
				if walk(nested) {
					return true
				}
			}
		case []any:
			for _, nested := range item {
				if walk(nested) {
					return true
				}
			}
		}
		return false
	}
	return walk(value)
}

func appPasswordBodyNeedsTerms(body []byte) bool {
	var value any
	if json.Unmarshal(body, &value) != nil {
		return false
	}
	var walk func(any) bool
	walk = func(current any) bool {
		switch item := current.(type) {
		case map[string]any:
			for key, nested := range item {
				key = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", ""))
				if key == "termsrequired" || key == "termsacceptancerequired" || key == "termsandconditionsrequired" {
					if nested != nil && nested != false && nested != "" {
						return true
					}
				}
				if walk(nested) {
					return true
				}
			}
		case []any:
			for _, nested := range item {
				if walk(nested) {
					return true
				}
			}
		case string:
			normalized := strings.ToLower(strings.Join(strings.Fields(item), " "))
			if strings.Contains(normalized, "terms required") ||
				strings.Contains(normalized, "terms acceptance required") ||
				strings.Contains(normalized, "terms and conditions required") {
				return true
			}
		}
		return false
	}
	return walk(value)
}

func appPasswordBodyHasRiskSignal(body []byte) bool {
	var value any
	if json.Unmarshal(body, &value) != nil {
		return appPasswordTextHasRiskSignal(string(body))
	}
	var walk func(any, string) bool
	walk = func(current any, key string) bool {
		switch item := current.(type) {
		case map[string]any:
			for nestedKey, nested := range item {
				if walk(nested, nestedKey) {
					return true
				}
			}
		case []any:
			for _, nested := range item {
				if walk(nested, key) {
					return true
				}
			}
		case bool:
			if item && appPasswordRiskKey(key) {
				return true
			}
		case string:
			if appPasswordRiskKey(key) && strings.TrimSpace(item) != "" {
				lower := strings.ToLower(item)
				if lower == "true" || lower == "locked" || lower == "disabled" || lower == "blocked" || lower == "risk" {
					return true
				}
			}
			return appPasswordTextHasRiskSignal(item)
		}
		return false
	}
	return walk(value, "")
}

func appPasswordRiskKey(key string) bool {
	switch strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", "")) {
	case "locked", "accountlocked", "disabled", "accountdisabled", "risk", "riskblocked":
		return true
	default:
		return false
	}
}

func appPasswordTextHasRiskSignal(text string) bool {
	lower := strings.ToLower(text)
	for _, signal := range []string{
		"account locked",
		"account_locked",
		"account disabled",
		"account_disabled",
		"locked",
		"disabled",
		"risk blocked",
		"risk_blocked",
		"risk",
		"suspicious",
		"too many attempts",
		"security risk",
		"account at risk",
	} {
		if strings.Contains(lower, signal) {
			return true
		}
	}
	return false
}

func decodeAppPasswordEntries(data []byte) ([]AppPasswordEntry, bool) {
	items, ok := findAppPasswordArray(data, 0)
	if !ok || len(items) > 128 {
		return nil, false
	}
	entries := make([]AppPasswordEntry, 0, len(items))
	for _, item := range items {
		entry, valid := decodeAppPasswordEntry(item)
		if !valid {
			return nil, false
		}
		entries = append(entries, entry)
	}
	return entries, true
}

func findAppPasswordArray(data []byte, depth int) ([]json.RawMessage, bool) {
	if depth > 5 {
		return nil, false
	}
	var items []json.RawMessage
	if json.Unmarshal(data, &items) == nil && items != nil {
		return items, true
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil || object == nil {
		return nil, false
	}
	for _, key := range []string{"secondaryPasswords", "appSpecificPasswords", "appPasswords", "passwords", "items", "data"} {
		child, ok := appPasswordRawField(object, key)
		if !ok {
			continue
		}
		if found, ok := findAppPasswordArray(child, depth+1); ok {
			return found, true
		}
	}
	return nil, false
}

func decodeAppPasswordEntry(data []byte) (AppPasswordEntry, bool) {
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil || object == nil {
		return AppPasswordEntry{}, false
	}
	idRaw, ok := appPasswordRawField(object, "id")
	if !ok {
		return AppPasswordEntry{}, false
	}
	id, ok := appPasswordJSONScalar(idRaw)
	if !ok || !validAppPasswordDisplayField(id, 128) || strings.TrimSpace(id) == "" {
		return AppPasswordEntry{}, false
	}

	entry := AppPasswordEntry{ID: id}
	if descriptionRaw, found := appPasswordRawField(object, "description"); found {
		description, valid := appPasswordJSONString(descriptionRaw)
		if !valid || !validAppPasswordDisplayField(description, 256) {
			return AppPasswordEntry{}, false
		}
		entry.Description = description
	}
	for _, key := range []string{"localizedCreateDate", "createDatetime", "createdAt", "created_at"} {
		if createdRaw, found := appPasswordRawField(object, key); found {
			if created, valid := appPasswordJSONScalar(createdRaw); valid {
				if !validAppPasswordDisplayField(created, 128) {
					return AppPasswordEntry{}, false
				}
				entry.CreatedAt = created
				break
			}
		}
	}
	return entry, true
}

func decodeAppPasswordResult(data []byte, fallbackDescription string) (AppPasswordResult, bool, bool) {
	return findAppPasswordResult(data, fallbackDescription, 0)
}

func findAppPasswordResult(data []byte, fallbackDescription string, depth int) (AppPasswordResult, bool, bool) {
	if depth > 5 {
		return AppPasswordResult{}, false, false
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil || object == nil {
		var items []json.RawMessage
		if json.Unmarshal(data, &items) == nil {
			for _, item := range items {
				if result, found, ok := findAppPasswordResult(item, fallbackDescription, depth+1); found || !ok {
					return result, found, ok
				}
			}
		}
		return AppPasswordResult{}, false, false
	}
	if passwordRaw, found := appPasswordRawField(object, "password"); found {
		password, ok := appPasswordJSONString(passwordRaw)
		if !ok || password == "" {
			return AppPasswordResult{}, true, false
		}
		entry, entryValid := decodeAppPasswordEntry(data)
		if !entryValid {
			entry = AppPasswordEntry{}
		}
		if entry.Description == "" {
			entry.Description = fallbackDescription
		}
		if !validAppPasswordDisplayField(entry.Description, 256) {
			return AppPasswordResult{}, true, false
		}
		return AppPasswordResult{AppPasswordEntry: entry, Password: password}, true, true
	}
	for _, key := range []string{"data", "secondaryPassword", "appSpecificPassword", "appPassword", "result"} {
		child, found := appPasswordRawField(object, key)
		if !found {
			continue
		}
		if result, found, ok := findAppPasswordResult(child, fallbackDescription, depth+1); found || !ok {
			return result, found, ok
		}
	}
	return AppPasswordResult{}, false, false
}

func appPasswordRawField(object map[string]json.RawMessage, name string) (json.RawMessage, bool) {
	if raw, ok := object[name]; ok {
		return raw, true
	}
	for key, raw := range object {
		if strings.EqualFold(key, name) {
			return raw, true
		}
	}
	return nil, false
}

func appPasswordJSONString(raw json.RawMessage) (string, bool) {
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}

func appPasswordJSONScalar(raw json.RawMessage) (string, bool) {
	if value, ok := appPasswordJSONString(raw); ok {
		return value, true
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return "", false
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	if decoder.Decode(&number) == nil && number.String() != "" {
		return number.String(), true
	}
	return "", false
}

func validAppPasswordDescription(description string) bool {
	if !utf8.ValidString(description) || utf8.RuneCountInString(description) > 64 || strings.TrimSpace(description) == "" {
		return false
	}
	for _, character := range description {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validAppPasswordDisplayField(value string, limit int) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > limit {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validAppSpecificPassword(password string) bool {
	value := []byte(password)
	if len(value) != 16 && len(value) != 19 {
		return false
	}
	letters := 0
	for index, character := range value {
		if len(value) == 19 && index == 4 || len(value) == 19 && index == 9 || len(value) == 19 && index == 14 {
			if character != '-' {
				return false
			}
			continue
		}
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' {
			letters++
			continue
		}
		return false
	}
	return letters == 16
}

func canonicalAppSpecificPassword(password string) (string, bool) {
	if !validAppSpecificPassword(password) {
		return "", false
	}
	letters := strings.ReplaceAll(password, "-", "")
	return letters[:4] + "-" + letters[4:8] + "-" + letters[8:12] + "-" + letters[12:16], true
}

func appleAccountOrigin(raw string) (string, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		return "", false
	}
	host := strings.ToLower(parsed.Hostname())
	if host != "account.apple.com" && host != "appleid.apple.com" && host != "idmsa.apple.com" {
		return "", false
	}
	port := parsed.Port()
	if port != "" && port != "443" {
		return "", false
	}
	if port == "443" {
		return "https://" + host + ":443", true
	}
	return "https://" + host, true
}

func validAccountSessionHeaderValue(value string) bool {
	if value == "" || len(value) > 8192 {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func (c *AppleAccountClient) ExportAccountSession() ([]byte, error) {
	if c == nil || c.jar == nil || strings.TrimSpace(c.appleID) == "" ||
		!validAccountSessionHeaderValue(c.apiKey) {
		return nil, appPasswordError("session_required", 0)
	}
	apiBase, ok := appleAccountOrigin(c.apiBase)
	if !ok {
		return nil, appPasswordError("session_required", 0)
	}
	if c.portalSCNT != "" && !validAccountSessionHeaderValue(c.portalSCNT) {
		return nil, appPasswordError("session_required", 0)
	}

	saved := savedAppleAccountSession{
		AppleID:   c.appleID,
		APIBase:   apiBase,
		APIKey:    c.apiKey,
		SCNT:      c.portalSCNT,
		UpdatedAt: time.Now().UTC(),
	}
	origins := []string{
		"https://account.apple.com",
		"https://appleid.apple.com",
		"https://idmsa.apple.com",
	}
	seen := make(map[string]bool)
	cookieCount := 0
	for _, scope := range origins {
		for _, path := range []string{"/", "/account", "/account/manage", "/account/manage/security/secondary-password", "/appleauth", "/appleauth/auth"} {
			parsed, _ := url.Parse(scope + path)
			for _, cookie := range c.jar.Cookies(parsed) {
				if cookie.Name == "" || cookie.Value == "" || cookie.Valid() != nil {
					return nil, appPasswordError("session_required", 0)
				}
				key := scope + "\x00" + cookie.Name + "\x00" + cookie.Path
				if seen[key] {
					continue
				}
				seen[key] = true
				saved.Cookies = append(saved.Cookies, hmeCookie{
					Scope:   scope,
					Name:    cookie.Name,
					Value:   cookie.Value,
					Path:    cookie.Path,
					Secure:  cookie.Secure,
					Expires: cookie.Expires,
				})
				cookieCount++
			}
		}
	}
	if cookieCount == 0 {
		return nil, appPasswordError("session_required", 0)
	}
	data, err := json.Marshal(saved)
	if err != nil || len(data) > maxAppleAccountSessionBytes {
		clear(data)
		return nil, appPasswordError("unavailable", 0)
	}
	return data, nil
}

func (c *AppleAccountClient) RestoreAccountSession(data []byte) error {
	if c == nil || c.http == nil || strings.TrimSpace(c.appleID) == "" ||
		len(data) == 0 || len(data) > maxAppleAccountSessionBytes {
		return appPasswordError("invalid_request", 0)
	}

	var saved savedAppleAccountSession
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&saved) != nil {
		return appPasswordError("invalid_request", 0)
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return appPasswordError("invalid_request", 0)
	}
	if !strings.EqualFold(strings.TrimSpace(saved.AppleID), strings.TrimSpace(c.appleID)) ||
		!validAccountSessionHeaderValue(saved.APIKey) ||
		(saved.SCNT != "" && !validAccountSessionHeaderValue(saved.SCNT)) {
		return appPasswordError("session_required", 0)
	}
	apiBase, ok := appleAccountOrigin(saved.APIBase)
	if !ok {
		return appPasswordError("session_required", 0)
	}
	if len(saved.Cookies) == 0 || len(saved.Cookies) > 1024 {
		return appPasswordError("invalid_request", 0)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return appPasswordError("unavailable", 0)
	}
	for _, item := range saved.Cookies {
		scope, validScope := appleAccountOrigin(item.Scope)
		if !validScope || item.Name == "" || item.Value == "" {
			return appPasswordError("session_required", 0)
		}
		parsed, _ := url.Parse(scope)
		cookie := &http.Cookie{
			Name:    item.Name,
			Value:   item.Value,
			Path:    item.Path,
			Secure:  item.Secure,
			Expires: item.Expires,
		}
		if cookie.Valid() != nil {
			return appPasswordError("invalid_request", 0)
		}
		jar.SetCookies(parsed, []*http.Cookie{cookie})
	}

	c.apiBase = apiBase
	c.apiKey = saved.APIKey
	c.portalSCNT = saved.SCNT
	c.jar = jar
	c.http.Jar = jar
	return nil
}
