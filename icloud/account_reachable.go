package icloud

import (
	"bytes"
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Laky-64/appleservices/gsa"
	"github.com/Laky-64/appleservices/internal/srp"
)

var ErrAccountManagementAuthenticationRequired = errors.New("Apple Account management authentication required")

type AppleAccountClient struct {
	appleID       string
	sessionPath   string
	http          *http.Client
	jar           http.CookieJar
	apiBase       string
	apiKey        string
	portalSCNT    string
	pendingEmail  string
	pendingVerify json.RawMessage
	lastStage     string
	lastHTTP      int
}

type savedAppleAccountSession struct {
	AppleID   string      `json:"apple_id"`
	APIBase   string      `json:"api_base"`
	APIKey    string      `json:"api_key"`
	SCNT      string      `json:"scnt,omitempty"`
	Cookies   []hmeCookie `json:"cookies"`
	UpdatedAt time.Time   `json:"updated_at"`
}

type portalBootstrap struct {
	APIURL     string `json:"apiUrl"`
	ServiceKey string `json:"serviceKey"`
	ServiceURL string `json:"serviceUrl"`
}

func NewAppleAccountClient(appleID string) (*AppleAccountClient, error) {
	return newAppleAccountClient("", appleID, false)
}

// NewAppleAccountClientWithStore restores an account-bound management session
// from the local account directory. It never stores or loads a password.
func NewAppleAccountClientWithStore(accountDir, appleID string) (*AppleAccountClient, error) {
	return newAppleAccountClient(accountDir, appleID, true)
}

// NewAppleAccountClientForAccount binds network routing to accountDir without
// reading or persisting an account-management session in that directory.
func NewAppleAccountClientForAccount(accountDir, appleID string) (*AppleAccountClient, error) {
	return newAppleAccountClient(accountDir, appleID, false)
}

func newAppleAccountClient(accountDir, appleID string, restoreSession bool) (*AppleAccountClient, error) {
	appleID = strings.TrimSpace(appleID)
	if appleID == "" {
		return nil, errors.New("Apple Account binding is incomplete")
	}
	jar, _ := cookiejar.New(nil)
	var transport *http.Transport
	if strings.TrimSpace(accountDir) == "" {
		transport = gsa.AppleRootTransport().(*http.Transport)
	} else {
		var err error
		transport, err = gsa.AppleRootTransportForAccount(accountDir)
		if err != nil {
			return nil, errors.New("Apple Account proxy route is unavailable")
		}
	}
	sessionPath := ""
	if restoreSession && strings.TrimSpace(accountDir) != "" {
		sessionPath = filepath.Join(accountDir, "account-management-session.json")
	}
	c := &AppleAccountClient{appleID: appleID, sessionPath: sessionPath, jar: jar, http: &http.Client{Jar: jar, Transport: transport, Timeout: 35 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	_ = c.loadSavedSession()
	return c, nil
}

func (c *AppleAccountClient) loadSavedSession() error {
	if c.sessionPath == "" {
		return os.ErrNotExist
	}
	data, err := os.ReadFile(c.sessionPath)
	if err != nil {
		return err
	}
	if len(data) > 2<<20 {
		return errors.New("saved Apple Account session is too large")
	}
	var saved savedAppleAccountSession
	if json.Unmarshal(data, &saved) != nil || !strings.EqualFold(saved.AppleID, c.appleID) || saved.APIBase == "" || saved.APIKey == "" {
		return errors.New("saved Apple Account session binding is invalid")
	}
	c.apiBase, c.apiKey, c.portalSCNT = strings.TrimRight(saved.APIBase, "/"), saved.APIKey, saved.SCNT
	for _, item := range saved.Cookies {
		u, parseErr := url.Parse(item.Scope)
		if parseErr != nil || u.Scheme != "https" || u.Hostname() == "" || item.Name == "" {
			continue
		}
		c.jar.SetCookies(u, []*http.Cookie{{Name: item.Name, Value: item.Value, Path: item.Path, Secure: item.Secure, Expires: item.Expires}})
	}
	return nil
}

func (c *AppleAccountClient) saveSession() error {
	if c.sessionPath == "" || c.apiBase == "" || c.apiKey == "" {
		return nil
	}
	saved := savedAppleAccountSession{AppleID: c.appleID, APIBase: c.apiBase, APIKey: c.apiKey, SCNT: c.portalSCNT, UpdatedAt: time.Now().UTC()}
	scopes := []string{"https://appleid.apple.com", "https://idmsa.apple.com", c.apiBase}
	seen := map[string]bool{}
	for _, scope := range scopes {
		u, err := url.Parse(scope)
		if err != nil || u.Hostname() == "" {
			continue
		}
		origin := "https://" + u.Hostname()
		for _, cookie := range c.jar.Cookies(u) {
			key := origin + "\x00" + cookie.Name
			if cookie.Value == "" || seen[key] {
				continue
			}
			seen[key] = true
			saved.Cookies = append(saved.Cookies, hmeCookie{Scope: origin, Name: cookie.Name, Value: cookie.Value, Path: cookie.Path, Secure: cookie.Secure, Expires: cookie.Expires})
		}
	}
	data, err := json.Marshal(saved)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.sessionPath), 0700); err != nil {
		return err
	}
	temp := c.sessionPath + ".tmp"
	if err := os.WriteFile(temp, data, 0600); err != nil {
		return err
	}
	return os.Rename(temp, c.sessionPath)
}

func (c *AppleAccountClient) ensurePortalSession(ctx context.Context) error {
	if c.apiBase == "" || c.apiKey == "" {
		return ErrAccountManagementAuthenticationRequired
	}
	if _, _, err := c.portalRequest(ctx, http.MethodGet, "/account/manage", nil, true); err != nil {
		return ErrAccountManagementAuthenticationRequired
	}
	return nil
}

// Resume verifies that a saved account-management session is still accepted.
// It performs no login and no account mutation.
func (c *AppleAccountClient) Resume(ctx context.Context) error {
	return c.ensurePortalSession(ctx)
}

func (c *AppleAccountClient) authHeaders(state *hmeAuthState) http.Header {
	h := make(http.Header)
	if state.scnt != "" {
		h.Set("scnt", state.scnt)
	}
	if state.sessionID != "" {
		h.Set("X-Apple-ID-Session-Id", state.sessionID)
	}
	if state.authAttributes != "" {
		h.Set("X-Apple-Auth-Attributes", state.authAttributes)
	}
	if state.sessionToken != "" {
		h.Set("X-Apple-Session-Token", state.sessionToken)
	}
	h.Set("X-Apple-OAuth-Client-Id", state.clientID)
	h.Set("X-Apple-OAuth-Client-Type", "firstPartyAuth")
	h.Set("X-Apple-OAuth-Redirect-URI", "https://account.apple.com")
	h.Set("X-Apple-OAuth-Response-Mode", "web_message")
	h.Set("X-Apple-OAuth-Response-Type", "code")
	h.Set("X-Apple-OAuth-State", "auth-"+state.frameID)
	h.Set("X-Apple-Widget-Key", state.clientID)
	h.Set("X-Apple-Frame-Id", state.frameID)
	h.Set("X-Apple-Domain-Id", "6")
	h.Set("X-Apple-Locale", "zh_CN")
	h.Set("X-Apple-Offer-Security-Upgrade", "1")
	h.Set("X-Apple-Privacy-Consent", "true")
	h.Set("X-Apple-I-FD-Client-Info", hmeFDClientInfo())
	h.Set("X-Requested-With", "XMLHttpRequest")
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "application/json")
	h.Set("Origin", "https://account.apple.com")
	h.Set("Referer", "https://account.apple.com/")
	h.Set("User-Agent", hmeWebUserAgent)
	return h
}

func (c *AppleAccountClient) authRequest(ctx context.Context, state *hmeAuthState, method, endpoint string, body []byte, headers http.Header) (*http.Response, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	request.Header = headers
	response, err := c.http.Do(request)
	if err != nil {
		return nil, nil, err
	}
	c.lastHTTP = response.StatusCode
	for name, target := range map[string]*string{
		"X-Apple-Auth-Attributes": &state.authAttributes, "X-Apple-ID-Session-Id": &state.sessionID,
		"scnt": &state.scnt, "X-Apple-Session-Token": &state.sessionToken,
		"X-Apple-TwoSV-Trust-Token": &state.trustToken, "X-Apple-ID-Account-Country": &state.accountCountry,
		"X-Apple-OAuth-Grant-Code": &state.grantCode,
	} {
		if value := response.Header.Get(name); value != "" {
			*target = value
		}
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	response.Body.Close()
	if readErr != nil || len(data) > 2<<20 {
		return response, nil, errors.New("Apple Account authentication response was invalid")
	}
	return response, data, nil
}

func (c *AppleAccountClient) Authenticate(ctx context.Context, password string, codeProvider func(context.Context) (string, error)) error {
	if password == "" {
		return ErrAccountManagementAuthenticationRequired
	}
	c.lastStage, c.lastHTTP = "bootstrap", 0
	bootstrapRequest, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://appleid.apple.com/bootstrap/portal", nil)
	bootstrapRequest.Header.Set("Accept", "application/json")
	bootstrapRequest.Header.Set("User-Agent", hmeWebUserAgent)
	bootstrapResponse, err := c.http.Do(bootstrapRequest)
	if err != nil {
		return errors.New("Apple Account bootstrap failed")
	}
	bootstrapData, readErr := io.ReadAll(io.LimitReader(bootstrapResponse.Body, (1<<20)+1))
	c.lastHTTP = bootstrapResponse.StatusCode
	bootstrapResponse.Body.Close()
	var bootstrap portalBootstrap
	if readErr != nil || bootstrapResponse.StatusCode != http.StatusOK || json.Unmarshal(bootstrapData, &bootstrap) != nil || bootstrap.ServiceKey == "" || bootstrap.ServiceURL == "" || bootstrap.APIURL == "" {
		return errors.New("Apple Account bootstrap was invalid")
	}
	authBase := strings.TrimRight(bootstrap.ServiceURL, "/") + "/auth"
	state := &hmeAuthState{frameID: randomHex(16), clientID: bootstrap.ServiceKey}
	frame := "auth-" + state.frameID
	query := url.Values{"frame_id": {frame}, "language": {"en_US"}, "skVersion": {"7"}, "iframeId": {frame}, "client_id": {state.clientID}, "redirect_uri": {"https://account.apple.com"}, "response_type": {"code"}, "response_mode": {"web_message"}, "state": {frame}, "authVersion": {"latest"}}
	startHeaders := make(http.Header)
	startHeaders.Set("Accept", "*/*")
	startHeaders.Set("User-Agent", hmeWebUserAgent)
	c.lastStage = "authorize"
	response, _, err := c.authRequest(ctx, state, http.MethodGet, authBase+"/authorize/signin?"+query.Encode(), nil, startHeaders)
	if err != nil || response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("Apple Account authentication could not be initialized")
	}
	federateBody, _ := json.Marshal(map[string]any{"accountName": c.appleID, "rememberMe": false})
	c.lastStage = "federate"
	response, _, err = c.authRequest(ctx, state, http.MethodPost, authBase+"/federate?isRememberMeEnabled=false", federateBody, c.authHeaders(state))
	if err != nil || response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("Apple Account federation failed")
	}
	params := srp.NewParams()
	srpClient := srp.NewClient(params, c.appleID)
	initBody, _ := json.Marshal(map[string]any{"a": base64.StdEncoding.EncodeToString(srpClient.PublicA().Bytes()), "accountName": c.appleID, "protocols": []string{"s2k", "s2k_fo"}})
	c.lastStage = "srp-init"
	response, initData, err := c.authRequest(ctx, state, http.MethodPost, authBase+"/signin/init", initBody, c.authHeaders(state))
	if err != nil || response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("Apple Account SRP challenge failed")
	}
	var challenge struct {
		Iteration            int `json:"iteration"`
		Salt, Protocol, B, C string
	}
	if json.Unmarshal(initData, &challenge) != nil || challenge.Iteration <= 0 || challenge.Salt == "" || challenge.B == "" || challenge.C == "" {
		return errors.New("Apple Account SRP challenge was incomplete")
	}
	state.srpSession = challenge.C
	salt, saltErr := base64.StdEncoding.DecodeString(challenge.Salt)
	bBytes, bErr := base64.StdEncoding.DecodeString(challenge.B)
	if saltErr != nil || bErr != nil {
		return errors.New("Apple Account SRP challenge encoding was invalid")
	}
	passwordHash := sha256.Sum256([]byte(password))
	passwordKey, keyErr := pbkdf2.Key(sha256.New, string(passwordHash[:]), salt, challenge.Iteration, 32)
	if keyErr != nil {
		return keyErr
	}
	x := params.DeriveX(salt, passwordKey)
	m1, _, proofErr := srpClient.ProcessChallenge(x, salt, new(big.Int).SetBytes(bBytes))
	if proofErr != nil {
		return proofErr
	}
	m2, proofErr := srpClient.ExpectedM2()
	if proofErr != nil {
		return proofErr
	}
	completeBody, _ := json.Marshal(map[string]any{"accountName": c.appleID, "rememberMe": false, "trustTokens": []string{}, "m1": base64.StdEncoding.EncodeToString(m1), "c": state.srpSession, "m2": base64.StdEncoding.EncodeToString(m2)})
	c.lastStage = "srp-complete"
	response, _, err = c.authRequest(ctx, state, http.MethodPost, authBase+"/signin/complete?isRememberMeEnabled=false", completeBody, c.authHeaders(state))
	if err != nil {
		return err
	}
	if response.StatusCode == http.StatusConflict {
		if codeProvider == nil {
			return ErrAccountManagementAuthenticationRequired
		}
		c.lastStage = "trusted-challenge"
		response, _, err = c.authRequest(ctx, state, http.MethodPut, authBase+"/verify/trusteddevice/securitycode", nil, c.authHeaders(state))
		if err != nil || response.StatusCode < 200 || response.StatusCode >= 300 {
			return errors.New("Apple Account trusted-device challenge failed")
		}
		codeCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		code, codeErr := codeProvider(codeCtx)
		cancel()
		if codeErr != nil || len(strings.TrimSpace(code)) != 6 {
			return errors.New("local trusted-device code generation failed")
		}
		verifyBody, _ := json.Marshal(map[string]any{"securityCode": map[string]string{"code": strings.TrimSpace(code)}})
		c.lastStage = "trusted-code"
		response, verifyData, err := c.authRequest(ctx, state, http.MethodPost, authBase+"/verify/trusteddevice/securitycode", verifyBody, c.authHeaders(state))
		for index := range verifyBody {
			verifyBody[index] = 0
		}
		code = ""
		if err != nil || !((response.StatusCode >= 200 && response.StatusCode < 300) || (response.StatusCode == http.StatusConflict && state.sessionToken != "" && bytes.Contains(verifyData, []byte(`"valid":true`)))) {
			return errors.New("Apple Account rejected the trusted-device verification code")
		}
	} else if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("Apple Account credentials were rejected")
	}
	c.lastStage = "trust-session"
	response, _, err = c.authRequest(ctx, state, http.MethodGet, authBase+"/2sv/trust", nil, c.authHeaders(state))
	if err != nil || response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("Apple Account web session trust failed")
	}
	// The normal password/2FA portal flow establishes its session directly and
	// returns no OAuth grant code. Only the native App SSO takeover branch emits
	// a grant that must be bridged through /authorize/validate.
	if state.grantCode != "" {
		c.lastStage = "oauth-validate"
		grantCodes := []string{state.grantCode}
		if decoded, decodeErr := base64.StdEncoding.DecodeString(state.grantCode); decodeErr == nil && len(decoded) > 0 && string(decoded) != state.grantCode {
			grantCodes = append([]string{string(decoded)}, grantCodes...)
		}
		validated := false
		for _, grantCode := range grantCodes {
			validateQuery := url.Values{
				"frame_id": {frame}, "iframeId": {frame}, "client_id": {state.clientID},
				"redirect_uri": {"https://account.apple.com"}, "response_type": {"code"},
				"response_mode": {"web_message"}, "state": {frame}, "code": {grantCode},
				"oauthRequireGrantCode": {"false"}, "authVersion": {"8.0.2"},
			}
			response, validateData, validateErr := c.authRequest(ctx, state, http.MethodGet, authBase+"/authorize/validate?"+validateQuery.Encode(), nil, c.authHeaders(state))
			if validateErr == nil && response.StatusCode >= 200 && response.StatusCode < 300 && portalGrantValidationSucceeded(validateData) {
				validated = true
				break
			}
		}
		state.grantCode = ""
		if !validated {
			return errors.New("Apple Account OAuth grant validation failed")
		}
	}
	c.apiBase = strings.TrimRight(bootstrap.APIURL, "/")
	c.lastStage = "portal-token"
	if _, status, err := c.portalRequest(ctx, http.MethodGet, "/account/manage/gs/ws/token", nil, false); err != nil {
		c.lastHTTP = status
		return errors.New("Apple Account management session was not established")
	}
	c.lastStage = "manage-data"
	data, status, err := c.portalRequest(ctx, http.MethodGet, "/account/manage", nil, false)
	c.lastHTTP = status
	if err != nil {
		return errors.New("Apple Account management data was unavailable")
	}
	var manage struct {
		APIKey string `json:"apiKey"`
	}
	if json.Unmarshal(data, &manage) != nil || manage.APIKey == "" {
		return errors.New("Apple Account management API key was unavailable")
	}
	c.apiKey = manage.APIKey
	if err := c.saveSession(); err != nil {
		return errors.New("Apple Account management session could not be saved")
	}
	c.lastStage, c.lastHTTP = "", 0
	return nil
}

func (c *AppleAccountClient) AuthenticationFailure() (string, int) {
	return c.lastStage, c.lastHTTP
}

func portalGrantValidationSucceeded(data []byte) bool {
	marker := []byte(`id="grant_code_args">`)
	start := bytes.Index(data, marker)
	if start < 0 {
		return false
	}
	start += len(marker)
	end := bytes.Index(data[start:], []byte(`</script>`))
	if end < 0 {
		return false
	}
	var result struct {
		Message struct {
			Event string `json:"event"`
		} `json:"message"`
	}
	return json.Unmarshal(bytes.TrimSpace(data[start:start+end]), &result) == nil && result.Message.Event == "WidgetBridgeComplete"
}

func (c *AppleAccountClient) portalRequest(ctx context.Context, method, path string, payload any, requireAPIKey bool) ([]byte, int, error) {
	if c.apiBase == "" {
		return nil, 0, ErrAccountManagementAuthenticationRequired
	}
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, 0, err
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.apiBase+path, body)
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Accept", "application/json, text/plain, */*")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://account.apple.com")
	request.Header.Set("Referer", "https://account.apple.com/")
	request.Header.Set("User-Agent", hmeWebUserAgent)
	request.Header.Set("X-Apple-I-Request-Context", "ca")
	request.Header.Set("X-Apple-I-FD-Client-Info", hmeFDClientInfo())
	if zone := time.Now().Location().String(); zone != "" && zone != "Local" {
		request.Header.Set("X-Apple-I-TimeZone", zone)
	}
	if c.portalSCNT != "" {
		request.Header.Set("scnt", c.portalSCNT)
	}
	if requireAPIKey {
		if c.apiKey == "" {
			return nil, 0, ErrAccountManagementAuthenticationRequired
		}
		request.Header.Set("X-Apple-Api-Key", c.apiKey)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	if scnt := response.Header.Get("scnt"); scnt != "" {
		c.portalSCNT = scnt
	}
	c.lastHTTP = response.StatusCode
	data, readErr := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if readErr != nil || len(data) > 4<<20 {
		return nil, response.StatusCode, errors.New("Apple Account response was invalid")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return data, response.StatusCode, errors.New("Apple Account request was rejected")
	}
	return data, response.StatusCode, nil
}

func (c *AppleAccountClient) BeginReachableEmail(ctx context.Context, address, password string) error {
	c.lastStage, c.lastHTTP = "reachable-send", 0
	if err := c.ensurePortalSession(ctx); err != nil {
		return err
	}
	address = strings.TrimSpace(address)
	if address == "" || !strings.Contains(address, "@") || len(address) > 254 {
		return errors.New("invalid reachable email address")
	}
	payload := map[string]string{"address": address}
	data, status, err := c.portalRequest(ctx, http.MethodPost, "/account/manage/email/alternate/add/verification", payload, true)
	if err != nil && status == http.StatusUnavailableForLegalReasons {
		// Apple Account protects critical profile edits with a second password
		// challenge even when the reusable management session is valid. Complete
		// that challenge in the same cookie jar, then replay the original mutation
		// exactly once, matching the account.apple.com frontend interceptor.
		c.lastStage = "reachable-password-challenge"
		if password == "" {
			return ErrAccountManagementAuthenticationRequired
		}
		if _, _, challengeErr := c.portalRequest(ctx, http.MethodPost, "/authenticate/password", map[string]string{"password": password}, true); challengeErr != nil {
			return challengeErr
		}
		if saveErr := c.saveSession(); saveErr != nil {
			return errors.New("Apple Account management session could not be saved")
		}
		c.lastStage = "reachable-send-retry"
		data, _, err = c.portalRequest(ctx, http.MethodPost, "/account/manage/email/alternate/add/verification", payload, true)
	}
	if err != nil {
		return err
	}
	var challenge struct {
		Address        string          `json:"address"`
		VerificationID json.RawMessage `json:"verificationId"`
	}
	if json.Unmarshal(data, &challenge) != nil || len(challenge.VerificationID) == 0 || string(challenge.VerificationID) == "null" {
		return errors.New("Apple Account did not return an email verification challenge")
	}
	if challenge.Address != "" && !strings.EqualFold(strings.TrimSpace(challenge.Address), address) {
		return errors.New("Apple Account returned a different email challenge")
	}
	c.pendingEmail, c.pendingVerify = address, append(json.RawMessage(nil), challenge.VerificationID...)
	c.lastStage, c.lastHTTP = "", 0
	return nil
}

func (c *AppleAccountClient) VerifyReachableEmail(ctx context.Context, code string) error {
	code = strings.TrimSpace(code)
	if c.pendingEmail == "" || len(c.pendingVerify) == 0 {
		return errors.New("no reachable email verification is pending")
	}
	if len(code) < 4 || len(code) > 8 {
		return errors.New("invalid reachable email verification code")
	}
	var verificationID any
	if json.Unmarshal(c.pendingVerify, &verificationID) != nil {
		return errors.New("invalid reachable email challenge")
	}
	payload := map[string]any{"address": c.pendingEmail, "verificationInfo": map[string]any{"id": verificationID, "answer": code}}
	if _, _, err := c.portalRequest(ctx, http.MethodPut, "/account/manage/email/alternate/verification", payload, true); err != nil {
		return err
	}
	if !c.HasReachableEmail(ctx, c.pendingEmail) {
		return errors.New("Apple Account did not confirm the reachable email")
	}
	c.pendingEmail, c.pendingVerify = "", nil
	return nil
}

func (c *AppleAccountClient) HasReachableEmail(ctx context.Context, address string) bool {
	data, _, err := c.portalRequest(ctx, http.MethodGet, "/account/manage", nil, true)
	if err != nil {
		return false
	}
	var manage struct {
		Account struct {
			Person struct {
				ReachableAtOptions struct {
					AlternateEmailAddresses []struct {
						Address string `json:"address"`
					} `json:"alternateEmailAddresses"`
				} `json:"reachableAtOptions"`
			} `json:"person"`
		} `json:"account"`
	}
	if json.Unmarshal(data, &manage) != nil {
		return false
	}
	for _, candidate := range manage.Account.Person.ReachableAtOptions.AlternateEmailAddresses {
		if strings.EqualFold(strings.TrimSpace(candidate.Address), strings.TrimSpace(address)) {
			return true
		}
	}
	return false
}
