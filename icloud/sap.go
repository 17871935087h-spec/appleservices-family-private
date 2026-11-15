package icloud

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Laky-64/appleservices/gsa"
	"github.com/Laky-64/appleservices/internal/sap"
	"howett.net/plist"
)

const (
	storeBagURL       = "https://init.itunes.apple.com/bag.xml"
	maxStoreBagBytes  = 2 << 20
	maxSAPRedirects   = 4
	storeSAPUserAgent = "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6"
	// storeNativeUserAgent matches the agent the native /auth/v1/native/fast
	// endpoint expects.
	storeNativeUserAgent = "Configurator/2.18 (Macintosh; OS X 15.4.1; 24E263) AppleWebKit/0621.1.15.11.10"
)

type storeSAPBag struct {
	AuthEndpoint   string
	SetupURL       string
	CertificateURL string
	Version        uint32
}

// loadStoreSAPBag reads Apple's versioned Store bag. The ix=6 response is a
// plain plist and carries the SAP endpoints used by the current Store login.
func loadStoreSAPBag(ctx context.Context, client *http.Client, guid string) (storeSAPBag, error) {
	return loadStoreSAPBagForAgent(ctx, client, guid, storeSAPUserAgent, false)
}

func loadStoreSAPBagForAgent(ctx context.Context, client *http.Client, guid, agent string, preserveNative bool) (storeSAPBag, error) {
	return loadStoreSAPBagForAgentMode(ctx, client, guid, agent, preserveNative, os.Getenv("APPLESERVICES_SKILL_MATCHED_BAG") == "1")
}

func loadStoreSAPBagForAgentMode(ctx context.Context, client *http.Client, guid, agent string, requireNative, preserveMatched bool) (storeSAPBag, error) {
	query := url.Values{"ix": {"6"}, "guid": {guid}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, storeBagURL+"?"+query.Encode(), nil)
	if err != nil {
		return storeSAPBag{}, err
	}
	req.Header.Set("Accept", "application/xml, text/xml, */*")
	req.Header.Set("User-Agent", agent)
	resp, err := client.Do(req)
	if err != nil {
		return storeSAPBag{}, fmt.Errorf("fetch Store bag: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return storeSAPBag{}, fmt.Errorf("Store bag returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxStoreBagBytes+1))
	if err != nil || len(body) > maxStoreBagBytes {
		return storeSAPBag{}, errors.New("Store bag response is invalid")
	}
	bag, err := decodeStoreSAPBag(body)
	if err != nil {
		return storeSAPBag{}, err
	}
	if requireNative || preserveMatched {
		var values map[string]any
		if _, err := plist.Unmarshal(body, &values); err != nil {
			return storeSAPBag{}, err
		}
		raw := plistString(values, "authenticateAccount")
		if err := validateSAPEndpoint("authenticate", raw); err != nil {
			return storeSAPBag{}, err
		}
		u, _ := url.Parse(raw)
		if requireNative && (u.Hostname() != "auth.itunes.apple.com" || (u.Path != "/auth/v1/native" && u.Path != "/auth/v1/native/fast" && u.Path != "/auth/v1/native/fast/")) {
			return storeSAPBag{}, errors.New("bag did not return a supported native Store endpoint")
		}
		bag.AuthEndpoint = raw
	}
	return bag, nil
}

func decodeStoreSAPBag(body []byte) (storeSAPBag, error) {
	var values map[string]any
	if _, err := plist.Unmarshal(body, &values); err != nil {
		return storeSAPBag{}, fmt.Errorf("decode Store bag: %w", err)
	}
	bag := storeSAPBag{
		AuthEndpoint:   plistString(values, "authenticateAccount"),
		SetupURL:       plistString(values, "sign-sap-setup"),
		CertificateURL: plistString(values, "sign-sap-setup-cert"),
	}
	if bag.SetupURL == "" {
		bag.SetupURL = plistString(values, "loc-sign-sap-setup")
	}
	if bag.CertificateURL == "" {
		bag.CertificateURL = plistString(values, "loc-sign-sap-setup-cert")
	}
	version := plistString(values, "sign-sap-version")
	if version == "" {
		version = plistString(values, "loc-sign-sap-version")
	}
	if version == "" {
		version = "200"
	}
	if version != "200" {
		return storeSAPBag{}, fmt.Errorf("unsupported SAP version %q", version)
	}
	bag.Version = 200
	if err := validateSAPEndpoint("authenticate", bag.AuthEndpoint); err != nil {
		return storeSAPBag{}, err
	}
	if err := validateSAPEndpoint("setup", bag.SetupURL); err != nil {
		return storeSAPBag{}, err
	}
	if err := validateSAPEndpoint("certificate", bag.CertificateURL); err != nil {
		return storeSAPBag{}, err
	}
	// Apple's bag still advertises the legacy MZFinance authenticate path to
	// part of its traffic. After the June 2026 store change that path only
	// answers 301 to an HTML body, and the password token it used to mint is
	// refused by the purchase flow (failureType 2034). The native endpoint
	// below is the only one that yields an acceptable token, so every bag is
	// normalized to it. The trailing slash matters too.
	authURL, parseErr := url.Parse(bag.AuthEndpoint)
	if parseErr != nil {
		return storeSAPBag{}, errors.New("invalid SAP authentication endpoint")
	}
	if strings.EqualFold(authURL.Hostname(), "auth.itunes.apple.com") && strings.HasPrefix(authURL.Path, "/auth/v1/native/") {
		if !strings.HasSuffix(authURL.Path, "/") {
			authURL.Path += "/"
		}
		bag.AuthEndpoint = authURL.String()
		return bag, nil
	}
	native := url.URL{Scheme: "https", Host: "auth.itunes.apple.com", Path: "/auth/v1/native/fast/"}
	bag.AuthEndpoint = native.String()
	return bag, nil
}

func plistString(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return strings.TrimSpace(value)
}

// safeEndpointLabel renders host and path without query values.
func safeEndpointLabel(u *url.URL) string {
	if u == nil {
		return "?"
	}
	return strings.ToLower(u.Hostname()) + u.EscapedPath()
}

func safeRedirectLabel(location string) string {
	u, err := url.Parse(strings.TrimSpace(location))
	if err != nil {
		return "invalid"
	}
	return safeEndpointLabel(u)
}

// isModernStoreAuthEndpoint reports whether the endpoint is Apple's current
// native store authentication path.
func isModernStoreAuthEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Hostname(), "auth.itunes.apple.com") &&
		(u.Path == "/auth/v1/native/fast" || u.Path == "/auth/v1/native/fast/")
}

// requestFingerprint describes an outgoing store login without values: the
// endpoint, header names, body length and the hardware-id prefix.
func requestFingerprint(req *http.Request, guid string) string {
	names := make([]string, 0, len(req.Header))
	for name := range req.Header {
		if storeControlName.MatchString(name) {
			names = append(names, strings.ToLower(name))
		}
	}
	sort.Strings(names)
	prefix := guid
	if len(prefix) > 4 {
		prefix = prefix[:4]
	}
	return fmt.Sprintf("post=%s;hdrs=%s;cl=%d;guid=%s", safeEndpointLabel(req.URL), strings.Join(names, ","), req.ContentLength, prefix)
}

// storeHeaderHint lists response header names (never values) so a rejected
// store login stays diagnosable.
func storeHeaderHint(header http.Header) string {
	names := make([]string, 0, len(header))
	for name := range header {
		if storeControlName.MatchString(name) {
			names = append(names, strings.ToLower(name))
		}
	}
	sort.Strings(names)
	return "headers=" + strings.Join(names, ",")
}

func validateSAPEndpoint(label, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawPath != "" || (u.Port() != "" && u.Port() != "443") {
		return fmt.Errorf("invalid SAP %s endpoint", label)
	}
	host := strings.ToLower(u.Hostname())
	if label == "authenticate" {
		// The current native endpoint, or the legacy MZFinance path used by
		// older bags. Everything is normalized to the native endpoint.
		modern := host == "auth.itunes.apple.com" && strings.HasPrefix(u.Path, "/auth/v1/native/")
		legacy := (host == "auth.itunes.apple.com" || host == "buy.itunes.apple.com" || strings.HasSuffix(host, "-buy.itunes.apple.com")) && (u.Path == "/WebObjects/MZFinance.woa/wa/authenticate" || u.Path == "/WebObjects/MZFinance.woa/wa/authenticate/")
		if !modern && !legacy {
			return errors.New("unsupported Store authentication endpoint")
		}
	} else if !strings.HasSuffix(host, ".apple.com") && !strings.HasSuffix(host, ".mzstatic.com") {
		return fmt.Errorf("unsupported SAP %s endpoint", label)
	}
	return nil
}

// virtualInterfaceNames and virtualMACPrefixes identify hypervisor, container
// and virtual-switch adapters. Apple's store answers requests built on such a
// device identity with an empty HTTP 204 and never mints a session, so the
// physical interface must win when one exists.
var virtualInterfaceNames = []string{"vethernet", "vmware", "hyper-v", "wsl", "loopback", "virtualbox", "docker", "tailscale", "zerotier", "wireguard", "tap-", "tun"}

var virtualMACPrefixes = [][]byte{
	{0x00, 0x15, 0x5d}, // Microsoft Hyper-V / WSL
	{0x00, 0x50, 0x56}, // VMware host-only / NAT
	{0x00, 0x0c, 0x29}, // VMware
	{0x00, 0x05, 0x69}, // VMware
	{0x08, 0x00, 0x27}, // VirtualBox
	{0x0a, 0x00, 0x27}, // VirtualBox host-only
	{0x00, 0x1c, 0x42}, // Parallels
	{0x00, 0xff},       // TAP-Windows / OpenVPN
}

func isVirtualInterface(name string, mac []byte) bool {
	lower := strings.ToLower(name)
	for _, marker := range virtualInterfaceNames {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	for _, prefix := range virtualMACPrefixes {
		if len(mac) >= len(prefix) && bytes.Equal(mac[:len(prefix)], prefix) {
			return true
		}
	}
	return false
}

// storeHardwareIdentity returns the stable physical interface address used as
// both the Store GUID and SAP hardware ID. Interface order is not stable, so
// candidates are sorted before selection.
func storeHardwareIdentity() (string, []byte, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", nil, fmt.Errorf("enumerate network interfaces: %w", err)
	}
	var physical, virtual [][]byte
	for _, iface := range interfaces {
		if iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 || len(iface.HardwareAddr) != 6 {
			continue
		}
		mac := append([]byte(nil), iface.HardwareAddr...)
		if mac[0]&1 != 0 || bytes.Equal(mac, make([]byte, 6)) {
			continue
		}
		// A disconnected adapter (TAP/VPN left behind by another product)
		// carries a lower address than the live NIC and would otherwise win
		// the sort below; Apple answers sessions built on it with an empty
		// HTTP 204.
		if isVirtualInterface(iface.Name, mac) || iface.Flags&net.FlagUp == 0 {
			virtual = append(virtual, mac)
			continue
		}
		physical = append(physical, mac)
	}
	candidates := physical
	if len(candidates) == 0 {
		candidates = virtual
	}
	if len(candidates) == 0 {
		return "", nil, errors.New("no usable network hardware address for SAP")
	}
	sort.Slice(candidates, func(i, j int) bool { return bytes.Compare(candidates[i], candidates[j]) < 0 })
	hardware := candidates[0]
	return strings.ToUpper(fmt.Sprintf("%02x%02x%02x%02x%02x%02x", hardware[0], hardware[1], hardware[2], hardware[3], hardware[4], hardware[5])), hardware, nil
}

func plistLoginBody(appleID, password, guid string) ([]byte, error) {
	return plistLoginAttemptBody(appleID, password, guid, 1)
}

func plistLoginAttemptBody(appleID, password, guid string, attempt int) ([]byte, error) {
	values := map[string]any{
		"appleId":  appleID,
		"attempt":  strconv.Itoa(attempt),
		"guid":     guid,
		"password": password,
		"rmp":      "0",
		"why":      "signIn",
	}
	var body bytes.Buffer
	if err := plist.NewEncoder(&body).Encode(values); err != nil {
		return nil, fmt.Errorf("encode Store login plist: %w", err)
	}
	return body.Bytes(), nil
}

func validStoreRedirect(base, location string) (string, error) {
	ref, err := url.Parse(strings.TrimSpace(location))
	if err != nil || strings.TrimSpace(location) == "" {
		return "", errors.New("invalid Store authentication redirect")
	}
	origin, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	dest := origin.ResolveReference(ref)
	if validateSAPEndpoint("authenticate", dest.String()) != nil {
		return "", errors.New("Store authentication redirected to an unsupported endpoint")
	}
	return dest.String(), nil
}

// authenticateStoreWithSAP performs the signed native Store login and keeps
// the resulting MZFinance cookies in the caller's jar. It signs only the
// plist request body; credentials never enter logs or error strings.
func authenticateStoreWithSAP(ctx context.Context, client *http.Client, appleID, password, code string, headers map[string]string) (*storeSession, error) {
	guid, hardware, err := storeHardwareIdentity()
	if err != nil {
		return nil, &StorageError{Stage: "purchase-store-sap"}
	}
	bag, err := loadStoreSAPBag(ctx, client, guid)
	if err != nil {
		return nil, &StorageError{Stage: "purchase-store-bag"}
	}
	signer, err := sap.NewSigner(ctx, sap.Config{SetupURL: bag.SetupURL, CertificateURL: bag.CertificateURL, Version: bag.Version, HardwareID: hardware})
	if err != nil {
		return nil, &StorageError{Stage: "purchase-store-sap"}
	}
	defer signer.Close()
	return authenticateSignedStore(ctx, client, bag.AuthEndpoint, appleID, password, code, guid, headers, signer)
}

type storeSession struct {
	DSID, PasswordToken, StoreFront, GUID string
	// Pod is the store pod the login was served from ("25" -> p25-buy...).
	Pod string
	// Anonymous marks a diagnostic page-chain session with no native Store
	// login: the WebView sets no MZFinance cookies of its own and lets the
	// volumeAuthenticate form create the session.
	Anonymous bool
}

// StoreAuthenticationInfo contains no account identity, token or cookie.
type StoreAuthenticationInfo struct {
	Ready bool `json:"ready"`
}

// StoreCommerceSession keeps Store credentials and cookies together, only in
// memory. Its private fields are never included in API responses.
type StoreCommerceSession struct {
	client   *http.Client
	identity *storeSession
}

func (s *StoreCommerceSession) MatchesAccount(dsid string) bool {
	return s != nil && s.client != nil && s.identity != nil && dsid != "" && s.identity.DSID == dsid && s.identity.PasswordToken != ""
}

// storeProxyTransport uses an account-bound route when one is present in the
// request context. The legacy STORE_PROXY override remains available only when
// no account pool is configured; invalid configured routes never fall back.
func storeProxyTransport(ctx context.Context) (http.RoundTripper, error) {
	if transport, accountBound := accountRouteTransport(ctx); accountBound {
		return transport.Clone(), nil
	}
	if strings.TrimSpace(os.Getenv("APPLESERVICES_PROXY_POOL")) != "" {
		return gsa.AppleRootTransport(), nil
	}
	if raw := strings.TrimSpace(os.Getenv("APPLESERVICES_STORE_PROXY")); raw != "" {
		if !strings.Contains(raw, "://") {
			raw = "socks5://" + raw
		}
		transport, err := gsa.AppleRootTransportForProxy(raw)
		if err != nil {
			return nil, errors.New("icloud: configured Store proxy is invalid")
		}
		return transport, nil
	}
	return gsa.AppleRootTransport(), nil
}

func AuthenticateStore(ctx context.Context, appleID, password, code string, headers map[string]string) (*StoreCommerceSession, error) {
	transport, err := storeProxyTransport(ctx)
	if err != nil {
		return nil, &StorageError{Stage: "purchase-store-proxy"}
	}
	client := &http.Client{Jar: mustCookieJar(), Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	identity, err := authenticateStoreWithSAP(ctx, client, appleID, password, code, headers)
	if err != nil {
		client.CloseIdleConnections()
		return nil, err
	}
	return &StoreCommerceSession{client: client, identity: identity}, nil
}

// AuthenticateStoreForAccount resolves and pins Store traffic to accountDir.
// This form is required when multiple accounts share one process.
func AuthenticateStoreForAccount(ctx context.Context, accountDir, appleID, password, code string, headers map[string]string) (*StoreCommerceSession, error) {
	routed, err := WithAccountRoute(ctx, accountDir)
	if err != nil {
		return nil, &StorageError{Stage: "purchase-store-proxy"}
	}
	return AuthenticateStore(routed, appleID, password, code, headers)
}

// AuthenticateStoreForHardware preserves an explicitly selected account Mac's
// network identity. It never selects a shared physical Windows interface or
// retries a rejected authentication request automatically.
func AuthenticateStoreForHardware(ctx context.Context, appleID, password, code string, headers map[string]string, hardware []byte) (*StoreCommerceSession, error) {
	return AuthenticateStoreForHardwareWithRetries(ctx, appleID, password, code, headers, hardware, 0)
}

// AuthenticateStoreForHardwareWithRetries permits a caller-selected, bounded
// retry of HTTP routing failures during authentication only. It never purchases
// or retries an application rejection or an HTTP 429.
func AuthenticateStoreForHardwareWithRetries(ctx context.Context, appleID, password, code string, headers map[string]string, hardware []byte, retries int) (*StoreCommerceSession, error) {
	return authenticateStoreForHardwareMode(ctx, appleID, password, code, headers, hardware, retries, false, false)
}

// AuthenticateSignedStoreForHardware signs the native authentication body
// according to Apple's sign-sap-request bag while keeping the account Mac.
func AuthenticateSignedStoreForHardware(ctx context.Context, appleID, password, code string, headers map[string]string, hardware []byte, retries int) (*StoreCommerceSession, error) {
	return authenticateStoreForHardwareMode(ctx, appleID, password, code, headers, hardware, retries, true, false)
}

// AuthenticateAppStoreForHardware uses Apple's bag endpoint verbatim, the
// account Mac's anisette headers, and the native App Store fingerprint.
func AuthenticateAppStoreForHardware(ctx context.Context, appleID, password, code string, headers map[string]string, hardware []byte, retries int) (*StoreCommerceSession, error) {
	return authenticateStoreForHardwareMode(ctx, appleID, password, code, headers, hardware, retries, true, true)
}

func authenticateStoreForHardwareMode(ctx context.Context, appleID, password, code string, headers map[string]string, hardware []byte, retries int, nativeSignature, appStoreProfile bool) (*StoreCommerceSession, error) {
	if retries < 0 || retries > 3 {
		return nil, &StorageError{Stage: "purchase-store-retry-limit"}
	}
	if len(hardware) != 6 || hardware[0]&1 != 0 || bytes.Equal(hardware, make([]byte, 6)) {
		return nil, &StorageError{Stage: "purchase-store-hardware"}
	}
	guid := strings.ToUpper(fmt.Sprintf("%x", hardware))
	transport, err := storeProxyTransport(ctx)
	if err != nil {
		return nil, &StorageError{Stage: "purchase-store-proxy"}
	}
	client := &http.Client{Jar: mustCookieJar(), Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var bag storeSAPBag
	if appStoreProfile {
		bag, err = loadStoreSAPBagForAgent(ctx, client, guid, storeMacUserAgent, true)
	} else {
		bag, err = loadStoreSAPBag(ctx, client, guid)
	}
	if err != nil {
		client.CloseIdleConnections()
		return nil, &StorageError{Stage: "purchase-store-bag"}
	}
	var signer sap.ActionSigner
	if nativeSignature {
		signer, err = sap.NewSigner(ctx, sap.Config{SetupURL: bag.SetupURL, CertificateURL: bag.CertificateURL, Version: bag.Version, HardwareID: hardware})
		if err != nil {
			client.CloseIdleConnections()
			return nil, &StorageError{Stage: "purchase-store-sap"}
		}
		defer signer.Close()
	}
	identity, err := authenticateSignedStoreConfigured(ctx, client, bag.AuthEndpoint, appleID, password, code, guid, headers, signer, retries, nativeSignature, appStoreProfile)
	if err != nil {
		client.CloseIdleConnections()
		return nil, err
	}
	return &StoreCommerceSession{client: client, identity: identity}, nil
}

// CheckStoreAuthentication establishes a Store session without reading an
// offer or contacting buyProduct/volumeAuthenticate.
func CheckStoreAuthentication(ctx context.Context, appleID, password, code string, headers map[string]string) (*StoreAuthenticationInfo, error) {
	session, err := AuthenticateStore(ctx, appleID, password, code, headers)
	if err != nil {
		return nil, err
	}
	session.client.CloseIdleConnections()
	return &StoreAuthenticationInfo{Ready: true}, nil
}

var storePlistPattern = regexp.MustCompile(`(?is)<plist\b[^>]*>.*?</plist>`)
var storeDictPattern = regexp.MustCompile(`(?is)<dict\b[^>]*>.*</dict>`)
var storeFailurePattern = regexp.MustCompile(`^-?[0-9]{1,10}$`)

func decodeStoreLogin(body []byte, status int, header http.Header) (*storeSession, error) {
	failure := &StorageError{Stage: "purchase-store-response", HTTPStatus: status}
	normalized := bytes.TrimSpace(body)
	if match := storePlistPattern.Find(normalized); len(match) > 0 {
		normalized = match
	} else if match := storeDictPattern.Find(normalized); len(match) > 0 {
		normalized = match
	}
	var result struct {
		FailureType     string `plist:"failureType"`
		CustomerMessage string `plist:"customerMessage"`
		DSID            string `plist:"dsPersonId"`
		PasswordToken   string `plist:"passwordToken"`
	}
	if _, err := plist.Unmarshal(normalized, &result); err != nil {
		return nil, failure
	}
	if storeFailurePattern.MatchString(result.FailureType) {
		failure.AppleCode = result.FailureType
	}
	if result.CustomerMessage == "MZFinance.BadLogin.Configurator_message" && result.FailureType == "" {
		failure.Stage = "purchase-store-2fa"
		return nil, failure
	}
	if result.CustomerMessage == "Your account is disabled." {
		failure.Stage = "purchase-store-account-disabled"
		return nil, failure
	}
	if result.FailureType != "" {
		failure.Stage = "purchase-store-authentication"
		return nil, failure
	}
	if status != http.StatusOK || result.DSID == "" || result.PasswordToken == "" || header.Get("X-Set-Apple-Store-Front") == "" {
		return nil, failure
	}
	return &storeSession{DSID: result.DSID, PasswordToken: result.PasswordToken, StoreFront: header.Get("X-Set-Apple-Store-Front"), Pod: strings.TrimSpace(header.Get("pod"))}, nil
}

// storeAuthAttempts bounds how many times a store login is sent before giving
// up. The edge in front of the authentication endpoint answers a request it
// cannot route with a bare 204, a 301 to an HTML body, a 403, a 404 or a 5xx —
// all with no usable payload. Those are the same statuses a working App Store
// client treats as transient and retries, and the share of requests that reach
// the application is small and varies widely, so one attempt almost always
// loses the draw.
const storeAuthAttempts = 12

// storeAuthRetryDelay and storeAuthRetryCap pace the retries. The edge's
// behaviour changes on the scale of minutes, so the retries stay close together
// while a login attempt is still worth completing.
const (
	storeAuthRetryDelay = 400 * time.Millisecond
	storeAuthRetryCap   = 2 * time.Second
)

// retryableStoreAuthStatus reports whether a status means the request never
// reached the application. Only a 200 carries an application answer; every
// other status is routing noise that says nothing about the credentials.
func retryableStoreAuthStatus(status int) bool {
	switch status {
	case http.StatusNoContent, http.StatusForbidden, http.StatusNotFound, http.StatusTooManyRequests:
		return true
	}
	return status/100 == 5
}

// storeAuthRetryAfter honors an explicit Retry-After when Apple sends one.
func storeAuthRetryAfter(header http.Header, now time.Time) time.Duration {
	value := strings.TrimSpace(header.Get("Retry-After"))
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseUint(value, 10, 32); err == nil {
		if seconds > uint64(storeAuthRetryCap/time.Second) {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	if date, err := http.ParseTime(value); err == nil {
		if wait := date.Sub(now); wait > 0 && wait <= storeAuthRetryCap {
			return wait
		}
	}
	return 0
}

func authenticateSignedStore(ctx context.Context, client *http.Client, endpoint, appleID, password, code, guid string, headers map[string]string, signer sap.ActionSigner) (*storeSession, error) {
	return authenticateSignedStoreBounded(ctx, client, endpoint, appleID, password, code, guid, headers, signer, storeAuthAttempts)
}

func authenticateSignedStoreBounded(ctx context.Context, client *http.Client, endpoint, appleID, password, code, guid string, headers map[string]string, signer sap.ActionSigner, retryLimit int) (*storeSession, error) {
	return authenticateSignedStoreConfigured(ctx, client, endpoint, appleID, password, code, guid, headers, signer, retryLimit, false, false)
}

func authenticateSignedStoreConfigured(ctx context.Context, client *http.Client, endpoint, appleID, password, code, guid string, headers map[string]string, signer sap.ActionSigner, retryLimit int, nativeSignature, appStoreProfile bool) (*storeSession, error) {
	if code != "" && (len(code) != 6 || strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' }) != -1) {
		return nil, &StorageError{Stage: "purchase-store-code"}
	}
	// The native /auth/v1/native/fast/ endpoint mints the store session from
	// the plist body itself; the SAP action signature belongs to the legacy
	// MZFinance authenticate endpoint only.
	modernAuth := isModernStoreAuthEndpoint(endpoint)
	routeRetries := 0
	for attempt, redirects := 1, 0; ; {
		body, err := plistLoginAttemptBody(appleID, password+code, guid, attempt)
		if err != nil {
			return nil, &StorageError{Stage: "purchase-store-sap"}
		}
		signatureHeader := ""
		if !modernAuth || nativeSignature {
			if signer == nil {
				return nil, &StorageError{Stage: "purchase-store-sap"}
			}
			signature, err := signer.Sign(body)
			if err != nil {
				return nil, &StorageError{Stage: "purchase-store-sap"}
			}
			signatureHeader = base64.StdEncoding.EncodeToString(signature)
		}
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if reqErr != nil {
			return nil, &StorageError{Stage: "purchase-store-authentication"}
		}
		if modernAuth {
			// The native endpoint takes the identity from the plist body and
			// the Configurator agent alone; the legacy anisette, accept and
			// signature headers belong to the MZFinance flow.
			req.Header.Set("User-Agent", storeNativeUserAgent)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			for key, value := range headers {
				req.Header.Set(key, value)
			}
			req.Header.Set("User-Agent", storeSAPUserAgent)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Accept", "application/xml, text/xml, */*")
			if signatureHeader != "" {
				req.Header.Set("X-Apple-ActionSignature", signatureHeader)
			}
		}
		if modernAuth && nativeSignature {
			req.Header.Set("X-Apple-ActionSignature", signatureHeader)
		}
		if appStoreProfile {
			for key, value := range headers {
				req.Header.Set(key, value)
			}
			req.Header.Set("User-Agent", storeMacUserAgent)
			req.Header.Set("Accept", "application/x-apple-plist, application/xml")
			req.Header.Set("X-Apple-ActionSignature", signatureHeader)
		}
		resp, doErr := client.Do(req)
		if doErr != nil {
			return nil, &StorageError{Stage: "purchase-store-authentication"}
		}
		responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxStoreBagBytes+1))
		location := resp.Header.Get("Location")
		status := resp.StatusCode
		resp.Body.Close()
		if readErr != nil || len(responseBody) > maxStoreBagBytes {
			return nil, &StorageError{Stage: "purchase-store-response", HTTPStatus: status}
		}
		if directory := os.Getenv("APPLESERVICES_STORE_AUTH_DIAGNOSTIC_DIR"); directory != "" {
			file, err := os.CreateTemp(directory, "store-auth-response-*.json")
			if err != nil {
				return nil, &StorageError{Stage: "purchase-store-private-diagnostic"}
			}
			writeErr := json.NewEncoder(file).Encode(map[string]any{"HTTP": status, "headers": resp.Header, "body": responseBody})
			closeErr := file.Close()
			if writeErr != nil || closeErr != nil {
				return nil, &StorageError{Stage: "purchase-store-private-diagnostic"}
			}
		}
		if status >= 300 && status < 400 {
			// A bare redirect has no navigation to follow. In the explicitly
			// bounded account-Mac mode, retry authentication routing only.
			if strings.TrimSpace(location) == "" && retryLimit <= 3 && routeRetries < retryLimit {
				routeRetries++
				select {
				case <-ctx.Done():
					return nil, &StorageError{Stage: "purchase-store-authentication", HTTPStatus: status}
				case <-time.After(storeAuthRetryDelay << min(routeRetries-1, 2)):
				}
				continue
			}
			if redirects >= maxSAPRedirects || (status != 301 && status != 302 && status != 307 && status != 308) {
				return nil, &StorageError{Stage: "purchase-store-authentication", HTTPStatus: status, Hint: "from=" + safeEndpointLabel(req.URL) + ";to=" + safeRedirectLabel(location)}
			}
			endpoint, err = validStoreRedirect(endpoint, location)
			if err != nil {
				return nil, &StorageError{Stage: "purchase-store-authentication", HTTPStatus: status, Hint: "from=" + safeEndpointLabel(req.URL) + ";to=" + safeRedirectLabel(location)}
			}
			redirects++
			continue
		}
		if status == http.StatusNoContent || status < 200 || status >= 300 {
			// A retryable status means the request never reached the
			// application, so it is resent unchanged rather than reported as a
			// credential failure.
			if status != http.StatusTooManyRequests && retryableStoreAuthStatus(status) && routeRetries < retryLimit {
				routeRetries++
				delay := storeAuthRetryDelay << min(routeRetries-1, 3)
				if delay > storeAuthRetryCap {
					delay = storeAuthRetryCap
				}
				if requested := storeAuthRetryAfter(resp.Header, time.Now()); requested > 0 {
					delay = requested
				}
				select {
				case <-ctx.Done():
					return nil, &StorageError{Stage: "purchase-store-authentication", HTTPStatus: status}
				case <-time.After(delay):
				}
				continue
			}
			return nil, &StorageError{Stage: "purchase-store-authentication", HTTPStatus: status,
				Hint: requestFingerprint(req, guid) + ";" + storeHeaderHint(resp.Header)}
		}
		session, loginErr := decodeStoreLogin(responseBody, status, resp.Header)
		if loginErr != nil {
			if loginFailure, ok := loginErr.(*StorageError); ok && loginFailure.Hint == "" {
				loginFailure.Hint = requestFingerprint(req, guid) + ";" + storeHeaderHint(resp.Header)
			}
		}
		var failure *StorageError
		if errors.As(loginErr, &failure) && failure.AppleCode == "-5000" && attempt == 1 && retryLimit == storeAuthAttempts {
			attempt++
			continue
		}
		if errors.As(loginErr, &failure) && failure.Stage == "purchase-store-2fa" && code != "" {
			failure.Stage = "purchase-store-code-unverified"
		}
		if session != nil {
			session.GUID = guid
		}
		return session, loginErr
	}
}
