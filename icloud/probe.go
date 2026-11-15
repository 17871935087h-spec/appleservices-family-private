package icloud

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"howett.net/plist"
)

// StorageEndpointProbe is a sanitized, value-free result of one read-only
// probe against an Apple storage/commerce endpoint.
type StorageEndpointProbe struct {
	Name        string `json:"name"`
	Auth        string `json:"auth"`
	Method      string `json:"method"`
	HTTPStatus  int    `json:"http_status"`
	ContentType string `json:"content_type,omitempty"`
	Shape       string `json:"shape,omitempty"`
}

// The iTunes store bag advertises these endpoints for iCloud storage and
// subscription management. Each probe is a plain GET; bodies are reduced to
// their structure and never retained.
// quotaServiceBase is the per-account quota service root. The path that follows
// it is /{dsid}/{quotaToken}/… and both segments come from the account's own
// cached client data at run time (see resolveProbeSpecs), never from source.
const quotaServiceBase = "https://p121-quota.icloud.com/quotaservice/external/ios"

var storageEndpointProbes = []struct{ name, method, url, body string }{
	{"storage-bar", http.MethodGet, "https://speedysub.itunes.apple.com/subscription/v3/manage/getStorageBarInfo", ""},
	{"subs-list", http.MethodGet, "https://speedysub.itunes.apple.com/subscription/v3/manage/list", ""},
	{"subs-detail", http.MethodGet, "https://speedysub.itunes.apple.com/subscription/v3/manage/detail", ""},
	{"subs-renewal", http.MethodGet, "https://speedysub.itunes.apple.com/subscription/v3/manage/renewalOption", ""},
	{"subscriptions", http.MethodGet, "https://buy.itunes.apple.com/commerce/account/subscriptions", ""},
	{"subscription-detail", http.MethodGet, "https://buy.itunes.apple.com/commerce/account/subscriptions/detail", ""},
	{"icloud-promo-offer", http.MethodGet, "https://buy.itunes.apple.com/commerce/offers/1/promo", ""},
	{"salable-update", http.MethodGet, "https://buy.itunes.apple.com/commerce/account/subscriptions/updateSubscriptionSalable", ""},
	// The modern iCloud storage update endpoint (UpdateIcloudStorageSrv from
	// the subscription web app). Empty requests first, then the offer triple
	// the classic sign-in form already proved correct for this account.
	{"icloud-update-get", http.MethodGet, "https://buy.itunes.apple.com/commerce/account/subscriptions/icloud/update", ""},
	{"icloud-update-empty", http.MethodPost, "https://buy.itunes.apple.com/commerce/account/subscriptions/icloud/update", ""},
	{"icloud-update-salable", http.MethodPost, "https://buy.itunes.apple.com/commerce/account/subscriptions/icloud/update", "salableAdamId=6449562876"},
	{"icloud-update-offer", http.MethodPost, "https://buy.itunes.apple.com/commerce/account/subscriptions/icloud/update", "offerName=com.apple.icloud50GB_monthly&storagePlanInBytes=53687091200&salableAdamId=6449562876"},
	{"icloud-update-query", http.MethodGet, "https://buy.itunes.apple.com/commerce/account/subscriptions/icloud/update?salableAdamId=6449562876", ""},
	// Account state flags (terms, billing, restrictions) tell whether the
	// server considers this store account ready to transact.
	{"account-flags", http.MethodGet, "https://buy.itunes.apple.com/commerce/account/flags", ""},
	{"account-subscriptions-dsid", http.MethodGet, "https://buy.itunes.apple.com/commerce/account/subscriptions?dsid=", ""},
	{"up-to-date-eligibility", http.MethodGet, "https://buy.itunes.apple.com/commerce/upToDate/eligibility", ""},
	{"adoption-eligibility", http.MethodGet, "https://buy.itunes.apple.com/commerce/adoption/eligibility", ""},
	{"terms-check", http.MethodGet, "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/termsCheckSrv", ""},
	// The account's own cached storage entry points (iCloudWinPref.plist
	// entry_points). These are per-account URLs whose path carries the
	// account's DSID and an opaque path token from the client's cache, so the
	// literals are placeholders: resolveProbeSpecs substitutes the running
	// session's own values. Never commit a real account's identifiers here.
	{"manage-cloud-storage", http.MethodGet, quotaServiceBase + "/{dsid}/{quotaToken}/getManageCloudStorage", ""},
	{"itms-app-details", http.MethodGet, quotaServiceBase + "/{dsid}/{quotaToken}/getITMSAppDetails", ""},
	// The "Change Storage Plan" row (name=buyStorage) is an XMLUI button; try
	// the parameter spellings the XMLUI client uses to trigger a row action.
	{"mcs-action", http.MethodGet, quotaServiceBase + "/{dsid}/{quotaToken}/getManageCloudStorage?action=buyStorage", ""},
	{"mcs-task", http.MethodGet, quotaServiceBase + "/{dsid}/{quotaToken}/getManageCloudStorage?task=buyStorage", ""},
	{"mcs-name", http.MethodGet, quotaServiceBase + "/{dsid}/{quotaToken}/getManageCloudStorage?name=buyStorage", ""},
	{"mcs-post-action", http.MethodPost, quotaServiceBase + "/{dsid}/{quotaToken}/getManageCloudStorage", "action=buyStorage"},
	{"mcs-buy-storage", http.MethodGet, quotaServiceBase + "/{dsid}/{quotaToken}/buyStorage", ""},
	{"mcs-storage-plans", http.MethodGet, quotaServiceBase + "/{dsid}/{quotaToken}/getStoragePlanOptions", ""},
	// Plan-selection actions of the XMLUI quota client (read-only listings).
	{"mcs-get-plans", http.MethodPost, quotaServiceBase + "/{dsid}/{quotaToken}/getManageCloudStorage", "action=getStoragePlans"},
	{"mcs-plans2", http.MethodPost, quotaServiceBase + "/{dsid}/{quotaToken}/getManageCloudStorage", "action=storagePlans"},
	{"mcs-plans3", http.MethodPost, quotaServiceBase + "/{dsid}/{quotaToken}/getManageCloudStorage", "action=getStoragePlanOptions"},
	{"mcs-plans4", http.MethodPost, quotaServiceBase + "/{dsid}/{quotaToken}/getManageCloudStorage", "action=changeStoragePlan"},
	{"mcs-plans5", http.MethodPost, quotaServiceBase + "/{dsid}/{quotaToken}/getManageCloudStorage", "action=getStoragePlanTiers"},
}

// diagnosticIdentifier matches error codes and identifier-shaped messages.
var diagnosticIdentifier = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_ .:/,-]{2,120}$`)

// diagnosticTextKeys are Apple-authored UI strings (error messages and
// dialog copy) that stay safe to render; they never carry credentials.
var diagnosticTextKeys = map[string]bool{
	"userpresentableerrormessage": true,
	"errormessagekey":             true,
	"errorkey":                    true,
	"errormessage":                true,
	"explanation":                 true,
	"explanationkey":              true,
	"storagelabel":                true,
	"usagelabel":                  true,
	"storagebarcolor":             true,
	// Quota service status strings (short, non-identifying).
	"status":                          true,
	"accountstatus":                   true,
	"quotathresholdwarning":           true,
	"localizedformattedcommercequota": true,
	"localizedformattedtotalquota":    true,
}

// ProbeStorageEndpoints reads the modern commerce and subscription endpoints
// the store bag advertises for iCloud storage. It performs GET requests only
// and reports status, content type and a value-free body shape. When a Store
// commerce session is supplied the same endpoints are probed a second time
// with the native Store credentials (X-Token plus session cookies) so the two
// authentication styles can be compared.
func ProbeStorageEndpoints(ctx context.Context, dsid, adsid, token string, headers map[string]string, commerce *StoreCommerceSession) []StorageEndpointProbe {
	client := appleHTTPClient(ctx, 30*time.Second)
	defer client.CloseIdleConnections()
	applyICloud := func(req *http.Request) {
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		req.Header.Set("X-Apple-ADSID", adsid)
		if dsid != "" && token != "" {
			req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(dsid+":"+token)))
		}
	}
	out := probeEndpoints(ctx, client, "icloud-basic", applyICloud)
	if commerce != nil && commerce.client != nil && commerce.identity != nil {
		storeClient := commerce.client
		storeSession := commerce.identity
		applyStore := func(req *http.Request) {
			for key, value := range headers {
				req.Header.Set(key, value)
			}
			req.Header.Set("X-Apple-ADSID", adsid)
			storeSession.setHeaders(req)
			if storeSession.StoreFront != "" {
				req.Header.Set("X-Apple-Store-Front", storeSession.StoreFront)
			}
		}
		out = append(out, probeEndpoints(ctx, storeClient, "store-session", applyStore)...)
	}
	return out
}

// quotaScope returns the DSID and quota path token the caller's own cached
// client data supplied for the per-account quota endpoints. It reads them from
// the caller's session rather than from a committed literal, so no real
// account's identifiers live in this package.
func quotaScope(auth string) (dsid, token string) {
	scope, ok := quotaScopes[auth]
	if !ok {
		return "", ""
	}
	return scope[0], scope[1]
}

// quotaScopes holds the per-account values the quota endpoints need. It is
// populated by the caller that owns the account's cached entry points
// (iCloudWinPref.plist) and is empty otherwise, in which case the quota probes
// are skipped rather than sent with a placeholder path.
var quotaScopes = map[string][2]string{}

// SetQuotaScope registers the DSID and quota path token for one auth style so
// the built-in quota probes can address the account's own storage service.
func SetQuotaScope(auth, dsid, token string) {
	quotaScopes[auth] = [2]string{dsid, token}
}

func probeEndpoints(ctx context.Context, client *http.Client, auth string, apply func(*http.Request)) []StorageEndpointProbe {
	return probeSpecs(ctx, client, auth, apply, resolveProbeSpecs(auth, storageEndpointProbes))
}

// resolveProbeSpecs substitutes the per-account placeholders in the built-in
// probe list. The quota endpoints embed the account's own DSID and an opaque
// path token, so the literals are never committed with a real account's values.
func resolveProbeSpecs(auth string, specs []struct{ name, method, url, body string }) []struct{ name, method, url, body string } {
	dsid, token := quotaScope(auth)
	if dsid == "" && token == "" {
		return specs
	}
	out := make([]struct{ name, method, url, body string }, len(specs))
	for i, spec := range specs {
		spec.url = strings.ReplaceAll(spec.url, "{dsid}", dsid)
		spec.url = strings.ReplaceAll(spec.url, "{quotaToken}", token)
		out[i] = spec
	}
	return out
}

// ProbeSpec is one caller-supplied probe (used to iterate diagnostics without
// rebuilding the worker).
type ProbeSpec struct {
	Name   string `json:"name"`
	Method string `json:"method"`
	URL    string `json:"url"`
	Body   string `json:"body,omitempty"`
}

// ProbeCustomEndpoints runs caller-supplied probes with the same auth styles
// as ProbeStorageEndpoints.
func ProbeCustomEndpoints(ctx context.Context, specs []ProbeSpec, dsid, adsid, token string, headers map[string]string, commerce *StoreCommerceSession) []StorageEndpointProbe {
	client := appleHTTPClient(ctx, 30*time.Second)
	defer client.CloseIdleConnections()
	applyICloud := func(req *http.Request) {
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		req.Header.Set("X-Apple-ADSID", adsid)
		if dsid != "" && token != "" {
			req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(dsid+":"+token)))
		}
	}
	if commerce != nil && commerce.client != nil && commerce.identity != nil {
		applyICloud = func(req *http.Request) {
			for key, value := range headers {
				req.Header.Set(key, value)
			}
			req.Header.Set("X-Apple-ADSID", adsid)
			commerce.identity.setHeaders(req)
		}
		client = commerce.client
	}
	tuples := make([]struct{ name, method, url, body string }, 0, len(specs))
	for _, spec := range specs {
		method := spec.Method
		if method == "" {
			method = http.MethodGet
		}
		tuples = append(tuples, struct{ name, method, url, body string }{spec.Name, method, spec.URL, spec.Body})
	}
	return probeSpecs(ctx, client, "custom", applyICloud, tuples)
}

func probeSpecs(ctx context.Context, client *http.Client, auth string, apply func(*http.Request), specs []struct{ name, method, url, body string }) []StorageEndpointProbe {
	out := make([]StorageEndpointProbe, 0, len(specs))
	for _, probe := range specs {
		result := StorageEndpointProbe{Name: probe.name, Auth: auth, Method: probe.method}
		var reqBody io.Reader
		if probe.method == http.MethodPost {
			reqBody = strings.NewReader(probe.body)
		}
		req, err := http.NewRequestWithContext(ctx, probe.method, probe.url, reqBody)
		if err != nil {
			result.Shape = "request-error"
			out = append(out, result)
			continue
		}
		apply(req)
		req.Header.Set("Accept", "application/json")
		if probe.method == http.MethodPost {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, err := client.Do(req)
		if err != nil {
			result.Shape = "transport-error"
			out = append(out, result)
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
		resp.Body.Close()
		result.HTTPStatus = resp.StatusCode
		result.ContentType = resp.Header.Get("Content-Type")
		if readErr != nil || len(body) > 64*1024 {
			result.Shape = "response-error"
			out = append(out, result)
			continue
		}
		result.Shape = bodyShape(body)
		out = append(out, result)
	}
	return out
}

// bodyShape describes a response body without retaining any value: JSON keys
// with string lengths, or a raw byte count for other content.
func bodyShape(body []byte) string {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return "empty"
	}
	var value any
	if json.Unmarshal(trimmed, &value) == nil {
		return jsonShape(value, 0)
	}
	var plistValue map[string]any
	if _, err := plist.Unmarshal(trimmed, &plistValue); err == nil && len(plistValue) > 0 {
		return "plist:" + jsonShape(plistValue, 0)
	}
	// Unknown content: show a scrubbed preview so opaque responses stay
	// diagnosable without exposing identifiers.
	return fmt.Sprintf("len=%d text=%q", len(body), scrubText(string(trimmed)))
}

var scrubPatterns = []*regexp.Regexp{
	regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+`),
	regexp.MustCompile(`[0-9a-fA-F]{16,}`),
	regexp.MustCompile(`[A-Za-z0-9+/]{32,}={0,2}`),
	regexp.MustCompile(`\b\d{9,}\b`),
}

func scrubText(s string) string {
	for _, p := range scrubPatterns {
		s = p.ReplaceAllString(s, "<redacted>")
	}
	if len(s) > 2000 {
		s = s[:2000] + "…"
	}
	return s
}

func jsonShape(value any, depth int) string {
	return jsonShapeKeyed(value, "", depth)
}

func jsonShapeKeyed(value any, key string, depth int) string {
	if depth > 3 {
		return "…"
	}
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s:%s", k, jsonShapeKeyed(v[k], k, depth+1)))
		}
		return "{" + strings.Join(parts, ",") + "}"
	case []any:
		if len(v) == 0 {
			return "[]"
		}
		return fmt.Sprintf("[%d×%s]", len(v), jsonShapeKeyed(v[0], key, depth+1))
	case string:
		if diagnosticTextKeys[strings.ToLower(key)] && len(v) <= 240 {
			return fmt.Sprintf("%q", v)
		}
		// Error identifier codes and short UI messages stay readable; numeric
		// codes (which could be one-time codes) are never rendered.
		if lk := strings.ToLower(key); (lk == "code" || lk == "message") && len(v) <= 120 && diagnosticIdentifier.MatchString(v) {
			return fmt.Sprintf("%q", v)
		}
		// URL-shaped strings are reduced to host, short path segments and
		// parameter names; long path segments (tokens) are redacted.
		if u, err := url.Parse(v); err == nil && u.Scheme != "" && u.Host != "" {
			keys := make([]string, 0, len(u.Query()))
			for k := range u.Query() {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			segments := strings.Split(u.Path, "/")
			for i, seg := range segments {
				if len(seg) > 24 {
					segments[i] = fmt.Sprintf("<seg%d>", len(seg))
				}
			}
			return fmt.Sprintf("url(%s%s?%s)", u.Hostname(), strings.Join(segments, "/"), strings.Join(keys, ","))
		}
		return fmt.Sprintf("str(%d)", len(v))
	case float64, bool, nil:
		return fmt.Sprintf("%v", v)
	default:
		return "?"
	}
}
