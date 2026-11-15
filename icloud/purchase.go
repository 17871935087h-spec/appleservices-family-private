package icloud

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/html"
	"howett.net/plist"
)

var ErrPurchaseSessionUnavailable = errors.New("icloud: Apple purchase session is unavailable")

// PurchaseResult describes the result of Apple's Store flow. Apple may return
// a completed marker, a confirmation form, or an iTunes handoff page; only the
// first one is a completed subscription.
// The handoff URL is deliberately never returned because it contains the
// account's short-lived authToken.
type PurchaseResult struct {
	State                  string `json:"state"` // handoff or completed
	HTTPStatus             int    `json:"http_status"`
	ExternalClientRequired bool   `json:"external_client_required"`
	HandoffPath            string `json:"handoff_path,omitempty"`
	QuotaVerified          bool   `json:"quota_verified"`
	confirmation           url.Values
	confirmationOriginal   url.Values
}

const (
	storeBuyProductURL    = "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/buyProduct"
	storePresentOffersURL = "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/presentOffers"
	storeAuthenticateURL  = "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/"
	storeAppAdamID        = "1581031638"
	storeAppExtVrsID      = "843583569"
	storeSalableAdamID    = "6449562876"
)

// The Windows client's storage window is a WebView2. The live capture of
// iCloudHome 15.8.118.0 (CDP, 2026-10-07) shows two shapes:
//   - the host-driven entry navigation carries the AOSKit identity set
//     (account credential plus X-Mme-* headers) and the iCloud user agent;
//   - page-driven requests (the volumeAuthenticate form post) carry plain
//     browser headers with the WebView2 user agent and none of that set.
//
// Replicate each shape for the matching hop.
const (
	storeWebViewUA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36 Edg/154.0.0.0"
	officialClientUA = "iCloud/15.8.118 Windows/10.0 build/26100 maker/Microsoft model/PC hwp/x64 AOSKit/282 iCloudSettings/1.0"
	// A macOS identity takes the App Store purchase route (MZBuy) instead of
	// the iCloud-for-Windows volume store route.
	storeMacClientInfo = "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.accountsd/113)>"
	storeMacUserAgent  = "App Store/3.0 (Macintosh; OS X 13.4.1; 22F8) AppleWebKit/605.1.15.1.5 (KHTML, like Gecko)"
)

// setOfficialClientHeaders applies the AOSKit identity set to the entry
// navigation: the entry page only renders the upgrade offers when Apple can
// bind the request to the account (the browser-shaped replay returns a page
// without any offer links).
func setOfficialClientHeaders(req *http.Request, dsid, token string) {
	req.Header.Set("X-Mme-Client-Info", "<PC> <Windows; 10.0.26100> <com.apple.AOSKit/129.8 (com.apple.iCloud/15.8.118)>")
	name, offset := time.Now().Zone()
	if name == "" || name == "Local" {
		name = fmt.Sprintf("GMT%+d", offset/3600)
	}
	req.Header.Set("X-Mme-Timezone", name)
	if dsid != "" && token != "" {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(dsid+":"+token)))
	}
}

// PurchaseTarget is the exact offer the caller intends to buy. PriceMinor is
// expressed in the currency's minor unit (for CNY, fen).
type PurchaseTarget struct {
	Bytes      uint64
	PriceMinor int64
	Currency   string
	Period     string
}

// supported50GBTarget maps only recurring offers with an explicit
// authorization path. Store prices use thousandths (99 cents is sent as
// 990), while PurchaseTarget uses the currency's minor unit.
func supported50GBTarget(target PurchaseTarget) (country, storePrice string, ok bool) {
	if target.Bytes != 50*1024*1024*1024 || target.Period != "month" {
		return "", "", false
	}
	switch {
	case target.Currency == "CNY" && target.PriceMinor == 600:
		return "CN", "6000", true
	case target.Currency == "USD" && target.PriceMinor == 99:
		return "US", "990", true
	default:
		return "", "", false
	}
}

func supported50GBQuery(q url.Values) bool {
	if q.Get("offerName") != "com.apple.icloud50GB_monthly" || q.Get("storagePlanInBytes") != "53687091200" || q.Get("salableAdamId") != storeSalableAdamID {
		return false
	}
	for _, target := range []PurchaseTarget{
		{Bytes: 50 * 1024 * 1024 * 1024, PriceMinor: 600, Currency: "CNY", Period: "month"},
		{Bytes: 50 * 1024 * 1024 * 1024, PriceMinor: 99, Currency: "USD", Period: "month"},
	} {
		country, price, _ := supported50GBTarget(target)
		if q.Get("cc") == country && q.Get("price") == price {
			return true
		}
	}
	return false
}

// ValidatePurchaseTarget performs the no-side-effect part of a purchase. It
// refuses to continue unless Apple's plan response contains the exact target.
func ValidatePurchaseTarget(info *StoragePlanInfo, target PurchaseTarget) error {
	if info == nil {
		return errors.New("icloud: storage plan response is missing")
	}
	for _, plan := range info.Plans {
		if plan.Bytes != target.Bytes || plan.Price != target.PriceMinor || plan.Currency != target.Currency {
			continue
		}
		if target.Period != "" && plan.Period != target.Period {
			continue
		}
		if !plan.Available {
			return errors.New("icloud: requested storage plan is not available")
		}
		return nil
	}
	return fmt.Errorf("icloud: requested storage plan was not returned by Apple")
}

// SubmitStoragePurchase contacts Apple's real presentOffers/buyProduct route
// after the exact offer has been validated, then submits the returned
// volumeAuthenticate form. It never reports a handoff as a completed
// subscription.
func SubmitStoragePurchase(ctx context.Context, info *StoragePlanInfo, appleID, password, dsid, adsid, token string, headers map[string]string, target PurchaseTarget) (*PurchaseResult, error) {
	return SubmitStoragePurchaseWithStorageToken(ctx, info, appleID, password, dsid, adsid, token, "", headers, target)
}

// SubmitStoragePurchaseWithStorageToken submits the verified storage offer
// with the GSA iCloud+ commerce service token when the login supplied one.
func SubmitStoragePurchaseWithStorageToken(ctx context.Context, info *StoragePlanInfo, appleID, password, dsid, adsid, token, storageBuyToken string, headers map[string]string, target PurchaseTarget) (*PurchaseResult, error) {
	return submitStoragePurchase(ctx, info, appleID, password, dsid, adsid, token, storageBuyToken, headers, target, nil)
}

func (s *StoreCommerceSession) SubmitStoragePurchase(ctx context.Context, info *StoragePlanInfo, appleID, password, dsid, adsid, token, storageBuyToken string, headers map[string]string, target PurchaseTarget) (*PurchaseResult, error) {
	return submitStoragePurchase(ctx, info, appleID, password, dsid, adsid, token, storageBuyToken, headers, target, s)
}

// SubmitConfirmedStoragePurchase consumes only Apple's exact CN 50GB monthly
// auto-renew confirmation after the owner has explicitly authorized purchase.
// Unknown dialogs and ambiguous results are not resubmitted.
func (s *StoreCommerceSession) SubmitConfirmedStoragePurchase(ctx context.Context, info *StoragePlanInfo, appleID, password, dsid, adsid, token, storageBuyToken string, headers map[string]string, target PurchaseTarget) (*PurchaseResult, error) {
	if !s.MatchesAccount(dsid) {
		return nil, &StorageError{Stage: "purchase-store-account-binding"}
	}
	result, err := s.SubmitStoragePurchase(ctx, info, appleID, password, dsid, adsid, token, storageBuyToken, headers, target)
	if err != nil || result == nil || result.confirmation == nil {
		return result, err
	}
	if err := validateNativeStorageConfirmation(result.confirmation, result.confirmationOriginal, s.identity); err != nil {
		return nil, err
	}
	return submitStoreBuyProduct(ctx, s.client, storeBuyProductURL+"?"+result.confirmation.Encode(), headers, adsid, s.identity)
}

func validateNativeStorageConfirmation(q, original url.Values, session *storeSession) error {
	for key, values := range q {
		if len(values) != 1 || key == "" {
			return &StorageError{Stage: "purchase-confirmation-binding"}
		}
	}
	if !supported50GBQuery(original) || q.Get("hasConfirmAutoRenew") != "true" {
		return &StorageError{Stage: "purchase-confirmation-offer"}
	}
	for _, key := range []string{"cc", "offerName", "storagePlanInBytes", "price", "salableAdamId"} {
		if q.Get(key) != original.Get(key) {
			return &StorageError{Stage: "purchase-confirmation-offer"}
		}
	}
	if session == nil || q.Get("salableAdamId") == "" || q.Get("salableAdamId") != original.Get("salableAdamId") {
		return &StorageError{Stage: "purchase-confirmation-binding"}
	}
	for key, expected := range map[string]string{"guid": session.GUID, "prsId": session.DSID, "dsid": session.DSID, "xToken": session.PasswordToken} {
		if q.Get(key) != "" && q.Get(key) != expected {
			return &StorageError{Stage: "purchase-confirmation-binding"}
		}
	}
	return nil
}

// SubmitStoragePurchaseAnonymous runs the verified offer chain on a fresh
// cookie jar with no native Store login, mirroring the storage WebView: the
// entry navigation carries the AOSKit identity set, the page-driven form
// post carries plain browser headers, and volumeAuthenticate is expected to
// create the commerce session.
func SubmitStoragePurchaseAnonymous(ctx context.Context, info *StoragePlanInfo, appleID, password, dsid, adsid, token, storageBuyToken string, headers map[string]string, target PurchaseTarget) (*PurchaseResult, error) {
	client := appleHTTPClient(ctx, 30*time.Second)
	client.Jar = mustCookieJar()
	anonymous := &StoreCommerceSession{
		client:   client,
		identity: &storeSession{DSID: dsid, Anonymous: true},
	}
	defer anonymous.client.CloseIdleConnections()
	return submitStoragePurchase(ctx, info, appleID, password, dsid, adsid, token, storageBuyToken, headers, target, anonymous)
}

func submitStoragePurchase(ctx context.Context, info *StoragePlanInfo, appleID, password, dsid, adsid, token, storageBuyToken string, headers map[string]string, target PurchaseTarget, commerce *StoreCommerceSession) (*PurchaseResult, error) {
	if err := ValidatePurchaseTarget(info, target); err != nil {
		return nil, err
	}
	if strings.TrimSpace(appleID) == "" || password == "" || strings.TrimSpace(dsid) == "" || strings.TrimSpace(adsid) == "" || token == "" {
		return nil, &StorageError{Stage: "purchase-authentication"}
	}
	anonymous := commerce != nil && commerce.identity != nil && commerce.identity.Anonymous
	if storageBuyToken == "" && !anonymous {
		return nil, &StorageError{Stage: "purchase-store-token"}
	}
	if target.Bytes != 50*1024*1024*1024 || target.PriceMinor != 600 || target.Currency != "CNY" || target.Period != "month" {
		return nil, errors.New("icloud: only the verified mainland China 50GB monthly offer is supported")
	}
	query := url.Values{"appleId": {appleID}, "dsid": {dsid}, "authToken": {token}}
	if commerce == nil {
		var err error
		commerce, err = AuthenticateStore(ctx, appleID, password, "", headers)
		if err != nil {
			return nil, err
		}
	}
	client, session := commerce.client, commerce.identity
	if client == nil || session == nil {
		return nil, &StorageError{Stage: "purchase-store-session"}
	}
	// The official window enters the store with a form POST carrying exactly
	// this account triple (captured 2026-10-07; no query string). The
	// server-provided upgrade URL resolves to the same WebObjects path, so
	// its host and path are reused and its query is dropped.
	endpoint := storePresentOffersURL
	if info.sourceEndpoint != "" {
		if u, err := url.Parse(info.sourceEndpoint); err == nil && u.Host != "" {
			endpoint = u.Scheme + "://" + u.Host + u.Path
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(query.Encode()))
	if err != nil {
		return nil, &StorageError{Stage: "purchase-request"}
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setStoreHeaders(request, headers, adsid, "", dsid, token)
	response, err := client.Do(request)
	if err != nil {
		return nil, &StorageError{Stage: "purchase-transport"}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024+1))
	if err != nil || len(body) > 2*1024*1024 {
		return nil, &StorageError{Stage: "purchase-response", HTTPStatus: response.StatusCode}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, &StorageError{Stage: "purchase", HTTPStatus: response.StatusCode, Hint: storeResponseHint(body, response.Header.Get("Content-Type"))}
	}
	offerURL, err := exactOfferURL(body, target)
	if err != nil {
		return nil, &StorageError{Stage: "purchase-offer", HTTPStatus: response.StatusCode, Hint: offerPageHint(body, endpoint)}
	}
	// A store session with a password token can take the App Store purchase
	// route directly; the iCloud-for-Windows volume store answers the web
	// form with a dead redirect for this storefront.
	if !session.Anonymous && session.PasswordToken != "" {
		result, buyErr := submitStoreBuyProduct(ctx, client, offerURL, headers, adsid, session)
		if buyErr != nil {
			return nil, buyErr
		}
		// An ambiguous native response may already represent an order. Never
		// start another purchase route automatically after that response.
		return result, nil
	}
	return submitStoreForm(ctx, client, offerURL, request.URL.String(), &password, appleID, token, target, headers, adsid, dsid, storageBuyToken, session)
}

// submitStoreBuyProduct replays the storefront offer query against the App
// Store purchase endpoint (MZBuy) with a macOS identity and the live store
// session. Apple answers with a plist describing the failure, a confirmation
// dialog, or completion.
func submitStoreBuyProduct(ctx context.Context, client *http.Client, offerURL string, headers map[string]string, adsid string, session *storeSession) (*PurchaseResult, error) {
	offer, err := url.Parse(offerURL)
	if err != nil || offer.RawQuery == "" {
		return nil, &StorageError{Stage: "purchase-buy"}
	}
	q := offer.Query()
	for _, values := range q {
		if len(values) != 1 {
			return nil, &StorageError{Stage: "purchase-buy-offer"}
		}
	}
	if !supported50GBQuery(q) {
		return nil, &StorageError{Stage: "purchase-buy-offer"}
	}
	// The App Store purchase client posts the buy parameters as a plist to
	// the storefront's pod with the hardware GUID in the query. Key spellings
	// follow the native purchase client.
	guid := session.GUID
	if guid == "" {
		return nil, &StorageError{Stage: "purchase-buy"}
	}
	offerValue := func(key, fallback string) string {
		if values := offer.Query()[key]; len(values) > 0 && values[0] != "" {
			return values[0]
		}
		return fallback
	}
	salable, parseErr := strconv.ParseInt(offerValue("salableAdamId", ""), 10, 64)
	if parseErr != nil {
		return nil, &StorageError{Stage: "purchase-buy-offer"}
	}
	buy := map[string]any{
		"appExtVrsId":               offerValue("appExtVrsId", "0"),
		"hasAskedToFulfillPreorder": "true",
		"buyWithoutAuthorization":   "true",
		"hasDoneAgeCheck":           "true",
		"guid":                      guid,
		"needDiv":                   "0",
		"origPage":                  "Software-" + offerValue("appAdamId", "1581031638"),
		"origPageLocation":          "Buy",
		"price":                     offerValue("price", "0"),
		"pricingParameters":         offerValue("pricingParameters", "STDQ"),
		"productType":               offerValue("productType", "A"),
		"salableAdamId":             salable,
		"offerName":                 q.Get("offerName"),
		"storagePlanInBytes":        q.Get("storagePlanInBytes"),
		"cc":                        q.Get("cc"),
	}
	for _, key := range []string{"hasConfirmAutoRenew", "nextChargeDate"} {
		if q.Get(key) != "" {
			buy[key] = q.Get(key)
		}
	}
	var payload bytes.Buffer
	encoder := plist.NewEncoderForFormat(&payload, plist.XMLFormat)
	if err := encoder.Encode(buy); err != nil {
		return nil, &StorageError{Stage: "purchase-buy"}
	}
	host := "buy.itunes.apple.com"
	if session.Pod != "" && storeControlName.MatchString(session.Pod) {
		host = "p" + session.Pod + "-buy.itunes.apple.com"
	}
	endpoint := "https://" + host + "/WebObjects/MZFinance.woa/wa/buyProduct?guid=" + url.QueryEscape(guid)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload.Bytes()))
	if err != nil {
		return nil, &StorageError{Stage: "purchase-buy"}
	}
	req.Header.Set("Content-Type", "application/x-apple-plist")
	req.Header.Set("User-Agent", storeMacUserAgent)
	session.setHeaders(req)
	req.Header.Set("Accept", "application/x-apple-plist, text/xml, application/xml")
	resp, err := client.Do(req)
	if err != nil {
		return nil, &StorageError{Stage: "purchase-buy-transport"}
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024+1))
	resp.Body.Close()
	if readErr != nil || len(body) > 2*1024*1024 {
		return nil, &StorageError{Stage: "purchase-buy-response", HTTPStatus: resp.StatusCode}
	}
	result := &PurchaseResult{State: "handoff", HTTPStatus: resp.StatusCode}
	var plistResp map[string]any
	if _, err := plist.Unmarshal(body, &plistResp); err != nil || len(plistResp) == 0 {
		hint := storeResponseHint(body, resp.Header.Get("Content-Type"))
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, &StorageError{Stage: "purchase-buy", HTTPStatus: resp.StatusCode,
				Hint: "host=" + host + ";pod=" + session.Pod + ";" + hint + ";" + storeHeaderHint(resp.Header)}
		}
		return result, nil
	}
	shape := jsonShape(plistResp, 0)
	if len(shape) > 400 {
		shape = shape[:400]
	}
	failure, _ := plistResp["failureType"].(string)
	if failure != "" {
		return nil, &StorageError{Stage: "purchase-buy", HTTPStatus: resp.StatusCode, AppleCode: failure, Hint: shape}
	}
	if dialog, ok := plistResp["dialog"].(map[string]any); ok {
		result.State = "confirmation-required"
		result.ExternalClientRequired = true
		id, _ := dialog["dialogId"].(string)
		action, _ := dialog["okButtonAction"].(map[string]any)
		kind, _ := action["kind"].(string)
		params, _ := action["buyParams"].(string)
		if id == "SRVOrderManager.ConfirmBuyingAutoRenewingSubscription" && kind == "Buy" && len(params) <= 65536 {
			if values, err := url.ParseQuery(params); err == nil && len(values) > 0 {
				result.confirmation, result.confirmationOriginal = values, q
			}
		}
		return result, nil
	}
	status, statusPresent := plistResp["status"].(uint64)
	if docType, _ := plistResp["jingleDocType"].(string); docType == "purchaseSuccess" && statusPresent && status == 0 {
		result.State = "completed"
		return result, nil
	}
	result.State = "handoff"
	result.ExternalClientRequired = true
	return result, nil
}

// authenticateStoreSession establishes the MZFinance session cookie used by
// volumeAuthenticate. The iCloud mmeAuthToken and the GSA storage capability
// are separate credentials; presenting only the latter on buyProduct leaves
// Apple with no Store session and produces an empty HTTP 400 response.
func authenticateStoreSession(ctx context.Context, client *http.Client, appleID, password string, headers map[string]string) (*storeSession, error) {
	return authenticateStoreWithSAP(ctx, client, appleID, password, "", headers)
}

func (s *storeSession) setHeaders(req *http.Request) {
	if s == nil {
		return
	}
	setStoreIdentityHeaders(req, s.DSID, s.StoreFront)
	req.Header.Set("iCloud-DSID", s.DSID)
	req.Header.Set("X-Token", s.PasswordToken)
}

func mustCookieJar() http.CookieJar {
	jar, _ := cookiejar.New(nil)
	return jar
}

type storeField struct {
	name, value, typ  string
	disabled, checked bool
	owner             string
}
type storeForm struct {
	action, method string
	fields         []storeField
}

func parseStoreForms(body []byte) []storeForm {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil
	}
	var forms []storeForm
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			f := storeForm{method: "GET"}
			for _, a := range n.Attr {
				if a.Key == "action" {
					f.action = a.Val
				}
				if a.Key == "method" {
					f.method = strings.ToUpper(a.Val)
				}
			}
			var fields func(*html.Node)
			fields = func(x *html.Node) {
				if x.Type == html.ElementNode && (x.Data == "input" || x.Data == "button") {
					var sf storeField
					for _, a := range x.Attr {
						switch a.Key {
						case "name":
							sf.name = a.Val
						case "value":
							sf.value = a.Val
						case "type":
							sf.typ = a.Val
						case "disabled":
							sf.disabled = true
						case "checked":
							sf.checked = true
						case "form":
							sf.owner = a.Val
						}
					}
					if sf.name != "" || sf.value != "" {
						f.fields = append(f.fields, sf)
					}
				}
				for c := x.FirstChild; c != nil; c = c.NextSibling {
					fields(c)
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				fields(c)
			}
			forms = append(forms, f)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return forms
}

// offerPageHint describes the shape of an offer page Apple returned without
// retaining any value: endpoint host, number of embedded buy links and coarse
// markers.
func offerPageHint(body []byte, endpoint string) string {
	low := strings.ToLower(string(body))
	links := 0
	for _, form := range parseStoreForms(body) {
		for _, field := range form.fields {
			if strings.Contains(field.value, "/WebObjects/MZFinance.woa/wa/buyProduct?") {
				links++
			}
		}
	}
	host := ""
	if u, err := url.Parse(endpoint); err == nil {
		host = u.Hostname()
	}
	var markers []string
	for _, marker := range []string{"icloud50gb", "offername", "storageplaninbytes", "sign in", "error", "not_found", "upgrade", "buyproduct", "presentoffers", "dialog", "signin"} {
		if strings.Contains(low, marker) {
			markers = append(markers, marker)
		}
	}
	return fmt.Sprintf("page;host=%s;len=%d;buy-links=%d;markers=%s", host, len(body), links, strings.Join(markers, ","))
}

func exactOfferURL(body []byte, target PurchaseTarget) (string, error) {
	for _, form := range parseStoreForms(body) {
		for _, field := range form.fields {
			if !strings.Contains(field.value, "/WebObjects/MZFinance.woa/wa/buyProduct?") {
				continue
			}
			u, err := url.Parse(field.value)
			if err != nil {
				continue
			}
			q := u.Query()
			storefront := map[string]string{"CNY": "CN"}[target.Currency]
			if storefront == "" {
				storefront = target.Currency
			}
			if q.Get("storagePlanInBytes") != fmt.Sprint(target.Bytes) || q.Get("cc") != storefront || q.Get("price") != fmt.Sprint(target.PriceMinor*10) || q.Get("offerName") != "com.apple.icloud50GB_monthly" {
				continue
			}
			if u.IsAbs() && validStoreCommerceURL(u) {
				return u.String(), nil
			}
			return "https://buy.itunes.apple.com" + u.RequestURI(), nil
		}
	}
	return "", errors.New("icloud: Apple did not return the exact 50GB offer")
}

func submitStoreForm(ctx context.Context, client *http.Client, offerURL, presentURL string, password *string, appleID, token string, target PurchaseTarget, headers map[string]string, adsid, dsid, storageBuyToken string, session *storeSession) (*PurchaseResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, offerURL, nil)
	if err != nil {
		return nil, &StorageError{Stage: "purchase-request"}
	}
	setStoreHeaders(req, headers, adsid, presentURL, dsid, token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, &StorageError{Stage: "purchase-transport"}
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024+1))
	resp.Body.Close()
	if readErr != nil {
		return nil, &StorageError{Stage: "purchase-response", HTTPStatus: resp.StatusCode}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &StorageError{Stage: "purchase", HTTPStatus: resp.StatusCode, Hint: storeResponseHint(body, resp.Header.Get("Content-Type"))}
	}
	forms := parseStoreForms(body)
	for _, form := range forms {
		if !strings.Contains(form.action, "volumeAuthenticate") {
			continue
		}
		// A browser submits only successful controls. In particular, it sends
		// the clicked purchase button, not every submit/cancel button in the
		// form. Sending both is rejected by MZFinance with a bare HTTP 400.
		vals := successfulStoreFormValues(form)
		if password == nil {
			return &PurchaseResult{State: "authentication-required", HTTPStatus: resp.StatusCode}, nil
		}
		if err := validateStoreFormBindings(vals, appleID, dsid, token, target, session); err != nil {
			return nil, err
		}
		// A live store session already satisfies this sign-in page. Apple's
		// own authenticated-buyer navigation is the form's okURL (it carries
		// hasBeenAuthedForBuy=true); posting the password again would only
		// bounce through the volume store's sign-in redirect.
		if !session.Anonymous && session.PasswordToken != "" {
			if okURL := vals.Get("okURL"); okURL != "" {
				referer := offerURL
				if resp.Request != nil && resp.Request.URL != nil {
					referer = resp.Request.URL.String()
				}
				result, err := followStorePurchase(ctx, client, okURL, referer, headers, adsid, storageBuyToken, session)
				if err != nil {
					return nil, err
				}
				if result != nil && result.State != "authentication-required" {
					return result, nil
				}
				// Apple still wants the volume store's own sign-in form;
				// fall through and submit it with the account password.
			}
		}
		postURL, err := storeFormURL(resp.Request.URL, body, form.action)
		if err != nil {
			return nil, err
		}
		encodedForm := encodeStoreForm(form, *password)
		post, _ := http.NewRequestWithContext(ctx, http.MethodPost, postURL.String(), strings.NewReader(encodedForm))
		// HTML navigation carries the returned tokens as form controls and
		// cookies. The Windows StorageUI sends this as a WebView form post.
		referer := offerURL
		if resp.Request != nil && resp.Request.URL != nil {
			referer = resp.Request.URL.String()
		}
		setStoreFormHeaders(post, referer)
		// The official window submits this page form as a plain browser
		// navigation: cookies and browser headers only. No store session
		// headers (X-Token, X-Dsid, X-Apple-Store-Front), no ADSID and no
		// AOSKit identity headers appear on the captured request.
		post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		pResp, pErr := client.Do(post)
		if pErr != nil {
			return nil, &StorageError{Stage: "purchase-authentication"}
		}
		pBody, _ := io.ReadAll(io.LimitReader(pResp.Body, 2*1024*1024+1))
		pHint := storeResponseHint(pBody, pResp.Header.Get("Content-Type"))
		if pResp.StatusCode == http.StatusBadRequest && len(pBody) == 0 {
			pHint = emptyPurchaseResponseHint(post, pResp)
		}
		pResp.Body.Close()
		if pResp.StatusCode < 200 || pResp.StatusCode >= 300 {
			if pResp.StatusCode >= 300 && pResp.StatusCode < 400 {
				location := strings.TrimSpace(pResp.Header.Get("Location"))
				ref, redirectErr := url.Parse(location)
				if redirectErr != nil || location == "" {
					return nil, &StorageError{Stage: "purchase-authentication", HTTPStatus: pResp.StatusCode, Hint: "invalid-redirect"}
				}
				endpoint := postURL.ResolveReference(ref)
				if !validStoreCommerceURL(endpoint) {
					return nil, &StorageError{Stage: "purchase-authentication", HTTPStatus: pResp.StatusCode, Hint: "redirect-host-" + safeRedirectTarget(endpoint)}
				}
				// Follow Apple's actual navigation using the same cookie jar.
				// A root-domain redirect alone does not prove native handoff.
				return followStorePurchase(ctx, client, endpoint.String(), postURL.String(), headers, adsid, storageBuyToken, session)
			}
			return nil, &StorageError{Stage: "purchase-authentication", HTTPStatus: pResp.StatusCode, Hint: pHint}
		}
		low := strings.ToLower(string(pBody))
		if strings.Contains(low, "invalid password") || strings.Contains(low, "incorrect password") {
			return nil, &StorageError{Stage: "purchase-authentication", HTTPStatus: pResp.StatusCode}
		}
		if storePurchaseComplete(pBody) {
			return &PurchaseResult{State: "completed", HTTPStatus: pResp.StatusCode}, nil
		}
		for _, next := range parseStoreForms(pBody) {
			if strings.Contains(next.action, "buyProduct") {
				return &PurchaseResult{State: "confirmation-required", HTTPStatus: pResp.StatusCode, ExternalClientRequired: true}, nil
			}
		}
		return &PurchaseResult{State: "handoff", HTTPStatus: pResp.StatusCode, ExternalClientRequired: true}, nil
	}
	result := &PurchaseResult{State: "handoff", HTTPStatus: resp.StatusCode, ExternalClientRequired: true}
	if match := regexp.MustCompile(`(?i)openItunes\('([^']+)`).FindSubmatch(body); len(match) == 2 {
		if u, e := url.Parse(strings.ReplaceAll(string(match[1]), "&amp;", "&")); e == nil && u.Hostname() == "buy.itunes.apple.com" {
			result.HandoffPath = u.EscapedPath()
		}
	}
	if storePurchaseComplete(body) {
		result.State = "completed"
		result.ExternalClientRequired = false
	}
	return result, nil
}

// emptyPurchaseResponseHint describes only request/response shape. Apple
// intentionally returns a blank 400 for rejected commerce sessions; cookie
// names and header values must never leave this process.
func emptyPurchaseResponseHint(req *http.Request, resp *http.Response) string {
	cookies := 0
	if req != nil {
		cookies = len(req.Cookies())
	}
	location := resp != nil && strings.TrimSpace(resp.Header.Get("Location")) != ""
	storefront := req != nil && req.Header.Get("X-Apple-Store-Front") != ""
	credential := req != nil && req.Header.Get("Authorization") != ""
	var setNames []string
	if resp != nil {
		for _, value := range resp.Header.Values("Set-Cookie") {
			name, _, _ := strings.Cut(value, "=")
			name = strings.TrimSpace(name)
			if storeControlName.MatchString(name) {
				setNames = append(setNames, cookieIDPattern.ReplaceAllString(name, "[id]"))
			}
		}
		sort.Strings(setNames)
	}
	return fmt.Sprintf("empty-response;cookies=%d;storefront=%t;credential=%t;set-cookie=%s;location=%t",
		cookies, storefront, credential, strings.Join(setNames, ","), location)
}

func safeRedirectTarget(target *url.URL) string {
	if target == nil {
		return "invalid"
	}
	host := strings.ToLower(target.Hostname())
	if host == "" {
		host = "missing-host"
	}
	path := target.EscapedPath()
	if path == "" {
		path = "/"
	}
	keys := make([]string, 0, len(target.Query()))
	for key := range target.Query() {
		if storeControlName.MatchString(key) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		path += "?keys=" + strings.Join(keys, ",")
	}
	return host + path
}

// The native SAP login supplies the same Store token used by Apple's okURL.
// Continue only the literal URL returned by Apple after checking the exact
// offer and all account bindings. No authentication flags are synthesized.
func validateStoreContinuation(raw string, form url.Values, session *storeSession) error {
	u, err := url.Parse(raw)
	if err != nil || !validStoreCommerceURL(u) || u.Path != "/WebObjects/MZFinance.woa/wa/buyProduct" || session == nil {
		return &StorageError{Stage: "purchase-continuation", Hint: "url"}
	}
	q := u.Query()
	for key := range q {
		if len(q[key]) != 1 {
			return &StorageError{Stage: "purchase-continuation", Hint: "duplicate-query"}
		}
	}
	if q.Get("offerName") != "com.apple.icloud50GB_monthly" || q.Get("storagePlanInBytes") != "53687091200" || q.Get("price") != "6000" || q.Get("cc") != "CN" {
		return &StorageError{Stage: "purchase-continuation-offer", Hint: "offer-mismatch"}
	}
	// The commerce page's guid is issued by MZFinance and may be the
	// account's prsId. It is not the MAC-derived GUID used for SAP login.
	if (q.Get("xToken") != "" && q.Get("xToken") != session.PasswordToken) || (q.Get("xToken") == "" && form.Get("xToken") != "") || q.Get("prsId") != session.DSID || q.Get("guid") == "" || q.Get("guid") != form.Get("guid") || q.Get("appleId") == "" || q.Get("appleId") != form.Get("appleId") || q.Get("authToken") == "" || q.Get("authToken") != form.Get("authToken") {
		return &StorageError{Stage: "purchase-continuation-binding", Hint: "account-token-binding"}
	}
	return nil
}

// validateStoreFormBindings checks Apple's returned form before any password
// or purchase control is submitted. The form's own guid is compared with its
// continuation URL, never with the separate SAP hardware identity.
func validateStoreFormBindings(form url.Values, appleID, dsid, token string, target PurchaseTarget, session *storeSession) error {
	if session == nil || dsid == "" || session.DSID != dsid || token == "" {
		return &StorageError{Stage: "purchase-form-binding", Hint: "session"}
	}
	// Without a native Store session there is no password token to bind; the
	// page must then carry no store token of its own either.
	if session.PasswordToken == "" && !(session.Anonymous && form.Get("xToken") == "") {
		return &StorageError{Stage: "purchase-form-binding", Hint: "session"}
	}
	ids := form["appleId"]
	if len(ids) == 0 || appleID == "" {
		return &StorageError{Stage: "purchase-form-binding", Hint: "apple-id-missing"}
	}
	for _, id := range ids {
		if !strings.EqualFold(id, appleID) {
			return &StorageError{Stage: "purchase-form-binding", Hint: "apple-id-mismatch"}
		}
	}
	if form.Get("prsId") != dsid {
		return &StorageError{Stage: "purchase-form-binding", Hint: "store-account-mismatch"}
	}
	if form.Get("xToken") != "" && form.Get("xToken") != session.PasswordToken {
		return &StorageError{Stage: "purchase-form-binding", Hint: "store-token-mismatch"}
	}
	if form.Get("authToken") != token {
		return &StorageError{Stage: "purchase-form-binding", Hint: "icloud-token-mismatch"}
	}
	if form.Get("guid") == "" {
		return &StorageError{Stage: "purchase-form-binding", Hint: "guid-missing"}
	}
	if target.Bytes != 50*1024*1024*1024 || target.PriceMinor != 600 || target.Currency != "CNY" || target.Period != "month" || form.Get("offerName") != "com.apple.icloud50GB_monthly" || form.Get("storagePlanInBytes") != "53687091200" || form.Get("price") != "6000" || form.Get("cc") != "CN" {
		return &StorageError{Stage: "purchase-form-offer", Hint: "offer-mismatch"}
	}
	if err := validateStoreContinuation(form.Get("okURL"), form, session); err != nil {
		return err
	}
	return nil
}

func validStoreCommerceURL(u *url.URL) bool {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "volume.itunes.apple.com" {
		return u.Path == "/" || strings.HasPrefix(u.Path, "/WebObjects/MZFinance.woa/wa/")
	}
	return (host == "buy.itunes.apple.com" || strings.HasSuffix(host, "-buy.itunes.apple.com")) && strings.HasPrefix(u.Path, "/WebObjects/MZFinance.woa/wa/")
}

func followStorePurchase(ctx context.Context, client *http.Client, endpoint, referer string, headers map[string]string, adsid, storageBuyToken string, session *storeSession) (*PurchaseResult, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || !validStoreCommerceURL(parsed) {
		return nil, &StorageError{Stage: "purchase-continuation"}
	}
	// A sanitized hop trace keeps Apple's navigation shape diagnosable without
	// ever retaining query values.
	var trace []string
	for redirects := 0; ; redirects++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, &StorageError{Stage: "purchase-continuation"}
		}
		setStoreHeaders(req, headers, adsid, referer, "", "")
		req.Header.Set("Sec-Fetch-User", "?1")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		if strings.EqualFold(req.URL.Hostname(), "volume.itunes.apple.com") {
			setStoreIdentityHeaders(req, "", session.StoreFront)
		} else {
			session.setHeaders(req)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, &StorageError{Stage: "purchase-continuation-transport"}
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxStoreBagBytes+1))
		resp.Body.Close()
		if readErr != nil || len(body) > maxStoreBagBytes {
			return nil, &StorageError{Stage: "purchase-continuation-response", HTTPStatus: resp.StatusCode}
		}
		trace = append(trace, fmt.Sprintf("%d/%s", resp.StatusCode, safeRedirectTarget(req.URL)))
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			base, _ := url.Parse(endpoint)
			ref, err := url.Parse(resp.Header.Get("Location"))
			if err != nil || ref.String() == "" || redirects >= 4 || !validStoreCommerceURL(base.ResolveReference(ref)) {
				return nil, &StorageError{Stage: "purchase-continuation-redirect", HTTPStatus: resp.StatusCode, Hint: strings.Join(trace, ">")}
			}
			referer, endpoint = endpoint, base.ResolveReference(ref).String()
			continue
		}
		if resp.StatusCode != 200 {
			hint := storeResponseHint(body, resp.Header.Get("Content-Type"))
			if resp.StatusCode == http.StatusNotFound {
				hint += ";target-" + safeRedirectTarget(resp.Request.URL)
			}
			var jarNames []string
			if client != nil && client.Jar != nil && resp.Request != nil {
				for _, cookie := range client.Jar.Cookies(resp.Request.URL) {
					if storeControlName.MatchString(cookie.Name) {
						jarNames = append(jarNames, cookieIDPattern.ReplaceAllString(cookie.Name, "[id]"))
					}
				}
				sort.Strings(jarNames)
			}
			return nil, &StorageError{Stage: "purchase-subscription", HTTPStatus: resp.StatusCode,
				Hint: hint + ";chain-" + strings.Join(trace, ">") + ";jar=" + strings.Join(jarNames, ",")}
		}
		if storePurchaseComplete(body) {
			return &PurchaseResult{State: "completed", HTTPStatus: resp.StatusCode}, nil
		}
		for _, form := range parseStoreForms(body) {
			if strings.Contains(form.action, "volumeAuthenticate") {
				return &PurchaseResult{State: "authentication-required", HTTPStatus: resp.StatusCode}, nil
			}
		}
		return &PurchaseResult{State: "confirmation-required", HTTPStatus: resp.StatusCode}, nil
	}
}

// Success is a document state, never a mention in a script or stylesheet.
func storePurchaseComplete(body []byte) bool {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return false
	}
	var walk func(*html.Node) bool
	walk = func(n *html.Node) bool {
		if n.Type == html.ElementNode && n.Data == "body" {
			for _, attr := range n.Attr {
				if attr.Key == "class" {
					for _, class := range strings.Fields(attr.Val) {
						if class == "buy-upgrade-success" {
							return true
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if walk(c) {
				return true
			}
		}
		return false
	}
	return walk(doc)
}

func storeDocumentBase(body []byte) string {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return ""
	}
	var find func(*html.Node) string
	find = func(n *html.Node) string {
		if n.Type == html.ElementNode && n.Data == "base" {
			for _, attr := range n.Attr {
				if attr.Key == "href" {
					return attr.Val
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if found := find(c); found != "" {
				return found
			}
		}
		return ""
	}
	return find(doc)
}

func storeFormURL(documentURL *url.URL, body []byte, action string) (*url.URL, error) {
	if documentURL == nil {
		return nil, &StorageError{Stage: "purchase-endpoint"}
	}
	baseURL := documentURL
	if base := storeDocumentBase(body); base != "" {
		ref, err := url.Parse(base)
		if err != nil {
			return nil, &StorageError{Stage: "purchase-endpoint"}
		}
		baseURL = documentURL.ResolveReference(ref)
	}
	ref, err := url.Parse(action)
	if err != nil {
		return nil, &StorageError{Stage: "purchase-endpoint"}
	}
	resolved := baseURL.ResolveReference(ref)
	host := strings.ToLower(resolved.Hostname())
	if resolved.Scheme != "https" || resolved.User != nil || resolved.Fragment != "" || (resolved.Port() != "" && resolved.Port() != "443") || (host != "buy.itunes.apple.com" && !strings.HasSuffix(host, "-buy.itunes.apple.com")) || resolved.Path != "/WebObjects/MZFinance.woa/wa/volumeAuthenticate" {
		return nil, &StorageError{Stage: "purchase-endpoint"}
	}
	return resolved, nil
}

// storeResponseHint classifies an Apple Store response without retaining its
// body. It is intentionally coarse: Store pages may contain credentials,
// cookies, or payment data and must never be copied into logs or API output.
func storeResponseHint(body []byte, contentType string) string {
	low := strings.ToLower(string(body))
	if len(strings.TrimSpace(low)) == 0 {
		return "empty-response"
	}
	for _, item := range []struct{ marker, hint string }{
		{"badlogin", "bad-login"},
		{"invalid password", "invalid-password"},
		{"incorrect password", "invalid-password"},
		{"terms", "terms-required"},
		{"payment", "payment-confirmation"},
		{"billing", "billing-confirmation"},
		{"sign in", "sign-in-required"},
		{"authorization", "authorization-required"},
		{"session", "session-rejected"},
	} {
		if strings.Contains(low, item.marker) {
			return item.hint
		}
	}
	if strings.Contains(strings.ToLower(contentType), "html") || strings.Contains(low, "<html") {
		return "html-error"
	}
	if strings.Contains(low, "<form") {
		return "confirmation-form"
	}
	return "unclassified-response"
}

// successfulStoreFormValues mirrors the browser's successful-controls rules
// for the small Apple commerce form. Hidden controls and ordinary text
// controls are always submitted. Only one submit control is selected, and
// destructive-looking cancel/back controls are ignored.
func successfulStoreFormValues(form storeForm) url.Values {
	values := url.Values{}
	for _, field := range successfulStoreFields(form) {
		if field.name != "password" {
			values.Add(field.name, field.value)
		}
	}
	return values
}

// HTML form submission keeps controls in document order, including repeated
// names. url.Values.Encode sorts names and does not reproduce that body.
func encodeStoreForm(form storeForm, password string) string {
	var body strings.Builder
	for _, field := range successfulStoreFields(form) {
		value := field.value
		if field.name == "password" {
			value = password
		}
		if body.Len() != 0 {
			body.WriteByte('&')
		}
		body.WriteString(url.QueryEscape(field.name))
		body.WriteByte('=')
		body.WriteString(url.QueryEscape(value))
	}
	return body.String()
}

func successfulStoreFields(form storeForm) []storeField {
	var fields []storeField
	clicked := false
	for _, field := range form.fields {
		if field.name == "" || field.disabled {
			continue
		}
		typ := strings.ToLower(field.typ)
		if typ == "button" || typ == "reset" || typ == "file" || (typ == "checkbox" || typ == "radio") && !field.checked {
			continue
		}
		if typ == "submit" {
			if clicked || isCancelStoreControl(field) {
				continue
			}
			clicked = true
		}
		fields = append(fields, field)
	}
	return fields
}

func isCancelStoreControl(field storeField) bool {
	text := strings.ToLower(strings.TrimSpace(field.name + " " + field.value))
	for _, word := range []string{"cancel", "back", "close", "dismiss"} {
		if strings.Contains(text, word) {
			return true
		}
	}
	return false
}

func setStoreIdentityHeaders(req *http.Request, dsid, storeFront string) {
	if dsid != "" {
		req.Header.Set("X-Dsid", dsid)
	}
	if storeFront != "" {
		req.Header.Set("X-Apple-Store-Front", storeFront)
	}
}

// setStorageBuyToken binds the request to the GSA commerce capability. The
// token is never returned to callers or logged; Apple expects the ADSID and
// service token together as a base64 encoded X-Apple-GS-Token value.
func setStorageBuyToken(req *http.Request, adsid, token string) {
	if strings.TrimSpace(adsid) == "" || token == "" {
		return
	}
	req.Header.Set("X-Apple-GS-Token", base64.StdEncoding.EncodeToString([]byte(adsid+":"+token)))
}

func setStoreHeaders(req *http.Request, headers map[string]string, adsid, referer, dsid, token string) {
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("X-Apple-ADSID", adsid)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("User-Agent", officialClientUA)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	// Only the account-bound entry navigation carries the identity set.
	if token != "" {
		setOfficialClientHeaders(req, dsid, token)
	}
	if referer != "" {
		req.Header.Set("Referer", referer)
		setStoreOrigin(req, referer)
	}
}

func setStoreFormHeaders(req *http.Request, referer string) {
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("User-Agent", storeWebViewUA)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Referer", referer)
	setStoreOrigin(req, referer)
}

func setStoreOrigin(req *http.Request, referer string) {
	if u, err := url.Parse(referer); err == nil && u.Scheme == "https" && u.Hostname() != "" {
		req.Header.Set("Origin", u.Scheme+"://"+u.Host)
	}
}

// DirectStorageOfferURL builds the buy parameters for the verified mainland
// China 50 GB monthly iCloud+ offer. The App Store purchase client posts
// these as a plist; only the native store session is required.
func DirectStorageOfferURL(guid string) string {
	u, _ := DirectStorageOfferURLForTarget(guid, PurchaseTarget{Bytes: 50 * 1024 * 1024 * 1024, PriceMinor: 600, Currency: "CNY", Period: "month"})
	return u
}

// DirectStorageOfferURLForTarget builds native buy parameters for one exact,
// supported 50 GB offer. Arbitrary currencies and prices are rejected.
func DirectStorageOfferURLForTarget(guid string, target PurchaseTarget) (string, error) {
	country, price, ok := supported50GBTarget(target)
	if !ok || guid == "" {
		return "", &StorageError{Stage: "purchase-skill-offer"}
	}
	q := url.Values{
		"appExtVrsId":        {"843583569"},
		"appAdamId":          {"1581031638"},
		"price":              {price},
		"pricingParameters":  {"STDQ"},
		"productType":        {"A"},
		"salableAdamId":      {"6449562876"},
		"offerName":          {"com.apple.icloud50GB_monthly"},
		"storagePlanInBytes": {"53687091200"},
		"cc":                 {country},
		"guid":               {guid},
	}
	return storeBuyProductURL + "?" + q.Encode(), nil
}

// SubmitStorageBuyDirect posts the App Store purchase plist for the 50 GB
// offer using only the native store session. It is the path that works when
// Apple refuses the iCloud delegate for an account.
func SubmitStorageBuyDirect(ctx context.Context, adsid string, headers map[string]string, session *StoreCommerceSession) (*PurchaseResult, error) {
	if session == nil || session.client == nil || session.identity == nil || session.identity.PasswordToken == "" {
		return nil, &StorageError{Stage: "purchase-buy-session"}
	}
	return submitStoreBuyProduct(ctx, session.client, DirectStorageOfferURL(session.identity.GUID), headers, adsid, session.identity)
}
