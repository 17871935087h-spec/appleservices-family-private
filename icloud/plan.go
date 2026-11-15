package icloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"howett.net/plist"
)

// FetchStorefrontPlanInfo reads the same authenticated iTunes Store offers
// page used by the Windows storage WebView. It is a read-only fallback for
// delegate sessions that omit com.apple.Dataclass.Quota storagePlanURL.
func FetchStorefrontPlanInfo(ctx context.Context, appleID, dsid, adsid, token string, headers map[string]string) (*StoragePlanInfo, error) {
	return FetchStorefrontPlanInfoWithStorageToken(ctx, appleID, dsid, adsid, token, "", headers)
}

// FetchStorefrontPlanInfoWithStorageToken is the authenticated Storefront
// lookup variant used by the purchase flow. The service token is optional for
// older read-only callers, but is supplied after a GSA login when available.
func FetchStorefrontPlanInfoWithStorageToken(ctx context.Context, appleID, dsid, adsid, token, storageBuyToken string, headers map[string]string) (*StoragePlanInfo, error) {
	if strings.TrimSpace(appleID) == "" || strings.TrimSpace(dsid) == "" || strings.TrimSpace(adsid) == "" || token == "" {
		return nil, &StorageError{Stage: "authentication"}
	}
	query := url.Values{"appleId": {appleID}, "dsid": {dsid}, "authToken": {token}}
	return fetchStorefrontPlanAt(ctx, storePresentOffersURL+"?"+query.Encode(), appleID, dsid, adsid, token, storageBuyToken, headers)
}

// FetchQuotaUpdatePlanInfo follows the quotaUpdateURL supplied by the
// authenticated Windows account settings. This is the native upgrade entry;
// it may redirect or render the same Store offer controls.
func FetchQuotaUpdatePlanInfo(ctx context.Context, sd map[string]any, appleID, dsid, adsid, token, storageBuyToken string, headers map[string]string) (*StoragePlanInfo, error) {
	if strings.TrimSpace(appleID) == "" || strings.TrimSpace(dsid) == "" || strings.TrimSpace(adsid) == "" || token == "" {
		return nil, &StorageError{Stage: "authentication"}
	}
	endpoint, err := ResolveQuotaUpdateEndpoint(sd, appleID, dsid)
	if err != nil {
		return nil, err
	}
	return fetchStorefrontPlanAt(ctx, endpoint, appleID, dsid, adsid, token, storageBuyToken, headers)
}

func fetchStorefrontPlanAt(ctx context.Context, endpoint, appleID, dsid, adsid, token, storageBuyToken string, headers map[string]string) (*StoragePlanInfo, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, &StorageError{Stage: "plan-request"}
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	request.Header.Set("X-Apple-ADSID", adsid)
	setStorageBuyToken(request, adsid, storageBuyToken)
	request.Header.Set("Accept", "text/html,application/xhtml+xml")
	if request.Header.Get("Accept-Language") == "" {
		request.Header.Set("Accept-Language", "en-US,en;q=0.9")
	}
	if request.Header.Get("X-Mme-Timezone") == "" {
		request.Header.Set("X-Mme-Timezone", time.Now().Location().String())
	}
	request.Header.Set("User-Agent", "iCloud/15.8.118 Windows/10.0 build/26100 maker/Microsoft model/PC hwp/x64 AOSKit/282 iCloudSettings/1.0")
	client := appleHTTPClient(ctx, 30*time.Second)
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return nil, &StorageError{Stage: "plan-transport"}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024+1))
	if err != nil || len(body) > 2*1024*1024 {
		return nil, &StorageError{Stage: "plan-response", HTTPStatus: response.StatusCode}
	}
	if response.StatusCode != http.StatusOK {
		return nil, &StorageError{Stage: "plan", HTTPStatus: response.StatusCode}
	}
	info := &StoragePlanInfo{Region: "CN", Plans: []StoragePlan{}}
	info.sourceEndpoint = endpoint
	for _, form := range parseStoreForms(body) {
		for _, field := range form.fields {
			if !strings.Contains(field.value, "/WebObjects/MZFinance.woa/wa/buyProduct?") {
				continue
			}
			u, parseErr := url.Parse(field.value)
			if parseErr != nil {
				continue
			}
			q := u.Query()
			bytes, bytesErr := strconv.ParseUint(q.Get("storagePlanInBytes"), 10, 64)
			if bytesErr != nil || bytes == 0 {
				continue
			}
			price, priceErr := strconv.ParseInt(q.Get("price"), 10, 64)
			if priceErr != nil || price < 0 {
				continue
			}
			currency := map[string]string{"CN": "CNY", "US": "USD", "HK": "HKD"}[q.Get("cc")]
			if currency == "" {
				currency = q.Get("cc")
			}
			period := "month"
			if !strings.HasSuffix(q.Get("offerName"), "_monthly") {
				period = ""
			}
			available := bytes > 5*1024*1024*1024 && q.Get("offerName") != ""
			plan := StoragePlan{ID: q.Get("offerName"), Bytes: bytes, Price: price / 10, Currency: currency, Period: period, Available: available}
			if info.CurrentBytes == 0 && !available {
				info.CurrentBytes = bytes
			}
			duplicate := false
			for i := range info.Plans {
				if info.Plans[i].Bytes == plan.Bytes && info.Plans[i].Currency == plan.Currency {
					duplicate = true
					break
				}
			}
			if !duplicate {
				info.Plans = append(info.Plans, plan)
			}
		}
	}
	if len(info.Plans) == 0 {
		return nil, &StorageError{Stage: "plan-decode", HTTPStatus: response.StatusCode,
			Hint: offerPageHint(body, endpoint) + ";ctype=" + response.Header.Get("Content-Type")}
	}
	return info, nil
}

// StoragePlan is the public, non-sensitive portion of a plan returned by
// Apple's storage service. Authentication material and purchase URLs are
// deliberately not exposed.
type StoragePlan struct {
	ID        string `json:"id,omitempty"`
	Bytes     uint64 `json:"bytes"`
	Price     int64  `json:"price_minor"`
	Currency  string `json:"currency,omitempty"`
	Period    string `json:"period,omitempty"`
	Available bool   `json:"available"`
}

// StoragePlanInfo describes the read-only offer response. It does not mean a
// subscription was purchased.
type StoragePlanInfo struct {
	CurrentBytes   uint64        `json:"current_bytes"`
	Region         string        `json:"region,omitempty"`
	Plans          []StoragePlan `json:"plans"`
	sourceEndpoint string
}

// FetchStoragePlanInfo performs only Apple's authenticated plan lookup. It
// never sends a purchase or payment request. Apple has returned either plist
// or JSON for this endpoint, so both are accepted.
func FetchStoragePlanInfo(ctx context.Context, sd map[string]any, appleID, dsid, adsid, token string, headers map[string]string) (*StoragePlanInfo, error) {
	if dsid == "" || adsid == "" || token == "" {
		return nil, &StorageError{Stage: "authentication"}
	}
	endpoint, err := ResolveStorageEndpoint(sd, "storagePlanURL", appleID, dsid, token)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, &StorageError{Stage: "plan-request"}
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(dsid+":"+token)))
	request.Header.Set("X-Apple-ADSID", adsid)
	request.Header.Set("X-MMe-Language", "en")
	request.Header.Set("Accept", "application/x-plist, application/json")
	request.Header.Set("User-Agent", "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0")
	client := appleHTTPClient(ctx, 30*time.Second)
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return nil, &StorageError{Stage: "plan-transport"}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, &StorageError{Stage: "plan", HTTPStatus: response.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024+1))
	if err != nil || len(body) > 2*1024*1024 {
		return nil, &StorageError{Stage: "plan-response", HTTPStatus: response.StatusCode}
	}
	info, err := parseStoragePlanInfo(body)
	if err != nil {
		return nil, &StorageError{Stage: "plan-decode", HTTPStatus: response.StatusCode}
	}
	return info, nil
}

func parseStoragePlanInfo(data []byte) (*StoragePlanInfo, error) {
	var body map[string]any
	if _, err := plist.Unmarshal(data, &body); err != nil {
		if err = json.Unmarshal(data, &body); err != nil {
			return nil, err
		}
	}
	info := &StoragePlanInfo{Plans: []StoragePlan{}}
	var walk func(map[string]any)
	walk = func(m map[string]any) {
		for key, value := range m {
			switch strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", "")) {
			case "region", "country", "storefront":
				if info.Region == "" {
					if s, ok := value.(string); ok && len(s) <= 32 {
						info.Region = s
					}
				}
			case "currentquota", "currentbytes", "totalquota":
				if n, ok := number(value); ok && n > 0 && info.CurrentBytes == 0 {
					info.CurrentBytes = n
				}
			}
			if child, ok := value.(map[string]any); ok {
				walk(child)
			}
			if list, ok := value.([]any); ok {
				for _, item := range list {
					if child, ok := item.(map[string]any); ok {
						if plan, ok := planFromMap(child); ok {
							info.Plans = append(info.Plans, plan)
						}
						walk(child)
					}
				}
			}
		}
	}
	walk(body)
	if len(info.Plans) == 0 {
		return nil, errors.New("missing storage plans")
	}
	return info, nil
}

func planFromMap(m map[string]any) (StoragePlan, bool) {
	var p StoragePlan
	for key, value := range m {
		normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", ""))
		switch normalized {
		case "id", "sku", "productid", "planid":
			if s, ok := value.(string); ok && len(s) <= 128 {
				p.ID = s
			}
		case "bytes", "capacity", "capacitybytes", "quotabytes", "storagebytes", "storagecapacity":
			if n, ok := number(value); ok && n > p.Bytes {
				p.Bytes = n
			}
		case "price", "amount", "priceinminorunits", "priceminor":
			if n, ok := number(value); ok && n <= uint64(^uint64(0)>>1) {
				p.Price = int64(n)
			}
		case "currency", "currencycode":
			if s, ok := value.(string); ok && len(s) <= 8 {
				p.Currency = s
			}
		case "period", "billingperiod", "billingcycle":
			if s, ok := value.(string); ok && len(s) <= 32 {
				p.Period = s
			}
		case "available", "isavailable", "purchasable":
			if b, ok := value.(bool); ok {
				p.Available = b
			}
		}
	}
	return p, p.Bytes > 0 && (p.ID != "" || p.Price != 0 || p.Currency != "")
}

func number(value any) (uint64, bool) {
	switch v := value.(type) {
	case uint64:
		return v, true
	case int64:
		return uint64(v), v >= 0
	case uint:
		return uint64(v), true
	case int:
		return uint64(v), v >= 0
	case float64:
		return uint64(v), v >= 0 && v < 1<<53 && v == float64(uint64(v))
	case string:
		n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		return n, err == nil
	default:
		return 0, false
	}
}
