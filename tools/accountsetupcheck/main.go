// accountsetupcheck refreshes GSA authentication and reads the account setup UI.
// Terms writes require explicit consent flags; delegate-only diagnostics never
// resubmit terms or purchase a product.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Laky-64/appleservices"
	"github.com/Laky-64/appleservices/anisette"
	"github.com/Laky-64/appleservices/gsa"
	"github.com/Laky-64/appleservices/icloud"
	"github.com/Laky-64/appleservices/internal/accountsetup"
	"github.com/Laky-64/appleservices/internal/egresspool"
	"github.com/Laky-64/appleservices/nativeadi"
	"howett.net/plist"
)

func writePrivateFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("cannot create new private output")
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return fmt.Errorf("cannot write private output")
	}
	return nil
}

func readStorageOffers(ctx context.Context, username, dsid, adsid, token, storageToken string, headers map[string]string) error {
	// GET-only offer lookup. No authentication form or purchase is submitted.
	plans, err := icloud.FetchStorefrontPlanInfoWithStorageToken(ctx, username, dsid, adsid, token, storageToken, headers)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(plans)
	if err != nil {
		return fmt.Errorf("cannot summarize storage offers")
	}
	fmt.Printf("read-only storage offers; purchase-submitted=false; %s\n", encoded)
	return nil
}

func run() error {
	dir := flag.String("dir", "", "account state directory")
	nativeProfile := flag.String("native-profile", "", "explicit isolated native profile for the same bound device; default is account native-adi")
	nativeOnly := flag.Bool("native-only", false, "validate only this bound profile's native ADI; no account login, SMS, terms or delegate")
	devicesOnly := flag.Bool("devices-only", false, "read account devices after authentication; no registration, SMS or account writes")
	dump := flag.String("dump", "", "private output for account setup response")
	checkpoint := flag.String("checkpoint", "", "private output for fresh GSA session; not iCloud acceptance")
	accept := flag.Bool("accept-terms", false, "submit the terms update only after the account owner explicitly agrees")
	expectedTerms := flag.String("expected-terms", "", "approved region:icloud-version:media-version, required for acceptance")
	resume := flag.String("resume", "", "reuse a private bound GSA checkpoint without another password request")
	icloudResume := flag.String("icloud-resume", "", "read quota and optional offers using a bound accepted iCloud checkpoint; no login or delegate exchange")
	freshGSA := flag.Bool("fresh-gsa", false, "ignore stored GSA cookies while keeping this account's device identity")
	codeFile := flag.String("sms-code-file", "", "new private file to receive this live SMS or trusted-device code")
	phoneID := flag.Int("sms-phone-id", 0, "explicit trusted phone diagnostic; zero fetches metadata")
	requestSMSOnly := flag.Bool("request-sms-only", false, "request an SMS for this account and exit before verification")
	smsAlreadySent := flag.Bool("sms-already-sent", false, "submit a previously requested, still-valid SMS without requesting another")
	localTrustedCode := flag.Bool("local-trusted-code", false, "generate and submit a code from this account directory's local device")
	trustedDeviceCode := flag.Bool("trusted-device-code", false, "request a code on existing trusted devices; never request SMS")
	delegateOnly := flag.Bool("delegate-only", false, "fresh authentication and one exchange; skip account UI and terms writes")
	storagePlan := flag.Bool("storage-plan", false, "read storage offers after delegate and quota success; never submit a purchase")
	nacValidation := flag.String("nac-validation", "", "private Mac NAC validation bytes for this profile")
	termsAccepted := flag.Bool("terms-accepted", false, "add the reference cookie after this account's verified terms success")
	icloudCheckpoint := flag.String("icloud-checkpoint", "", "private accepted iCloud session output; separate from live dashboard session")
	flag.Parse()
	if err := egresspool.Apply(*dir); err != nil {
		return err
	}
	if *dir == "" || (*dump == "" && !*nativeOnly && *icloudResume == "") {
		return fmt.Errorf("dir and private dump are required")
	}
	if *devicesOnly && (*nativeOnly || *accept || *delegateOnly || *requestSMSOnly || *localTrustedCode || *trustedDeviceCode || *smsAlreadySent || *codeFile != "") {
		return fmt.Errorf("devices-only cannot perform registration, second-factor requests or account writes")
	}
	for _, path := range []string{*dump, *checkpoint, *icloudCheckpoint} {
		if path != "" {
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				return fmt.Errorf("private output must be a new path")
			}
		}
	}
	if *delegateOnly && *accept {
		return fmt.Errorf("delegate-only cannot accept terms")
	}
	if *storagePlan && !*delegateOnly && *icloudResume == "" {
		return fmt.Errorf("storage-plan requires delegate-only or icloud-resume diagnostics")
	}
	if *icloudResume != "" && (*resume != "" || *nativeOnly || *devicesOnly || *accept || *delegateOnly || *freshGSA || *requestSMSOnly || *smsAlreadySent || *localTrustedCode || *trustedDeviceCode || *phoneID != 0 || *codeFile != "" || *termsAccepted || *nacValidation != "" || *checkpoint != "" || *icloudCheckpoint != "") {
		return fmt.Errorf("icloud-resume cannot log in, exchange delegates or perform account writes")
	}
	if *nacValidation != "" && !*delegateOnly {
		return fmt.Errorf("NAC validation is only supported by delegate-only diagnostics")
	}
	if (*requestSMSOnly && *smsAlreadySent) || (*localTrustedCode && (*requestSMSOnly || *smsAlreadySent)) {
		return fmt.Errorf("SMS and local trusted-code modes are mutually exclusive")
	}
	if *trustedDeviceCode && (*requestSMSOnly || *smsAlreadySent || *localTrustedCode || *phoneID != 0) {
		return fmt.Errorf("trusted-device delivery cannot be combined with SMS or local-code modes")
	}
	username, password := os.Getenv("APPLESERVICES_APPLEID"), os.Getenv("APPLESERVICES_PASSWORD")
	if username == "" || (password == "" && *resume == "" && *icloudResume == "" && !*nativeOnly) {
		return fmt.Errorf("account identifier is required; new login also requires a password through environment")
	}
	var device appleservices.Device
	data, err := os.ReadFile(filepath.Join(*dir, "device.json"))
	if err != nil || json.Unmarshal(data, &device) != nil {
		return fmt.Errorf("device unavailable")
	}
	var saved appleservices.Session
	data, err = os.ReadFile(filepath.Join(*dir, "session.json"))
	if err != nil || json.Unmarshal(data, &saved) != nil || !strings.EqualFold(saved.AppleID, username) {
		return fmt.Errorf("bound session unavailable")
	}
	if *resume != "" {
		var resumed appleservices.Session
		data, err = os.ReadFile(*resume)
		if err != nil || json.Unmarshal(data, &resumed) != nil || !strings.EqualFold(resumed.AppleID, saved.AppleID) || resumed.DSID != saved.DSID {
			return fmt.Errorf("resume checkpoint account binding failed")
		}
		saved = resumed
	}
	profile := filepath.Join(*dir, "native-adi")
	if *nativeProfile != "" {
		profile, err = filepath.Abs(*nativeProfile)
		if err != nil {
			return fmt.Errorf("isolated native profile unavailable")
		}
		fmt.Println("isolated native profile selected; original account state retained")
	}
	data, err = os.ReadFile(filepath.Join(profile, "hw_info.plist"))
	var hardware struct {
		OSConfig struct {
			UDID string `plist:"udid"`
		} `plist:"os_config"`
		Push struct {
			Token []byte `plist:"token"`
		} `plist:"push"`
	}
	if err != nil {
		return fmt.Errorf("hardware unavailable")
	}
	if _, err := plist.Unmarshal(data, &hardware); err != nil || len(hardware.Push.Token) != 32 {
		return fmt.Errorf("APS token unavailable")
	}
	library, _ := filepath.Abs(".cache/openbubbles-store/rust_lib_bluebubbles.dll")
	native, err := nativeadi.NewClient(nativeadi.Config{LibraryPath: library, ProfileDir: profile, Python: "python", Identifier: device.Identifier, Serial: device.SerialNumber, PushToken: hardware.Push.Token})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := native.Start(ctx); err != nil {
		return err
	}
	defer native.Close()
	if *nativeOnly {
		headers, err := native.Headers()
		if err != nil {
			return err
		}
		fmt.Printf("native ADI ready; bound-device=true; MD-bytes=%d; MID-bytes=%d; account authentication untested\n", len(headers["X-Apple-I-MD"]), len(headers["X-Apple-I-MD-M"]))
		return nil
	}
	if *icloudResume != "" {
		var accepted struct {
			Session     appleservices.Session `json:"session"`
			ADSID       string                `json:"adsid"`
			ServiceData map[string]any        `json:"service-data"`
		}
		data, err := os.ReadFile(*icloudResume)
		if err != nil || json.Unmarshal(data, &accepted) != nil || !strings.EqualFold(accepted.Session.AppleID, username) || accepted.ADSID != saved.DSID || accepted.Session.DSID == "" || accepted.Session.Tokens["mmeAuthToken"] == "" {
			return fmt.Errorf("accepted iCloud checkpoint account binding failed")
		}
		headers, err := native.Headers()
		if err != nil {
			return err
		}
		token := accepted.Session.Tokens["mmeAuthToken"]
		quota, err := icloud.FetchStorageInfo(ctx, accepted.ServiceData, username, accepted.Session.DSID, accepted.ADSID, token, headers)
		if err != nil {
			return err
		}
		fmt.Printf("accepted checkpoint quota read; total-bytes=%d; used-bytes=%d; paid-bytes=%d\n", quota.TotalBytes, quota.UsedBytes, quota.PaidBytes)
		if *storagePlan {
			return readStorageOffers(ctx, username, accepted.Session.DSID, accepted.ADSID, token, saved.Tokens["com.apple.gs.icloud.storage.buy"], headers)
		}
		return nil
	}
	var headersProvider gsa.AnisetteProvider = native
	if strings.TrimSpace(os.Getenv("APPLESERVICES_REMOTE_ANISETTE")) == "1" {
		headersProvider = anisette.NewProvider()
		fmt.Println("remote anisette enabled; Apple requests remain direct (no HTTP/SOCKS proxy)")
	}
	cookies := map[string][]gsa.CookieKV{}
	for _, cookie := range saved.Cookies {
		cookies[cookie.URL] = append(cookies[cookie.URL], gsa.CookieKV{Name: cookie.Name, Value: cookie.Value})
	}
	client := gsa.NewClientFromSession(headersProvider, gsa.Session{DSID: saved.DSID, Cookies: cookies, Tokens: saved.Tokens})
	if *freshGSA {
		if *resume != "" {
			return fmt.Errorf("fresh-gsa cannot use a checkpoint")
		}
		client = gsa.NewClient(headersProvider)
	}
	client.EnableNativeDeviceAuthentication()
	if err := client.SetPushToken(hardware.Push.Token); err != nil {
		return err
	}
	var auth *gsa.LoginResult
	if *resume != "" {
		services := map[string]any{}
		for service, token := range saved.Tokens {
			services[service] = map[string]any{"token": token}
		}
		auth = &gsa.LoginResult{SessionPayload: map[string]any{"adsid": saved.DSID, "t": services}}
		if _, err := client.AnisetteHeaders(); err != nil {
			return err
		}
	} else {
		auth, err = client.Login(username, password)
		if err != nil {
			return err
		}
	}
	if auth.NeedsTwoFactor {
		if *devicesOnly {
			return fmt.Errorf("device query requires renewed 2FA; no verification code requested")
		}
		fmt.Printf("Mac GSA password accepted; continuation=%s; full authentication pending\n", auth.TwoFactorMethod)
		adsid, _ := auth.SessionPayload["adsid"].(string)
		idms, _ := auth.SessionPayload["GsIdmsToken"].(string)
		if adsid == "" || idms == "" {
			return fmt.Errorf("2FA challenge has no identity binding")
		}
		if *localTrustedCode {
			code, err := native.Code(ctx)
			if err != nil {
				return fmt.Errorf("local trusted code unavailable")
			}
			if err := client.SubmitTrustedDeviceCode(adsid, idms, code); err != nil {
				return err
			}
			fmt.Println("local trusted-device code accepted")
			if verified := client.VerifiedLoginResult(); verified != nil {
				auth = verified
			} else {
				auth, err = client.Login(username, password)
				if err != nil {
					return err
				}
			}
			if auth.NeedsTwoFactor {
				return fmt.Errorf("still prompted for 2FA after local trusted-device verification")
			}
		} else {
			if *codeFile == "" && !*requestSMSOnly {
				return fmt.Errorf("fresh authentication requires a new 2FA challenge")
			}
			if *codeFile != "" {
				if _, err := os.Stat(*codeFile); !os.IsNotExist(err) {
					return fmt.Errorf("SMS code file must not exist before this challenge")
				}
			}
			if !*smsAlreadySent {
				var requestErr error
				if *trustedDeviceCode {
					requestErr = client.RequestTrustedDeviceCode(adsid, idms)
				} else if *phoneID > 0 {
					requestErr = client.RequestSMSCodeForPhone(adsid, idms, *phoneID)
				} else {
					requestErr = client.RequestSMSCode(adsid, idms)
				}
				if requestErr != nil {
					return requestErr
				}
				if *trustedDeviceCode {
					fmt.Println("trusted-device code request accepted; no SMS requested")
				} else {
					fmt.Println("SMS request accepted")
				}
			}
			if *requestSMSOnly {
				return nil
			}
			if *codeFile == "" {
				return fmt.Errorf("private verification code file path is required")
			}
			fmt.Println("awaiting a code for this live challenge")
			var code string
			for code == "" {
				data, err := os.ReadFile(*codeFile)
				if err == nil {
					code = strings.TrimSpace(string(data))
					break
				}
				if !os.IsNotExist(err) {
					return fmt.Errorf("cannot read private verification code file")
				}
				select {
				case <-ctx.Done():
					return fmt.Errorf("verification challenge wait expired")
				case <-time.After(200 * time.Millisecond):
				}
			}
			if len(code) != 6 || strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				return fmt.Errorf("invalid verification code format")
			}
			if *trustedDeviceCode {
				err = client.SubmitTrustedDeviceCode(adsid, idms, code)
			} else {
				err = client.SubmitSMSCode(adsid, idms, code)
			}
			if err != nil {
				return err
			}
			fmt.Println("verification code accepted")
			if verified := client.VerifiedLoginResult(); verified != nil {
				auth = verified
			} else {
				auth, err = client.Login(username, password)
				if err != nil {
					return err
				}
				if auth.NeedsTwoFactor {
					return fmt.Errorf("still prompted for 2FA after code acceptance")
				}
			}
		}
	}
	if *devicesOnly {
		devices, err := client.AccountDevices(auth.SessionPayload)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(devices)
		if err != nil || writePrivateFile(*dump, encoded) != nil {
			return fmt.Errorf("cannot save private device list")
		}
		matches := 0
		currentMatches := 0
		for _, entry := range devices {
			if entry.CurrentDevice {
				currentMatches++
				trusted := "not-reported"
				if entry.IsTrustedDevice != nil {
					trusted = fmt.Sprintf("%t", *entry.IsTrustedDevice)
				}
				fmt.Printf("Apple marks this request's Mac as current device; trusted=%s\n", trusted)
				if entry.SupportsVerificationCodes != nil {
					fmt.Printf("current Mac supportsVerificationCodes=%t\n", *entry.SupportsVerificationCodes)
				}
				if entry.DeviceDetailURI != "" {
					details, err := client.AccountDeviceDetails(auth.SessionPayload, entry)
					if err != nil {
						return err
					}
					data, err := json.Marshal(details)
					if err != nil || writePrivateFile(*dump+".current-detail.json", data) != nil {
						return fmt.Errorf("cannot save private current-device detail")
					}
					fmt.Println("current Mac device detail read; private output saved")
					if trusted, ok := details["trustedDevice"].(bool); ok {
						fmt.Printf("Apple device detail trustedDevice=%t; local-serial-matches=%t\n", trusted, details["serialNumber"] == device.SerialNumber)
					}
					if push, ok := details["pushDevice"].(bool); ok {
						fmt.Printf("Apple device detail pushDevice=%t\n", push)
					}
				}
			}
			if device.SerialNumber != "" && strings.EqualFold(entry.SerialNumber, device.SerialNumber) {
				matches++
				trusted := "not-reported"
				if entry.IsTrustedDevice != nil {
					trusted = fmt.Sprintf("%t", *entry.IsTrustedDevice)
				}
				fmt.Printf("local Mac matched by serial; current-device=%t; trusted=%s\n", entry.CurrentDevice, trusted)
			}
		}
		fmt.Printf("account devices read; device-count=%d; local-serial-matches=%d; current-device-count=%d; no account writes\n", len(devices), matches, currentMatches)
		return nil
	}
	pet, err := icloud.PETFromSPD(auth.SessionPayload)
	if err != nil {
		return err
	}
	adsid, _ := auth.SessionPayload["adsid"].(string)
	services, _ := auth.SessionPayload["t"].(map[string]any)
	family, _ := services["com.apple.gs.icloud.family.auth"].(map[string]any)
	familyToken, _ := family["token"].(string)
	if adsid == "" || familyToken == "" {
		return fmt.Errorf("fresh GSA has no account setup credentials")
	}
	headers, err := headersProvider.Headers()
	if err != nil {
		return err
	}
	state, err := client.Snapshot(adsid, saved.Tokens)
	if err != nil {
		return err
	}
	if *checkpoint != "" {
		fresh := appleservices.Session{AppleID: username, DSID: adsid, Tokens: map[string]string{}}
		for service, value := range services {
			if fields, ok := value.(map[string]any); ok {
				if token, ok := fields["token"].(string); ok {
					fresh.Tokens[service] = token
				}
			}
		}
		for endpoint, values := range state.Cookies {
			for _, cookie := range values {
				fresh.Cookies = append(fresh.Cookies, appleservices.Cookie{URL: endpoint, Name: cookie.Name, Value: cookie.Value})
			}
		}
		encoded, err := json.Marshal(fresh)
		if err != nil || writePrivateFile(*checkpoint, encoded) != nil {
			return fmt.Errorf("cannot save requested private checkpoint")
		}
	}
	if *delegateOnly {
		if *nacValidation != "" {
			validation, err := os.ReadFile(*nacValidation)
			if err != nil || len(validation) == 0 || len(validation) > 65536 {
				return fmt.Errorf("private NAC validation unavailable or invalid")
			}
			headers["X-Mme-Nas-Qualify"] = base64.StdEncoding.EncodeToString(validation)
			fmt.Printf("Mac NAC attached; validation-bytes=%d\n", len(validation))
		}
		if *termsAccepted {
			headers["Cookie"] = "termsAccepted=true"
		}
		os.Setenv("APPLESERVICES_DELEGATE_DUMP", *dump)
		tokens, err := icloud.FetchDelegateTokens(headers, username, adsid, pet)
		if err != nil {
			return err
		}
		fmt.Printf("delegate accepted; mme-token-present=%t\n", tokens.MMEAuthToken != "")
		quota, err := icloud.FetchStorageInfo(ctx, tokens.ServiceData, username, tokens.DSID, adsid, tokens.MMEAuthToken, headers)
		if err != nil {
			return err
		}
		fmt.Printf("quota accepted; total-bytes=%d; used-bytes=%d; paid-bytes=%d\n", quota.TotalBytes, quota.UsedBytes, quota.PaidBytes)
		if *icloudCheckpoint != "" {
			fresh := appleservices.Session{AppleID: username, DSID: tokens.DSID, Tokens: map[string]string{"mmeAuthToken": tokens.MMEAuthToken, "cloudKitToken": tokens.CloudKitToken}}
			encoded, err := json.Marshal(map[string]any{"session": fresh, "adsid": adsid, "service-data": tokens.ServiceData})
			if err != nil || writePrivateFile(*icloudCheckpoint, encoded) != nil {
				return fmt.Errorf("cannot save accepted private iCloud checkpoint")
			}
		}
		if *storagePlan {
			commerce, _ := services["com.apple.gs.icloud.storage.buy"].(map[string]any)
			storageToken, _ := commerce["token"].(string)
			return readStorageOffers(ctx, username, tokens.DSID, adsid, tokens.MMEAuthToken, storageToken, headers)
		}
		return nil
	}
	body, _ := plist.Marshal(map[string]any{}, plist.XMLFormat)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://setup.icloud.com/setup/update_account_ui", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("cannot build setup request")
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	request.SetBasicAuth(username, pet)
	request.Header.Set("X-Apple-ADSID", adsid)
	request.Header.Set("X-Apple-GS-Token", base64.StdEncoding.EncodeToString([]byte(adsid+":"+familyToken)))
	request.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)")
	info := headers["X-Mme-Client-Info"]
	if index := strings.LastIndex(info, "<"); index > 0 {
		info = info[:index] + "<com.apple.AppleAccount/1.0 (com.apple.systempreferences.AppleIDSettings/1)>"
	}
	request.Header.Set("X-MMe-Client-Info", info)
	for key, value := range map[string]string{
		"X-Apple-I-Current-Application": "com.apple.systempreferences.AppleIDSettings", "X-Apple-I-Current-Application-Version": "1",
		"X-MMe-Country": "US", "X-MMe-Language": "en,en-US", "X-Apple-I-Device-Type": "1",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en", "Content-Type": "text/plist",
		"Origin": "null", "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "cross-site",
	} {
		request.Header.Set(key, value)
	}
	jar, _ := cookiejar.New(nil)
	for endpoint, cookies := range state.Cookies {
		u, err := url.Parse(endpoint)
		if err != nil {
			continue
		}
		for _, cookie := range cookies {
			jar.SetCookies(u, []*http.Cookie{{Name: cookie.Name, Value: cookie.Value}})
		}
	}
	transport := gsa.AppleRootTransport()
	defer transport.(*http.Transport).CloseIdleConnections()
	reader := &http.Client{Transport: transport, Jar: jar, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := reader.Do(request)
	if err != nil {
		return fmt.Errorf("account setup transport failed")
	}
	defer response.Body.Close()
	data, err = io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(data) > 2<<20 {
		return fmt.Errorf("invalid setup response")
	}
	if err := writePrivateFile(*dump, data); err != nil {
		return fmt.Errorf("cannot save private setup response")
	}
	text := string(data)
	markers := []string{}
	for _, marker := range []string{"MOBILEME_TERMS_OF_SERVICE_UPDATE", "ICLOUD_INVALID_DEVICE_TOKEN", "UNAUTHORIZED", "Terms and Conditions", "termsAccepted", "agreeUrl"} {
		if strings.Contains(text, marker) {
			markers = append(markers, marker)
		}
	}
	facts := map[string]any{"gsa-authenticated": true, "HTTP": response.StatusCode, "bytes": len(data), "html": strings.Contains(strings.ToLower(text), "<html"), "form-present": strings.Contains(strings.ToLower(text), "<form"), "markers": markers}
	facts["used-gsa-checkpoint"] = *resume != ""
	encoded, _ := json.Marshal(facts)
	fmt.Println(string(encoded))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("account setup page was refused")
	}
	plan, err := accountsetup.PrepareTerms(data, username, hardware.OSConfig.UDID, hardware.Push.Token, "Asia/Singapore")
	if err != nil {
		return err
	}
	brief, _ := json.Marshal(map[string]any{"terms-plan": true, "region": plan.Country, "icloud-version": plan.ICloudVersion, "media-version": plan.MediaVersion, "endpoint": "setup.icloud.com/setup/web/basic_auth_update_account/{account}/{native-udid}", "consent-required": !*accept})
	fmt.Println(string(brief))
	if !*accept {
		return nil
	}
	if *expectedTerms != plan.Country+":"+plan.ICloudVersion+":"+plan.MediaVersion {
		return fmt.Errorf("terms page differs from the explicitly approved versions; update not submitted")
	}
	update, err := plan.Request(true)
	if err != nil {
		return err
	}
	update = update.WithContext(ctx)
	// The pinned OpenBubbles updateAccountUi intercepts every AJAX request
	// and attaches fresh anisette headers. They are required in addition to
	// the headers set by Apple's page script itself.
	updateHeaders, err := native.Headers()
	if err != nil {
		return err
	}
	for _, key := range []string{"X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO", "X-Mme-Device-Id"} {
		if updateHeaders[key] == "" {
			return fmt.Errorf("missing anisette data for terms update")
		}
	}
	for key, value := range updateHeaders {
		if !strings.EqualFold(key, "User-Agent") {
			update.Header.Set(key, value)
		}
	}
	// This is one consequential request. An ambiguous result is reported;
	// neither transport failures nor server refusals are automatically retried.
	updated, err := reader.Do(update)
	if err != nil {
		return fmt.Errorf("terms update transport failed; outcome unknown, do not repeat automatically")
	}
	defer updated.Body.Close()
	acknowledgement, err := io.ReadAll(io.LimitReader(updated.Body, (2<<20)+1))
	if err != nil || len(acknowledgement) > 2<<20 {
		return fmt.Errorf("terms update response invalid; outcome unknown")
	}
	if err := writePrivateFile(*dump+".update.json", acknowledgement); err != nil {
		return fmt.Errorf("cannot preserve private update response")
	}
	metadata, _ := json.Marshal(map[string]any{"HTTP": updated.StatusCode, "body-bytes": len(acknowledgement), "content-type": updated.Header.Get("Content-Type"), "accepted-terms-header-present": updated.Header.Get("X-Apple-I-Accepted-Terms") != "", "response-cookie-count": len(updated.Cookies())})
	if err := writePrivateFile(*dump+".update-meta.json", metadata); err != nil {
		return fmt.Errorf("cannot preserve update metadata")
	}
	fmt.Println(string(metadata))
	var receipt map[string]any
	if json.Unmarshal(acknowledgement, &receipt) != nil {
		return fmt.Errorf("terms update HTTP %d; no recognized acknowledgement", updated.StatusCode)
	}
	accepted, _ := receipt["success"].(bool)
	fmt.Printf("terms-update HTTP=%d; success=%t\n", updated.StatusCode, accepted)
	if updated.StatusCode != http.StatusOK || !accepted {
		return fmt.Errorf("terms update refused; iCloud acceptance not established")
	}
	headers, err = headersProvider.Headers()
	if err != nil {
		return err
	}
	// RustPush's UpdateAccountFinish::MacOS uses this cookie after agreement.
	// It is only added after an explicit success acknowledgement above.
	headers["Cookie"] = "termsAccepted=true"
	tokens, err := icloud.FetchDelegateTokens(headers, username, adsid, pet)
	if err != nil {
		return err
	}
	fmt.Printf("delegate accepted; mme-token-present=%t\n", tokens.MMEAuthToken != "")
	quota, err := icloud.FetchStorageInfo(ctx, tokens.ServiceData, username, tokens.DSID, adsid, tokens.MMEAuthToken, headers)
	if err != nil {
		return err
	}
	fmt.Printf("quota accepted; total-bytes=%d; used-bytes=%d; paid-bytes=%d\n", quota.TotalBytes, quota.UsedBytes, quota.PaidBytes)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
