package v2gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	safeUnknownMessage      = "操作结果不确定，请勿重试并先人工核验"
	safeAddedMessage        = "家庭成员已加入并完成回读"
	safeRemovedMessage      = "成员已移出并完成回读"
	safeRemoveCacheMessage  = "成员已移出并完成回读；本地缓存未完成"
	safeReadMessage         = "家庭状态已读取"
	safeReadFailureMessage  = "家庭状态未确认"
	safePreflightMessage    = "家庭变更预检未通过"
	safeCodeFailureMessage  = "设备码未取得"
	safeServiceFailure      = "服务暂不可用"
	safeInvalidRequest      = "请求格式无效"
	safeAccountNotFound     = "账号未登记"
	safeAccountAmbiguous    = "账号映射不唯一"
	safeOperationIDConflict = "operation_id 已绑定其他请求"
)

var appTokenPattern = regexp.MustCompile(`(?i)<meta\s+name=["']app-token["']\s+content=["']([a-f0-9]{64})["']\s*/?>`)

type dashboardFamily struct {
	Member                 bool   `json:"member"`
	Eligible               bool   `json:"eligible"`
	EligibilityKnown       bool   `json:"eligibility_known"`
	Members                int    `json:"members"`
	Organizers             int    `json:"organizers"`
	Self                   int    `json:"self"`
	Children               int    `json:"children"`
	Invitations            int    `json:"invitations"`
	Pending                int    `json:"pending"`
	Organizer              bool   `json:"organizer"`
	OrganizerAccount       string `json:"organizer_account,omitempty"`
	OrganizerName          string `json:"organizer_name,omitempty"`
	StorageKnown           bool   `json:"storage_known"`
	StorageParticipating   bool   `json:"storage_participating"`
	StorageAvailable       bool   `json:"storage_available"`
	StorageEnabled         bool   `json:"storage_enabled"`
	StorageBytes           int64  `json:"storage_bytes,omitempty"`
	PurchaseSharingKnown   bool   `json:"purchase_sharing_known"`
	PurchaseSharingEnabled bool   `json:"purchase_sharing_enabled"`
	LocationSharingKnown   bool   `json:"location_sharing_known"`
	LocationSharingEnabled bool   `json:"location_sharing_enabled"`
}

type dashboardResult struct {
	OK                  bool                  `json:"ok"`
	Message             json.RawMessage       `json:"message,omitempty"`
	Code                string                `json:"code,omitempty"`
	CodeKind            string                `json:"code_kind,omitempty"`
	HideAt              json.RawMessage       `json:"hide_at,omitempty"`
	Storage             json.RawMessage       `json:"storage,omitempty"`
	StoragePlan         json.RawMessage       `json:"storage_plan,omitempty"`
	Purchase            json.RawMessage       `json:"purchase,omitempty"`
	Stage               string                `json:"stage,omitempty"`
	HTTPStatus          int                   `json:"http_status,omitempty"`
	AppleCode           json.RawMessage       `json:"apple_code,omitempty"`
	AppleHint           json.RawMessage       `json:"apple_hint,omitempty"`
	StoreAuthentication json.RawMessage       `json:"store_authentication,omitempty"`
	StoreForm           json.RawMessage       `json:"store_form,omitempty"`
	Probes              json.RawMessage       `json:"probes,omitempty"`
	Family              *dashboardFamily      `json:"family,omitempty"`
	FamilyPool          *familyPoolProjection `json:"family_pool,omitempty"`
	HideMyEmail         json.RawMessage       `json:"hide_my_email,omitempty"`
	HMECandidate        string                `json:"hme_candidate,omitempty"`
	Activation          json.RawMessage       `json:"activation,omitempty"`
}

type dashboardAction struct {
	Action string `json:"action"`
	Code   string `json:"code,omitempty"`
}

type Gateway struct {
	config       Config
	dashboardURL url.URL
	journal      *journal
	client       *http.Client
	transport    *http.Transport
	locksMu      sync.Mutex
	locks        map[string]chan struct{}
}

func New(cfg Config) (*Gateway, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = DefaultListenAddr
	}
	if cfg.DashboardURL == "" {
		cfg.DashboardURL = DefaultDashboard
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = defaultRequestTimeout(0)
	}
	dashboardURL, err := validateConfig(cfg)
	if err != nil {
		return nil, err
	}
	intentDir, err := validateIntentDirectory(cfg.IntentDir)
	if err != nil {
		return nil, err
	}
	store, err := openJournal(intentDir)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: cfg.RequestTimeout,
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: -1,
		}).DialContext,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		// No CookieJar: dashboard cookies are never accepted or forwarded.
	}
	return &Gateway{config: cfg, dashboardURL: dashboardURL, journal: store, client: client, transport: transport, locks: make(map[string]chan struct{})}, nil
}

func (g *Gateway) Close() { g.transport.CloseIdleConnections() }

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if !g.authorized(r) {
		writeJSON(w, http.StatusUnauthorized, errorReply{OK: false, Stage: "unauthorized", Message: "未授权"})
		return
	}
	if r.Header.Get("Origin") != "" || r.Header.Get("Cookie") != "" {
		writeJSON(w, http.StatusForbidden, errorReply{OK: false, Stage: "request_rejected", Message: "请求被拒绝"})
		return
	}
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		writeJSON(w, http.StatusMethodNotAllowed, errorReply{OK: false, Stage: "method_not_allowed", Message: "请求方法不受支持"})
		return
	}
	mediaType, _, typeErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if typeErr != nil || mediaType != "application/json" {
		writeJSON(w, http.StatusUnsupportedMediaType, errorReply{OK: false, Stage: "invalid_request", Message: safeInvalidRequest})
		return
	}
	if r.ContentLength > maxRequestBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, errorReply{OK: false, Stage: "invalid_request", Message: safeInvalidRequest})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	switch r.URL.Path {
	case "/v1/resolve":
		g.handleResolve(w, r)
	case "/v1/family/read":
		g.handleFamilyRead(w, r)
	case "/v1/family/pool":
		g.handleFamilyPool(w, r)
	case "/v1/family/add":
		g.handleMutation(w, r, "family-add")
	case "/v1/family/remove":
		g.handleMutation(w, r, "family-remove")
	case "/v1/device/code":
		g.handleDeviceCode(w, r)
	default:
		writeJSON(w, http.StatusNotFound, errorReply{OK: false, Stage: "not_found", Message: "接口不存在"})
	}
}

func (g *Gateway) authorized(r *http.Request) bool {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return false
	}
	candidate := strings.TrimPrefix(values[0], "Bearer ")
	configuredHash := sha256.Sum256([]byte(g.config.BearerToken))
	candidateHash := sha256.Sum256([]byte(candidate))
	return subtle.ConstantTimeCompare(configuredHash[:], candidateHash[:]) == 1
}

func decodeRequest(w http.ResponseWriter, r *http.Request, target any) bool {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, http.StatusBadRequest, errorReply{OK: false, Stage: "invalid_request", Message: safeInvalidRequest})
		return false
	}
	return true
}

func (g *Gateway) handleResolve(w http.ResponseWriter, r *http.Request) {
	var body resolveRequest
	if !decodeRequest(w, r, &body) {
		return
	}
	normalized, valid := normalizeAppleID(body.AppleID)
	if !valid {
		writeJSON(w, http.StatusBadRequest, resolveReply{OK: false})
		return
	}
	registry, err := loadRegistry(g.config.RegistryPath)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, resolveReply{OK: false})
		return
	}
	matchedID := ""
	matches := 0
	for _, account := range registry.Accounts {
		candidate, ok := normalizeAppleID(account.AppleID)
		if ok && candidate == normalized {
			matchedID = account.ID
			matches++
		}
	}
	switch matches {
	case 1:
		writeJSON(w, http.StatusOK, resolveReply{OK: true, AccountID: matchedID})
	case 0:
		writeJSON(w, http.StatusNotFound, resolveReply{OK: false})
	default:
		writeJSON(w, http.StatusConflict, resolveReply{OK: false})
	}
}

func (g *Gateway) handleFamilyRead(w http.ResponseWriter, r *http.Request) {
	var body accountRequest
	if !decodeRequest(w, r, &body) {
		return
	}
	registry, err := loadRegistry(g.config.RegistryPath)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, familyReply{OK: false, Stage: "family-read-failed", Message: safeReadFailureMessage})
		return
	}
	if _, ok := accountIDFromRegistry(registry, body.AccountID); !ok {
		writeJSON(w, http.StatusNotFound, familyReply{OK: false, Stage: "account-not-found", Message: safeAccountNotFound})
		return
	}
	result, err := g.dashboardAction(r.Context(), body.AccountID, "family-info-direct", "")
	if err != nil || !readStageOK(result) || result.Family == nil {
		writeJSON(w, http.StatusBadGateway, familyReply{OK: false, Stage: "family-read-failed", Message: safeReadFailureMessage})
		return
	}
	writeJSON(w, http.StatusOK, familyReply{OK: true, Stage: "family-read", Message: safeReadMessage, Family: publicFamily(result.Family)})
}

func (g *Gateway) handleFamilyPool(w http.ResponseWriter, r *http.Request) {
	var body accountRequest
	if !decodeRequest(w, r, &body) {
		return
	}
	registry, err := loadRegistry(g.config.RegistryPath)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, familyPoolReply{OK: false, Stage: "family-pool-failed", Message: safeReadFailureMessage})
		return
	}
	if _, ok := accountIDFromRegistry(registry, body.AccountID); !ok {
		writeJSON(w, http.StatusNotFound, familyPoolReply{OK: false, Stage: "account-not-found", Message: safeAccountNotFound})
		return
	}
	projection, err := g.readFamilyPool(r.Context(), body.AccountID, registry)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, familyPoolReply{OK: false, Stage: "family-pool-failed", Message: safeReadFailureMessage})
		return
	}
	writeJSON(w, http.StatusOK, familyPoolReply{OK: true, Stage: "family-pool", Message: "家庭成员映射已确认", Members: projection.Members, UnmappedCount: projection.UnmappedCount, TotalCount: projection.TotalCount})
}

func (g *Gateway) handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	var body accountRequest
	if !decodeRequest(w, r, &body) {
		return
	}
	registry, err := loadRegistry(g.config.RegistryPath)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, codeReply{OK: false})
		return
	}
	if _, ok := accountIDFromRegistry(registry, body.AccountID); !ok {
		writeJSON(w, http.StatusNotFound, codeReply{OK: false})
		return
	}
	result, err := g.dashboardAction(r.Context(), body.AccountID, "code", "")
	if err != nil || !result.OK || !codePattern.MatchString(result.Code) {
		writeJSON(w, http.StatusBadGateway, codeReply{OK: false})
		return
	}
	writeJSON(w, http.StatusOK, codeReply{OK: true, Code: result.Code})
}

func (g *Gateway) handleMutation(w http.ResponseWriter, r *http.Request, action string) {
	var body mutationRequest
	if !decodeRequest(w, r, &body) {
		return
	}
	if !validAccountID(body.OrganizerAccountID) || !validAccountID(body.TargetAccountID) || body.OrganizerAccountID == body.TargetAccountID || !validOperationID(body.OperationID) {
		writeJSON(w, http.StatusBadRequest, errorReply{OK: false, Stage: "invalid_request", Message: safeInvalidRequest})
		return
	}
	registry, err := loadRegistry(g.config.RegistryPath)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errorReply{OK: false, Stage: "service-unavailable", Message: safeServiceFailure})
		return
	}
	if _, ok := accountIDFromRegistry(registry, body.OrganizerAccountID); !ok {
		writeJSON(w, http.StatusNotFound, errorReply{OK: false, Stage: "account-not-found", Message: safeAccountNotFound})
		return
	}
	if _, ok := accountIDFromRegistry(registry, body.TargetAccountID); !ok {
		writeJSON(w, http.StatusNotFound, errorReply{OK: false, Stage: "account-not-found", Message: safeAccountNotFound})
		return
	}
	release, ok := g.acquireOrganizer(r.Context(), body.OrganizerAccountID)
	if !ok {
		writeJSON(w, http.StatusConflict, familyReply{OK: false, Stage: "family-busy", Message: "该组织者已有操作正在处理"})
		return
	}
	defer release()
	if previous, exists := g.journal.lookup(body.OperationID); exists {
		if previous.Action != action || previous.OrganizerAccountID != body.OrganizerAccountID || previous.TargetAccountID != body.TargetAccountID {
			writeJSON(w, http.StatusConflict, errorReply{OK: false, Stage: "operation-id-conflict", Message: safeOperationIDConflict})
			return
		}
		writeJSON(w, http.StatusOK, replyFromRecord(previous))
		return
	}
	if g.journal.isBlocked(body.OrganizerAccountID) {
		writeJSON(w, http.StatusConflict, familyReply{OK: false, Stage: "outcome_unknown", Message: safeUnknownMessage})
		return
	}
	organizer, target, preflightErr := g.preflight(r.Context(), body, action)
	if preflightErr != nil {
		writeJSON(w, http.StatusConflict, familyReply{OK: false, Stage: "family-preflight", Message: safePreflightMessage})
		return
	}
	poolBefore, poolErr := g.readFamilyPool(r.Context(), body.OrganizerAccountID, registry)
	if poolErr != nil || validatePoolWritePrecondition(poolBefore, body.OrganizerAccountID, body.TargetAccountID, action, organizer.Members) != nil {
		writeJSON(w, http.StatusConflict, familyReply{OK: false, Stage: "family-preflight", Message: safePreflightMessage})
		return
	}
	record := operationRecord{Version: journalVersion, OperationID: body.OperationID, Action: action, OrganizerAccountID: body.OrganizerAccountID, TargetAccountID: body.TargetAccountID, State: stateIntent}
	if err := g.journal.create(record); err != nil {
		if previous, exists := g.journal.lookup(body.OperationID); exists {
			if previous.Action == action && previous.OrganizerAccountID == body.OrganizerAccountID && previous.TargetAccountID == body.TargetAccountID {
				writeJSON(w, http.StatusOK, replyFromRecord(previous))
				return
			}
		}
		writeJSON(w, http.StatusServiceUnavailable, familyReply{OK: false, Stage: "intent-not-persisted", Message: safeServiceFailure})
		return
	}
	result, callErr := g.mutationAction(r.Context(), body, action)
	if callErr != nil || !result.OK {
		g.bestEffortReadback(body)
		g.journal.markUnknown(body.OperationID)
		writeJSON(w, http.StatusOK, g.unknownReply(body.OperationID))
		return
	}
	var confirmed *Family
	var stage, message string
	if action == "family-add" {
		stage, message, confirmed = "family-added", safeAddedMessage, g.verifyAdded(r.Context(), body, result, organizer, target, poolBefore, registry)
	} else {
		stage, message = "family-member-removed", safeRemovedMessage
		if result.Stage == "family-remove-cache-warning" {
			stage, message = "family-remove-cache-warning", safeRemoveCacheMessage
		}
		confirmed = g.verifyRemoved(r.Context(), body, result, organizer, target, poolBefore, registry)
	}
	if confirmed == nil {
		g.bestEffortReadback(body)
		g.journal.markUnknown(body.OperationID)
		writeJSON(w, http.StatusOK, g.unknownReply(body.OperationID))
		return
	}
	completed := record
	completed.State, completed.Stage, completed.Message, completed.Family = stateSucceeded, stage, message, confirmed
	if !g.journal.complete(completed) {
		g.journal.markUnknown(body.OperationID)
		writeJSON(w, http.StatusOK, g.unknownReply(body.OperationID))
		return
	}
	writeJSON(w, http.StatusOK, replyFromRecord(completed))
}

func (g *Gateway) preflight(ctx context.Context, body mutationRequest, action string) (*dashboardFamily, *dashboardFamily, error) {
	organizerResult, err := g.dashboardAction(ctx, body.OrganizerAccountID, "family-info-direct", "")
	if err != nil || !readStageOK(organizerResult) || organizerResult.Family == nil {
		return nil, nil, errors.New("organizer state not confirmed")
	}
	targetResult, err := g.dashboardAction(ctx, body.TargetAccountID, "family-info-direct", "")
	if err != nil || !readStageOK(targetResult) || targetResult.Family == nil {
		return nil, nil, errors.New("target state not confirmed")
	}
	organizer, target := organizerResult.Family, targetResult.Family
	if !organizer.Member || !organizer.Organizer || organizer.Organizers != 1 || organizer.Self != 1 {
		return nil, nil, errors.New("organizer binding not confirmed")
	}
	if action == "family-add" {
		if target.Member || !target.EligibilityKnown || !target.Eligible {
			return nil, nil, errors.New("target is not eligible")
		}
		if !organizer.StorageKnown || !organizer.StorageParticipating || !organizer.StorageAvailable || !organizer.StorageEnabled || organizer.StorageBytes <= 0 {
			return nil, nil, errors.New("organizer shared storage is not confirmed")
		}
		return organizer, target, nil
	}
	if !target.Member || target.Organizer || organizer.Members < 2 {
		return nil, nil, errors.New("target is not a removable member")
	}
	return organizer, target, nil
}

func (g *Gateway) readFamilyPool(ctx context.Context, accountID string, registry accountRegistry) (*familyPoolProjection, error) {
	result, err := g.dashboardAction(ctx, accountID, "family-pool", "")
	projection := result.FamilyPool
	if err != nil || !result.OK || result.Stage != "family-pool" || projection == nil || projection.TotalCount <= 0 || projection.UnmappedCount < 0 || projection.UnmappedCount+len(projection.Members) != projection.TotalCount {
		return nil, errors.New("live family member projection unavailable")
	}
	seen := make(map[string]bool, len(projection.Members))
	organizers := 0
	for _, member := range projection.Members {
		if _, registered := accountIDFromRegistry(registry, member.AccountID); !registered || seen[member.AccountID] {
			return nil, errors.New("live family member projection invalid")
		}
		seen[member.AccountID] = true
		if member.Organizer {
			organizers++
		}
	}
	if organizers > 1 || projection.UnmappedCount == 0 && organizers != 1 {
		return nil, errors.New("live family organizer projection invalid")
	}
	return projection, nil
}

func findPoolMember(projection *familyPoolProjection, accountID string) (familyPoolMember, bool) {
	if projection == nil {
		return familyPoolMember{}, false
	}
	var found familyPoolMember
	count := 0
	for _, member := range projection.Members {
		if member.AccountID == accountID {
			found = member
			count++
		}
	}
	return found, count == 1
}

func validatePoolWritePrecondition(projection *familyPoolProjection, organizerID, targetID string, action string, expectedCount int) error {
	if projection == nil || projection.TotalCount != expectedCount {
		return errors.New("live family membership count changed")
	}
	organizer, organizerFound := findPoolMember(projection, organizerID)
	if !organizerFound || !organizer.Organizer || organizer.Child {
		return errors.New("live family organizer identity not confirmed")
	}
	target, targetFound := findPoolMember(projection, targetID)
	if action == "family-add" {
		if projection.UnmappedCount != 0 || targetFound {
			return errors.New("target presence cannot be ruled out")
		}
		return nil
	}
	if !targetFound || target.Organizer || target.Child {
		return errors.New("target is not an exact removable member")
	}
	return nil
}

func readStageOK(result dashboardResult) bool {
	return result.OK && (result.Stage == "family-info" || result.Stage == "family-cache-warning")
}

func (g *Gateway) mutationAction(ctx context.Context, body mutationRequest, action string) (dashboardResult, error) {
	if action == "family-add" {
		return g.dashboardAction(ctx, body.TargetAccountID, "family-add-self", body.OrganizerAccountID)
	}
	return g.dashboardAction(ctx, body.OrganizerAccountID, "family-remove-member", body.TargetAccountID)
}

func (g *Gateway) verifyAdded(ctx context.Context, body mutationRequest, result dashboardResult, beforeOrganizer, beforeTarget *dashboardFamily, poolBefore *familyPoolProjection, registry accountRegistry) *Family {
	if beforeOrganizer == nil || beforeTarget == nil || !beforeOrganizer.Member || !beforeOrganizer.Organizer || beforeOrganizer.Members < 1 || beforeTarget.Member {
		return nil
	}
	if poolBefore == nil || poolBefore.TotalCount != beforeOrganizer.Members || poolBefore.UnmappedCount != 0 {
		return nil
	}
	expectedMembers := beforeOrganizer.Members + 1
	if result.Stage != "family-added" || !validAddedState(result.Family, false, expectedMembers, beforeOrganizer.StorageBytes) {
		return nil
	}
	organizerAfter, err := g.dashboardAction(ctx, body.OrganizerAccountID, "family-info-direct", "")
	if err != nil || !readStageOK(organizerAfter) || !validAddedState(organizerAfter.Family, true, expectedMembers, beforeOrganizer.StorageBytes) || !sameStorageState(beforeOrganizer, organizerAfter.Family) {
		return nil
	}
	targetAfter, err := g.dashboardAction(ctx, body.TargetAccountID, "family-info-direct", "")
	if err != nil || !readStageOK(targetAfter) || !validAddedState(targetAfter.Family, false, expectedMembers, beforeOrganizer.StorageBytes) {
		return nil
	}
	if !sameAddedSummary(result.Family, targetAfter.Family) || !sameStorageState(organizerAfter.Family, targetAfter.Family) {
		return nil
	}
	poolAfter, err := g.readFamilyPool(ctx, body.OrganizerAccountID, registry)
	if err != nil || poolAfter.UnmappedCount != 0 || poolAfter.TotalCount != poolBefore.TotalCount+1 {
		return nil
	}
	if organizerMember, ok := findPoolMember(poolAfter, body.OrganizerAccountID); !ok || !organizerMember.Organizer || organizerMember.Child {
		return nil
	}
	if targetMember, ok := findPoolMember(poolAfter, body.TargetAccountID); !ok || targetMember.Organizer || targetMember.Child {
		return nil
	}
	return publicFamily(targetAfter.Family)
}

func validAddedState(family *dashboardFamily, organizer bool, expectedMembers int, expectedStorage int64) bool {
	return family != nil && family.Member && family.Organizer == organizer && family.Members == expectedMembers && family.Organizers == 1 && family.Self == 1 && family.StorageKnown && family.StorageParticipating && family.StorageAvailable && family.StorageEnabled && family.StorageBytes == expectedStorage
}

func sameAddedSummary(left, right *dashboardFamily) bool {
	return left != nil && right != nil && left.Member == right.Member && left.Organizer == right.Organizer && left.Members == right.Members && left.Organizers == right.Organizers && left.Self == right.Self && left.StorageKnown == right.StorageKnown && left.StorageParticipating == right.StorageParticipating && left.StorageAvailable == right.StorageAvailable && left.StorageEnabled == right.StorageEnabled && left.StorageBytes == right.StorageBytes
}

func sameStorageState(left, right *dashboardFamily) bool {
	return left != nil && right != nil && left.StorageKnown == right.StorageKnown && left.StorageParticipating == right.StorageParticipating && left.StorageAvailable == right.StorageAvailable && left.StorageEnabled == right.StorageEnabled && left.StorageBytes == right.StorageBytes
}

func (g *Gateway) verifyRemoved(ctx context.Context, body mutationRequest, result dashboardResult, beforeOrganizer, beforeTarget *dashboardFamily, poolBefore *familyPoolProjection, registry accountRegistry) *Family {
	if result.Stage != "family-member-removed" && result.Stage != "family-remove-cache-warning" {
		return nil
	}
	if result.Family == nil || !validOrganizerState(result.Family) || result.Family.Members != beforeOrganizer.Members-1 {
		return nil
	}
	organizerAfter, err := g.dashboardAction(ctx, body.OrganizerAccountID, "family-info-direct", "")
	if err != nil || !readStageOK(organizerAfter) || !validOrganizerState(organizerAfter.Family) || organizerAfter.Family.Members != beforeOrganizer.Members-1 || !sameStorageState(beforeOrganizer, organizerAfter.Family) {
		return nil
	}
	targetAfter, err := g.dashboardAction(ctx, body.TargetAccountID, "family-info-direct", "")
	if err != nil || !readStageOK(targetAfter) || targetAfter.Family == nil || targetAfter.Family.Member {
		return nil
	}
	if beforeTarget == nil || !beforeTarget.Member {
		return nil
	}
	if poolBefore == nil || poolBefore.TotalCount != beforeOrganizer.Members {
		return nil
	}
	poolAfter, err := g.readFamilyPool(ctx, body.OrganizerAccountID, registry)
	if err != nil || poolAfter.UnmappedCount != 0 || poolAfter.TotalCount != poolBefore.TotalCount-1 {
		return nil
	}
	if organizerMember, ok := findPoolMember(poolAfter, body.OrganizerAccountID); !ok || !organizerMember.Organizer || organizerMember.Child {
		return nil
	}
	if _, targetPresent := findPoolMember(poolAfter, body.TargetAccountID); targetPresent {
		return nil
	}
	return publicFamily(organizerAfter.Family)
}

func (g *Gateway) bestEffortReadback(body mutationRequest) {
	timeout := 30 * time.Second
	if g.config.RequestTimeout < timeout {
		timeout = g.config.RequestTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, _ = g.dashboardAction(ctx, body.OrganizerAccountID, "family-info-direct", "")
	_, _ = g.dashboardAction(ctx, body.TargetAccountID, "family-info-direct", "")
}

func validOrganizerState(family *dashboardFamily) bool {
	return family != nil && family.Member && family.Organizer && family.Organizers == 1 && family.Self == 1
}

func publicFamily(source *dashboardFamily) *Family {
	if source == nil {
		return nil
	}
	return &Family{Member: source.Member, Organizer: source.Organizer, Members: source.Members, Organizers: source.Organizers, Self: source.Self, StorageKnown: source.StorageKnown, StorageParticipating: source.StorageParticipating, StorageAvailable: source.StorageAvailable, StorageEnabled: source.StorageEnabled}
}

func replyFromRecord(record operationRecord) familyReply {
	return familyReply{OK: record.State == stateSucceeded, Stage: record.Stage, Message: record.Message, Family: record.Family}
}

func (g *Gateway) unknownReply(operationID string) familyReply {
	if record, ok := g.journal.lookup(operationID); ok && record.State == stateUnknown {
		return replyFromRecord(record)
	}
	return familyReply{OK: false, Stage: "outcome_unknown", Message: safeUnknownMessage}
}

func (g *Gateway) acquireOrganizer(ctx context.Context, organizerID string) (func(), bool) {
	g.locksMu.Lock()
	lock := g.locks[organizerID]
	if lock == nil {
		lock = make(chan struct{}, 1)
		g.locks[organizerID] = lock
	}
	g.locksMu.Unlock()
	select {
	case lock <- struct{}{}:
		return func() { <-lock }, true
	case <-ctx.Done():
		return nil, false
	}
}

func (g *Gateway) dashboardAction(parent context.Context, accountID, action, code string) (dashboardResult, error) {
	var result dashboardResult
	ctx, cancel := context.WithTimeout(parent, g.config.RequestTimeout)
	defer cancel()
	token, err := g.dashboardToken(ctx)
	if err != nil {
		return result, errors.New("local dashboard unavailable")
	}
	body, err := json.Marshal(dashboardAction{Action: action, Code: code})
	if err != nil {
		return result, errors.New("local dashboard request failed")
	}
	endpoint := g.dashboardURL.ResolveReference(&url.URL{Path: "/api/action", RawQuery: "account=" + url.QueryEscape(accountID)})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return result, errors.New("local dashboard request failed")
	}
	request.Header.Set("X-App-Token", token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := g.client.Do(request)
	if err != nil {
		return result, errors.New("local dashboard request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, errors.New("local dashboard rejected request")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(data) > maxResponseBytes {
		return result, errors.New("local dashboard response is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return dashboardResult{}, errors.New("local dashboard response is invalid")
	}
	return result, nil
}

func (g *Gateway) dashboardToken(ctx context.Context) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, g.dashboardURL.String()+"/", nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept", "text/html")
	response, err := g.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", errors.New("local dashboard unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 256<<10))
	if err != nil || len(data) >= 256<<10 {
		return "", errors.New("local dashboard page is invalid")
	}
	match := appTokenPattern.FindSubmatch(data)
	if len(match) != 2 || len(match[1]) != 64 {
		return "", errors.New("local dashboard capability is unavailable")
	}
	return string(match[1]), nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (g *Gateway) String() string { return fmt.Sprintf("v2gateway(%s)", g.config.ListenAddr) }
