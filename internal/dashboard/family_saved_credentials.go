package dashboard

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/Laky-64/appleservices/internal/control"
	"github.com/Laky-64/appleservices/internal/credentialvault"
)

// prepareSavedFamilyAdd checks readiness without contacting Apple. Passwordless
// workers can use their own encrypted credential for one family-add command;
// the credential is never returned to the browser or retained by the dashboard.
// A nil action performs the same preflight without submitting a command.
func (s *Server) prepareSavedFamilyAdd(ctx context.Context, account *Account, action *control.Action) control.Result {
	unready := control.Result{Stage: "family-worker-unready", Message: "目标账号后台未就绪或需要重新连接"}
	if account == nil {
		return unready
	}
	if action != nil && (action.Action != "family-add-self" || action.HasOneShotFamilyCredential()) {
		return control.Result{Stage: "family-binding", Message: "目标账号凭据或会话绑定未确认"}
	}
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var worker control.View
	if err := s.callFor(checkCtx, account.Dir, "/view", nil, &worker); err != nil {
		return unready
	}
	var status Status
	if json.Unmarshal(worker.Status, &status) != nil || !status.Running || !status.Authenticated || status.VerificationRequired {
		return unready
	}
	ready := control.Result{OK: true, Stage: "family-add-ready", Message: "目标账号后台已就绪"}
	if slices.Contains(worker.Capabilities, control.FamilyAddReadyCapability) {
		return ready
	}
	if !slices.Contains(worker.Capabilities, control.FamilyAddOneShotCredentialCapability) ||
		!verifiedGSACheckpointReady(account.Dir, account.AppleID) || !acceptedCheckpointReady(account.Dir, account.AppleID) {
		return unready
	}
	load := s.familyCredentialLoader
	if load == nil {
		load = credentialvault.Load
	}
	password, err := load(account.Dir, account.AppleID)
	defer func() { password = "" }()
	if err != nil || !control.ValidOneShotFamilyPassword(password) {
		return control.Result{Stage: "family-credential-required", Message: "当前账号已登录，但无法读取本账号保存的凭据；请在连接窗口补充密码后再加入家庭"}
	}
	if action != nil {
		action.TargetAppleID, action.TargetPassword = account.AppleID, password
	}
	return ready
}
