package dashboard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	appleservices "github.com/Laky-64/appleservices"
	"github.com/Laky-64/appleservices/internal/control"
	"github.com/Laky-64/appleservices/internal/egresspool"
)

func verifiedGSACheckpointReady(dir, appleID string) bool {
	data, err := os.ReadFile(filepath.Join(dir, "session.json"))
	if err != nil || len(data) > 2<<20 {
		return false
	}
	var session appleservices.Session
	if json.Unmarshal(data, &session) != nil || !strings.EqualFold(session.AppleID, appleID) || session.DSID == "" {
		return false
	}
	return session.Tokens["com.apple.gs.idms.pet"] != ""
}

func activationTermsURLs(region string) (string, string) {
	icloudURL := "https://www.apple.com/legal/internet-services/icloud/"
	mediaURL := "https://www.apple.com/legal/internet-services/itunes/us/terms.html"
	if !strings.EqualFold(region, "US") {
		mediaURL = "https://www.apple.com/legal/internet-services/itunes/"
	}
	return icloudURL, mediaURL
}

func parseActivationPlan(output []byte) (*control.ActivationInfo, error) {
	for _, line := range strings.Split(string(output), "\n") {
		var value struct {
			TermsPlan     bool   `json:"terms-plan"`
			Region        string `json:"region"`
			ICloudVersion string `json:"icloud-version"`
			MediaVersion  string `json:"media-version"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(line)), &value) != nil || !value.TermsPlan {
			continue
		}
		if value.Region == "" || value.ICloudVersion == "" {
			return nil, errors.New("Apple 未返回完整条款版本")
		}
		icloudURL, mediaURL := activationTermsURLs(value.Region)
		return &control.ActivationInfo{Required: true, Region: value.Region, ICloudVersion: value.ICloudVersion, MediaVersion: value.MediaVersion, ICloudTermsURL: icloudURL, MediaTermsURL: mediaURL}, nil
	}
	return nil, errors.New("Apple 未返回可确认的 iCloud 条款计划")
}

func activationTuple(info *control.ActivationInfo) string {
	if info == nil {
		return ""
	}
	return info.Region + ":" + info.ICloudVersion + ":" + info.MediaVersion
}

func filteredActivationEnv(appleID string) []string {
	result := make([]string, 0, len(os.Environ())+3)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		switch {
		case strings.EqualFold(key, "APPLESERVICES_APPLEID"), strings.EqualFold(key, "APPLESERVICES_PASSWORD"),
			strings.EqualFold(key, "HTTP_PROXY"), strings.EqualFold(key, "HTTPS_PROXY"), strings.EqualFold(key, "ALL_PROXY"),
			strings.EqualFold(key, "APPLESERVICES_SOCKS_PROXY"), strings.EqualFold(key, "APPLESERVICES_DELEGATE_DUMP"),
			strings.EqualFold(key, "APPLESERVICES_DELEGATE_PATH"):
			continue
		}
		result = append(result, entry)
	}
	return append(result, "APPLESERVICES_APPLEID="+appleID, "APPLESERVICES_DELEGATE_PATH=v2", "NO_PROXY=*")
}

func runActivationCommand(ctx context.Context, root, accountDir, appleID, executable string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, executable, args...)
	configureProcess(command)
	command.Dir = root
	var envErr error
	command.Env, envErr = egresspool.Environment(filteredActivationEnv(appleID), accountDir)
	if envErr != nil {
		return nil, envErr
	}
	output, err := command.CombinedOutput()
	if len(output) > 256<<10 {
		return nil, errors.New("激活组件返回内容过大")
	}
	return output, err
}

func copyActivationTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || strings.HasPrefix(relative, "..") || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("激活运行时路径无效")
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		defer input.Close()
		output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(output, input)
		closeErr := output.Close()
		return errors.Join(copyErr, closeErr)
	})
}

func (s *Server) activationRoot() string {
	return filepath.Dir(filepath.Dir(s.config.MacPushSetup))
}

func (s *Server) activationPlan(ctx context.Context, account *Account, runDir string) (*control.ActivationInfo, error) {
	root := s.activationRoot()
	helper := filepath.Join(filepath.Dir(s.config.Worker), "accountsetupcheck.exe")
	dump := filepath.Join(runDir, "setup.html")
	output, err := s.runActivation(ctx, root, account.Dir, account.AppleID, helper,
		"-dir", account.Dir, "-resume", filepath.Join(account.Dir, "session.json"), "-dump", dump)
	if err != nil {
		return nil, errors.New("无法读取 Apple 当前条款状态")
	}
	return parseActivationPlan(output)
}

func (s *Server) runActivation(ctx context.Context, root, dir, appleID, executable string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.activationRunner != nil {
		return s.activationRunner(ctx, root, dir, appleID, executable, args...)
	}
	return runActivationCommand(ctx, root, dir, appleID, executable, args...)
}

func (s *Server) activationStorageInfo(ctx context.Context, account *Account) control.Result {
	if s.activationStorage != nil {
		return s.activationStorage(ctx, account, false)
	}
	return s.acceptedStorageAction(ctx, account, false)
}

// This receipt proves only an acknowledged terms update. It contains no Apple
// credentials and cannot substitute for the separate delegate/quota checkpoint.
type activationTermsReceipt struct {
	Version int       `json:"version"`
	Binding string    `json:"binding"`
	Tuple   string    `json:"tuple"`
	At      time.Time `json:"confirmed_at"`
}

func activationTermsBinding(account *Account) string {
	if account == nil || !verifiedGSACheckpointReady(account.Dir, account.AppleID) {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(account.Dir, "session.json"))
	if err != nil || len(data) > 2<<20 {
		return ""
	}
	var session appleservices.Session
	if json.Unmarshal(data, &session) != nil || session.DSID == "" || !strings.EqualFold(session.AppleID, account.AppleID) {
		return ""
	}
	digest := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(account.AppleID)) + "\x00" + session.DSID))
	return hex.EncodeToString(digest[:])
}

func readActivationTermsReceipt(account *Account) (activationTermsReceipt, bool) {
	var receipt activationTermsReceipt
	if account == nil {
		return receipt, false
	}
	data, err := os.ReadFile(filepath.Join(account.Dir, "icloud-activation-terms.json"))
	if err != nil || len(data) > 4096 || json.Unmarshal(data, &receipt) != nil {
		return receipt, false
	}
	binding := activationTermsBinding(account)
	return receipt, receipt.Version == 1 && binding != "" && receipt.Binding == binding && receipt.Tuple != "" && !receipt.At.IsZero()
}

func confirmedActivationTermsReceiptReady(account *Account) bool {
	_, ok := readActivationTermsReceipt(account)
	return ok
}

func saveActivationTermsReceipt(account *Account, tuple string) error {
	binding := activationTermsBinding(account)
	if binding == "" || tuple == "" {
		return errors.New("activation terms identity unavailable")
	}
	receipt := activationTermsReceipt{Version: 1, Binding: binding, Tuple: tuple, At: time.Now().UTC()}
	data, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	path := filepath.Join(account.Dir, "icloud-activation-terms.json")
	temp, err := os.CreateTemp(account.Dir, ".activation-terms-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err = temp.Chmod(0600); err == nil {
		_, err = temp.Write(data)
	}
	if err == nil {
		err = temp.Sync()
	}
	err = errors.Join(err, temp.Close())
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}

func readTermsReceipt(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 1<<20 {
		return false
	}
	var receipt struct {
		Success bool `json:"success"`
	}
	if json.Unmarshal(data, &receipt) != nil || !receipt.Success {
		return false
	}
	metadata, err := os.ReadFile(strings.TrimSuffix(path, ".json") + "-meta.json")
	var status struct {
		HTTP int `json:"HTTP"`
	}
	return err == nil && len(metadata) < 4096 && json.Unmarshal(metadata, &status) == nil && status.HTTP == 200
}

func installAcceptedCheckpoint(source, destination string) error {
	data, err := os.ReadFile(source)
	if err != nil || len(data) == 0 || len(data) > 2<<20 {
		return errors.New("Apple 验收会话不可用")
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}

func (s *Server) activationAction(parent context.Context, account *Account, accept bool, approvedTuple string) control.Result {
	return s.activationActionMode(parent, account, accept, approvedTuple, false)
}

// The installation flag opts into the owner's requested login-to-activation
// workflow. The browser never needs to initiate or keep this operation alive.
func (s *Server) automaticActivationAction(parent context.Context, account *Account) control.Result {
	return s.activationActionMode(parent, account, true, "", true)
}

func (s *Server) activationActionMode(parent context.Context, account *Account, accept bool, approvedTuple string, automatic bool) control.Result {
	if account == nil || !verifiedGSACheckpointReady(account.Dir, account.AppleID) {
		return control.Result{Message: "请先完成账号密码与验证码验证", Stage: "activation-session"}
	}
	if acceptedCheckpointReady(account.Dir, account.AppleID) {
		result := s.activationStorageInfo(parent, account)
		result.Activation = &control.ActivationInfo{Completed: result.OK}
		return result
	}
	if !s.launchMu.TryLock() {
		return control.Result{Message: "当前账号正在处理其他登录或激活操作", Stage: "activation-busy"}
	}
	defer s.launchMu.Unlock()
	root := s.activationRoot()
	cacheRoot := filepath.Join(root, ".cache")
	runDir, err := os.MkdirTemp(cacheRoot, "dashboard-activation-")
	if err != nil {
		return control.Result{Message: "无法创建私有激活工作区", Stage: "activation-local"}
	}
	defer os.RemoveAll(runDir)
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	plan, err := s.activationPlan(ctx, account, runDir)
	if err != nil {
		return control.Result{Message: err.Error(), Stage: "activation-plan"}
	}
	if !accept {
		return control.Result{OK: true, Message: "Apple 要求接受当前 iCloud 与媒体服务条款", Stage: "activation-terms", Activation: plan}
	}
	if automatic {
		approvedTuple = activationTuple(plan)
	}
	if approvedTuple == "" || approvedTuple != activationTuple(plan) {
		return control.Result{Message: "Apple 条款版本已变化，请重新查看并确认", Stage: "activation-consent", Activation: plan}
	}
	helper := filepath.Join(filepath.Dir(s.config.Worker), "accountsetupcheck.exe")
	receipt, termsConfirmed := readActivationTermsReceipt(account)
	if termsConfirmed && receipt.Tuple != approvedTuple {
		return control.Result{Message: "Apple 条款版本已变化，需要重新核对", Stage: "activation-consent", Activation: plan}
	}
	if !termsConfirmed {
		termsDump := filepath.Join(runDir, "terms.html")
		_, _ = s.runActivation(ctx, root, account.Dir, account.AppleID, helper,
			"-dir", account.Dir, "-resume", filepath.Join(account.Dir, "session.json"), "-accept-terms", "-expected-terms", approvedTuple, "-dump", termsDump)
		if !readTermsReceipt(termsDump + ".update.json") {
			return control.Result{Message: "Apple 未确认条款接受状态", Stage: "activation-terms", Activation: plan}
		}
		if err := saveActivationTermsReceipt(account, approvedTuple); err != nil {
			return control.Result{Message: "条款已确认，但本地验收状态未保存", Stage: "activation-terms-save", Activation: plan}
		}
	}
	if ctx.Err() != nil {
		return control.Result{Message: "激活已取消，已保留条款确认状态", Stage: "activation-followup-retry"}
	}
	runtimeSource := filepath.Join(root, ".cache", "mac-nac-runtime")
	runtimeCopy := filepath.Join(runDir, "nac-runtime")
	if err := copyActivationTree(runtimeSource, runtimeCopy); err != nil {
		return control.Result{Message: "无法准备 Mac NAC 运行时", Stage: "activation-followup-retry"}
	}
	validation := filepath.Join(runDir, "nac-validation.bin")
	nacOutput, nacErr := s.runActivation(ctx, root, account.Dir, account.AppleID, s.config.Python,
		filepath.Join(root, "tools", "mac-nac-check.py"), "--profile", filepath.Join(account.Dir, "native-adi", "hw_info.plist"),
		"--runtime", runtimeCopy, "--encrypt-dll", filepath.Join(root, ".cache", "activation-source-review", "mac-io-encrypt.dll"),
		"--validation-out", validation, "--synthetic-missing-board-fields", "--transport", filepath.Join(filepath.Dir(s.config.Worker), "nacexchange.exe"))
	if nacErr != nil || !strings.Contains(string(nacOutput), `"stage": "NACSign"`) {
		return control.Result{Message: "Mac NAC 生成未完成", Stage: "activation-followup-retry"}
	}
	checkpoint := filepath.Join(runDir, "icloud-accepted.json")
	delegateOutput, delegateErr := s.runActivation(ctx, root, account.Dir, account.AppleID, helper,
		"-dir", account.Dir, "-resume", filepath.Join(account.Dir, "session.json"), "-delegate-only", "-terms-accepted",
		"-nac-validation", validation, "-dump", filepath.Join(runDir, "delegate.plist"), "-icloud-checkpoint", checkpoint)
	if delegateErr != nil || !strings.Contains(string(delegateOutput), "delegate accepted; mme-token-present=true") || !strings.Contains(string(delegateOutput), "quota accepted;") {
		return control.Result{Message: "Apple 尚未接受 Mac v2/NAC 激活", Stage: "activation-followup-retry"}
	}
	destination := filepath.Join(account.Dir, "icloud-accepted.json")
	if err := installAcceptedCheckpoint(checkpoint, destination); err != nil && !acceptedCheckpointReady(account.Dir, account.AppleID) {
		return control.Result{Message: "激活成功，但本地验收状态未保存", Stage: "activation-save"}
	}
	result := s.activationStorageInfo(ctx, account)
	if !result.OK {
		return result
	}
	result.Stage = "activation-completed"
	result.Message = "iCloud 条款、Mac NAC、delegate 与配额验收均已完成"
	result.Activation = &control.ActivationInfo{Completed: true, Region: plan.Region, ICloudVersion: plan.ICloudVersion, MediaVersion: plan.MediaVersion, ICloudTermsURL: plan.ICloudTermsURL, MediaTermsURL: plan.MediaTermsURL}
	return result
}
