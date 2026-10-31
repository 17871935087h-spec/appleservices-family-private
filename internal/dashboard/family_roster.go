package dashboard

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Laky-64/appleservices/internal/control"
)

const familyRosterPrefix = "FAMILY_ROSTER_JSON="
const familyRemoveOutcomePrefix = "FAMILY_REMOVE_OUTCOME="

type familyRosterReaderFunc func(context.Context, string, string, string) (*control.FamilyRosterProjection, error)
type familyRefRemoverFunc func(context.Context, string, string, string, string) (*control.FamilyInfo, string, error)

func validFamilyMemberRef(ref string) bool {
	if len(ref) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(ref)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == ref
}

func validateFamilyRoster(roster *control.FamilyRosterProjection) error {
	if roster == nil || roster.TotalCount < 1 || roster.TotalCount > 100 ||
		roster.UnidentifiedCount < 0 || roster.UnidentifiedCount > roster.TotalCount ||
		len(roster.Members)+roster.UnidentifiedCount > roster.TotalCount {
		return errors.New("family roster is invalid")
	}
	seen := make(map[string]bool, len(roster.Members))
	for _, member := range roster.Members {
		label := strings.TrimSpace(member.Label)
		if !validFamilyMemberRef(member.Ref) || seen[member.Ref] || label == "" ||
			len(label) > 128 || !utf8.ValidString(label) || strings.IndexFunc(label, unicode.IsControl) >= 0 {
			return errors.New("family roster is invalid")
		}
		if at := strings.IndexByte(label, '@'); at >= 0 &&
			!strings.ContainsAny(label[:at], "*•") {
			return errors.New("family roster label is not masked")
		}
		seen[member.Ref] = true
	}
	return nil
}

func parseFamilyRoster(output string) (*control.FamilyRosterProjection, error) {
	var found *control.FamilyRosterProjection
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, familyRosterPrefix) {
			continue
		}
		if found != nil {
			return nil, errors.New("family roster is ambiguous")
		}
		decoder := json.NewDecoder(strings.NewReader(strings.TrimPrefix(line, familyRosterPrefix)))
		decoder.DisallowUnknownFields()
		var roster control.FamilyRosterProjection
		if decoder.Decode(&roster) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
			validateFamilyRoster(&roster) != nil {
			return nil, errors.New("family roster is invalid")
		}
		found = &roster
	}
	if found == nil {
		return nil, errors.New("family roster is missing")
	}
	return found, nil
}

func familyRefEnvironment(key, ref string) []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, "APPLESERVICES_FAMILY_REF_KEY") ||
			strings.EqualFold(name, "APPLESERVICES_FAMILY_MEMBER_REF") ||
			strings.EqualFold(name, "APPLESERVICES_TARGET_PASSWORD") {
			continue
		}
		env = append(env, entry)
	}
	env = append(env, "APPLESERVICES_FAMILY_REF_KEY="+key)
	if ref != "" {
		env = append(env, "APPLESERVICES_FAMILY_MEMBER_REF="+ref)
	}
	return env
}

func runFamilyRoster(ctx context.Context, helper, dir, key string) (*control.FamilyRosterProjection, error) {
	command := exec.CommandContext(ctx, helper, "-dir", dir, "-organizer-roster")
	command.Env = familyRefEnvironment(key, "")
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil || output.Len() > 128<<10 {
		return nil, errors.New("current family roster unavailable")
	}
	return parseFamilyRoster(output.String())
}

func (s *Server) familyRosterAction(ctx context.Context, organizer *Account) control.Result {
	if organizer == nil || !acceptedCheckpointReady(organizer.Dir, organizer.AppleID) {
		return control.Result{Stage: "family-roster-unready", Message: "请先完成组织者的 iCloud 登录和激活"}
	}
	reader := s.familyRosterReader
	helper := filepath.Join(filepath.Dir(s.config.Worker), "familyinspect.exe")
	if reader == nil {
		if info, err := os.Stat(helper); err != nil || !info.Mode().IsRegular() {
			return control.Result{Stage: "family-worker", Message: "家庭工具不可用，请重新构建后台"}
		}
		reader = runFamilyRoster
	}
	actionCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	roster, err := reader(actionCtx, helper, organizer.Dir, s.familyRosterKey)
	if err != nil || validateFamilyRoster(roster) != nil {
		return control.Result{Stage: "family-roster-failed", Message: "无法确认组织者当前的家庭成员，请稍后重新读取"}
	}
	return control.Result{OK: true, Stage: "family-roster", Message: "已读取组织者当前家庭成员", FamilyRoster: roster}
}

func parseFamilyRemoveOutcome(output string) (string, error) {
	var outcome string
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, familyRemoveOutcomePrefix) {
			continue
		}
		if outcome != "" {
			return "", errors.New("family removal outcome is ambiguous")
		}
		outcome = strings.TrimPrefix(line, familyRemoveOutcomePrefix)
		if outcome != "not_submitted" && outcome != "confirmed" && outcome != "unknown" {
			return "", errors.New("family removal outcome is invalid")
		}
	}
	if outcome == "" {
		return "", errors.New("family removal outcome is missing")
	}
	return outcome, nil
}

func runFamilyRefRemove(ctx context.Context, helper, dir, key, ref string) (*control.FamilyInfo, string, error) {
	command := exec.CommandContext(ctx, helper, "-dir", dir, "-remove-member-ref", "-safe-json")
	command.Env = familyRefEnvironment(key, ref)
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	runErr := command.Run()
	if output.Len() > 128<<10 {
		return nil, "unknown", errors.New("family removal outcome unavailable")
	}
	outcome, err := parseFamilyRemoveOutcome(output.String())
	if err != nil {
		return nil, "unknown", errors.New("family removal outcome unavailable")
	}
	if outcome != "confirmed" {
		return nil, outcome, errors.New("family removal not confirmed")
	}
	if runErr != nil {
		return nil, "unknown", errors.New("family removal outcome unavailable")
	}
	family, err := parseFamilyStatus(output.String())
	if err != nil {
		return nil, "unknown", errors.New("family removal status unavailable")
	}
	return family, outcome, nil
}

// A durable marker prevents a second submission after interruption or an
// unconfirmed result, including after the dashboard process restarts.
func createFamilyRemovalIntent(accountDir string) (string, error) {
	resolved, err := filepath.EvalSymlinks(accountDir)
	if err != nil || !filepath.IsAbs(resolved) ||
		(runtime.GOOS == "windows" && !strings.EqualFold(filepath.VolumeName(resolved), "D:")) {
		return "", errors.New("family removal intent directory unavailable")
	}
	path := filepath.Join(resolved, ".family-remove-pending")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", errors.New("family removal intent unavailable")
	}
	if _, err = file.WriteString("intent-v1"); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return "", errors.New("family removal intent unavailable")
	}
	return path, nil
}

func (s *Server) familyRemoveRefAction(ctx context.Context, organizer *Account, ref string) control.Result {
	if organizer == nil || !validFamilyMemberRef(ref) {
		return control.Result{Stage: "family-binding", Message: "成员选择已失效，请重新读取家庭成员"}
	}
	if !acceptedCheckpointReady(organizer.Dir, organizer.AppleID) {
		return control.Result{Stage: "family-preflight", Message: "请先完成组织者的 iCloud 登录和激活"}
	}

	s.familyRemovalMu.Lock()
	defer s.familyRemovalMu.Unlock()
	if s.familyRemovalUnknown[organizer.ID] {
		return control.Result{Stage: "family-remove-unknown", Message: "上次移除结果尚未确认，请先到 Apple 核对，暂勿重复提交"}
	}

	remover := s.familyRefRemover
	helper := filepath.Join(filepath.Dir(s.config.Worker), "familyinspect.exe")
	if remover == nil {
		if info, err := os.Stat(helper); err != nil || !info.Mode().IsRegular() {
			return control.Result{Stage: "family-worker", Message: "家庭工具不可用，请重新构建后台"}
		}
		remover = runFamilyRefRemove
	}
	if ctx.Err() != nil {
		return control.Result{Stage: "family-remove-preflight", Message: "请求已取消，未提交移除"}
	}
	intentPath, intentErr := createFamilyRemovalIntent(organizer.Dir)
	if intentErr != nil {
		return control.Result{Stage: "family-remove-unknown", Message: "存在未完成的移除记录或无法保存操作意图，请先到 Apple 核对"}
	}
	actionCtx, cancel := context.WithTimeout(ctx, 105*time.Second)
	defer cancel()
	family, outcome, err := remover(actionCtx, helper, organizer.Dir, s.familyRosterKey, ref)
	if outcome == "not_submitted" {
		if os.Remove(intentPath) != nil {
			return control.Result{Stage: "family-remove-unknown", Message: "未提交移除，但本地操作记录未能清理，请先核对"}
		}
		return control.Result{Stage: "family-remove-preflight", Message: "未提交移除；成员信息已变化或无法安全确认，请重新读取"}
	}
	if outcome != "confirmed" || err != nil || family == nil ||
		!family.Member || !family.Organizer || family.Organizers != 1 || family.Self != 1 {
		if s.familyRemovalUnknown == nil {
			s.familyRemovalUnknown = make(map[string]bool)
		}
		s.familyRemovalUnknown[organizer.ID] = true
		return control.Result{Stage: "family-remove-unknown", Message: "移除结果尚未确认，请先到 Apple 核对，暂勿重复提交"}
	}

	if os.Remove(intentPath) != nil {
		return control.Result{OK: true, Stage: "family-remove-cache-warning", Message: "组织者已确认成员移除，但本地操作记录未能清理", Family: family}
	}
	family.OrganizerAccount, family.OrganizerName = organizer.ID, organizer.Name
	_, cacheErr := writeFamilyCache(organizer, family)
	if cacheErr != nil {
		return control.Result{OK: true, Stage: "family-remove-cache-warning", Message: "组织者已确认成员移除；本地缓存未保存，请重新读取", Family: family}
	}
	return control.Result{OK: true, Stage: "family-member-removed", Message: "组织者已确认成员移出家庭", Family: family}
}
