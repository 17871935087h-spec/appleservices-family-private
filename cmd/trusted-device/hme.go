package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/Laky-64/appleservices/icloud"
	"github.com/Laky-64/appleservices/internal/control"
)

func hmeSessionFailure(err error) control.Result {
	result := control.Result{Message: "隐藏邮件地址会话未就绪：" + err.Error(), Stage: "hme-session"}
	var setup *icloud.HMEWebSetupError
	if errors.As(err, &setup) {
		result.HTTPStatus = setup.HTTPStatus
	}
	if errors.Is(err, icloud.ErrHMEWebRepairRequired) {
		result.Stage = "hme-terms-required"
	}
	return result
}

type hmeFamilyCache struct {
	Version   int                `json:"version"`
	AccountID string             `json:"account_id"`
	CheckedAt time.Time          `json:"checked_at"`
	Family    control.FamilyInfo `json:"family"`
}

func requireHMEFamilyMember(dir string, now time.Time) error {
	data, err := os.ReadFile(filepath.Join(dir, "family-status.json"))
	if err != nil || len(data) == 0 || len(data) > 64<<10 {
		return errors.New("请先读取当前子号的家庭状态")
	}
	var record hmeFamilyCache
	if json.Unmarshal(data, &record) != nil || record.Version != 1 || record.AccountID != filepath.Base(filepath.Clean(dir)) || record.CheckedAt.IsZero() || record.CheckedAt.After(now.Add(5*time.Minute)) {
		return errors.New("当前子号的家庭状态绑定无效")
	}
	if now.Sub(record.CheckedAt) > 15*time.Minute {
		return errors.New("家庭状态已过期，请先重新核验 Apple")
	}
	family := record.Family
	if !family.Member || family.Organizer || family.Organizers != 1 || family.Self != 1 {
		return errors.New("隐藏邮件地址只允许家庭组普通成员使用")
	}
	if !family.StorageKnown || !family.StorageParticipating || !family.StorageAvailable || !family.StorageEnabled || family.StorageBytes < 50<<30 {
		return errors.New("当前子号尚未启用家庭共享 iCloud+")
	}
	return nil
}
