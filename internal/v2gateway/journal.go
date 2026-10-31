package v2gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	journalVersion    = 1
	stateIntent       = "intent"
	stateSucceeded    = "succeeded"
	stateUnknown      = "outcome_unknown"
	stateNotSubmitted = "not_submitted"
)

type operationRecord struct {
	Version            int     `json:"version"`
	OperationID        string  `json:"operation_id"`
	Action             string  `json:"action"`
	OrganizerAccountID string  `json:"organizer_account_id"`
	TargetAccountID    string  `json:"target_account_id"`
	State              string  `json:"state"`
	Stage              string  `json:"stage,omitempty"`
	Message            string  `json:"message,omitempty"`
	Family             *Family `json:"family,omitempty"`
}

type journal struct {
	dir     string
	mu      sync.Mutex
	records map[string]operationRecord
	blocked map[string]bool
}

func openJournal(dir string) (*journal, error) {
	resolved, err := validateIntentDirectory(dir)
	if err != nil {
		return nil, err
	}
	store := &journal{dir: resolved, records: make(map[string]operationRecord), blocked: make(map[string]bool)}
	entries, err := os.ReadDir(resolved)
	if err != nil {
		return nil, errors.New("intent journal is unavailable")
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "op-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(resolved, entry.Name()))
		if readErr != nil || len(data) > 16<<10 {
			return nil, errors.New("intent journal is invalid")
		}
		var record operationRecord
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&record) != nil || decoder.Decode(&struct{}{}) != io.EOF || !validRecord(record) || entry.Name() != journalName(record.OperationID) {
			return nil, errors.New("intent journal is invalid")
		}
		if _, duplicate := store.records[record.OperationID]; duplicate {
			return nil, errors.New("intent journal is ambiguous")
		}
		if record.State == stateIntent {
			record = unknownRecord(record)
			if err := store.writeRecord(record); err != nil {
				return nil, errors.New("could not recover interrupted intent")
			}
		}
		store.records[record.OperationID] = record
		if record.State == stateUnknown {
			store.blocked[record.OrganizerAccountID] = true
		}
	}
	return store, nil
}

func validRecord(record operationRecord) bool {
	if record.Version != journalVersion || !validOperationID(record.OperationID) || !validAccountID(record.OrganizerAccountID) || !validJournalTarget(record.Action, record.OrganizerAccountID, record.TargetAccountID) {
		return false
	}
	switch record.State {
	case stateIntent:
		return record.Stage == "" && record.Message == "" && record.Family == nil
	case stateUnknown:
		return record.Stage == "outcome_unknown" && record.Message == safeUnknownMessage && record.Family == nil
	case stateNotSubmitted:
		return record.Action == "family-remove-ref" && record.Stage == "family-remove-preflight" && record.Message == safePreflightMessage && record.Family == nil
	case stateSucceeded:
		if record.Action == "family-add" {
			return record.Stage == "family-added" && record.Message == safeAddedMessage && record.Family != nil
		}
		if record.Action == "family-remove" || record.Action == "family-remove-ref" {
			return (record.Stage == "family-member-removed" && record.Message == safeRemovedMessage || record.Stage == "family-remove-cache-warning" && record.Message == safeRemoveCacheMessage) && record.Family != nil
		}
		return false
	default:
		return false
	}
}

func validJournalTarget(action, organizerID, target string) bool {
	switch action {
	case "family-add", "family-remove":
		return validAccountID(target) && organizerID != target
	case "family-remove-ref":
		if len(target) != 64 {
			return false
		}
		for _, r := range target {
			if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func journalName(operationID string) string { return "op-" + operationID + ".json" }

func (j *journal) lookup(operationID string) (operationRecord, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	record, ok := j.records[operationID]
	return record, ok
}

func (j *journal) isBlocked(organizerID string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.blocked[organizerID]
}

func (j *journal) create(record operationRecord) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, exists := j.records[record.OperationID]; exists {
		return errors.New("operation id already exists")
	}
	if !validRecord(record) || record.State != stateIntent {
		return errors.New("invalid intent record")
	}
	if err := j.writeRecord(record); err != nil {
		return errors.New("could not persist intent")
	}
	j.records[record.OperationID] = record
	return nil
}

func (j *journal) markUnknown(operationID string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	record, ok := j.records[operationID]
	if !ok {
		return
	}
	unknown := unknownRecord(record)
	// Block in memory before persistence. If disk is unavailable, the on-disk
	// intent remains and is recovered as unknown at the next startup.
	j.blocked[record.OrganizerAccountID] = true
	if j.writeRecord(unknown) == nil {
		j.records[operationID] = unknown
	}
}

func (j *journal) complete(record operationRecord) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	current, ok := j.records[record.OperationID]
	if !ok || current.State != stateIntent || current.Action != record.Action || current.OrganizerAccountID != record.OrganizerAccountID || current.TargetAccountID != record.TargetAccountID || !validRecord(record) || record.State != stateSucceeded {
		if ok {
			j.blocked[current.OrganizerAccountID] = true
		}
		return false
	}
	if err := j.writeRecord(record); err != nil {
		j.blocked[current.OrganizerAccountID] = true
		return false
	}
	j.records[record.OperationID] = record
	return true
}

func (j *journal) completeNotSubmitted(record operationRecord) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	current, ok := j.records[record.OperationID]
	if !ok || current.State != stateIntent || current.Action != record.Action || current.OrganizerAccountID != record.OrganizerAccountID || current.TargetAccountID != record.TargetAccountID || !validRecord(record) || record.State != stateNotSubmitted {
		if ok {
			j.blocked[current.OrganizerAccountID] = true
		}
		return false
	}
	if err := j.writeRecord(record); err != nil {
		j.blocked[current.OrganizerAccountID] = true
		return false
	}
	j.records[record.OperationID] = record
	return true
}

func unknownRecord(record operationRecord) operationRecord {
	record.State = stateUnknown
	record.Stage = "outcome_unknown"
	record.Message = safeUnknownMessage
	record.Family = nil
	return record
}

func (j *journal) writeRecord(record operationRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(j.dir, ".intent-*.tmp")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, filepath.Join(j.dir, journalName(record.OperationID))); err != nil {
		return err
	}
	return nil
}
