package v2gateway

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"time"
)

const (
	accountDeletionsPath    = "/v1/accounts/deletions"
	maxAccountDeletionBatch = 100
	maxDeletionWaitSeconds  = 30
)

type accountDeletionsReply struct {
	Events       []accountDeletionEvent `json:"events"`
	NextSequence int64                  `json:"next_sequence"`
}

func (g *Gateway) handleAccountDeletions(w http.ResponseWriter, r *http.Request) {
	after, limit, waitSeconds, err := parseAccountDeletionQuery(r.URL.Query())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorReply{OK: false, Stage: "invalid_request", Message: safeInvalidRequest})
		return
	}

	registry, err := loadRegistry(g.config.RegistryPath)
	if err != nil {
		writeDeletionFeedUnavailable(w)
		return
	}
	if after > registry.DeletionSequence {
		writeJSON(w, http.StatusBadRequest, errorReply{OK: false, Stage: "invalid_cursor", Message: safeInvalidRequest})
		return
	}
	if reply, ok := deletionReplyAfter(registry, after, limit); ok || waitSeconds == 0 {
		writeJSON(w, http.StatusOK, reply)
		return
	}

	resolvedRegistryPath, err := filepath.EvalSymlinks(filepath.Clean(g.config.RegistryPath))
	if err != nil {
		writeDeletionFeedUnavailable(w)
		return
	}
	watcher, err := newRegistryWatcher(filepath.Dir(resolvedRegistryPath))
	if err != nil {
		writeDeletionFeedUnavailable(w)
		return
	}
	defer watcher.Close()
	deadline := time.Now().Add(time.Duration(waitSeconds) * time.Second)
	for {
		// The watcher is armed before this read, so a deletion between the
		// initial snapshot and watcher creation is still observed here.
		registry, err = loadRegistry(g.config.RegistryPath)
		if err != nil {
			writeDeletionFeedUnavailable(w)
			return
		}
		if after > registry.DeletionSequence {
			writeJSON(w, http.StatusBadRequest, errorReply{OK: false, Stage: "invalid_cursor", Message: safeInvalidRequest})
			return
		}
		if reply, ok := deletionReplyAfter(registry, after, limit); ok {
			writeJSON(w, http.StatusOK, reply)
			return
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			writeJSON(w, http.StatusOK, accountDeletionsReply{Events: []accountDeletionEvent{}, NextSequence: after})
			return
		}
		changed, err := watcher.Wait(r.Context(), remaining)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || r.Context().Err() != nil {
				return
			}
			writeDeletionFeedUnavailable(w)
			return
		}
		if !changed {
			writeJSON(w, http.StatusOK, accountDeletionsReply{Events: []accountDeletionEvent{}, NextSequence: after})
			return
		}
	}
}

func parseAccountDeletionQuery(query url.Values) (after int64, limit, waitSeconds int, err error) {
	for key, values := range query {
		if (key != "after" && key != "limit" && key != "wait_seconds") || len(values) != 1 {
			return 0, 0, 0, errors.New("invalid account deletion query")
		}
	}
	if value, ok := query["after"]; ok {
		after, err = strconv.ParseInt(value[0], 10, 64)
		if err != nil || after < 0 {
			return 0, 0, 0, errors.New("invalid account deletion cursor")
		}
	}
	limit = maxAccountDeletionBatch
	if value, ok := query["limit"]; ok {
		limit, err = strconv.Atoi(value[0])
		if err != nil || limit < 1 || limit > maxAccountDeletionBatch {
			return 0, 0, 0, errors.New("invalid account deletion limit")
		}
	}
	if value, ok := query["wait_seconds"]; ok {
		waitSeconds, err = strconv.Atoi(value[0])
		if err != nil || waitSeconds < 0 || waitSeconds > maxDeletionWaitSeconds {
			return 0, 0, 0, errors.New("invalid account deletion wait")
		}
	}
	return after, limit, waitSeconds, nil
}

func deletionReplyAfter(registry accountRegistry, after int64, limit int) (accountDeletionsReply, bool) {
	events := make([]accountDeletionEvent, 0, limit)
	for _, event := range registry.DeletionEvents {
		if event.Sequence <= after {
			continue
		}
		events = append(events, event)
		if len(events) == limit {
			break
		}
	}
	if len(events) == 0 {
		return accountDeletionsReply{Events: events, NextSequence: after}, false
	}
	return accountDeletionsReply{Events: events, NextSequence: events[len(events)-1].Sequence}, true
}

func writeDeletionFeedUnavailable(w http.ResponseWriter) {
	writeJSON(w, http.StatusServiceUnavailable, errorReply{OK: false, Stage: "deletion_feed_unavailable", Message: safeServiceFailure})
}
