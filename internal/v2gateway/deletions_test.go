package v2gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestAccountDeletionsFeedReplaysRedactedEventsAndPagesBySequence(t *testing.T) {
	registry := accountRegistry{
		DeletionSequence: 2,
		DeletionEvents: []accountDeletionEvent{
			{Sequence: 1, AccountID: "account-a", AppleIDSHA256: strings.Repeat("a", 64)},
			{Sequence: 2, AccountID: "account-b", AppleIDSHA256: strings.Repeat("b", 64)},
		},
	}
	data, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	registryPath := testRegistry(t, string(data))
	fake := newFakeDashboard(t, func(http.ResponseWriter, *http.Request, dashboardActionCall) {
		t.Error("account deletion feed must not call the dashboard")
	})
	gateway := testGateway(t, fake, registryPath, "", time.Second)

	first := accountDeletionsRequest(t, gateway, "/v1/accounts/deletions?after=0&limit=1&wait_seconds=0", testBearer)
	if first.Code != http.StatusOK {
		t.Fatalf("first page status = %d, body=%s", first.Code, first.Body.String())
	}
	firstReply := decodeGatewayResponse[accountDeletionsReply](t, first)
	if len(firstReply.Events) != 1 || firstReply.Events[0].Sequence != 1 || firstReply.Events[0].AccountID != "account-a" || firstReply.NextSequence != 1 {
		t.Fatalf("first page = %#v", firstReply)
	}
	if strings.Contains(first.Body.String(), "Person@Example") || strings.Contains(first.Body.String(), "apple_id\"") {
		t.Fatalf("feed exposed an unredacted Apple ID: %s", first.Body.String())
	}

	second := accountDeletionsRequest(t, gateway, "/v1/accounts/deletions?after=1&limit=1", testBearer)
	secondReply := decodeGatewayResponse[accountDeletionsReply](t, second)
	if second.Code != http.StatusOK || len(secondReply.Events) != 1 || secondReply.Events[0].Sequence != 2 || secondReply.NextSequence != 2 {
		t.Fatalf("second page status=%d reply=%#v", second.Code, secondReply)
	}

	invalidCursor := accountDeletionsRequest(t, gateway, "/v1/accounts/deletions?after=3", testBearer)
	if invalidCursor.Code != http.StatusBadRequest {
		t.Fatalf("cursor beyond durable sequence status = %d", invalidCursor.Code)
	}
	invalidQuery := accountDeletionsRequest(t, gateway, "/v1/accounts/deletions?after=0&unknown=1", testBearer)
	if invalidQuery.Code != http.StatusBadRequest {
		t.Fatalf("unknown query key status = %d", invalidQuery.Code)
	}
	unauthorized := accountDeletionsRequest(t, gateway, "/v1/accounts/deletions?after=0", "wrong")
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.Code)
	}
}

func TestAccountDeletionsLongPollWakesAfterRegistryChange(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the production registry watcher uses Windows directory change notifications")
	}
	registryPath := testRegistry(t, `{"accounts":[]}`)
	fake := newFakeDashboard(t, func(http.ResponseWriter, *http.Request, dashboardActionCall) {
		t.Error("account deletion feed must not call the dashboard")
	})
	gateway := testGateway(t, fake, registryPath, "", time.Second)
	started := time.Now()
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		result <- accountDeletionsRequest(t, gateway, "/v1/accounts/deletions?after=0&limit=100&wait_seconds=30", testBearer)
	}()

	// Use the same atomic temp-file replacement performed by the dashboard.
	// If it happens before the watcher is armed, the handler's second snapshot
	// still returns the durable event.
	time.Sleep(100 * time.Millisecond)
	updated := accountRegistry{
		DeletionSequence: 1,
		DeletionEvents:   []accountDeletionEvent{{Sequence: 1, AccountID: "account-a", AppleIDSHA256: strings.Repeat("c", 64)}},
	}
	data, err := json.Marshal(updated)
	if err != nil {
		t.Fatal(err)
	}
	temp := registryPath + ".tmp"
	if err := os.WriteFile(temp, data, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(temp, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temp, registryPath); err != nil {
		t.Fatal(err)
	}

	select {
	case response := <-result:
		if response.Code != http.StatusOK {
			t.Fatalf("long-poll status = %d, body=%s", response.Code, response.Body.String())
		}
		reply := decodeGatewayResponse[accountDeletionsReply](t, response)
		if len(reply.Events) != 1 || reply.Events[0].AccountID != "account-a" || reply.NextSequence != 1 {
			t.Fatalf("long-poll reply = %#v", reply)
		}
		if time.Since(started) > 5*time.Second {
			t.Fatal("long-poll did not wake promptly after the registry event was committed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("long-poll did not wake after the registry event was committed")
	}
}

func accountDeletionsRequest(t *testing.T, gateway *Gateway, path, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Authorization", "Bearer "+bearer)
	response := httptest.NewRecorder()
	gateway.ServeHTTP(response, request)
	return response
}
