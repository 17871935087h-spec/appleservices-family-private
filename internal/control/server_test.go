package control

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestControlRequiresLocalHostSecretAndNoBrowserOrigin(t *testing.T) {
	server, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, test := range []struct{ name, token, host, origin string }{
		{"missing-token", "", "", ""}, {"wrong-token", "wrong", "", ""},
		{"foreign-host", server.Record.Token, "attacker.example", ""},
		{"browser-origin", server.Record.Token, "", "http://attacker.example"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, _ := http.NewRequest("POST", server.Record.URL+"/action", bytes.NewBufferString(`{"action":"code"}`))
			request.Header.Set("X-Control-Token", test.token)
			if test.host != "" {
				request.Host = test.host
			}
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != 403 {
				t.Fatal("unauthorized control request reached daemon")
			}
		})
	}
}

func TestFamilyAddCapabilityReflectsInMemoryPasswordAvailability(t *testing.T) {
	dir := t.TempDir()
	server, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	data, _ := json.Marshal(map[string]any{"pid": server.Record.PID})
	if err := os.WriteFile(filepath.Join(dir, "runtime.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, ready := range []bool{false, true, false} {
		server.SetFamilyAddReady(ready)
		request, _ := http.NewRequest(http.MethodGet, server.Record.URL+"/view", nil)
		request.Header.Set("X-Control-Token", server.Record.Token)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		var view View
		decodeErr := json.NewDecoder(response.Body).Decode(&view)
		_ = response.Body.Close()
		if decodeErr != nil || slices.Contains(view.Capabilities, FamilyAddReadyCapability) != ready {
			t.Fatalf("family add capability does not match readiness=%v", ready)
		}
	}
}

func TestOneShotFamilyCredentialCapabilityAndRequestStayTransient(t *testing.T) {
	dir := t.TempDir()
	server, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	data, _ := json.Marshal(map[string]any{"pid": server.Record.PID, "running": true})
	if err := os.WriteFile(filepath.Join(dir, "runtime.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	server.SetFamilyAddOneShotCredentialReady(true)
	request, _ := http.NewRequest(http.MethodGet, server.Record.URL+"/view", nil)
	request.Header.Set("X-Control-Token", server.Record.Token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var view View
	decodeErr := json.NewDecoder(response.Body).Decode(&view)
	_ = response.Body.Close()
	if decodeErr != nil || !slices.Contains(view.Capabilities, FamilyAddOneShotCredentialCapability) {
		t.Fatalf("one-shot capability missing: %#v %v", view.Capabilities, decodeErr)
	}

	secret := `target-one-shot-"credential"`
	received := make(chan Action, 1)
	go func() {
		command := <-server.Commands
		received <- command.Action
		command.Reply <- Result{OK: true, Stage: "family-added", Message: "completed"}
	}()
	body, _ := json.Marshal(Action{Action: "family-add-self", Code: "org-01", TargetAppleID: "target@example.test", TargetPassword: secret})
	request, _ = http.NewRequest(http.MethodPost, server.Record.URL+"/action", bytes.NewReader(body))
	request.Header.Set("X-Control-Token", server.Record.Token)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	decodeErr = json.NewDecoder(response.Body).Decode(&result)
	_ = response.Body.Close()
	if decodeErr != nil || !result.OK || strings.Contains(result.Message, secret) {
		t.Fatalf("one-shot credential response was invalid or leaked: %#v %v", result, decodeErr)
	}
	command := <-received
	if command.Action != "family-add-self" || command.TargetAppleID != "target@example.test" || command.TargetPassword != secret {
		t.Fatalf("one-shot credential did not reach the request command: %#v", command)
	}
	for _, name := range []string{"control.json", "runtime.json"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || bytes.Contains(data, []byte(secret)) {
			t.Fatalf("one-shot credential persisted in %s: err=%v", name, err)
		}
	}
}

func TestControlRejectsCredentialFieldsOutsideFamilyAddAndOversizedPassword(t *testing.T) {
	server, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, body := range []string{
		`{"action":"code","target_apple_id":"target@example.test","target_password":"secret"}`,
		`{"action":"family-add-self","target_apple_id":"target@example.test","target_password":"` + strings.Repeat("a", MaxOneShotFamilyPasswordBytes+1) + `"}`,
	} {
		request, _ := http.NewRequest(http.MethodPost, server.Record.URL+"/action", strings.NewReader(body))
		request.Header.Set("X-Control-Token", server.Record.Token)
		request.Header.Set("Content-Type", "application/json")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid credential action status=%d", response.StatusCode)
		}
	}
}

func TestControlDeliversCodeOnlyToRequestAndRemovesCapability(t *testing.T) {
	dir := t.TempDir()
	server, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]any{"pid": server.Record.PID, "running": true})
	if err := os.WriteFile(filepath.Join(dir, "runtime.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	received := make(chan string, 1)
	go func() {
		command := <-server.Commands
		received <- command.Action.Action
		command.Reply <- Result{OK: true, Code: "000123", HideAt: time.Now().Add(time.Minute)}
	}()
	request, _ := http.NewRequest("POST", server.Record.URL+"/action", bytes.NewBufferString(`{"action":"code"}`))
	request.Header.Set("X-Control-Token", server.Record.Token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	err = json.NewDecoder(response.Body).Decode(&result)
	response.Body.Close()
	if err != nil || !result.OK || result.Code != "000123" || <-received != "code" {
		t.Fatal("code response was lost")
	}
	files, _ := os.ReadDir(dir)
	for _, file := range files {
		data, _ := os.ReadFile(filepath.Join(dir, file.Name()))
		if bytes.Contains(data, []byte("000123")) {
			t.Fatal("verification code persisted to disk")
		}
	}
	server.Close()
	if _, err := os.Stat(filepath.Join(dir, "control.json")); !os.IsNotExist(err) {
		t.Fatal("control capability survived shutdown")
	}
}

func TestControlRejectsUnknownOrOversizedInput(t *testing.T) {
	server, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, body := range []string{`{"action":"delete-account"}`, `{"action":"code","unexpected":"value"}`, `{"action":"code"} {"action":"allow"}`} {
		request, _ := http.NewRequest("POST", server.Record.URL+"/action", bytes.NewBufferString(body))
		request.Header.Set("X-Control-Token", server.Record.Token)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != 400 {
			t.Fatal("ambiguous control input accepted")
		}
	}
}

func TestControlAcceptsHMEWebTermsAction(t *testing.T) {
	dir := t.TempDir()
	server, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	data, _ := json.Marshal(map[string]any{"pid": server.Record.PID, "running": true})
	if err := os.WriteFile(filepath.Join(dir, "runtime.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	go func() {
		command := <-server.Commands
		command.Reply <- Result{OK: command.Action.Action == "hme-accept-terms"}
	}()
	request, _ := http.NewRequest("POST", server.Record.URL+"/action", bytes.NewBufferString(`{"action":"hme-accept-terms"}`))
	request.Header.Set("X-Control-Token", server.Record.Token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result Result
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&result) != nil || !result.OK {
		t.Fatal("hme-accept-terms action was not delivered")
	}
}
