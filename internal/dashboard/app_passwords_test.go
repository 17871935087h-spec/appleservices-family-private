package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Laky-64/appleservices/icloud"
	"github.com/Laky-64/appleservices/internal/credentialvault"
)

const appPasswordFixtureID = "00000000-0000-4000-8000-000000000001"
const appPasswordFixtureNext = "00000000-0000-4000-8000-000000000002"
const appPasswordFixtureSecret = "abcd-efgh-ijkl-mnop"

type fixtureAppPasswordClient struct {
	lists, creates, auths, newClients, restores int
	createErr, listErr, authenticateErr         error
	restoreErr, exportErr                       error
	failurePhase                                string
	failureStatus                               int
	challenge                                   string
	entered                                     chan struct{}
	release                                     chan struct{}
}

func (c *fixtureAppPasswordClient) ListAppPasswords(context.Context) ([]icloud.AppPasswordEntry, error) {
	c.lists++
	return []icloud.AppPasswordEntry{{ID: "7", Description: "fixture client"}}, c.listErr
}
func (c *fixtureAppPasswordClient) CreateAppPassword(_ context.Context, description, password string) (*icloud.AppPasswordResult, error) {
	c.creates++
	c.challenge = password
	if c.entered != nil {
		close(c.entered)
		<-c.release
	}
	if c.createErr != nil {
		return nil, c.createErr
	}
	return &icloud.AppPasswordResult{AppPasswordEntry: icloud.AppPasswordEntry{ID: "8", Description: description}, Password: appPasswordFixtureSecret}, nil
}
func (c *fixtureAppPasswordClient) Authenticate(ctx context.Context, password string, code func(context.Context) (string, error)) error {
	c.auths++
	if password != "fixture primary password" {
		return errors.New("unexpected fixture credential")
	}
	if c.authenticateErr != nil {
		return c.authenticateErr
	}
	_, err := code(ctx)
	return err
}
func (c *fixtureAppPasswordClient) AuthenticationFailure() (string, int) {
	if c.failurePhase != "" || c.failureStatus != 0 {
		return c.failurePhase, c.failureStatus
	}
	return "trusted-code", 409
}
func (c *fixtureAppPasswordClient) ExportAccountSession() ([]byte, error) {
	if c.exportErr != nil {
		return nil, c.exportErr
	}
	return []byte("fixture management session"), nil
}
func (c *fixtureAppPasswordClient) RestoreAccountSession([]byte) error {
	c.restores++
	return c.restoreErr
}

type appPasswordFixtureStore struct {
	mu           sync.Mutex
	data         map[string][]byte
	fail         string
	loadFailures map[string]error
}

func (m *appPasswordFixtureStore) load(_ string, id, name string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.loadFailures[name]; err != nil {
		return nil, err
	}
	data, ok := m.data[id+"/"+name]
	if !ok {
		return nil, credentialvault.ErrNotFound
	}
	return append([]byte(nil), data...), nil
}
func (m *appPasswordFixtureStore) save(_ string, id, name string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail == name {
		return credentialvault.ErrEncryption
	}
	m.data[id+"/"+name] = append([]byte(nil), data...)
	return nil
}

func appPasswordFixture(t *testing.T) (*Server, *Account, *fixtureAppPasswordClient, *appPasswordFixtureStore, *int, *int) {
	t.Helper()
	s, err := New(Config{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.listener.Close() })
	a := &Account{ID: "fixture-01", AppleID: "fixture@example.test", Dir: t.TempDir()}
	s.accounts = []*Account{a}
	c := &fixtureAppPasswordClient{}
	m := &appPasswordFixtureStore{data: map[string][]byte{}}
	p := s.appPasswords
	p.newClient = func(string) (appPasswordClient, error) {
		c.newClients++
		return c, nil
	}
	p.loadBlob = m.load
	p.saveBlob = m.save
	credentials, codes := new(int), new(int)
	p.loadPassword = func(_, id string) (string, error) {
		*credentials++
		if id != a.AppleID {
			t.Error("wrong account credential")
		}
		return "fixture primary password", nil
	}
	p.deviceCode = func(_ context.Context, account *Account) (string, error) {
		*codes++
		if account != a {
			t.Error("wrong account device")
		}
		return "123456", nil
	}
	return s, a, c, m, credentials, codes
}

func fixtureManagementSession(t *testing.T, m *appPasswordFixtureStore, a *Account) {
	t.Helper()
	if err := m.save(a.Dir, a.AppleID, "app-password-session", []byte("fixture")); err != nil {
		t.Fatal(err)
	}
}

func TestAppPasswordStatusNeverLogsInOrLoadsCredentials(t *testing.T) {
	s, a, c, m, credentials, codes := appPasswordFixture(t)
	got := s.appPasswords.run(context.Background(), a, "status", appPasswordInput{})
	if got.Stage != "session_required" || c.lists != 0 || c.auths != 0 || *credentials != 0 || *codes != 0 {
		t.Fatal("status attempted authentication")
	}
	fixtureManagementSession(t, m, a)
	c.listErr = &icloud.AppPasswordError{Stage: "session_required", HTTPStatus: 401}
	got = s.appPasswords.run(context.Background(), a, "status", appPasswordInput{})
	if got.Stage != "session_required" || got.FailurePhase != "list" || got.HTTPStatus != 401 || c.auths != 0 || *credentials != 0 || *codes != 0 {
		t.Fatal("expired status attempted authentication")
	}
}

func TestAppPasswordAuthenticationDiagnosticsAreAllowlistedAndSafe(t *testing.T) {
	allowed := []string{
		"bootstrap", "authorize", "federate", "srp-init", "srp-complete", "trusted-challenge",
		"trusted-code", "trust-session", "oauth-validate", "portal-token", "manage-data",
	}
	for _, phase := range allowed {
		t.Run(phase, func(t *testing.T) {
			s, a, c, _, _, _ := appPasswordFixture(t)
			c.authenticateErr = errors.New("private auth error containing fixture primary password and 123456")
			c.failurePhase = phase
			c.failureStatus = 403
			got := s.appPasswords.run(context.Background(), a, "connect", appPasswordInput{AllowWebLogin: true, AllowDeviceVerification: true})
			if got.FailurePhase != phase || got.HTTPStatus != 403 {
				t.Fatalf("diagnostic projection mismatch: phase=%q status=%d", got.FailurePhase, got.HTTPStatus)
			}
			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var wire map[string]any
			if json.Unmarshal(encoded, &wire) != nil || wire["failure_phase"] != phase || wire["http_status"] != float64(403) {
				t.Fatalf("diagnostics were not serialized safely: %s", encoded)
			}
			for _, forbidden := range []string{"private auth error", "fixture primary password", "123456"} {
				if strings.Contains(string(encoded), forbidden) {
					t.Fatalf("diagnostic leaked %q", forbidden)
				}
			}
		})
	}

	s, a, c, _, _, _ := appPasswordFixture(t)
	c.authenticateErr = errors.New("private auth error with token-shaped stage")
	c.failurePhase = "secret-cookie-or-token"
	c.failureStatus = 600
	got := s.appPasswords.run(context.Background(), a, "connect", appPasswordInput{AllowWebLogin: true, AllowDeviceVerification: true})
	if got.FailurePhase != "" || got.HTTPStatus != 0 {
		t.Fatalf("untrusted diagnostic values passed through: phase=%q status=%d", got.FailurePhase, got.HTTPStatus)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret-cookie-or-token", "private auth error", "fixture primary password", "123456"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("diagnostic leaked %q", forbidden)
		}
	}
	var wire map[string]any
	if json.Unmarshal(encoded, &wire) != nil || wire["failure_phase"] != nil || wire["http_status"] != float64(0) {
		t.Fatal("invalid phase or HTTP status was serialized")
	}
}

func TestAppPasswordLocalFailuresUseFixedPhasesWithoutErrorText(t *testing.T) {
	t.Run("client init", func(t *testing.T) {
		s, a, _, _, _, _ := appPasswordFixture(t)
		s.appPasswords.newClient = func(string) (appPasswordClient, error) {
			return nil, errors.New("private constructor error with cookie value")
		}
		got := s.appPasswords.run(context.Background(), a, "status", appPasswordInput{})
		if got.Stage != "unavailable" || got.FailurePhase != "client_init" || got.HTTPStatus != 0 {
			t.Fatalf("unexpected local diagnostic: %+v", got)
		}
		encoded, _ := json.Marshal(got)
		if strings.Contains(string(encoded), "private constructor error") || strings.Contains(string(encoded), "cookie value") {
			t.Fatal("constructor error text escaped")
		}
	})

	t.Run("records load", func(t *testing.T) {
		s, a, _, m, _, _ := appPasswordFixture(t)
		m.loadFailures = map[string]error{"app-password-intent": errors.New("private records error")}
		got := s.appPasswords.run(context.Background(), a, "status", appPasswordInput{})
		if got.Stage != "unavailable" || got.FailurePhase != "records_load" {
			t.Fatalf("record load failure phase mismatch: %+v", got)
		}
		encoded, _ := json.Marshal(got)
		if strings.Contains(string(encoded), "private records error") {
			t.Fatal("record load error text escaped")
		}
	})

	t.Run("credential load", func(t *testing.T) {
		s, a, c, _, _, codes := appPasswordFixture(t)
		s.appPasswords.loadPassword = func(string, string) (string, error) {
			return "", errors.New("private credential vault detail")
		}
		got := s.appPasswords.run(context.Background(), a, "connect", appPasswordInput{AllowWebLogin: true, AllowDeviceVerification: true})
		if got.Stage != "credential_required" || got.FailurePhase != "credential_load" || c.auths != 0 || *codes != 0 {
			t.Fatalf("credential failure did not stop before login: %+v", got)
		}
		encoded, _ := json.Marshal(got)
		if strings.Contains(string(encoded), "private credential vault detail") {
			t.Fatal("credential vault error text escaped")
		}
	})

	t.Run("session save", func(t *testing.T) {
		s, a, c, _, _, _ := appPasswordFixture(t)
		c.exportErr = errors.New("private session export detail")
		got := s.appPasswords.run(context.Background(), a, "connect", appPasswordInput{AllowWebLogin: true, AllowDeviceVerification: true})
		if got.Stage != "unavailable" || got.FailurePhase != "session_save" || c.auths != 1 || c.lists != 0 || c.creates != 0 || got.CanCreate {
			t.Fatalf("session save failure was not projected: %+v", got)
		}
		encoded, _ := json.Marshal(got)
		if strings.Contains(string(encoded), "private session export detail") {
			t.Fatal("session export error text escaped")
		}
	})
}

func TestAppPasswordConnectPersistsSessionBeforeListFailure(t *testing.T) {
	s, a, c, m, credentials, codes := appPasswordFixture(t)
	c.listErr = &icloud.AppPasswordError{Stage: "unavailable", HTTPStatus: 200}

	connected := s.appPasswords.run(context.Background(), a, "connect", appPasswordInput{AllowWebLogin: true, AllowDeviceVerification: true})
	if connected.Stage != "unavailable" || connected.FailurePhase != "list" || connected.HTTPStatus != 200 ||
		c.auths != 1 || c.lists != 1 || *credentials != 1 || *codes != 1 || connected.CanCreate {
		t.Fatalf("list decode failure projection mismatch: state=%+v auth=%d list=%d credentials=%d codes=%d",
			connected, c.auths, c.lists, *credentials, *codes)
	}
	if _, exists := m.data[a.AppleID+"/app-password-session"]; !exists {
		t.Fatal("successful management authentication was not saved before list decoding")
	}

	status := s.appPasswords.run(context.Background(), a, "status", appPasswordInput{})
	if status.Stage != "unavailable" || status.FailurePhase != "list" || status.HTTPStatus != 200 ||
		c.auths != 1 || c.lists != 2 || *credentials != 1 || *codes != 1 {
		t.Fatalf("status repeated authentication after list failure: state=%+v auth=%d list=%d credentials=%d codes=%d",
			status, c.auths, c.lists, *credentials, *codes)
	}
}

func TestAppPasswordSessionSaveFailurePreventsCreate(t *testing.T) {
	s, a, c, m, _, _ := appPasswordFixture(t)
	fixtureManagementSession(t, m, a)
	m.fail = "app-password-session"

	got := s.appPasswords.run(context.Background(), a, "create", appPasswordInput{Description: "fixture", RequestID: appPasswordFixtureID})
	if got.Stage != "unavailable" || got.FailurePhase != "session_save" || got.CanCreate || c.lists != 1 || c.creates != 0 {
		t.Fatalf("session save failure reached password creation: state=%+v list=%d create=%d", got, c.lists, c.creates)
	}
}

func TestAppPasswordInvalidSessionCacheStatusDoesNotLoginAndConnectRebuildsOnce(t *testing.T) {
	s, a, c, m, credentials, codes := appPasswordFixture(t)
	fixtureManagementSession(t, m, a)
	c.restoreErr = &icloud.AppPasswordError{Stage: "invalid_request"}

	status := s.appPasswords.run(context.Background(), a, "status", appPasswordInput{})
	if status.Stage != "session_required" || status.FailurePhase != "session_restore" || c.auths != 0 || *credentials != 0 || *codes != 0 {
		t.Fatalf("status did not safely report a malformed cache: %+v", status)
	}
	if _, exists := m.data[a.AppleID+"/app-password-session"]; !exists {
		t.Fatal("status removed the cached session")
	}

	clientsBefore := c.newClients
	connected := s.appPasswords.run(context.Background(), a, "connect", appPasswordInput{AllowWebLogin: true, AllowDeviceVerification: true})
	if connected.Stage != "ready" || connected.FailurePhase != "" || connected.HTTPStatus != 0 ||
		c.newClients-clientsBefore != 2 || c.restores != 2 || c.auths != 1 || c.lists != 1 || *credentials != 1 || *codes != 1 {
		t.Fatalf("connect did not rebuild then authenticate once: state=%+v clients=%d restores=%d auth=%d lists=%d credentials=%d codes=%d",
			connected, c.newClients-clientsBefore, c.restores, c.auths, c.lists, *credentials, *codes)
	}
}

func TestAppPasswordSessionReadFailureCannotBeTreatedAsMissingSession(t *testing.T) {
	s, a, c, m, credentials, codes := appPasswordFixture(t)
	m.loadFailures = map[string]error{"app-password-session": credentialvault.ErrInvalidData}

	for _, action := range []string{"status", "connect"} {
		in := appPasswordInput{}
		if action == "connect" {
			in = appPasswordInput{AllowWebLogin: true, AllowDeviceVerification: true}
		}
		got := s.appPasswords.run(context.Background(), a, action, in)
		if got.Stage != "unavailable" || got.FailurePhase != "session_load" || got.HTTPStatus != 0 {
			t.Fatalf("%s bypassed a DPAPI read failure: %+v", action, got)
		}
	}
	if c.auths != 0 || *credentials != 0 || *codes != 0 {
		t.Fatal("a failed session read was treated as an absent session")
	}
}

func TestAppPasswordConnectIsExplicitAndBoundToSelectedDevice(t *testing.T) {
	s, a, c, _, credentials, codes := appPasswordFixture(t)
	for _, in := range []appPasswordInput{{}, {AllowWebLogin: true}, {AllowDeviceVerification: true}, {AllowWebLogin: true, AllowDeviceVerification: true, RequestID: appPasswordFixtureID}} {
		if validAppPasswordInput("connect", in) {
			t.Fatal("incomplete consent accepted")
		}
	}
	got := s.appPasswords.run(context.Background(), a, "connect", appPasswordInput{AllowWebLogin: true, AllowDeviceVerification: true})
	if got.Stage != "ready" || c.auths != 1 || c.lists != 1 || *credentials != 1 || *codes != 1 || !got.CanCreate {
		t.Fatal("connect did not bind authentication to selected account")
	}
}

func TestAppPasswordCreateIsDurablyIdempotentAndRecoverable(t *testing.T) {
	s, a, c, m, credentials, codes := appPasswordFixture(t)
	fixtureManagementSession(t, m, a)
	in := appPasswordInput{Description: "邮件客户端", RequestID: appPasswordFixtureID}
	got := s.appPasswords.run(context.Background(), a, "create", in)
	if got.Stage != "generated" || got.Password != appPasswordFixtureSecret || c.creates != 1 || *credentials != 0 || *codes != 0 {
		t.Fatal("create failed")
	}
	// Recreate the service to simulate a restart; only the DPAPI seam persists.
	p := newAppPasswordService(s)
	p.newClient = s.appPasswords.newClient
	p.loadBlob = m.load
	p.saveBlob = m.save
	got = p.run(context.Background(), a, "create", in)
	if got.Stage != "generated" || got.Password != appPasswordFixtureSecret || c.creates != 1 {
		t.Fatal("retry issued another Apple POST")
	}
	got = p.run(context.Background(), a, "status", appPasswordInput{})
	if got.Password != "" || !got.ResultAvailable || got.RequestID != in.RequestID {
		t.Fatal("status disclosed or lost result")
	}
	got = p.run(context.Background(), a, "result", appPasswordInput{RequestID: in.RequestID})
	if got.Password != appPasswordFixtureSecret || c.creates != 1 {
		t.Fatal("explicit recovery failed")
	}
	in.RequestID = appPasswordFixtureNext
	got = p.run(context.Background(), a, "create", in)
	if got.Stage != "generated" || c.creates != 2 {
		t.Fatal("new request did not generate")
	}
	in.RequestID = appPasswordFixtureID
	got = p.run(context.Background(), a, "create", in)
	if got.Stage != "invalid_request" || c.creates != 2 {
		t.Fatal("old result retry became a new generation")
	}
}

func TestAppPasswordUnknownRequiresReviewAndNeverReusesOldID(t *testing.T) {
	s, a, c, m, _, _ := appPasswordFixture(t)
	fixtureManagementSession(t, m, a)
	c.createErr = &icloud.AppPasswordError{Stage: "outcome_unknown"}
	in := appPasswordInput{Description: "fixture", RequestID: appPasswordFixtureID}
	got := s.appPasswords.run(context.Background(), a, "create", in)
	if got.Stage != "outcome_unknown" || c.creates != 1 {
		t.Fatal("uncertain result was lost")
	}
	got = s.appPasswords.run(context.Background(), a, "create", in)
	if got.Stage != "outcome_unknown" || c.creates != 1 {
		t.Fatal("retry of an unknown write repeated the Apple POST")
	}
	in.RequestID = appPasswordFixtureNext
	got = s.appPasswords.run(context.Background(), a, "create", in)
	if got.Stage != "outcome_unknown" || c.creates != 1 || got.RequestID != appPasswordFixtureID {
		t.Fatal("unknown operation was retried")
	}
	got = s.appPasswords.run(context.Background(), a, "status", appPasswordInput{})
	if got.Stage != "outcome_unknown" || got.CanCreate || len(got.Items) != 1 {
		t.Fatal("unknown status did not allow read-only inspection")
	}
	c.listErr = &icloud.AppPasswordError{Stage: "session_required"}
	got = s.appPasswords.run(context.Background(), a, "review", appPasswordInput{RequestID: appPasswordFixtureID})
	if got.Stage != "outcome_unknown" || got.CanCreate || c.auths != 0 || c.creates != 1 {
		t.Fatal("review unlocked without a successful list")
	}
	c.listErr = nil
	got = s.appPasswords.run(context.Background(), a, "review", appPasswordInput{RequestID: appPasswordFixtureID})
	if got.Stage != "ready" || !got.CanCreate || c.creates != 1 {
		t.Fatal("review mutated Apple")
	}
	in.RequestID = appPasswordFixtureID
	got = s.appPasswords.run(context.Background(), a, "create", in)
	if got.Stage != "invalid_request" || c.creates != 1 {
		t.Fatal("reviewed ID was replayed")
	}
	c.createErr = nil
	in.RequestID = appPasswordFixtureNext
	got = s.appPasswords.run(context.Background(), a, "create", in)
	if got.Stage != "generated" || c.creates != 2 {
		t.Fatal("new operation stayed blocked after review")
	}
}

func TestAppPasswordCrashRecoveryCompletesLedgerBeforeReplacingResult(t *testing.T) {
	s, a, c, m, _, _ := appPasswordFixture(t)
	fixtureManagementSession(t, m, a)
	input := appPasswordInput{Description: "fixture", RequestID: appPasswordFixtureID}
	if s.appPasswords.run(context.Background(), a, "create", input).Stage != "generated" {
		t.Fatal("fixture generation failed")
	}
	// Simulate process loss after saving the password but before the success
	// marker was committed. Do not reconstruct an actual Apple response.
	ledger, _, err := s.appPasswords.readRecords(a)
	if err != nil {
		t.Fatal(err)
	}
	ledger.Entries[0].Stage = "pending"
	if s.appPasswords.saveJSON(a, "app-password-intent", ledger) != nil {
		t.Fatal("fixture intent failed")
	}
	input.RequestID = appPasswordFixtureNext
	m.fail = "app-password-intent"
	blocked := s.appPasswords.run(context.Background(), a, "create", input)
	if blocked.Stage != "unavailable" || c.creates != 1 {
		t.Fatal("unreconciled success was replaced")
	}
	m.fail = ""
	if s.appPasswords.run(context.Background(), a, "create", input).Stage != "generated" || c.creates != 2 {
		t.Fatal("reconciled next generation failed")
	}
	status := s.appPasswords.run(context.Background(), a, "status", appPasswordInput{})
	if status.Stage != "ready" || !status.CanCreate {
		t.Fatal("old completed intent became unknown after result replacement")
	}
}

func TestAppPasswordChallengeRequiresSeparateConsentAndSameDescription(t *testing.T) {
	s, a, c, m, credentials, codes := appPasswordFixture(t)
	fixtureManagementSession(t, m, a)
	c.createErr = &icloud.AppPasswordError{Stage: "password_required", HTTPStatus: 451}
	in := appPasswordInput{Description: "fixture", RequestID: appPasswordFixtureID}
	got := s.appPasswords.run(context.Background(), a, "create", in)
	if got.Stage != "password_required" || *credentials != 0 {
		t.Fatal("challenge loaded unapproved password")
	}
	in.Description = "different"
	in.AllowPasswordChallenge = true
	got = s.appPasswords.run(context.Background(), a, "create", in)
	if got.Stage != "invalid_request" || c.creates != 1 || *credentials != 0 {
		t.Fatal("request ID was rebound")
	}
	in.Description = "fixture"
	c.createErr = nil
	got = s.appPasswords.run(context.Background(), a, "create", in)
	if got.Stage != "generated" || c.creates != 2 || c.challenge != "fixture primary password" || *credentials != 1 || *codes != 0 || c.auths != 0 {
		t.Fatal("challenge consent was not isolated")
	}
}

func TestAppPasswordIntentAndResultWriteFailuresNeverRepeatApplePost(t *testing.T) {
	for _, failed := range []string{"app-password-intent", "app-password-result"} {
		t.Run(failed, func(t *testing.T) {
			s, a, c, m, _, _ := appPasswordFixture(t)
			fixtureManagementSession(t, m, a)
			m.fail = failed
			in := appPasswordInput{Description: "fixture", RequestID: appPasswordFixtureID}
			got := s.appPasswords.run(context.Background(), a, "create", in)
			if failed == "app-password-intent" {
				if c.creates != 0 || got.Stage != "unavailable" {
					t.Fatal("POST occurred before durable intent")
				}
				return
			}
			if c.creates != 1 || got.Stage != "outcome_unknown" {
				t.Fatal("result failure reported success")
			}
			m.fail = ""
			got = s.appPasswords.run(context.Background(), a, "create", in)
			if c.creates != 1 || got.Stage != "outcome_unknown" {
				t.Fatal("result storage failure caused a repeated POST")
			}
		})
	}
}

func TestAppPasswordAccountLockRejectsConcurrentGenerate(t *testing.T) {
	s, a, c, m, _, _ := appPasswordFixture(t)
	fixtureManagementSession(t, m, a)
	c.entered = make(chan struct{})
	c.release = make(chan struct{})
	done := make(chan appPasswordState, 1)
	go func() {
		done <- s.appPasswords.run(context.Background(), a, "create", appPasswordInput{Description: "fixture", RequestID: appPasswordFixtureID})
	}()
	<-c.entered
	got := s.appPasswords.run(context.Background(), a, "create", appPasswordInput{Description: "fixture", RequestID: appPasswordFixtureNext})
	if got.Stage != "busy" {
		t.Fatal("concurrent generation was not blocked")
	}
	close(c.release)
	if (<-done).Stage != "generated" || c.creates != 1 {
		t.Fatal("concurrent generation sent extra POST")
	}
}

func TestAppPasswordsAPIAuthenticationValidationAndSecretProjection(t *testing.T) {
	s, a, c, m, _, _ := appPasswordFixture(t)
	fixtureManagementSession(t, m, a)
	for _, item := range []struct {
		action, body, account, token string
		status                       int
	}{
		{"status", `{}`, a.ID, "", 403},
		{"status", `{}`, "", s.token, 400},
		{"status", `{"allow_web_login":true}`, a.ID, s.token, 400},
		{"connect", `{"allow_web_login":true}`, a.ID, s.token, 400},
		{"create", `{"description":"fixture","request_id":"bad"}`, a.ID, s.token, 400},
		{"status", `{"password":"primary-fixture"}`, a.ID, s.token, 400},
	} {
		req := httptest.NewRequest("POST", s.URL()+"/api/app-passwords/"+item.action+"?account="+item.account, strings.NewReader(item.body))
		req.Header.Set("X-App-Token", item.token)
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		s.ServeHTTP(res, req)
		if res.Code != item.status {
			t.Fatalf("unexpected status: %d", res.Code)
		}
	}
	if c.auths != 0 || c.creates != 0 || c.lists != 0 {
		t.Fatal("invalid input invoked Apple")
	}
	s.appPasswords.run(context.Background(), a, "create", appPasswordInput{Description: "fixture", RequestID: appPasswordFixtureID})
	req := httptest.NewRequest("POST", s.URL()+"/api/app-passwords/status?account="+a.ID, strings.NewReader(`{}`))
	req.Header.Set("X-App-Token", s.token)
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	s.ServeHTTP(res, req)
	if res.Code != 200 || strings.Contains(res.Body.String(), appPasswordFixtureSecret) || strings.Contains(res.Body.String(), "fixture management session") {
		t.Fatal("state leaked secret")
	}
	var value appPasswordState
	if json.Unmarshal(res.Body.Bytes(), &value) != nil || !value.ResultAvailable || value.AccountID != a.ID {
		t.Fatal("safe projection failed")
	}
}
