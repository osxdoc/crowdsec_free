package blocklistserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/modelscapi"
	"github.com/go-openapi/strfmt"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T, mutate func(*Config)) (*httptest.Server, *Store) {
	t.Helper()

	store, err := OpenStore(filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)

	cfg := &Config{
		DBPath:     filepath.Join(t.TempDir(), "unused.db"),
		AdminToken: "admin-secret",
	}
	require.NoError(t, cfg.SetDefaults())

	if mutate != nil {
		mutate(cfg)
		require.NoError(t, cfg.SetDefaults())
	}

	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	srv, err := NewServer(cfg, store, logger)
	require.NoError(t, err)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(func() { _ = store.Close() })

	return ts, store
}

type testResponse struct {
	StatusCode int
	Header     http.Header
}

func doJSON(t *testing.T, method, url string, body any, token string) (testResponse, []byte) {
	t.Helper()

	var reader io.Reader

	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)

		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(method, url, reader)
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return testResponse{StatusCode: resp.StatusCode, Header: resp.Header}, payload
}

func registerAndLogin(t *testing.T, baseURL string) string {
	t.Helper()

	pwd := strfmt.Password("supersecret")

	resp, body := doJSON(t, http.MethodPost, baseURL+"/v1/watchers",
		models.WatcherRegistrationRequest{
			MachineID: new("test-machine"),
			Password:  &pwd,
		}, "")
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(body))

	resp, body = doJSON(t, http.MethodPost, baseURL+"/v1/watchers/login",
		models.WatcherAuthRequest{
			MachineID: new("test-machine"),
			Password:  &pwd,
		}, "")
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))

	var auth models.WatcherAuthResponse
	require.NoError(t, json.Unmarshal(body, &auth))
	require.NotEmpty(t, auth.Token)

	return auth.Token
}

func pushAlert(t *testing.T, baseURL, token, ip, origin string) (int, []byte) {
	t.Helper()

	alert := &models.Alert{
		Scenario: new("manual"),
		Decisions: []*models.Decision{
			{
				Value:    new(ip),
				Scope:    new("Ip"),
				Type:     new("ban"),
				Duration: new("4h"),
				Origin:   new(origin),
			},
		},
	}

	resp, body := doJSON(t, http.MethodPost, baseURL+"/v1/alerts", models.AddAlertsRequest{alert}, token)

	return resp.StatusCode, body
}

func stream(t *testing.T, baseURL, token string, startup bool) *modelscapi.GetDecisionsStreamResponse {
	t.Helper()

	url := fmt.Sprintf("%s/v1/decisions/stream?startup=%t", baseURL, startup)

	resp, body := doJSON(t, http.MethodGet, url, nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))

	var result modelscapi.GetDecisionsStreamResponse
	require.NoError(t, json.Unmarshal(body, &result), string(body))

	return &result
}

func TestRegistrationAndLogin(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	baseURL := ts.URL

	t.Run("registration requires a password", func(t *testing.T) {
		pwd := strfmt.Password("short")

		resp, _ := doJSON(t, http.MethodPost, baseURL+"/v1/watchers",
			models.WatcherRegistrationRequest{MachineID: new("short-pwd"), Password: &pwd}, "")
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("duplicate machine is rejected", func(t *testing.T) {
		pwd := strfmt.Password("supersecret")
		req := models.WatcherRegistrationRequest{MachineID: new("dup-machine"), Password: &pwd}

		resp, _ := doJSON(t, http.MethodPost, baseURL+"/v1/watchers", req, "")
		require.Equal(t, http.StatusCreated, resp.StatusCode)

		resp, _ = doJSON(t, http.MethodPost, baseURL+"/v1/watchers", req, "")
		require.Equal(t, http.StatusConflict, resp.StatusCode)
	})

	t.Run("wrong password is rejected", func(t *testing.T) {
		pwd := strfmt.Password("supersecret")

		resp, _ := doJSON(t, http.MethodPost, baseURL+"/v1/watchers",
			models.WatcherRegistrationRequest{MachineID: new("login-machine"), Password: &pwd}, "")
		require.Equal(t, http.StatusCreated, resp.StatusCode)

		bad := strfmt.Password("wrong-password")

		resp, _ = doJSON(t, http.MethodPost, baseURL+"/v1/watchers/login",
			models.WatcherAuthRequest{MachineID: new("login-machine"), Password: &bad}, "")
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("unauthenticated stream is rejected", func(t *testing.T) {
		resp, _ := doJSON(t, http.MethodGet, baseURL+"/v1/decisions/stream?startup=true", nil, "")
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestPushAndPull(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	baseURL := ts.URL

	token := registerAndLogin(t, baseURL)

	// Nothing to share yet.
	require.Empty(t, stream(t, baseURL, token, true).New)

	status, body := pushAlert(t, baseURL, token, "1.2.3.4", "cscli")
	require.Equal(t, http.StatusCreated, status, string(body))

	// Delta pull sees the new decision.
	result := stream(t, baseURL, token, false)
	require.Len(t, result.New, 1)
	require.Equal(t, "crowdsec/community-blocklist", *result.New[0].Scenario)
	require.Equal(t, "Ip", *result.New[0].Scope)
	require.Len(t, result.New[0].Decisions, 1)
	require.Equal(t, "1.2.3.4", *result.New[0].Decisions[0].Value)

	// A second pull without changes is empty.
	result = stream(t, baseURL, token, false)
	require.Empty(t, result.New)
	require.Empty(t, result.Deleted)

	// Decisions from scenarios (not manual) are not shared.
	status, _ = pushAlert(t, baseURL, token, "5.6.7.8", "crowdsec")
	require.Equal(t, http.StatusCreated, status)
	require.Empty(t, stream(t, baseURL, token, false).New)

	// Startup pulls everything again, no matter the cursor.
	result = stream(t, baseURL, token, true)
	require.Len(t, result.New, 1)
}

func TestInvalidDecisionsAreSkipped(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	baseURL := ts.URL

	token := registerAndLogin(t, baseURL)

	for _, decision := range []*models.Decision{
		{Value: new("not-an-ip"), Scope: new("Ip"), Type: new("ban"), Duration: new("4h"), Origin: new("cscli")},
		{Value: new("1.2.3.4"), Scope: new("username"), Type: new("ban"), Duration: new("4h"), Origin: new("cscli")},
		{Value: new("9.9.9.9"), Scope: new("Ip"), Type: new("ban"), Duration: new("4h"), Origin: new("crowdsec")},
	} {
		alert := &models.Alert{Scenario: new("manual"), Decisions: []*models.Decision{decision}}

		resp, body := doJSON(t, http.MethodPost, baseURL+"/v1/alerts", models.AddAlertsRequest{alert}, token)
		require.Equal(t, http.StatusCreated, resp.StatusCode, string(body))
	}

	require.Empty(t, stream(t, baseURL, token, true).New)
}

func TestAdminCRUDAndDeletions(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	baseURL := ts.URL

	token := registerAndLogin(t, baseURL)

	// Manual entry through the admin API.
	resp, body := doJSON(t, http.MethodPost, baseURL+"/admin/v1/decisions", map[string]string{
		"value":    "203.0.113.0/24",
		"scope":    "range",
		"duration": "1d",
		"scenario": "manual",
	}, "admin-secret")
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(body))

	var created Decision
	require.NoError(t, json.Unmarshal(body, &created))
	require.Equal(t, "Range", created.Scope)
	require.Equal(t, "203.0.113.0/24", created.Value)

	result := stream(t, baseURL, token, false)
	require.Len(t, result.New, 1)
	require.Equal(t, "Range", *result.New[0].Scope)

	// Deleting it produces a tombstone for subscribed engines.
	resp, body = doJSON(t, http.MethodDelete, fmt.Sprintf("%s/admin/v1/decisions/%d", baseURL, created.ID), nil, "admin-secret")
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))

	result = stream(t, baseURL, token, false)
	require.Empty(t, result.New)
	require.Len(t, result.Deleted, 1)
	require.Equal(t, []string{"203.0.113.0/24"}, result.Deleted[0].Decisions)

	// Exporting invalid values is refused.
	resp, _ = doJSON(t, http.MethodPost, baseURL+"/admin/v1/decisions", map[string]string{
		"value": "nope", "scope": "ip", "duration": "1h",
	}, "admin-secret")
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Deleting an unknown decision is a 404.
	resp, _ = doJSON(t, http.MethodDelete, baseURL+"/admin/v1/decisions/999999", nil, "admin-secret")
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAdminAuth(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	baseURL := ts.URL

	resp, _ := doJSON(t, http.MethodGet, baseURL+"/admin/v1/stats", nil, "")
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	resp, _ = doJSON(t, http.MethodGet, baseURL+"/admin/v1/stats", nil, "wrong-token")
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	resp, body := doJSON(t, http.MethodGet, baseURL+"/admin/v1/stats", nil, "admin-secret")
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
}

func TestAdminWithoutTokenIsLoopbackOnly(t *testing.T) {
	ts, _ := newTestServer(t, func(cfg *Config) {
		cfg.AdminToken = ""
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/stats", http.NoBody)
	req.RemoteAddr = "10.1.2.3:5555"

	rec := httptest.NewRecorder()
	ts.Config.Handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	req.RemoteAddr = "127.0.0.1:5555"
	rec = httptest.NewRecorder()
	ts.Config.Handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestRegistrationToken(t *testing.T) {
	ts, _ := newTestServer(t, func(cfg *Config) {
		cfg.RegistrationToken = "enroll-me"
	})

	pwd := strfmt.Password("supersecret")

	resp, _ := doJSON(t, http.MethodPost, ts.URL+"/v1/watchers",
		models.WatcherRegistrationRequest{MachineID: new("needs-token"), Password: &pwd}, "")
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	resp, _ = doJSON(t, http.MethodPost, ts.URL+"/v1/watchers",
		models.WatcherRegistrationRequest{MachineID: new("needs-token"), Password: &pwd, RegistrationToken: "enroll-me"}, "")
	require.Equal(t, http.StatusCreated, resp.StatusCode)
}

func TestExpiredDecisionsAreRemoved(t *testing.T) {
	ts, store := newTestServer(t, nil)
	baseURL := ts.URL

	token := registerAndLogin(t, baseURL)

	past := time.Now().Add(-time.Hour)

	decision := &Decision{
		Value:    "198.51.100.1",
		Scope:    "Ip",
		Type:     "ban",
		Duration: "1h",
		Scenario: "manual",
		Origin:   "cscli",
		Source:   "manual",
		Until:    &past,
	}
	require.NoError(t, store.UpsertDecision(t.Context(), decision))

	result := stream(t, baseURL, token, false)
	require.Empty(t, result.New)
	require.Len(t, result.Deleted, 1)
	require.Equal(t, []string{"198.51.100.1"}, result.Deleted[0].Decisions)
}

func TestStreamCursorIsPerMachine(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	baseURL := ts.URL

	first := registerAndLogin(t, baseURL)

	pwd := strfmt.Password("supersecret")
	resp, body := doJSON(t, http.MethodPost, baseURL+"/v1/watchers",
		models.WatcherRegistrationRequest{MachineID: new("second-machine"), Password: &pwd}, "")
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(body))

	resp, body = doJSON(t, http.MethodPost, baseURL+"/v1/watchers/login",
		models.WatcherAuthRequest{MachineID: new("second-machine"), Password: &pwd}, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var auth models.WatcherAuthResponse
	require.NoError(t, json.Unmarshal(body, &auth))

	status, body := pushAlert(t, baseURL, first, "10.0.0.1", "cscli")
	require.Equal(t, http.StatusCreated, status, string(body))

	// The first machine consumes the delta.
	require.Len(t, stream(t, baseURL, first, false).New, 1)

	// The second machine still gets it.
	result := stream(t, baseURL, auth.Token, false)
	require.Len(t, result.New, 1)
	require.Equal(t, "10.0.0.1", *result.New[0].Decisions[0].Value)
}

func TestTokenSigner(t *testing.T) {
	signer, err := NewTokenSigner(time.Hour)
	require.NoError(t, err)

	now := time.Now()

	token, expire := signer.Sign("machine-1", now)
	require.True(t, expire.After(now))

	machineID, err := signer.Verify(token, now)
	require.NoError(t, err)
	require.Equal(t, "machine-1", machineID)

	_, err = signer.Verify(token, now.Add(2*time.Hour))
	require.Error(t, err)

	tampered := strings.Replace(token, ".", ".x", 1)
	_, err = signer.Verify(tampered, now)
	require.Error(t, err)

	_, err = signer.Verify("garbage", now)
	require.Error(t, err)
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input   string
		want    time.Duration
		wantErr bool
	}{
		{input: "4h", want: 4 * time.Hour},
		{input: "30m", want: 30 * time.Minute},
		{input: "1d", want: 24 * time.Hour},
		{input: "2d", want: 48 * time.Hour},
		{input: "1w", want: 7 * 24 * time.Hour},
		{input: "1.5h", want: 90 * time.Minute},
		{input: "0", wantErr: true},
		{input: "", wantErr: true},
		{input: "abc", wantErr: true},
		{input: "-4h", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ParseDuration(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestConfigDefaultsAndValidation(t *testing.T) {
	cfg := &Config{}
	require.NoError(t, cfg.SetDefaults())
	require.Equal(t, DefaultListen, cfg.Listen)
	require.Equal(t, []string{"cscli"}, cfg.Push.AcceptOrigins)
	require.True(t, cfg.AcceptsOrigin("cscli"))
	require.False(t, cfg.AcceptsOrigin("crowdsec"))

	cfg = &Config{TokenTTL: "nope"}
	require.Error(t, cfg.SetDefaults())

	cfg = &Config{TLSCert: "/tmp/cert.pem"}
	require.Error(t, cfg.SetDefaults())
}

func TestV3RegistrationAndSignalPush(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	baseURL := ts.URL

	pwd := strfmt.Password("supersecret")

	resp, body := doJSON(t, http.MethodPost, baseURL+"/v3/watchers",
		models.WatcherRegistrationRequest{MachineID: new("engine-v3"), Password: &pwd}, "")
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(body))

	resp, body = doJSON(t, http.MethodPost, baseURL+"/v3/watchers/login",
		models.WatcherAuthRequest{MachineID: new("engine-v3"), Password: &pwd}, "")
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))

	var auth models.WatcherAuthResponse
	require.NoError(t, json.Unmarshal(body, &auth))

	signal := &modelscapi.AddSignalsRequestItem{
		Scenario: new("manual"),
		Source:   &modelscapi.AddSignalsRequestItemSource{IP: "1.2.3.4"},
		Decisions: modelscapi.AddSignalsRequestItemDecisions{
			{
				Value:    new("1.2.3.4"),
				Scope:    new("Ip"),
				Type:     new("ban"),
				Duration: new("4h"),
				Origin:   new("cscli"),
			},
			// Simulated decisions and non-ban types are never shared.
			{
				Value:     new("5.5.5.5"),
				Scope:     new("Ip"),
				Type:      new("ban"),
				Duration:  new("4h"),
				Origin:    new("cscli"),
				Simulated: true,
			},
			{
				Value:    new("6.6.6.6"),
				Scope:    new("Ip"),
				Type:     new("captcha"),
				Duration: new("4h"),
				Origin:   new("cscli"),
			},
			// Origins that are not shared by configuration.
			{
				Value:    new("7.7.7.7"),
				Scope:    new("Ip"),
				Type:     new("ban"),
				Duration: new("4h"),
				Origin:   new("crowdsec"),
			},
		},
	}

	resp, body = doJSON(t, http.MethodPost, baseURL+"/v3/signals",
		modelscapi.AddSignalsRequest{signal}, auth.Token)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	require.Contains(t, string(body), `"decisions":1`)

	url := baseURL + "/v3/decisions/stream?startup=true"

	resp, body = doJSON(t, http.MethodGet, url, nil, auth.Token)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))

	var stream modelscapi.GetDecisionsStreamResponse
	require.NoError(t, json.Unmarshal(body, &stream))
	require.Len(t, stream.New, 1)
	require.Len(t, stream.New[0].Decisions, 1)
	require.Equal(t, "1.2.3.4", *stream.New[0].Decisions[0].Value)
}

func TestServedDurationsAreParseableByEngines(t *testing.T) {
	ts, _ := newTestServer(t, nil)
	baseURL := ts.URL

	token := registerAndLogin(t, baseURL)

	pwd := strfmt.Password("supersecret")

	// Register a second machine through the v3 API.
	resp, body := doJSON(t, http.MethodPost, baseURL+"/v3/watchers",
		models.WatcherRegistrationRequest{MachineID: new("duration-check"), Password: &pwd}, "")
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(body))

	signal := &modelscapi.AddSignalsRequestItem{
		Scenario: new("manual"),
		Source:   &modelscapi.AddSignalsRequestItemSource{IP: "1.2.3.4"},
		Decisions: modelscapi.AddSignalsRequestItemDecisions{
			{Value: new("1.2.3.4"), Scope: new("Ip"), Type: new("ban"), Duration: new("7d"), Origin: new("cscli")},
		},
	}

	resp, body = doJSON(t, http.MethodPost, baseURL+"/v3/signals",
		modelscapi.AddSignalsRequest{signal}, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))

	result := stream(t, baseURL, token, true)
	require.Len(t, result.New, 1)

	// time.ParseDuration is what the engine uses when storing pulled decisions.
	_, err := time.ParseDuration(*result.New[0].Decisions[0].Duration)
	require.NoError(t, err)
}
