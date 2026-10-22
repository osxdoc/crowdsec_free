package webui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// newStubLAPI fakes the parts of the local API that cswebui uses.
func newStubLAPI(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/v1/watchers/login", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"code":   200,
			"token":  "stub-token",
			"expire": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		})
	})

	mux.HandleFunc("/v1/heartbeat", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/v1/alerts", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, []any{})
		case http.MethodPost:
			writeJSON(w, http.StatusCreated, []string{})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/v1/alerts/42", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"id":           42,
			"scenario":     "crowdsecurity/ssh-bf",
			"message":      "test alert",
			"created_at":   time.Now().UTC().Format(time.RFC3339),
			"events_count": 3,
			"decisions":    []any{},
		})
	})

	mux.HandleFunc("/v1/decisions", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, []any{})
	})

	mux.HandleFunc("/v1/allowlists", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, []any{})
	})

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	return ts
}

type testUI struct {
	server *Server
	ts     *httptest.Server
	client *http.Client
	cfg    *Config
	csrf   string
}

func newTestUI(t *testing.T, mutate func(*Config)) *testUI {
	t.Helper()

	lapi := newStubLAPI(t)
	return newTestUIWithLAPI(t, mutate, lapi.URL)
}

func newTestUIWithLAPI(t *testing.T, mutate func(*Config), lapiURL string) *testUI {
	t.Helper()

	configDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "acquis.yaml"), []byte("filenames:\n  - /var/log/auth.log\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "profiles.yaml"), []byte("name: default\n"), 0o600))

	hash, err := HashPassword("supersecret")
	require.NoError(t, err)

	cfg := &Config{
		LAPI: LAPIConfig{
			URL:      lapiURL,
			Login:    "webui-test",
			Password: "supersecret",
		},
		Engine: EngineConfig{ConfigDir: configDir},
		Auth: AuthConfig{
			Users:      []User{{Username: "admin", PasswordHash: hash}},
			SessionTTL: "1h",
		},
		Files: []string{"acquis.yaml", "profiles.yaml", "config.yaml"},
	}

	if mutate != nil {
		mutate(cfg)
	}

	require.NoError(t, cfg.SetDefaults())

	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	server, err := NewServer(cfg, logger, "test")
	require.NoError(t, err)

	ts := httptest.NewServer(server.Handler())
	t.Cleanup(ts.Close)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	return &testUI{
		server: server,
		ts:     ts,
		cfg:    cfg,
		client: &http.Client{Jar: jar, Timeout: 10 * time.Second},
	}
}

func (ui *testUI) do(t *testing.T, method, path string, body any, headers map[string]string) (*http.Response, []byte) {
	t.Helper()

	var reader io.Reader

	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)

		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(method, ui.ts.URL+path, reader)
	require.NoError(t, err)

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := ui.client.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp, payload
}

func (ui *testUI) login(t *testing.T) {
	t.Helper()

	resp, payload := ui.do(t, http.MethodPost, "/api/login", map[string]string{
		"username": "admin",
		"password": "supersecret",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(payload))

	var result struct {
		User string `json:"user"`
		CSRF string `json:"csrf"`
	}

	require.NoError(t, json.Unmarshal(payload, &result))
	require.Equal(t, "admin", result.User)
	require.NotEmpty(t, result.CSRF)

	ui.csrf = result.CSRF
}

func (ui *testUI) authHeaders() map[string]string {
	return map[string]string{"X-CSRF-Token": ui.csrf}
}

func TestLoginFlow(t *testing.T) {
	ui := newTestUI(t, nil)

	t.Run("wrong password", func(t *testing.T) {
		resp, _ := ui.do(t, http.MethodPost, "/api/login", map[string]string{
			"username": "admin",
			"password": "wrong",
		}, nil)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("valid login and session", func(t *testing.T) {
		ui.login(t)

		resp, payload := ui.do(t, http.MethodGet, "/api/session", nil, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode, string(payload))

		var session struct {
			User     string          `json:"user"`
			CSRF     string          `json:"csrf"`
			Features map[string]bool `json:"features"`
		}

		require.NoError(t, json.Unmarshal(payload, &session))
		require.Equal(t, "admin", session.User)
		require.Equal(t, ui.csrf, session.CSRF)
		require.False(t, session.Features["blocklist"])
	})

	t.Run("unauthenticated request", func(t *testing.T) {
		ui2 := newTestUI(t, nil)

		resp, _ := ui2.do(t, http.MethodGet, "/api/session", nil, nil)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestCSRFProtection(t *testing.T) {
	ui := newTestUI(t, nil)
	ui.login(t)

	resp, _ := ui.do(t, http.MethodPost, "/api/decisions", map[string]string{
		"value": "1.2.3.4", "scope": "ip", "duration": "1h",
	}, nil)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	resp, payload := ui.do(t, http.MethodPost, "/api/decisions", map[string]string{
		"value": "1.2.3.4", "scope": "ip", "duration": "1h",
	}, ui.authHeaders())
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(payload))
}

func TestCreateDecisionValidation(t *testing.T) {
	ui := newTestUI(t, nil)
	ui.login(t)

	for _, body := range []map[string]string{
		{"value": "not-an-ip", "scope": "ip"},
		{"value": "1.2.3.4", "scope": "username"},
		{"value": "1.2.3.0/33", "scope": "range"},
		{"value": "1.2.3.4", "scope": "ip", "duration": "nope"},
	} {
		resp, payload := ui.do(t, http.MethodPost, "/api/decisions", body, ui.authHeaders())
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, string(payload))
	}
}

func TestOverview(t *testing.T) {
	ui := newTestUI(t, nil)
	ui.login(t)

	resp, payload := ui.do(t, http.MethodGet, "/api/overview?since=1h", nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(payload))

	var overview struct {
		AlertsTotal   int  `json:"alerts_total"`
		LAPIReachable bool `json:"lapi_reachable"`
	}

	require.NoError(t, json.Unmarshal(payload, &overview))
	require.Equal(t, 0, overview.AlertsTotal)
	require.True(t, overview.LAPIReachable)
}

func TestConfigEditing(t *testing.T) {
	ui := newTestUI(t, nil)
	ui.login(t)

	acquisPath := filepath.Join(ui.cfg.Engine.ConfigDir, "acquis.yaml")

	t.Run("list files", func(t *testing.T) {
		resp, payload := ui.do(t, http.MethodGet, "/api/config", nil, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode, string(payload))

		var result struct {
			Files []configFileInfo `json:"files"`
		}

		require.NoError(t, json.Unmarshal(payload, &result))
		require.Len(t, result.Files, 3)
		require.True(t, result.Files[0].Exists)
		require.False(t, result.Files[2].Exists) // config.yaml
	})

	t.Run("read file", func(t *testing.T) {
		resp, payload := ui.do(t, http.MethodGet, "/api/config/acquis.yaml", nil, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode, string(payload))
		require.Contains(t, string(payload), "auth.log")
	})

	t.Run("save valid yaml creates backup", func(t *testing.T) {
		newContent := "filenames:\n  - /var/log/nginx/access.log\n"

		resp, payload := ui.do(t, http.MethodPut, "/api/config/acquis.yaml", map[string]string{
			"content": newContent,
		}, ui.authHeaders())
		require.Equal(t, http.StatusOK, resp.StatusCode, string(payload))

		written, err := os.ReadFile(acquisPath)
		require.NoError(t, err)
		require.Equal(t, newContent, string(written))

		backup, err := os.ReadFile(acquisPath + ".bak")
		require.NoError(t, err)
		require.Contains(t, string(backup), "auth.log")
	})

	t.Run("invalid yaml is refused", func(t *testing.T) {
		before, err := os.ReadFile(acquisPath)
		require.NoError(t, err)

		resp, payload := ui.do(t, http.MethodPut, "/api/config/acquis.yaml", map[string]string{
			"content": "filenames: [unclosed",
		}, ui.authHeaders())
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, string(payload))

		after, err := os.ReadFile(acquisPath)
		require.NoError(t, err)
		require.Equal(t, before, after)
	})

	t.Run("files outside the whitelist are refused", func(t *testing.T) {
		resp, _ := ui.do(t, http.MethodGet, "/api/config/local_api_credentials.yaml", nil, nil)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)

		resp, _ = ui.do(t, http.MethodPut, "/api/config/../../etc/passwd", map[string]string{
			"content": "x",
		}, ui.authHeaders())
		require.GreaterOrEqual(t, resp.StatusCode, 400)
	})
}

func TestReload(t *testing.T) {
	t.Run("not configured", func(t *testing.T) {
		ui := newTestUI(t, nil)
		ui.login(t)

		resp, _ := ui.do(t, http.MethodPost, "/api/reload", nil, ui.authHeaders())
		require.Equal(t, http.StatusNotImplemented, resp.StatusCode)
	})

	t.Run("reload command runs", func(t *testing.T) {
		ui := newTestUI(t, func(cfg *Config) {
			cfg.Engine.ReloadCommand = []string{"/bin/sh", "-c", "echo reloaded-ok"}
		})
		ui.login(t)

		resp, payload := ui.do(t, http.MethodPost, "/api/reload", nil, ui.authHeaders())
		require.Equal(t, http.StatusOK, resp.StatusCode, string(payload))
		require.Contains(t, string(payload), "reloaded-ok")
	})

	t.Run("failing reload command", func(t *testing.T) {
		ui := newTestUI(t, func(cfg *Config) {
			cfg.Engine.ReloadCommand = []string{"/bin/sh", "-c", "exit 3"}
		})
		ui.login(t)

		resp, payload := ui.do(t, http.MethodPost, "/api/reload", nil, ui.authHeaders())
		require.Equal(t, http.StatusInternalServerError, resp.StatusCode, string(payload))
	})
}

func TestCredentialsFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "local_api_credentials.yaml")

	require.NoError(t, os.WriteFile(path, []byte("url: http://127.0.0.1:8080\nlogin: machine\npassword: secret\n"), 0o600))

	cfg := &Config{LAPI: LAPIConfig{CredentialsPath: path}}
	cfg.Engine.ConfigDir = dir
	cfg.Auth.Users = []User{{Username: "admin", PasswordHash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"}}
	require.NoError(t, cfg.SetDefaults())

	lapiURL, login, password, err := cfg.Credentials()
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1:8080", lapiURL)
	require.Equal(t, "machine", login)
	require.Equal(t, "secret", password)
}

func TestPasswordHashing(t *testing.T) {
	hash, err := HashPassword("supersecret")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(hash, "$2"))

	_, err = HashPassword("short")
	require.Error(t, err)
}

func TestServerRejectsIncompleteCredentials(t *testing.T) {
	cfg := &Config{
		LAPI: LAPIConfig{URL: "http://127.0.0.1:1", Login: "a", Password: "b"},
		Auth: AuthConfig{SessionTTL: "1h"},
	}
	cfg.Engine.ConfigDir = t.TempDir()

	_, err := HashPassword("supersecret")
	require.NoError(t, err)

	cfg.Auth.Users = []User{{Username: "admin", PasswordHash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"}}
	require.NoError(t, cfg.SetDefaults())

	// A missing scheme must be reported, not cause a panic.
	cfg.LAPI.URL = "localhost:8080"

	_, err = NewServer(cfg, logrus.New(), "test")
	require.Error(t, err)
	require.Contains(t, err.Error(), "scheme")
}

func TestIndexPageIsServed(t *testing.T) {
	ui := newTestUI(t, nil)

	resp, payload := ui.do(t, http.MethodGet, "/", nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, string(payload), "Self-hosted console")

	resp, payload = ui.do(t, http.MethodGet, "/some/spa/route", nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, string(payload), "Self-hosted console")

	resp, _ = ui.do(t, http.MethodGet, "/app.js", nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "text/javascript; charset=utf-8", resp.Header.Get("Content-Type"))
	require.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
	require.Contains(t, resp.Header.Get("Content-Security-Policy"), "default-src 'self'")

	resp, _ = ui.do(t, http.MethodGet, "/api/does-not-exist", nil, nil)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestBlocklistEndpointsWithoutConfig(t *testing.T) {
	ui := newTestUI(t, nil)
	ui.login(t)

	resp, _ := ui.do(t, http.MethodGet, "/api/blocklist/stats", nil, nil)
	require.Equal(t, http.StatusNotImplemented, resp.StatusCode)
}

func ExampleConfig() {
	fmt.Println("see config/webui.yaml for a fully commented example")
	// Output: see config/webui.yaml for a fully commented example
}
