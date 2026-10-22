package webui

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func operationsLAPI(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/watchers/login" {
			writeJSON(w, http.StatusOK, map[string]any{"token": "test-token", "expire": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
			return
		}
		if r.URL.Path == "/v1/heartbeat" {
			w.WriteHeader(http.StatusOK)
			return
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestAllowlistContent(t *testing.T) {
	upstream := operationsLAPI(t, func(w http.ResponseWriter, r *http.Request) {
		items := []any{}
		if r.URL.Query().Get("with_content") == "true" {
			items = append(items, map[string]string{"value": "192.0.2.1"})
		}
		list := map[string]any{"name": "trusted", "items": items}
		if r.URL.Path == "/v1/allowlists" {
			writeJSON(w, http.StatusOK, []any{list})
		} else {
			writeJSON(w, http.StatusOK, list)
		}
	})
	ui := newTestUIWithLAPI(t, nil, upstream.URL)
	ui.login(t)
	for _, path := range []string{"/api/allowlists", "/api/allowlists/trusted"} {
		t.Run(path, func(t *testing.T) {
			response, body := ui.do(t, http.MethodGet, path, nil, nil)
			require.Equal(t, http.StatusOK, response.StatusCode, string(body))
			require.Contains(t, string(body), "192.0.2.1")
		})
	}
}

func TestAllowlistActions(t *testing.T) {
	upstream := operationsLAPI(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"name": "trusted", "console_managed": strings.HasSuffix(r.URL.Path, "/managed")})
	})
	ui := newTestUIWithLAPI(t, nil, upstream.URL)
	ui.login(t)
	cases := []struct {
		name, method, path string
		body               any
		status             int
		args               []string
	}{
		{"create", "POST", "/api/allowlists", map[string]string{"name": "trusted", "description": "Test list"}, 200, []string{"allowlists", "create", "--description", "Test list", "--", "trusted"}},
		{"option-like name stays positional", "POST", "/api/allowlists", map[string]string{"name": "--help", "description": "Test"}, 200, []string{"allowlists", "create", "--description", "Test", "--", "--help"}},
		{"add expiring range", "POST", "/api/allowlists/trusted/items", map[string]string{"value": "192.0.2.0/24", "duration": "7d", "description": "Office"}, 200, []string{"allowlists", "add", "--expiration", "7d", "--comment", "Office", "--", "trusted", "192.0.2.0/24"}},
		{"add IPv6", "POST", "/api/allowlists/trusted/items", map[string]string{"value": "2001:db8::1"}, 200, []string{"allowlists", "add", "--", "trusted", "2001:db8::1"}},
		{"remove entry", "DELETE", "/api/allowlists/trusted/items", map[string]string{"value": "192.0.2.1"}, 200, []string{"allowlists", "remove", "--", "trusted", "192.0.2.1"}},
		{"delete", "DELETE", "/api/allowlists/trusted", nil, 200, []string{"allowlists", "delete", "--", "trusted"}},
		{"missing description", "POST", "/api/allowlists", map[string]string{"name": "trusted"}, 400, nil},
		{"invalid value", "POST", "/api/allowlists/trusted/items", map[string]string{"value": "--force"}, 400, nil},
		{"invalid range", "POST", "/api/allowlists/trusted/items", map[string]string{"value": "192.0.2.0/33"}, 400, nil},
		{"negative duration", "POST", "/api/allowlists/trusted/items", map[string]string{"value": "192.0.2.1", "duration": "-1h"}, 400, nil},
		{"invalid duration", "POST", "/api/allowlists/trusted/items", map[string]string{"value": "192.0.2.1", "duration": "later"}, 400, nil},
		{"managed add", "POST", "/api/allowlists/managed/items", map[string]string{"value": "192.0.2.1"}, 403, nil},
		{"managed delete", "DELETE", "/api/allowlists/managed", nil, 403, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := &cscliRecorder{}
			ui.server.runCscli = recorder.run
			response, body := ui.do(t, tc.method, tc.path, tc.body, ui.authHeaders())
			require.Equal(t, tc.status, response.StatusCode, string(body))
			calls := recorder.invoked()
			if tc.args == nil {
				require.Empty(t, calls)
			} else {
				require.Equal(t, [][]string{tc.args}, calls)
			}
		})
	}
	t.Run("csrf required", func(t *testing.T) {
		recorder := &cscliRecorder{}
		ui.server.runCscli = recorder.run
		response, _ := ui.do(t, "DELETE", "/api/allowlists/trusted", nil, nil)
		require.Equal(t, http.StatusForbidden, response.StatusCode)
		require.Empty(t, recorder.invoked())
	})
}

func TestInspectIP(t *testing.T) {
	for _, failAllowlist := range []bool{false, true} {
		t.Run(fmt.Sprintf("allowlist failure=%v", failAllowlist), func(t *testing.T) {
			upstream := operationsLAPI(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/alerts":
					if r.URL.Query().Get("ip") != "2001:db8::1" || r.URL.Query().Get("contains") != "true" || r.URL.Query().Get("limit") != "100" {
						writeErrorf(w, http.StatusBadRequest, "incorrect IP lookup filters")
						return
					}
					decisions := []any{}
					if r.URL.Query().Get("has_active_decision") == "true" {
						decisions = append(decisions, map[string]any{"id": 7, "scope": "range", "value": "2001:db8::/32", "type": "ban"})
					}
					writeJSON(w, http.StatusOK, []any{map[string]any{"id": 42, "scenario": "manual", "decisions": decisions}})
				default:
					if failAllowlist {
						writeErrorf(w, 503, "allowlist unavailable")
					} else {
						writeJSON(w, 200, map[string]any{"allowlisted": true, "reason": "trusted office"})
					}
				}
			})
			ui := newTestUIWithLAPI(t, nil, upstream.URL)
			ui.login(t)
			response, body := ui.do(t, "GET", "/api/inspect?ip=2001:0db8::1", nil, nil)
			require.Equal(t, 200, response.StatusCode, string(body))
			var result struct {
				IP        string            `json:"ip"`
				Alerts    []alertSummary    `json:"alerts"`
				Decisions []decisionView    `json:"decisions"`
				Errors    map[string]string `json:"errors"`
			}
			require.NoError(t, json.Unmarshal(body, &result))
			require.Equal(t, "2001:db8::1", result.IP)
			require.Len(t, result.Alerts, 1)
			require.Len(t, result.Decisions, 1)
			require.Equal(t, int64(42), result.Decisions[0].AlertID)
			if failAllowlist {
				require.Contains(t, result.Errors["allowlist"], "unavailable")
			} else {
				require.Empty(t, result.Errors)
				require.Contains(t, string(body), "trusted office")
			}
			response, _ = ui.do(t, "GET", "/api/inspect?ip=--help", nil, nil)
			require.Equal(t, 400, response.StatusCode)
		})
	}
}

func TestOverviewPartialFailures(t *testing.T) {
	for _, available := range []bool{false, true} {
		t.Run(fmt.Sprintf("alerts available=%v", available), func(t *testing.T) {
			upstream := operationsLAPI(t, func(w http.ResponseWriter, _ *http.Request) {
				if available {
					writeJSON(w, 200, []any{})
				} else {
					writeErrorf(w, 503, "alerts unavailable")
				}
			})
			metrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, sampleExposition) }))
			defer metrics.Close()
			ui := newTestUIWithLAPI(t, func(cfg *Config) { cfg.Data.MetricsURL = metrics.URL }, upstream.URL)
			ui.login(t)
			response, body := ui.do(t, "GET", "/api/overview", nil, nil)
			require.Equal(t, 200, response.StatusCode, string(body))
			var data overviewResponse
			require.NoError(t, json.Unmarshal(body, &data))
			require.Equal(t, available, data.DataSources.Alerts)
			require.Equal(t, available, data.DataSources.Decisions)
			require.False(t, data.DataSources.Machines)
			require.True(t, data.DataSources.Metrics)
			require.Equal(t, "ok", data.Health["metrics"].State)
			require.Equal(t, "not_configured", data.Health["database"].State)
			require.Equal(t, "not_configured", data.Health["blocklist"].State)
			if available {
				require.Equal(t, "ok", data.Health["lapi"].State)
				require.Equal(t, 0, data.Alerts.Total)
			} else {
				require.Equal(t, "unavailable", data.Health["lapi"].State)
			}
			require.NotNil(t, data.Alerts.Timeline)
		})
	}
}

func TestMetricDiagnostics(t *testing.T) {
	samples, err := parseMetrics(strings.NewReader(`cs_parser_hits_total{source="shared",type="syslog"} 10
cs_parser_hits_total{source="shared",type="http"} 4
cs_parser_hits_ok_total{source="shared",type="syslog"} 0
cs_parser_hits_ok_total{source="shared",type="syslog",acquis_type="file"} 2
cs_node_wl_hits_ok_total{source="shared",type="syslog",name="office"} 1
cs_appsec_reqs_total{appsec_engine="waf"} 20
cs_appsec_block_total{appsec_engine="waf"} 0
cs_appsec_rule_hits{appsec_engine="waf",rule_name="test-rule"} 3
`))
	require.NoError(t, err)
	summary := buildMetricsSummary(&metricsSnapshot{Samples: samples})
	require.Len(t, summary.Sources, 2)
	require.Equal(t, "http:shared", summary.Sources[0].Name)
	require.InDelta(t, 4.0, summary.Sources[0].Values["read"], 0.000001)
	require.NotContains(t, summary.Sources[0].Values, "parsed")
	require.InDelta(t, 2.0, summary.Sources[1].Values["parsed"], 0.000001)
	require.InDelta(t, 1.0, summary.Sources[1].Values["allowlisted"], 0.000001)
	require.Len(t, summary.Appsec, 1)
	require.Contains(t, summary.Appsec[0].Values, "blocked")
	require.InDelta(t, 0.0, summary.Appsec[0].Values["blocked"], 0.000001)
	require.NotContains(t, summary.Appsec[0].Values, "requested")
	require.Equal(t, "test-rule", summary.AppsecRules[0].Name)
	require.True(t, summary.Present["cs_appsec_block_total"])
	require.False(t, summary.Present["cs_capi_errors_total"])
}

func TestHubInstalledVersion(t *testing.T) {
	for _, tc := range []struct {
		name, content, version string
		update, tainted        bool
	}{
		{"old", "old\n", "1.0", true, false}, {"latest", "latest\n", "2.0", false, false}, {"modified", "custom\n", "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ui := newTestUI(t, nil)
			full := filepath.Join(ui.cfg.Engine.ConfigDir, "hub", "item.yaml")
			require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o700))
			require.NoError(t, os.WriteFile(full, []byte(tc.content), 0o600))
			raw := fmt.Sprintf(`{"path":"item.yaml","version":"2.0","versions":{"1.0":{"digest":"%x"},"2.0":{"digest":"%x"}}}`, sha256.Sum256([]byte("old\n")), sha256.Sum256([]byte("latest\n")))
			var entry hubIndexEntry
			require.NoError(t, json.Unmarshal([]byte(raw), &entry))
			item := hubItem{Installed: true}
			ui.server.hubVersion(&item, &entry, "item.yaml")
			require.Equal(t, tc.version, item.LocalVersion)
			require.Equal(t, tc.update, item.UpdateAvailable)
			require.Equal(t, tc.tainted, item.Tainted)
		})
	}
}

func TestEngineConfigurationCheck(t *testing.T) {
	ui := newTestUI(t, nil)
	ui.login(t)
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	for _, tc := range []struct {
		name, script string
		status       int
		message      string
	}{
		{"success", "printf '%s\\n' \"$@\"", 200, "Saved engine configuration is valid"},
		{"semantic error", "echo 'unknown engine setting'; exit 2", 400, "unknown engine setting"},
		{"binary missing", "", 501, "must be installed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := filepath.Join(bin, "crowdsec")
			if tc.script != "" {
				require.NoError(t, os.WriteFile(command, []byte("#!/bin/sh\n"+tc.script+"\n"), 0o700))
			} else {
				require.NoError(t, os.Remove(command))
			}
			response, body := ui.do(t, "POST", "/api/config/check", map[string]any{}, ui.authHeaders())
			require.Equal(t, tc.status, response.StatusCode, string(body))
			require.Contains(t, string(body), tc.message)
			if tc.status == 200 {
				require.Contains(t, string(body), "config.yaml")
				require.Contains(t, string(body), "-t")
			}
		})
	}
	response, _ := ui.do(t, "POST", "/api/config/check", map[string]any{}, nil)
	require.Equal(t, 403, response.StatusCode)
}

func TestListFiltersForwarded(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		expected   map[string]string
	}{
		{"alerts", "/api/alerts?origin=CAPI&kind=appsec&include_capi=true&limit=50", map[string]string{"origin": "CAPI", "kind": "appsec", "include_capi": "true", "limit": "50"}},
		{"decisions", "/api/decisions?origin=cscli&scenario=manual&scope=range&type=ban&limit=100", map[string]string{"origin": "cscli", "scenario": "manual", "scope": "range", "decision_type": "ban", "limit": "100", "has_active_decision": "true"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			received := make(chan map[string]string, 1)
			upstream := operationsLAPI(t, func(w http.ResponseWriter, r *http.Request) {
				values := map[string]string{}
				for key := range tc.expected {
					values[key] = r.URL.Query().Get(key)
				}
				received <- values
				writeJSON(w, http.StatusOK, []any{})
			})
			ui := newTestUIWithLAPI(t, nil, upstream.URL)
			ui.login(t)
			response, body := ui.do(t, "GET", tc.path, nil, nil)
			require.Equal(t, http.StatusOK, response.StatusCode, string(body))
			require.Equal(t, tc.expected, <-received)
		})
	}
}

func TestEngineOperationsRejectBusy(t *testing.T) {
	ui := newTestUI(t, nil)
	ui.login(t)
	ui.server.hubMu.Lock()
	defer ui.server.hubMu.Unlock()
	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/api/config/check", map[string]any{}},
		{"POST", "/api/reload", map[string]any{}},
		{"PUT", "/api/config/config.yaml", map[string]string{"content": "common: {}\n"}},
		{"POST", "/api/allowlists", map[string]string{"name": "busy", "description": "Test"}},
	} {
		t.Run(tc.path, func(t *testing.T) {
			response, body := ui.do(t, tc.method, tc.path, tc.body, ui.authHeaders())
			require.Equal(t, http.StatusConflict, response.StatusCode, string(body))
		})
	}
}

func TestUnavailableDatabaseIsNotAnEmptyInfrastructure(t *testing.T) {
	for _, closed := range []bool{false, true} {
		t.Run(fmt.Sprintf("closed=%v", closed), func(t *testing.T) {
			ui := newTestUI(t, nil)
			if closed {
				store := newTestStateStore(t)
				require.NoError(t, store.Close())
				ui.server.state = store
			}
			ui.login(t)
			response, body := ui.do(t, "GET", "/api/infra", nil, nil)
			require.Equal(t, 200, response.StatusCode, string(body))
			var result struct {
				Machines  []machineInfo     `json:"machines"`
				Bouncers  []bouncerInfo     `json:"bouncers"`
				Available map[string]bool   `json:"available"`
				Errors    map[string]string `json:"errors"`
			}
			require.NoError(t, json.Unmarshal(body, &result))
			require.NotNil(t, result.Machines)
			require.NotNil(t, result.Bouncers)
			require.False(t, result.Available["machines"])
			require.False(t, result.Available["bouncers"])
			if closed {
				require.Contains(t, result.Errors, "machines")
				require.Contains(t, result.Errors, "bouncers")
			}
		})
	}
}
