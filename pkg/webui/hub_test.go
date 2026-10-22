package webui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The index carries the yaml body and every past version per item; the fixture
// keeps both so the reader is tested against the real shape.
const hubTestIndex = `{
  "parsers": {
    "acme/parser-a": {"path": "parsers/s01-parse/acme/parser-a.yaml", "stage": "s01-parse", "version": "1.2",
      "description": "parse a", "content": "name: acme/parser-a\n", "versions": {"1.1": {}, "1.2": {}}},
    "acme/parser-b": {"path": "parsers/s01-parse/acme/parser-b.yaml", "stage": "s01-parse", "version": "0.1"},
    "acme/parser-c": {"path": "parsers/s01-parse/acme/parser-c.yaml", "stage": "s01-parse", "version": "0.4"}
  },
  "scenarios": {
    "acme/local-copy": {"path": "scenarios/acme/local-copy.yaml", "version": "1.0"},
    "acme/missing": {"path": "scenarios/acme/missing.yaml", "version": "0.2", "description": "not installed"},
    "acme/sc-a": {"path": "scenarios/acme/sc-a.yaml", "version": "2.0", "description": "scenario a"},
    "acme/unlinked": {"path": "scenarios/acme/unlinked.yaml", "version": "1.0", "description": "downloaded, not linked"}
  },
  "collections": {
    "acme/coll-a": {"path": "collections/acme/coll-a.yaml", "version": "1.1", "description": "collection a",
      "parsers": ["acme/parser-a"], "scenarios": ["acme/sc-a", "acme/missing"]},
    "acme/coll-b": {"path": "collections/acme/coll-b.yaml", "version": "0.3", "scenarios": ["acme/missing"]}
  }
}`

// seedHub writes a hub index plus the live config tree in the states that
// matter: linked, downloaded but unlinked, edited by hand, and a file that
// never came from the hub.
func seedHub(t *testing.T, dir string) {
	t.Helper()

	hubFiles := []string{
		"hub/parsers/s01-parse/acme/parser-a.yaml",
		"hub/parsers/s01-parse/acme/parser-c.yaml",
		"hub/scenarios/acme/local-copy.yaml",
		"hub/scenarios/acme/sc-a.yaml",
		"hub/scenarios/acme/unlinked.yaml",
		"hub/collections/acme/coll-a.yaml",
	}

	for _, rel := range hubFiles {
		path := filepath.Join(dir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte("name: hub\n"), 0o600))
	}

	require.NoError(t, os.WriteFile(filepath.Join(dir, "hub", hubIndexFile), []byte(hubTestIndex), 0o600))

	links := map[string]string{
		"parsers/s01-parse/parser-a.yaml": "hub/parsers/s01-parse/acme/parser-a.yaml",
		"scenarios/sc-a.yaml":             "hub/scenarios/acme/sc-a.yaml",
		"collections/coll-a.yaml":         "hub/collections/acme/coll-a.yaml",
	}

	for link, target := range links {
		path := filepath.Join(dir, link)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.Symlink(filepath.Join(dir, target), path))
	}

	// Hand-edited hub items are plain files in the live tree, not symlinks.
	live := []string{"parsers/s01-parse/parser-c.yaml", "scenarios/local-copy.yaml", "scenarios/mine.yaml"}

	for _, rel := range live {
		path := filepath.Join(dir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte("name: local\n"), 0o600))
	}
}

type hubTestItem struct {
	Name         string         `json:"name"`
	Version      string         `json:"version"`
	Installed    bool           `json:"installed"`
	Enabled      bool           `json:"enabled"`
	Tainted      bool           `json:"tainted"`
	Dependencies map[string]int `json:"dependencies"`
}

type hubTestCategory struct {
	Name      string        `json:"name"`
	Available int           `json:"available"`
	Installed int           `json:"installed"`
	Enabled   int           `json:"enabled"`
	Items     []hubTestItem `json:"items"`
}

type hubTestStatus struct {
	ConfigDir    string            `json:"config_dir"`
	HubDir       string            `json:"hub_dir"`
	IndexMissing bool              `json:"index_missing"`
	IndexUpdated time.Time         `json:"index_updated"`
	LocalOnly    []string          `json:"local_only"`
	Categories   []hubTestCategory `json:"categories"`
	Collections  []hubTestItem     `json:"collections"`
}

func (s *hubTestStatus) category(name string) hubTestCategory {
	for _, category := range s.Categories {
		if category.Name == name {
			return category
		}
	}

	return hubTestCategory{}
}

func hubItemsByName(items []hubTestItem) map[string]hubTestItem {
	byName := map[string]hubTestItem{}
	for _, item := range items {
		byName[item.Name] = item
	}

	return byName
}

func hubItemNames(items []hubTestItem) []string {
	names := make([]string, 0, len(items))
	for _, item := range items {
		names = append(names, item.Name)
	}

	return names
}

// reloadCount counts engine reloads recorded by the configured reload command.
func reloadCount(t *testing.T, marker string) int {
	t.Helper()

	raw, err := os.ReadFile(marker)
	if err != nil {
		require.ErrorIs(t, err, os.ErrNotExist, "reading %s", marker)

		return 0
	}

	if strings.TrimSpace(string(raw)) == "" {
		return 0
	}

	return len(strings.Fields(string(raw)))
}

type cscliRecorder struct {
	mu    sync.Mutex
	calls [][]string
	err   error
}

func (c *cscliRecorder) run(_ context.Context, args ...string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.calls = append(c.calls, args)

	if c.err != nil {
		return "", c.err
	}

	return "", nil
}

func (c *cscliRecorder) invoked() [][]string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.calls
}

func TestHubStatus(t *testing.T) {
	ui := newTestUI(t, nil)
	seedHub(t, ui.cfg.Engine.ConfigDir)
	ui.login(t)

	resp, payload := ui.do(t, http.MethodGet, "/api/hub", nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(payload))

	var status hubTestStatus
	require.NoError(t, json.Unmarshal(payload, &status))

	require.Equal(t, ui.cfg.Engine.ConfigDir, status.ConfigDir)
	require.Equal(t, filepath.Join(ui.cfg.Engine.ConfigDir, "hub"), status.HubDir)
	require.False(t, status.IndexMissing)
	require.False(t, status.IndexUpdated.IsZero(), "the index age comes from the index file mtime")
	require.Equal(t, []string{"scenarios/mine.yaml"}, status.LocalOnly)

	names := make([]string, 0, len(status.Categories))
	for _, category := range status.Categories {
		names = append(names, category.Name)
	}

	require.ElementsMatch(t, hubCategories, names)

	parsers := status.category("parsers")
	require.Equal(t, 3, parsers.Available)
	require.Equal(t, 2, parsers.Installed)
	require.Equal(t, 1, parsers.Enabled)
	// Installed items lead the list so the default view stays short.
	require.Equal(t, []string{"acme/parser-a", "acme/parser-c", "acme/parser-b"}, hubItemNames(parsers.Items))

	items := hubItemsByName(parsers.Items)
	require.True(t, items["acme/parser-a"].Installed)
	require.True(t, items["acme/parser-a"].Enabled)
	require.False(t, items["acme/parser-a"].Tainted)
	require.Equal(t, "1.2", items["acme/parser-a"].Version)
	require.False(t, items["acme/parser-b"].Installed)
	require.False(t, items["acme/parser-b"].Enabled)
	// Downloaded but never linked into the live tree: installed, inactive.
	require.True(t, items["acme/parser-c"].Installed)
	require.False(t, items["acme/parser-c"].Enabled)
	require.True(t, items["acme/parser-c"].Tainted)

	scenarios := status.category("scenarios")
	require.Equal(t, 4, scenarios.Available)
	require.Equal(t, 3, scenarios.Installed)
	require.Equal(t, 1, scenarios.Enabled)

	items = hubItemsByName(scenarios.Items)
	require.True(t, items["acme/sc-a"].Enabled)
	require.True(t, items["acme/local-copy"].Installed)
	require.False(t, items["acme/local-copy"].Enabled)
	require.True(t, items["acme/local-copy"].Tainted)

	// Downloaded into the hub but never linked into the live tree.
	require.True(t, items["acme/unlinked"].Installed)
	require.False(t, items["acme/unlinked"].Enabled)
	require.False(t, items["acme/unlinked"].Tainted)

	require.Zero(t, status.category("contexts").Available)

	collections := hubItemsByName(status.Collections)
	require.Len(t, status.Collections, 2)
	require.True(t, collections["acme/coll-a"].Installed)
	require.True(t, collections["acme/coll-a"].Enabled)
	require.Equal(t, map[string]int{"parsers": 1, "scenarios": 2}, collections["acme/coll-a"].Dependencies)
	require.False(t, collections["acme/coll-b"].Installed)
	require.Equal(t, map[string]int{"scenarios": 1}, collections["acme/coll-b"].Dependencies)

	t.Run("unauthenticated", func(t *testing.T) {
		fresh := newTestUI(t, nil)

		resp, _ := fresh.do(t, http.MethodGet, "/api/hub", nil, nil)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("mutating without a csrf token is refused", func(t *testing.T) {
		resp, _ := ui.do(t, http.MethodPost, "/api/hub/update", map[string]string{}, nil)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})
}

func TestHubActions(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		body       any
		wantStatus int
		wantArgs   []string
		wantReload bool
		wantBody   string
	}{
		{
			name:       "index update",
			path:       "/api/hub/update",
			body:       map[string]string{},
			wantStatus: http.StatusOK,
			wantArgs:   []string{"hub", "update", "--with-content"},
			wantReload: false,
		},
		{
			name:       "upgrade everything",
			path:       "/api/hub/upgrade",
			body:       map[string]string{},
			wantStatus: http.StatusOK,
			wantArgs:   []string{"hub", "upgrade"},
			wantReload: true,
		},
		{
			name:       "upgrade one scenario",
			path:       "/api/hub/upgrade",
			body:       map[string]string{"category": "scenarios", "name": "acme/sc-a"},
			wantStatus: http.StatusOK,
			wantArgs:   []string{"scenarios", "upgrade", "acme/sc-a"},
			wantReload: true,
		},
		{
			name:       "install a scenario",
			path:       "/api/hub/install",
			body:       map[string]string{"category": "scenarios", "name": "acme/missing"},
			wantStatus: http.StatusOK,
			wantArgs:   []string{"scenarios", "install", "acme/missing"},
			wantReload: true,
		},
		{
			name:       "install a downloaded but unlinked item",
			path:       "/api/hub/install",
			body:       map[string]string{"category": "scenarios", "name": "acme/unlinked"},
			wantStatus: http.StatusOK,
			wantArgs:   []string{"scenarios", "install", "acme/unlinked"},
			wantReload: true,
		},
		{
			name:       "install a collection",
			path:       "/api/hub/install",
			body:       map[string]string{"category": "collections", "name": "acme/coll-b"},
			wantStatus: http.StatusOK,
			wantArgs:   []string{"collections", "install", "acme/coll-b"},
			wantReload: true,
		},
		{
			name:       "remove an installed parser",
			path:       "/api/hub/remove",
			body:       map[string]string{"category": "parsers", "name": "acme/parser-a"},
			wantStatus: http.StatusOK,
			wantArgs:   []string{"parsers", "remove", "acme/parser-a"},
			wantReload: true,
		},
		{
			name:       "path traversal in the name",
			path:       "/api/hub/install",
			body:       map[string]string{"category": "parsers", "name": "../evil"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "shell metacharacters in the name",
			path:       "/api/hub/install",
			body:       map[string]string{"category": "scenarios", "name": "acme/missing; rm -rf /"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unknown item type",
			path:       "/api/hub/install",
			body:       map[string]string{"category": "widgets", "name": "acme/missing"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing item name",
			path:       "/api/hub/remove",
			body:       map[string]string{"category": "scenarios"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "item absent from the index",
			path:       "/api/hub/install",
			body:       map[string]string{"category": "scenarios", "name": "acme/nope"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "installing an installed item",
			path:       "/api/hub/install",
			body:       map[string]string{"category": "parsers", "name": "acme/parser-a"},
			wantStatus: http.StatusBadRequest,
			wantBody:   "already installed",
		},
		{
			name:       "removing an item that is not installed",
			path:       "/api/hub/remove",
			body:       map[string]string{"category": "scenarios", "name": "acme/missing"},
			wantStatus: http.StatusBadRequest,
			wantBody:   "is not installed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "reloads")

			ui := newTestUI(t, func(cfg *Config) {
				cfg.Engine.ReloadCommand = []string{"/bin/sh", "-c", "echo reloaded >> " + marker}
			})
			seedHub(t, ui.cfg.Engine.ConfigDir)

			recorder := &cscliRecorder{}
			ui.server.runCscli = recorder.run

			ui.login(t)

			resp, payload := ui.do(t, http.MethodPost, test.path, test.body, ui.authHeaders())
			require.Equal(t, test.wantStatus, resp.StatusCode, string(payload))

			if test.wantBody != "" {
				require.Contains(t, string(payload), test.wantBody)
			}

			if test.wantArgs == nil {
				require.Empty(t, recorder.invoked(), "cscli must not run for a rejected request")
				require.Zero(t, reloadCount(t, marker), "a rejected request must not reload the engine")

				return
			}

			require.Equal(t, [][]string{test.wantArgs}, recorder.invoked())

			if test.wantReload {
				require.Equal(t, 1, reloadCount(t, marker), "every hub change reloads the engine")
			} else {
				require.Zero(t, reloadCount(t, marker), "an index update changes nothing the engine has loaded")
			}
		})
	}
}

func TestHubActionFailureLeavesEngineAlone(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "reloads")

	ui := newTestUI(t, func(cfg *Config) {
		cfg.Engine.ReloadCommand = []string{"/bin/sh", "-c", "echo reloaded >> " + marker}
	})
	seedHub(t, ui.cfg.Engine.ConfigDir)

	recorder := &cscliRecorder{err: errors.New("exit status 1")}
	ui.server.runCscli = recorder.run

	ui.login(t)

	resp, payload := ui.do(t, http.MethodPost, "/api/hub/install",
		map[string]string{"category": "scenarios", "name": "acme/missing"}, ui.authHeaders())
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode, string(payload))
	require.Contains(t, string(payload), "exit status 1")
	require.Zero(t, reloadCount(t, marker), "a failed install must not reload the engine")
}

// TestHubReloadReporting covers what the UI is told after a hub change: a silent
// reload command is not evidence that the engine picked the change up, and a
// failing one must never be swallowed.
func TestHubReloadReporting(t *testing.T) {
	tests := []struct {
		name          string
		reloadCommand func(marker string) []string
		wantReload    string
		wantReloadErr string
	}{
		{
			name:          "a silent reload command still reports the reload",
			reloadCommand: func(marker string) []string { return []string{"/bin/sh", "-c", "touch " + marker} },
			wantReload:    "engine reloaded",
		},
		{
			name:          "reload command output reaches the client",
			reloadCommand: func(marker string) []string { return []string{"/bin/sh", "-c", "echo reloaded"} },
			wantReload:    "reloaded",
		},
		{
			name:          "a failing reload command is reported",
			reloadCommand: func(marker string) []string { return []string{"/bin/sh", "-c", "exit 1"} },
			wantReloadErr: "exit status 1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "reloads")

			ui := newTestUI(t, func(cfg *Config) {
				cfg.Engine.ReloadCommand = test.reloadCommand(marker)
			})
			seedHub(t, ui.cfg.Engine.ConfigDir)

			recorder := &cscliRecorder{}
			ui.server.runCscli = recorder.run

			ui.login(t)

			resp, payload := ui.do(t, http.MethodPost, "/api/hub/remove",
				map[string]string{"category": "parsers", "name": "acme/parser-a"}, ui.authHeaders())
			require.Equal(t, http.StatusOK, resp.StatusCode, string(payload))
			require.Equal(t, [][]string{{"parsers", "remove", "acme/parser-a"}}, recorder.invoked())

			var body struct {
				Reload      string `json:"reload"`
				ReloadError string `json:"reload_error"`
			}
			require.NoError(t, json.Unmarshal(payload, &body))

			require.Equal(t, test.wantReload, body.Reload)

			if test.wantReloadErr != "" {
				require.Contains(t, body.ReloadError, test.wantReloadErr)
			} else {
				require.Empty(t, body.ReloadError)
			}
		})
	}
}

func TestHubActionsWithoutIndex(t *testing.T) {
	ui := newTestUI(t, nil)
	ui.login(t)

	recorder := &cscliRecorder{}
	ui.server.runCscli = recorder.run

	resp, payload := ui.do(t, http.MethodGet, "/api/hub", nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(payload))

	var status hubTestStatus
	require.NoError(t, json.Unmarshal(payload, &status))
	require.True(t, status.IndexMissing)

	for _, category := range status.Categories {
		require.Zero(t, category.Available, "%s has no index to count", category.Name)
		require.Empty(t, category.Items)
	}

	resp, payload = ui.do(t, http.MethodPost, "/api/hub/install",
		map[string]string{"category": "scenarios", "name": "acme/missing"}, ui.authHeaders())
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, string(payload))
	require.Contains(t, string(payload), "index update first")
	require.Empty(t, recorder.invoked())
}
