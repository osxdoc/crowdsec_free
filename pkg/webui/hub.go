package webui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	hubIndexFile     = ".index.json"
	maxHubOutput     = 8 << 10
	hubUpdateTimeout = 10 * time.Minute
	hubActionTimeout = 2 * time.Minute
)

// hubCategories are the item types cscli installs, as listed by `cscli hub types`.
var hubCategories = []string{
	"parsers",
	"scenarios",
	"postoverflows",
	"contexts",
	"appsec-configs",
	"appsec-rules",
	"collections",
}

// hubNamePattern accepts "author/name" and "name" only: the value is passed to
// cscli as a single argv element, never through a shell.
var hubNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)?$`)

// hubIndexEntry is one item of the downloaded hub index. The dependency lists
// only appear on collections; the yaml body the index also carries is ignored.
type hubIndexEntry struct {
	Path          string   `json:"path"`
	Stage         string   `json:"stage"`
	Version       string   `json:"version"`
	Description   string   `json:"description"`
	Parsers       []string `json:"parsers"`
	Scenarios     []string `json:"scenarios"`
	Postoverflows []string `json:"postoverflows"`
	Contexts      []string `json:"contexts"`
	AppsecConfigs []string `json:"appsec-configs"`
	AppsecRules   []string `json:"appsec-rules"`
	Collections   []string `json:"collections"`
}

// hubItem is one entry of the index, annotated with what is on disk.
type hubItem struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Version     string `json:"version,omitempty"`
	Path        string `json:"path,omitempty"`
	Installed   bool   `json:"installed"`
	Enabled     bool   `json:"enabled"`
	Tainted     bool   `json:"tainted,omitempty"`
}

type hubCategory struct {
	Name      string    `json:"name"`
	Available int       `json:"available"`
	Installed int       `json:"installed"`
	Enabled   int       `json:"enabled"`
	Items     []hubItem `json:"items"`
}

// hubCollection additionally reports what a collection pulls in, so the user
// can judge what installing it would change.
type hubCollection struct {
	hubItem
	Dependencies map[string]int `json:"dependencies,omitempty"`
}

// hubStatus is the payload of GET /api/hub.
type hubStatus struct {
	ConfigDir    string          `json:"config_dir"`
	HubDir       string          `json:"hub_dir"`
	IndexUpdated time.Time       `json:"index_updated"`
	IndexMissing bool            `json:"index_missing"`
	LocalOnly    []string        `json:"local_only,omitempty"`
	Categories   []hubCategory   `json:"categories"`
	Collections  []hubCollection `json:"collections"`
}

func (s *Server) hubDir() string {
	return filepath.Join(s.cfg.Engine.ConfigDir, "hub")
}

// readHubIndex loads the downloaded catalog. A missing index only means no hub
// update has run yet: the on-disk state is still reported.
func (s *Server) readHubIndex() (map[string]map[string]*hubIndexEntry, time.Time, error) {
	name := filepath.Join(s.hubDir(), hubIndexFile)

	stat, err := os.Stat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, time.Time{}, nil
		}

		return nil, time.Time{}, err
	}

	raw, err := os.ReadFile(name)
	if err != nil {
		return nil, stat.ModTime(), fmt.Errorf("reading %s: %w", name, err)
	}

	// The index stores the full yaml body per item, which the UI does not need.
	catalog := map[string]map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &catalog); err != nil {
		return nil, stat.ModTime(), fmt.Errorf("parsing %s: %w", name, err)
	}

	entries := make(map[string]map[string]*hubIndexEntry, len(catalog))

	for category, items := range catalog {
		converted := make(map[string]*hubIndexEntry, len(items))

		for name, rawItem := range items {
			var entry hubIndexEntry
			if err := json.Unmarshal(rawItem, &entry); err != nil {
				return nil, stat.ModTime(), fmt.Errorf("parsing index entry %s/%s: %w", category, name, err)
			}

			converted[name] = &entry
		}

		entries[category] = converted
	}

	return entries, stat.ModTime(), nil
}

// liveKey turns an index path such as "parsers/s01-parse/acme/foo.yaml" into
// the path cscli links it to below the category directory, "s01-parse/foo.yaml".
func liveKey(category, path string) (string, error) {
	rel, err := filepath.Rel(category, filepath.FromSlash(path))
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("index path %q is not below %s", path, category)
	}

	parts := strings.Split(rel, string(filepath.Separator))

	// cscli drops the author directory when it links a hub file into the live tree.
	kept := make([]string, 0, len(parts))
	if len(parts) > 1 {
		kept = append(kept, parts[:len(parts)-2]...)
	}

	kept = append(kept, parts[len(parts)-1])

	return filepath.ToSlash(filepath.Join(append([]string{category}, kept...)...)), nil
}

// hubState reports which hub files cscli has linked into the live config tree,
// and which live files are plain local files (an edited hub item is "tainted").
func (s *Server) hubState() (linked map[string]bool, local map[string]bool) {
	linked = map[string]bool{}
	local = map[string]bool{}

	hubRoot := filepath.Clean(s.hubDir())

	for _, category := range hubCategories {
		dir := filepath.Join(s.cfg.Engine.ConfigDir, category)

		_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return nil //nolint:nilerr  // an unreadable subtree must not hide the rest of the listing
			}

			if !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml") {
				return nil
			}

			if target, linkErr := os.Readlink(path); linkErr == nil {
				abs := target
				if !filepath.IsAbs(abs) {
					abs = filepath.Join(dir, target)
				}

				hubRel, relErr := filepath.Rel(hubRoot, filepath.Clean(abs))
				if relErr == nil && !strings.HasPrefix(hubRel, "..") {
					// The path below the hub directory is the index path, which is
					// how index entries and live files are matched up.
					linked[filepath.ToSlash(hubRel)] = true
				}

				return nil
			}

			rel, relErr := filepath.Rel(dir, path)
			if relErr != nil {
				return nil //nolint:nilerr  // unreachable: dir is the root of this walk
			}

			local[filepath.ToSlash(filepath.Join(category, rel))] = true

			return nil
		})
	}

	return linked, local
}

func (s *Server) handleHub(w http.ResponseWriter, r *http.Request) {
	status := hubStatus{
		ConfigDir: s.cfg.Engine.ConfigDir,
		HubDir:    s.hubDir(),
	}

	entries, updated, err := s.readHubIndex()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%s", err)
		return
	}

	if entries == nil {
		status.IndexMissing = true
	}

	status.IndexUpdated = updated

	linked, local := s.hubState()
	claimed := make(map[string]bool, len(entries))

	status.Categories = make([]hubCategory, 0, len(hubCategories))
	status.Collections = []hubCollection{}

	for _, category := range hubCategories {
		list := hubCategory{Name: category, Items: []hubItem{}}

		for name, entry := range entries[category] {
			item := hubItem{
				Name:        name,
				Description: entry.Description,
				Version:     entry.Version,
				Path:        entry.Path,
				Enabled:     linked[filepath.ToSlash(entry.Path)],
			}

			if entry.Path != "" {
				if _, err := os.Stat(filepath.Join(s.hubDir(), filepath.FromSlash(entry.Path))); err == nil {
					item.Installed = true
				}
			}

			if key, err := liveKey(category, entry.Path); err == nil {
				claimed[key] = true
				item.Tainted = local[key]
			}

			if category == "collections" {
				status.Collections = append(status.Collections, hubCollection{
					hubItem:      item,
					Dependencies: entry.dependencies(),
				})

				continue
			}

			list.Items = append(list.Items, item)

			if item.Installed {
				list.Installed++
			}

			if item.Enabled {
				list.Enabled++
			}
		}

		list.Available = len(entries[category])

		slices.SortFunc(list.Items, func(a, b hubItem) int {
			if a.Installed != b.Installed {
				if a.Installed {
					return -1
				}

				return 1
			}

			return strings.Compare(a.Name, b.Name)
		})

		status.Categories = append(status.Categories, list)
	}

	slices.SortFunc(status.Collections, func(a, b hubCollection) int {
		if a.Installed != b.Installed {
			if a.Installed {
				return -1
			}

			return 1
		}

		return strings.Compare(a.Name, b.Name)
	})

	// Live files no hub item accounts for belong to the user, not the hub.
	for key := range local {
		if !claimed[key] {
			status.LocalOnly = append(status.LocalOnly, key)
		}
	}

	slices.Sort(status.LocalOnly)

	writeJSON(w, http.StatusOK, status)
}

// dependencies counts what a collection pulls in, so the user can judge what
// installing it would change.
func (e hubIndexEntry) dependencies() map[string]int {
	counts := map[string]int{}

	for kind, names := range map[string][]string{
		"parsers":        e.Parsers,
		"scenarios":      e.Scenarios,
		"postoverflows":  e.Postoverflows,
		"contexts":       e.Contexts,
		"appsec-configs": e.AppsecConfigs,
		"appsec-rules":   e.AppsecRules,
		"collections":    e.Collections,
	} {
		if len(names) > 0 {
			counts[kind] = len(names)
		}
	}

	if len(counts) == 0 {
		return nil
	}

	return counts
}

type hubActionRequest struct {
	Category string `json:"category"`
	Name     string `json:"name"`
}

func (s *Server) execCscli(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"-c", filepath.Join(s.cfg.Engine.ConfigDir, "config.yaml")}, args...)

	output, err := exec.CommandContext(ctx, "cscli", full...).CombinedOutput() //nolint:gosec // argv, no shell
	text := strings.TrimSpace(string(output))

	if len(text) > maxHubOutput {
		text = text[:maxHubOutput] + " …"
	}

	if err != nil {
		return text, fmt.Errorf("cscli %s: %w", strings.Join(args, " "), err)
	}

	return text, nil
}

// hubActionArgs turns a request into cscli arguments, validating the item name
// against the catalog so that no unexpected argument can reach cscli.
func (s *Server) hubActionArgs(action string, req hubActionRequest) ([]string, time.Duration, error) {
	switch action {
	case "update":
		return []string{"hub", "update", "--with-content"}, hubUpdateTimeout, nil
	case "upgrade":
		if req.Name == "" {
			return []string{"hub", "upgrade"}, hubUpdateTimeout, nil
		}
	case "install", "remove":
	default:
		return nil, 0, fmt.Errorf("unknown hub action %q", action)
	}

	if !slices.Contains(hubCategories, req.Category) {
		return nil, 0, fmt.Errorf("unknown item type %q", req.Category)
	}

	if !hubNamePattern.MatchString(req.Name) {
		return nil, 0, fmt.Errorf("invalid item name %q", req.Name)
	}

	entries, _, err := s.readHubIndex()
	if err != nil {
		return nil, 0, err
	}

	if entries == nil {
		return nil, 0, errors.New("the hub index is missing: run an index update first")
	}

	entry, known := entries[req.Category][req.Name]
	if !known {
		return nil, 0, fmt.Errorf("%s/%s is not in the hub index, update it first", req.Category, req.Name)
	}

	installed, linked := s.hubItemOnDisk(req.Category, entry)

	// cscli install links a hub file it already downloaded, so only an active
	// link counts as installed; cscli remove needs one of the two to exist.
	switch action {
	case "install":
		if linked {
			return nil, 0, fmt.Errorf("%s/%s is already installed and active", req.Category, req.Name)
		}
	case "remove":
		if !installed && !linked {
			return nil, 0, fmt.Errorf("%s/%s is not installed", req.Category, req.Name)
		}
	}

	return []string{req.Category, action, req.Name}, hubActionTimeout, nil
}

// hubItemOnDisk reports whether the hub file of an index entry is on disk and
// whether cscli has linked it into the live config tree.
func (s *Server) hubItemOnDisk(category string, entry *hubIndexEntry) (installed bool, linked bool) {
	if entry.Path != "" {
		if _, err := os.Stat(filepath.Join(s.hubDir(), filepath.FromSlash(entry.Path))); err == nil {
			installed = true
		}
	}

	key, err := liveKey(category, entry.Path)
	if err != nil {
		return installed, false
	}

	if _, err := os.Readlink(filepath.Join(s.cfg.Engine.ConfigDir, filepath.FromSlash(key))); err == nil {
		linked = true
	}

	return installed, linked
}

func (s *Server) handleHubAction(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req hubActionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: %s", err)
			return
		}

		args, timeout, err := s.hubActionArgs(action, req)
		if err != nil {
			writeError(w, http.StatusBadRequest, "%s", err)
			return
		}

		s.hubMu.Lock()
		defer s.hubMu.Unlock()

		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		output, err := s.runCscli(ctx, args...)
		if err != nil {
			s.log.Errorf("hub %s failed: %s: %s", action, err, output)
			writeError(w, http.StatusInternalServerError, "%s: %s", err, output)
			return
		}

		// New or upgraded hub files are only picked up when the engine reloads; an
		// index update changes nothing the engine has loaded.
		response := map[string]any{
			"message": fmt.Sprintf("cscli %s finished", strings.Join(args, " ")),
			"output":  output,
		}

		if action != "update" {
			reload, reloadErr := s.reloadEngine(ctx)
			if reloadErr != nil {
				// The change is on disk but inactive: say so instead of hiding it.
				s.log.Warnf("hub %s succeeded but the engine was not reloaded: %s", action, reloadErr)
				response["reload_error"] = reloadErr.Error()
			} else if reload != "" {
				response["reload"] = reload
			} else {
				// reload commands are usually silent (pkill -HUP), but the UI has to
				// say the change went live.
				response["reload"] = "engine reloaded"
			}
		}

		s.log.Infof("user %q ran cscli %v", currentUser(r), args)

		writeJSON(w, http.StatusOK, response)
	}
}
