package webui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

const maxConfigSize = 2 << 20 // 2 MiB

type configFileInfo struct {
	Name     string    `json:"name"`
	Exists   bool      `json:"exists"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
}

// resolveConfigPath maps a user supplied name to a file below the config
// directory, refusing anything outside of the configured whitelist.
func (s *Server) resolveConfigPath(name string) (string, error) {
	name = strings.TrimSpace(name)

	if name == "" {
		return "", errors.New("empty file name")
	}

	if path.IsAbs(name) || strings.Contains(name, "..") || strings.Contains(name, "\\") {
		return "", errors.New("invalid file name")
	}

	allowed := false

	for _, candidate := range s.cfg.Files {
		if candidate == name {
			allowed = true
			break
		}
	}

	if !allowed {
		return "", fmt.Errorf("file %q is not editable, add it to the files list in the cswebui config", name)
	}

	root, err := filepath.Abs(s.cfg.Engine.ConfigDir)
	if err != nil {
		return "", fmt.Errorf("resolving config dir: %w", err)
	}

	full := filepath.Join(root, name)

	rel, err := filepath.Rel(root, full)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", errors.New("invalid file name")
	}

	return full, nil
}

func (s *Server) handleListConfig(w http.ResponseWriter, r *http.Request) {
	files := make([]configFileInfo, 0, len(s.cfg.Files))

	for _, name := range s.cfg.Files {
		full, err := s.resolveConfigPath(name)
		if err != nil {
			continue
		}

		info := configFileInfo{Name: name}

		stat, err := os.Stat(full)
		if err == nil {
			info.Exists = true
			info.Size = stat.Size()
			info.Modified = stat.ModTime()
		}

		files = append(files, info)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"config_dir": s.cfg.Engine.ConfigDir,
		"files":      files,
	})
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	full, err := s.resolveConfigPath(name)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}

	stat, err := os.Stat(full)
	if err != nil {
		writeError(w, http.StatusNotFound, "file %q does not exist", name)
		return
	}

	if stat.Size() > maxConfigSize {
		writeError(w, http.StatusRequestEntityTooLarge, "file %q is larger than %d bytes", name, maxConfigSize)
		return
	}

	content, err := os.ReadFile(full)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read %q: %s", name, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"name":     name,
		"content":  string(content),
		"size":     stat.Size(),
		"modified": stat.ModTime(),
	})
}

type updateConfigRequest struct {
	Content string `json:"content"`
}

func (s *Server) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	full, err := s.resolveConfigPath(name)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}

	var req updateConfigRequest

	if err := decodeBody(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}

	if len(req.Content) > maxConfigSize {
		writeError(w, http.StatusRequestEntityTooLarge, "content is larger than %d bytes", maxConfigSize)
		return
	}

	if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
		var node yaml.Node

		if err := yaml.Unmarshal([]byte(req.Content), &node); err != nil {
			writeError(w, http.StatusBadRequest, "invalid YAML: %s", err)
			return
		}
	}

	mode := os.FileMode(0o640)

	if stat, err := os.Stat(full); err == nil {
		mode = stat.Mode().Perm()

		// Keep the previous version around, but don't spam backups with
		// unchanged content.
		if previous, err := os.ReadFile(full); err == nil && !strings.EqualFold(string(previous), req.Content) {
			if err := os.WriteFile(full+".bak", previous, mode); err != nil {
				s.log.Warnf("could not write backup of %q: %s", name, err)
			}
		}
	}

	if err := writeFileAtomic(full, []byte(req.Content), mode); err != nil {
		s.log.Errorf("writing %q: %s", name, err)
		writeError(w, http.StatusInternalServerError, "could not write %q: %s", name, err)
		return
	}

	s.log.Infof("user %q updated %q", currentUser(r), name)

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "saved",
		"name":    name,
	})
}

func writeFileAtomic(filename string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(filename)

	tmp, err := os.CreateTemp(dir, ".cswebui-*")
	if err != nil {
		return fmt.Errorf("creating temporary file: %w", err)
	}

	tmpName := tmp.Name()

	cleanup := func() {
		tmp.Close()        //nolint:errcheck
		os.Remove(tmpName) //nolint:errcheck
	}

	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("writing temporary file: %w", err)
	}

	if err := tmp.Chmod(mode); err != nil {
		cleanup()
		return fmt.Errorf("setting permissions: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("syncing temporary file: %w", err)
	}

	if err := tmp.Close(); err != nil {
		os.Remove(tmpName) //nolint:errcheck
		return fmt.Errorf("closing temporary file: %w", err)
	}

	if err := os.Rename(tmpName, filename); err != nil {
		os.Remove(tmpName) //nolint:errcheck
		return fmt.Errorf("replacing file: %w", err)
	}

	return nil
}

// errNoReloadMethod is returned when neither engine.pid_file nor
// engine.reload_command is configured.
var errNoReloadMethod = errors.New(
	"no reload method configured: set engine.pid_file or engine.reload_command in the cswebui config")

// reloadEngine makes the engine re-read its configuration and hub files.
func (s *Server) reloadEngine(ctx context.Context) (string, error) {
	if s.cfg.Engine.PIDFile != "" {
		return s.reloadViaSignal()
	}

	if len(s.cfg.Engine.ReloadCommand) > 0 {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, s.cfg.Engine.ReloadCommand[0], s.cfg.Engine.ReloadCommand[1:]...) //nolint:gosec
		output, err := cmd.CombinedOutput()
		if err != nil {
			text := strings.TrimSpace(string(output))
			return text, fmt.Errorf("reload command failed: %w: %s", err, text)
		}

		return strings.TrimSpace(string(output)), nil
	}

	return "", errNoReloadMethod
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	output, err := s.reloadEngine(r.Context())
	if err != nil {
		if errors.Is(err, errNoReloadMethod) {
			writeError(w, http.StatusNotImplemented, "%s", err)
			return
		}

		s.log.Errorf("engine reload failed: %s: %s", err, output)
		writeError(w, http.StatusInternalServerError, "%s", err)

		return
	}

	s.log.Infof("user %q reloaded the engine", currentUser(r))
	writeJSON(w, http.StatusOK, map[string]string{"message": "engine reloaded", "output": output})
}

func (s *Server) reloadViaSignal() (string, error) {
	raw, err := os.ReadFile(s.cfg.Engine.PIDFile)
	if err != nil {
		return "", fmt.Errorf("reading pid file %q: %w", s.cfg.Engine.PIDFile, err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return "", fmt.Errorf("invalid pid in %q: %w", s.cfg.Engine.PIDFile, err)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return "", fmt.Errorf("finding process %d: %w", pid, err)
	}

	if err := process.Signal(syscall.SIGHUP); err != nil {
		return "", fmt.Errorf("sending SIGHUP to %d: %w", pid, err)
	}

	return fmt.Sprintf("SIGHUP sent to pid %d", pid), nil
}
