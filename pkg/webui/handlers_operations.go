package webui

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/go-cs-lib/cstime"
)

func (s *Server) handleInspectIP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	ip, err := netip.ParseAddr(strings.TrimSpace(r.URL.Query().Get("ip")))
	if err != nil {
		writeErrorf(w, http.StatusBadRequest, "enter a valid IPv4 or IPv6 address")
		return
	}
	limit := 100
	contains := true
	alerts, _, alertsErr := s.lapi.Alerts.List(ctx, apiclient.AlertsListOpts{
		IPEquals: ip.String(), Contains: &contains, Limit: &limit, IncludeCAPI: new(true), IncludeSimulated: new(true),
	})
	active, _, decisionsErr := s.lapi.Alerts.List(ctx, apiclient.AlertsListOpts{
		IPEquals: ip.String(), Contains: &contains, Limit: &limit, ActiveDecisionEquals: new(true), IncludeCAPI: new(true), IncludeSimulated: new(true),
	})
	allowlist, _, allowlistErr := s.lapi.Allowlists.CheckIfAllowlistedWithReason(ctx, ip.String())
	summaries := []alertSummary{}
	decisions := []decisionView{}
	failures := map[string]string{}
	if alertsErr != nil {
		failures["alerts"] = alertsErr.Error()
	} else if alerts != nil {
		for _, alert := range *alerts {
			summaries = append(summaries, summarizeAlert(alert))
		}
	}
	if decisionsErr != nil {
		failures["decisions"] = decisionsErr.Error()
	} else if active != nil {
		decisions = flattenDecisions(*active)
	}
	if allowlistErr != nil {
		failures["allowlist"] = allowlistErr.Error()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ip": ip.String(), "alerts": summaries, "decisions": decisions, "allowlist": allowlist, "errors": failures,
		"limit": limit, "alerts_limited": len(summaries) == limit, "decisions_limited": active != nil && len(*active) == limit,
		"generated_at": time.Now(),
	})
}

type allowlistActionRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Value       string `json:"value"`
	Duration    string `json:"duration"`
}

func (s *Server) handleAllowlistAction(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req allowlistActionRequest
		if action != "delete" {
			if err := decodeBody(w, r, &req); err != nil {
				writeErrorf(w, http.StatusBadRequest, "%s", err)
				return
			}
		}
		name := r.PathValue("name")
		if action == "create" {
			name = strings.TrimSpace(req.Name)
		}
		if name == "" || name == "." || name == ".." || len(name) > 128 || strings.ContainsAny(name, "\x00\r\n/?#\\") {
			writeErrorf(w, http.StatusBadRequest, "invalid allowlist name")
			return
		}
		if len(req.Description) > 1024 {
			writeErrorf(w, http.StatusBadRequest, "description is too long")
			return
		}
		args := []string{"allowlists", action}
		if action == "create" {
			if strings.TrimSpace(req.Description) == "" {
				writeErrorf(w, http.StatusBadRequest, "description is required")
				return
			}
			args = append(args, "--description", req.Description)
		} else {
			list, _, err := s.lapi.Allowlists.Get(r.Context(), name, apiclient.AllowlistGetOpts{})
			if err != nil {
				writeErrorf(w, http.StatusBadGateway, "could not load allowlist: %s", err)
				return
			}
			if list == nil || list.ConsoleManaged {
				writeErrorf(w, http.StatusForbidden, "console-managed allowlists cannot be edited here")
				return
			}
		}
		if action == "add" || action == "remove" {
			req.Value = strings.TrimSpace(req.Value)
			if _, err := netip.ParseAddr(req.Value); err != nil {
				if _, err := netip.ParsePrefix(req.Value); err != nil {
					writeErrorf(w, http.StatusBadRequest, "value must be an IP address or CIDR range")
					return
				}
			}
		}
		if action == "add" && req.Duration != "" {
			duration, err := cstime.ParseDurationWithDays(req.Duration)
			if err != nil || duration <= 0 {
				writeErrorf(w, http.StatusBadRequest, "duration must be positive, or empty for permanent")
				return
			}
			args = append(args, "--expiration", req.Duration)
		}
		if action == "add" && req.Description != "" {
			args = append(args, "--comment", req.Description)
		}
		args = append(args, "--", name)
		if action == "add" || action == "remove" {
			args = append(args, req.Value)
		}
		if !s.hubMu.TryLock() {
			writeErrorf(w, http.StatusConflict, "another engine or allowlist operation is in progress")
			return
		}
		defer s.hubMu.Unlock()
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		output, err := s.runCscli(ctx, args...)
		if err != nil {
			writeErrorf(w, http.StatusInternalServerError, "%s: %s", err, output)
			return
		}
		s.log.Infof("user %q changed allowlist %q (%s)", currentUser(r), name, action)
		writeJSON(w, http.StatusOK, map[string]string{"message": "Allowlist updated", "output": output})
	}
}

func (s *Server) testEngineConfig(ctx context.Context) (string, error) {
	output, err := exec.CommandContext(ctx, "crowdsec", "-c", filepath.Join(s.cfg.Engine.ConfigDir, "config.yaml"), "-t").CombinedOutput()
	text := strings.TrimSpace(string(output))
	if len(text) > maxHubOutput {
		text = text[:maxHubOutput] + " …"
	}
	return text, err
}

func (s *Server) handleCheckConfig(w http.ResponseWriter, r *http.Request) {
	if !s.hubMu.TryLock() {
		writeErrorf(w, http.StatusConflict, "another engine or allowlist operation is in progress")
		return
	}
	defer s.hubMu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	output, err := s.runConfigTest(ctx)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			writeErrorf(w, http.StatusNotImplemented, "crowdsec must be installed in PATH to validate the saved configuration")
			return
		}
		writeErrorf(w, http.StatusBadRequest, "configuration check failed: %s: %s", err, output)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Saved engine configuration is valid", "output": output})
}
