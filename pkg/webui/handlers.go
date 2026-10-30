package webui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/crowdsecurity/go-cs-lib/cstime"
)

const maxOverviewAlerts = 1000

type namedCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type timelinePoint struct {
	Time  time.Time `json:"time"`
	Count int       `json:"count"`
	// Breakdown splits Count by scenario for the stacked chart; empty when the
	// data source cannot group per bucket.
	Breakdown map[string]int `json:"breakdown,omitempty"`
}

type alertSummary struct {
	ID          int64   `json:"id"`
	CreatedAt   string  `json:"created_at"`
	Scenario    string  `json:"scenario"`
	Message     string  `json:"message"`
	SourceIP    string  `json:"source_ip"`
	SourceValue string  `json:"source_value"`
	SourceScope string  `json:"source_scope"`
	Country     string  `json:"source_country"`
	ASName      string  `json:"source_as_name"`
	Latitude    float32 `json:"latitude,omitempty"`
	Longitude   float32 `json:"longitude,omitempty"`
	Kind        string  `json:"kind"`
	Events      int32   `json:"events"`
	Decisions   int     `json:"decisions"`
}

type decisionStats struct {
	Total      int          `json:"total"`
	Simulated  int          `json:"simulated"`
	ByType     []namedCount `json:"by_type"`
	ByScope    []namedCount `json:"by_scope"`
	ByOrigin   []namedCount `json:"by_origin"`
	ByScenario []namedCount `json:"by_scenario"`
}

type blocklistStats struct {
	ActiveDecisions int            `json:"active_decisions"`
	Machines        int            `json:"machines"`
	Revision        int64          `json:"revision"`
	ByScenario      map[string]int `json:"by_scenario"`
	ByType          map[string]int `json:"by_type"`
}

func queryDuration(q url.Values, key string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(q.Get(key))
	if raw == "" {
		return def
	}

	parsed, err := cstime.ParseDurationWithDays(raw)
	if err != nil || parsed <= 0 {
		return def
	}

	return parsed
}

func queryInt(q url.Values, key string, def, minValue, maxValue int) int {
	value, err := strconv.Atoi(q.Get(key))
	if err != nil {
		return def
	}

	if value < minValue {
		return minValue
	}

	if value > maxValue {
		return maxValue
	}

	return value
}

func topCounts(counts map[string]int, limit int) []namedCount {
	result := make([]namedCount, 0, len(counts))

	for name, count := range counts {
		result = append(result, namedCount{Name: name, Count: count})
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Count == result[j].Count {
			return result[i].Name < result[j].Name
		}

		return result[i].Count > result[j].Count
	})

	if len(result) > limit {
		result = result[:limit]
	}

	return result
}

func summarizeAlert(alert *models.Alert) alertSummary {
	summary := alertSummary{
		ID:        alert.ID,
		CreatedAt: alert.CreatedAt,
		Kind:      alert.Kind,
		Decisions: len(alert.Decisions),
	}

	if alert.Scenario != nil {
		summary.Scenario = *alert.Scenario
	}

	if alert.Message != nil {
		summary.Message = *alert.Message
	}

	if alert.EventsCount != nil {
		summary.Events = *alert.EventsCount
	}

	if alert.Source != nil {
		summary.SourceIP = alert.Source.IP
		summary.Country = alert.Source.Cn
		summary.ASName = alert.Source.AsName
		summary.Latitude = alert.Source.Latitude
		summary.Longitude = alert.Source.Longitude

		if alert.Source.Value != nil {
			summary.SourceValue = *alert.Source.Value
		}

		if alert.Source.Scope != nil {
			summary.SourceScope = *alert.Source.Scope
		}
	}

	return summary
}

func buildTimeline(alerts []*models.Alert, since time.Duration) []timelinePoint {
	now := time.Now().Truncate(time.Hour)
	start := now.Add(-since)

	// Keep the chart readable: fall back to daily buckets for long ranges.
	step := time.Hour
	if since > 72*time.Hour {
		step = 24 * time.Hour
		start = start.Truncate(24 * time.Hour)
	}

	// time.Time keys compare the location pointer too, so bucket by Unix time.
	type bucketKey struct {
		bucket   int64
		scenario string
	}

	buckets := map[int64]int{}
	byScenario := map[bucketKey]int{}
	totals := map[string]int{}

	for _, alert := range alerts {
		created, err := time.Parse(time.RFC3339, alert.CreatedAt)
		if err != nil {
			continue
		}

		bucket := created.Truncate(step)
		if bucket.Before(start) {
			continue
		}

		scenario := ""
		if alert.Scenario != nil {
			scenario = *alert.Scenario
		}

		if scenario == "" {
			scenario = "unknown"
		}

		buckets[bucket.Unix()]++
		byScenario[bucketKey{bucket.Unix(), scenario}]++
		totals[scenario]++
	}

	// Same band selection as the database path, so both data sources render the
	// same chart: the busiest scenarios, the rest folded into "other".
	ranked := make([]namedCount, 0, len(totals))

	for name, count := range totals {
		ranked = append(ranked, namedCount{Name: name, Count: count})
	}

	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].Count == ranked[j].Count {
			return ranked[i].Name < ranked[j].Name
		}

		return ranked[i].Count > ranked[j].Count
	})

	const bandLimit = 5

	if len(ranked) > bandLimit {
		ranked = ranked[:bandLimit]
	}

	points := make([]timelinePoint, 0)

	for t := start; !t.After(now); t = t.Add(step) {
		point := timelinePoint{Time: t}

		for _, band := range ranked {
			if count := byScenario[bucketKey{t.Unix(), band.Name}]; count > 0 {
				if point.Breakdown == nil {
					point.Breakdown = map[string]int{}
				}

				point.Breakdown[band.Name] = count
			}
		}

		point.Count = buckets[t.Unix()]

		points = append(points, point)
	}

	return points
}

// timelineScenarios mirrors the band list the database path reports.
func timelineScenarios(points []timelinePoint) []namedCount {
	totals := map[string]int{}

	for _, point := range points {
		for name, count := range point.Breakdown {
			totals[name] += count
		}
	}

	return topCounts(totals, len(totals))
}

func summarizeDecisions(decisions []decisionView) decisionStats {
	stats := decisionStats{Total: len(decisions)}

	byType := map[string]int{}
	byOrigin := map[string]int{}
	byScenario := map[string]int{}

	for i := range decisions {
		decision := &decisions[i]
		if decision.Simulated {
			stats.Simulated++
		}

		if decision.Type != "" {
			byType[decision.Type]++
		}

		if decision.Origin != "" {
			byOrigin[decision.Origin]++
		}

		if decision.Scenario != "" {
			byScenario[decision.Scenario]++
		}
	}

	stats.ByType = topCounts(byType, 10)
	stats.ByOrigin = topCounts(byOrigin, 10)
	stats.ByScenario = topCounts(byScenario, 10)

	return stats
}

func (s *Server) attachBlocklistStats(ctx context.Context, result *overviewResponse) {
	if s.blocklist == nil {
		return
	}

	var stats blocklistStats
	if err := s.blocklist.do(ctx, http.MethodGet, "/admin/v1/stats", nil, &stats); err != nil {
		result.BlocklistError = err.Error()
		return
	}

	result.Blocklist = &stats
}

func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	limit := queryInt(q, "limit", 100, 1, 1000)
	since := queryDuration(q, "since", 0)

	opts := apiclient.AlertsListOpts{
		ScenarioEquals:   strings.TrimSpace(q.Get("scenario")),
		IPEquals:         strings.TrimSpace(q.Get("ip")),
		ValueEquals:      strings.TrimSpace(q.Get("value")),
		OriginEquals:     strings.TrimSpace(q.Get("origin")),
		TypeEquals:       strings.TrimSpace(q.Get("decision_type")),
		Kind:             strings.TrimSpace(q.Get("kind")),
		Limit:            &limit,
		IncludeCAPI:      new(q.Get("include_capi") == "true"),
		IncludeSimulated: new(true),
	}

	if since > 0 {
		opts.Since = cstime.DurationWithDays(since)
	}

	// Substring matching only makes sense together with a value to look for.
	if opts.ValueEquals != "" && q.Get("contains") == "true" {
		opts.Contains = new(true)
	}

	switch q.Get("has_active_decision") {
	case "true":
		opts.ActiveDecisionEquals = new(true)
	case "false":
		opts.ActiveDecisionEquals = new(false)
	}

	alerts, _, err := s.lapi.Alerts.List(ctx, opts)
	if err != nil {
		s.log.Errorf("listing alerts: %s", err)
		writeErrorf(w, http.StatusBadGateway, "could not list alerts: %s", err)
		return
	}

	// The list view only needs the summary shape shared with the dashboard.
	summaries := make([]alertSummary, 0, len(*alerts))

	for _, alert := range *alerts {
		summaries = append(summaries, summarizeAlert(alert))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"alerts":       summaries,
		"count":        len(summaries),
		"generated_at": time.Now(),
	})
}

func (s *Server) handleGetAlert(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeErrorf(w, http.StatusBadRequest, "invalid alert id")
		return
	}

	alert, _, err := s.lapi.Alerts.GetByID(r.Context(), id)
	if err != nil {
		writeErrorf(w, http.StatusBadGateway, "could not load alert %d: %s", id, err)
		return
	}

	writeJSON(w, http.StatusOK, alert)
}

func (s *Server) handleDeleteAlert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	resp, _, err := s.lapi.Alerts.DeleteOne(r.Context(), id)
	if err != nil {
		s.log.Errorf("deleting alert %s: %s", id, err)
		writeErrorf(w, http.StatusBadGateway, "could not delete alert %s: %s", id, err)
		return
	}

	s.log.Infof("user %q deleted alert %s", currentUser(r), id)

	writeJSON(w, http.StatusOK, resp)
}

// decisionView is a decision flattened out of its alert, because the local
// API only exposes decisions through alerts to machines (the decision list
// endpoint is reserved for bouncers).
type decisionView struct {
	ID        int64  `json:"id"`
	Value     string `json:"value"`
	Scope     string `json:"scope"`
	Type      string `json:"type"`
	Duration  string `json:"duration"`
	Scenario  string `json:"scenario"`
	Origin    string `json:"origin"`
	Country   string `json:"country,omitempty"`
	ASName    string `json:"as_name,omitempty"`
	Until     string `json:"until,omitempty"`
	Simulated bool   `json:"simulated"`
	AlertID   int64  `json:"alert_id"`
}

func flattenDecisions(alerts []*models.Alert) []decisionView {
	decisions := make([]decisionView, 0)

	for _, alert := range alerts {
		if alert == nil {
			continue
		}

		for _, decision := range alert.Decisions {
			if decision == nil {
				continue
			}

			view := decisionView{
				ID:      decision.ID,
				AlertID: alert.ID,
			}

			if decision.Value != nil {
				view.Value = *decision.Value
			}

			if decision.Scope != nil {
				view.Scope = *decision.Scope
			}

			if decision.Type != nil {
				view.Type = *decision.Type
			}

			if decision.Duration != nil {
				view.Duration = *decision.Duration
			}

			if decision.Scenario != nil {
				view.Scenario = *decision.Scenario
			}

			if decision.Origin != nil {
				view.Origin = *decision.Origin
			}

			if decision.Simulated != nil {
				view.Simulated = *decision.Simulated
			}

			view.Until = decision.Until

			if alert.Source != nil {
				view.Country = alert.Source.Cn
				view.ASName = alert.Source.AsName
			}

			decisions = append(decisions, view)
		}
	}

	return decisions
}

func (s *Server) handleListDecisions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	limit := queryInt(q, "limit", 500, 1, 5000)

	opts := apiclient.AlertsListOpts{
		ScopeEquals:          strings.TrimSpace(q.Get("scope")),
		ScenarioEquals:       strings.TrimSpace(q.Get("scenario")),
		OriginEquals:         strings.TrimSpace(q.Get("origin")),
		ValueEquals:          strings.TrimSpace(q.Get("value")),
		TypeEquals:           strings.TrimSpace(q.Get("type")),
		IPEquals:             strings.TrimSpace(q.Get("ip")),
		RangeEquals:          strings.TrimSpace(q.Get("range")),
		ActiveDecisionEquals: new(true),
		IncludeCAPI:          new(true),
		IncludeSimulated:     new(true),
		Limit:                &limit,
	}

	alerts, _, err := s.lapi.Alerts.List(r.Context(), opts)
	if err != nil {
		s.log.Errorf("listing decisions: %s", err)
		writeErrorf(w, http.StatusBadGateway, "could not list decisions: %s", err)
		return
	}

	decisions := flattenDecisions(*alerts)

	writeJSON(w, http.StatusOK, map[string]any{
		"decisions":    decisions,
		"count":        len(decisions),
		"alert_limit":  limit,
		"limited":      len(*alerts) >= limit,
		"generated_at": time.Now(),
	})
}

type createDecisionRequest struct {
	Value    string `json:"value"`
	Scope    string `json:"scope"`
	Type     string `json:"type"`
	Duration string `json:"duration"`
	Reason   string `json:"reason"`
}

func (req *createDecisionRequest) normalize() error {
	req.Value = strings.TrimSpace(req.Value)

	switch strings.ToLower(strings.TrimSpace(req.Scope)) {
	case "", "ip":
		req.Scope = types.Ip
		if _, err := netip.ParseAddr(req.Value); err != nil {
			return fmt.Errorf("invalid IP %q", req.Value)
		}
	case "range":
		req.Scope = types.Range

		prefix, err := netip.ParsePrefix(req.Value)
		if err != nil {
			return fmt.Errorf("invalid range %q", req.Value)
		}

		req.Value = prefix.Masked().String()
	default:
		return fmt.Errorf("invalid scope %q, expected ip or range", req.Scope)
	}

	if req.Value == "" {
		return errors.New("a value is required")
	}

	if req.Type == "" {
		req.Type = types.DecisionTypeBan
	}

	if req.Duration == "" {
		req.Duration = "4h"
	}

	if req.Duration != "0" {
		if _, err := cstime.ParseDurationWithDays(req.Duration); err != nil {
			return fmt.Errorf("invalid duration %q", req.Duration)
		}
	}

	if req.Reason == "" {
		req.Reason = "manual decision from cswebui"
	}

	return nil
}

// buildManualAlert mirrors what `cscli decisions add` sends to the local API:
// an alert whose single decision is the ban itself.
func buildManualAlert(req createDecisionRequest) *models.Alert {
	empty := ""
	simulated := false
	leakspeed := "0"
	capacity := int32(0)
	eventsCount := int32(1)
	startAt := time.Now().UTC().Format(time.RFC3339)
	createdAt := startAt

	decision := &models.Decision{
		Value:    &req.Value,
		Scope:    &req.Scope,
		Type:     &req.Type,
		Duration: &req.Duration,
		Scenario: &req.Reason,
		Origin:   new(types.CscliOrigin),
	}

	return &models.Alert{
		Capacity:        &capacity,
		Decisions:       []*models.Decision{decision},
		Events:          []*models.Event{},
		EventsCount:     &eventsCount,
		Leakspeed:       &leakspeed,
		Message:         &req.Reason,
		Scenario:        &req.Reason,
		ScenarioHash:    &empty,
		ScenarioVersion: &empty,
		Simulated:       &simulated,
		StartAt:         &startAt,
		StopAt:          &startAt,
		CreatedAt:       createdAt,
		Remediation:     true,
		Kind:            types.CscliAlertKind.String(),
		Source: &models.Source{
			IP:       req.Value,
			Value:    &req.Value,
			Scope:    &req.Scope,
			AsName:   "",
			AsNumber: "",
			Cn:       "",
			Range:    "",
		},
	}
}

func (s *Server) handleCreateDecision(w http.ResponseWriter, r *http.Request) {
	var req createDecisionRequest

	if err := decodeBody(w, r, &req); err != nil {
		writeErrorf(w, http.StatusBadRequest, "%s", err)
		return
	}

	if err := req.normalize(); err != nil {
		writeErrorf(w, http.StatusBadRequest, "%s", err)
		return
	}

	alert := buildManualAlert(req)

	if _, _, err := s.lapi.Alerts.Add(r.Context(), models.AddAlertsRequest{alert}); err != nil {
		s.log.Errorf("creating decision: %s", err)
		writeErrorf(w, http.StatusBadGateway, "could not create decision: %s", err)
		return
	}

	s.log.Infof("user %q added %s %s (%s)", currentUser(r), req.Scope, req.Value, req.Duration)

	writeJSON(w, http.StatusCreated, map[string]any{
		"message": "decision created",
		"value":   req.Value,
		"scope":   req.Scope,
		"type":    req.Type,
	})
}

func (s *Server) handleDeleteDecision(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	if _, err := strconv.ParseInt(id, 10, 64); err != nil {
		writeErrorf(w, http.StatusBadRequest, "invalid decision id")
		return
	}

	resp, _, err := s.lapi.Decisions.DeleteOne(r.Context(), id)
	if err != nil {
		s.log.Errorf("deleting decision %s: %s", id, err)
		writeErrorf(w, http.StatusBadGateway, "could not delete decision %s: %s", id, err)
		return
	}

	s.log.Infof("user %q deleted decision %s", currentUser(r), id)

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleListAllowlists(w http.ResponseWriter, r *http.Request) {
	allowlists, _, err := s.lapi.Allowlists.List(r.Context(), apiclient.AllowlistListOpts{WithContent: true})
	if err != nil {
		s.log.Errorf("listing allowlists: %s", err)
		writeErrorf(w, http.StatusBadGateway, "could not list allowlists: %s", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"allowlists":   *allowlists,
		"count":        len(*allowlists),
		"generated_at": time.Now(),
	})
}

func (s *Server) handleGetAllowlist(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	allowlist, _, err := s.lapi.Allowlists.Get(r.Context(), name, apiclient.AllowlistGetOpts{WithContent: true})
	if err != nil {
		writeErrorf(w, http.StatusBadGateway, "could not load allowlist %q: %s", name, err)
		return
	}

	writeJSON(w, http.StatusOK, allowlist)
}

func (s *Server) handleBlocklistStats(w http.ResponseWriter, r *http.Request) {
	if s.blocklist == nil {
		writeErrorf(w, http.StatusNotImplemented, "no blocklist server configured")
		return
	}

	var stats blocklistStats
	if err := s.blocklist.do(r.Context(), http.MethodGet, "/admin/v1/stats", nil, &stats); err != nil {
		writeErrorf(w, http.StatusBadGateway, "%s", err)
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleBlocklistDecisions(w http.ResponseWriter, r *http.Request) {
	if s.blocklist == nil {
		writeErrorf(w, http.StatusNotImplemented, "no blocklist server configured")
		return
	}

	q := r.URL.Query()
	path := "/admin/v1/decisions?"

	if value := strings.TrimSpace(q.Get("value")); value != "" {
		path += "value=" + url.QueryEscape(value) + "&"
	}

	if scenario := strings.TrimSpace(q.Get("scenario")); scenario != "" {
		path += "scenario=" + url.QueryEscape(scenario) + "&"
	}

	path += "limit=" + strconv.Itoa(queryInt(q, "limit", 200, 1, 1000))

	var payload struct {
		Decisions any `json:"decisions"`
	}

	if err := s.blocklist.do(r.Context(), http.MethodGet, path, nil, &payload); err != nil {
		writeErrorf(w, http.StatusBadGateway, "%s", err)
		return
	}

	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleBlocklistCreate(w http.ResponseWriter, r *http.Request) {
	if s.blocklist == nil {
		writeErrorf(w, http.StatusNotImplemented, "no blocklist server configured")
		return
	}

	var req createDecisionRequest

	if err := decodeBody(w, r, &req); err != nil {
		writeErrorf(w, http.StatusBadRequest, "%s", err)
		return
	}

	// Reuse the same validation as the local API path.
	local := req

	if err := local.normalize(); err != nil {
		writeErrorf(w, http.StatusBadRequest, "%s", err)
		return
	}

	body := map[string]string{
		"value":    local.Value,
		"scope":    local.Scope,
		"type":     local.Type,
		"duration": local.Duration,
		"scenario": local.Reason,
	}

	var created any
	if err := s.blocklist.do(r.Context(), http.MethodPost, "/admin/v1/decisions", body, &created); err != nil {
		writeErrorf(w, http.StatusBadGateway, "%s", err)
		return
	}

	s.log.Infof("user %q shared %s %s on the blocklist server", currentUser(r), local.Scope, local.Value)

	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleBlocklistDelete(w http.ResponseWriter, r *http.Request) {
	if s.blocklist == nil {
		writeErrorf(w, http.StatusNotImplemented, "no blocklist server configured")
		return
	}

	id := r.PathValue("id")
	if _, err := strconv.ParseInt(id, 10, 64); err != nil {
		writeErrorf(w, http.StatusBadRequest, "invalid decision id")
		return
	}

	if err := s.blocklist.do(r.Context(), http.MethodDelete, "/admin/v1/decisions/"+id, nil, nil); err != nil {
		writeErrorf(w, http.StatusBadGateway, "%s", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "deleted"})
}

func (s *Server) handleBlocklistMachines(w http.ResponseWriter, r *http.Request) {
	if s.blocklist == nil {
		writeErrorf(w, http.StatusNotImplemented, "no blocklist server configured")
		return
	}

	var payload any
	if err := s.blocklist.do(r.Context(), http.MethodGet, "/admin/v1/machines", nil, &payload); err != nil {
		writeErrorf(w, http.StatusBadGateway, "%s", err)
		return
	}

	writeJSON(w, http.StatusOK, payload)
}
