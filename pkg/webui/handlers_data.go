package webui

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sort"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/go-cs-lib/cstime"
)

type dataSources struct {
	DB      bool `json:"db"`
	Metrics bool `json:"metrics"`
}

type machinesOverview struct {
	Total  int           `json:"total"`
	Online int           `json:"online"`
	Items  []machineInfo `json:"items"`
}

type bouncersOverview struct {
	Total  int           `json:"total"`
	Active int           `json:"active"`
	Items  []bouncerInfo `json:"items"`
}

type metricsSummary struct {
	Available bool `json:"available"`

	Version string `json:"version,omitempty"`

	ParserHits float64 `json:"parser_hits"`
	ParserOK   float64 `json:"parser_ok"`
	ParserKO   float64 `json:"parser_ko"`

	BucketPoured    float64 `json:"bucket_poured"`
	BucketOverflows float64 `json:"bucket_overflows"`
	BucketsCurrent  float64 `json:"buckets_current"`

	AcquisitionLines float64 `json:"acquisition_lines"`
	LAPIRequests     float64 `json:"lapi_requests"`
	BouncerRequests  float64 `json:"bouncer_requests"`

	CapiErrors        float64    `json:"capi_errors"`
	CapiLastPull      *time.Time `json:"capi_last_pull,omitempty"`
	PostoverflowQueue float64    `json:"postoverflow_queue"`
	PostoverflowDrop  float64    `json:"postoverflow_dropped"`
	AvgParseMS        *float64   `json:"avg_parse_ms,omitempty"`

	TopNodes     []namedCount `json:"top_nodes"`
	TopNodeKO    []namedCount `json:"top_nodes_ko"`
	TopBuckets   []namedCount `json:"top_buckets"`
	TopOverflows []namedCount `json:"top_overflows"`
	TopSources   []namedCount `json:"top_sources"`
	TopRoutes    []namedCount `json:"top_routes"`
	TopBouncers  []namedCount `json:"top_bouncers"`
	TopMachines  []namedCount `json:"top_machines"`

	Features []string `json:"features,omitempty"`
}

type overviewResponse struct {
	GeneratedAt   time.Time      `json:"generated_at"`
	Since         time.Time      `json:"since"`
	LAPIReachable bool           `json:"lapi_reachable"`
	Alerts        alertDBStats   `json:"alerts"`
	Decisions     decisionStats  `json:"decisions"`
	RecentAlerts  []alertSummary `json:"recent_alerts"`

	Machines machinesOverview `json:"machines"`
	Bouncers bouncersOverview `json:"bouncers"`

	Blocklist      *blocklistStats `json:"blocklist,omitempty"`
	BlocklistError string          `json:"blocklist_error,omitempty"`
	Metrics        *metricsSummary `json:"metrics,omitempty"`

	DataSources dataSources `json:"data_sources"`
}

func topFloat(counts map[string]float64, limit int) []namedCount {
	type kv struct {
		name  string
		count float64
	}

	items := make([]kv, 0, len(counts))

	for name, count := range counts {
		items = append(items, kv{name: name, count: count})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].count == items[j].count {
			return items[i].name < items[j].name
		}

		return items[i].count > items[j].count
	})

	if len(items) > limit {
		items = items[:limit]
	}

	result := make([]namedCount, 0, len(items))

	for _, item := range items {
		result = append(result, namedCount{Name: item.name, Count: int(item.count)})
	}

	return result
}

func buildMetricsSummary(snapshot *metricsSnapshot) *metricsSummary {
	if snapshot == nil {
		return nil
	}

	summary := &metricsSummary{Available: true}

	summary.ParserHits = snapshot.sum("cs_parser_hits_total")
	summary.ParserOK = snapshot.sum("cs_parser_hits_ok_total")
	summary.ParserKO = snapshot.sum("cs_parser_hits_ko_total")
	summary.BucketPoured = snapshot.sum("cs_bucket_poured_total")
	summary.BucketOverflows = snapshot.sum("cs_bucket_overflowed_total")
	summary.BucketsCurrent = snapshot.sum("cs_buckets")
	summary.AcquisitionLines = snapshot.sum("cs_filesource_hits_total")
	summary.LAPIRequests = snapshot.sum("cs_lapi_route_requests_total")
	summary.BouncerRequests = snapshot.sum("cs_lapi_bouncer_requests_total")
	summary.CapiErrors = snapshot.sum("cs_capi_errors_total")
	summary.PostoverflowQueue = snapshot.sum("cs_postoverflow_queue_depth")
	summary.PostoverflowDrop = snapshot.sum("cs_postoverflow_dropped_total")

	if ts, ok := snapshot.value("cs_capi_last_pull_timestamp"); ok && ts > 0 {
		pulled := time.Unix(int64(ts), 0).UTC()
		summary.CapiLastPull = &pulled
	}

	if average, ok := snapshot.histogramAverage("cs_parsing_time_seconds"); ok {
		ms := average * 1000
		summary.AvgParseMS = &ms
	}

	if versions := snapshot.labelValues("cs_info", "version"); len(versions) == 1 {
		summary.Version = versions[0]
	}

	summary.Features = enabledFeatures(snapshot)
	summary.TopNodes = topFloat(snapshot.groupSum("cs_node_hits_total", "name"), 8)
	summary.TopNodeKO = topFloat(snapshot.groupSum("cs_node_hits_ko_total", "name"), 8)
	summary.TopBuckets = topFloat(snapshot.groupSum("cs_buckets", "name"), 8)
	summary.TopOverflows = topFloat(snapshot.groupSum("cs_bucket_overflowed_total", "name"), 8)
	summary.TopSources = topFloat(snapshot.groupSum("cs_filesource_hits_total", "source"), 8)
	summary.TopRoutes = topFloat(snapshot.groupSum("cs_lapi_route_requests_total", "route"), 8)
	summary.TopBouncers = topFloat(snapshot.groupSum("cs_lapi_bouncer_requests_total", "bouncer"), 8)
	summary.TopMachines = topFloat(snapshot.groupSum("cs_lapi_machine_requests_total", "machine"), 8)

	return summary
}

func enabledFeatures(snapshot *metricsSnapshot) []string {
	features := []string{}

	for _, sample := range snapshot.Samples {
		if sample.Name != "cs_features" || sample.Value == 0 {
			continue
		}

		if feature := sample.Labels["feature"]; feature != "" {
			features = append(features, feature)
		}
	}

	sort.Strings(features)

	return features
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	result, err := s.buildOverview(r.Context(), queryDuration(r.URL.Query(), "since", 24*time.Hour))
	if err != nil {
		writeError(w, http.StatusBadGateway, "%s", err)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) buildOverview(ctx context.Context, since time.Duration) (*overviewResponse, error) {
	limit := maxOverviewAlerts

	alerts, _, err := s.lapi.Alerts.List(ctx, apiclient.AlertsListOpts{
		Since:            cstime.DurationWithDays(since),
		Limit:            &limit,
		IncludeCAPI:      boolPtr(true),
		IncludeSimulated: boolPtr(true),
	})
	if err != nil {
		s.log.Errorf("listing alerts: %s", err)
		return nil, fmt.Errorf("could not list alerts from the local API: %w", err)
	}

	result := &overviewResponse{
		GeneratedAt:  time.Now(),
		Since:        time.Now().Add(-since),
		RecentAlerts: make([]alertSummary, 0, 10),
	}

	for i, alert := range *alerts {
		summary := summarizeAlert(alert)
		if i < 10 {
			result.RecentAlerts = append(result.RecentAlerts, summary)
		}
	}

	result.DataSources.DB = s.state != nil

	if s.state != nil {
		alertStats, err := s.state.AlertStats(ctx, result.Since)
		if err != nil {
			s.log.Warnf("database alerts stats: %s", err)
		} else {
			result.Alerts = *alertStats
		}

		decisionStats, err := s.state.DecisionStats(ctx)
		if err != nil {
			s.log.Warnf("database decision stats: %s", err)
		} else {
			result.Decisions = decisionStatsFromDB(decisionStats)
		}

		machines, err := s.state.Machines(ctx)
		if err != nil {
			s.log.Warnf("database machines: %s", err)
		} else {
			result.Machines = summarizeMachines(machines)
		}

		bouncers, err := s.state.Bouncers(ctx)
		if err != nil {
			s.log.Warnf("database bouncers: %s", err)
		} else {
			result.Bouncers = summarizeBouncers(bouncers)
		}
	} else {
		// Fallback: everything we can derive from the limited alert list.
		result.Alerts = alertStatsFromAPI(*alerts, since)
		result.Decisions = summarizeDecisions(flattenDecisions(*alerts))
	}

	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if ok, _, err := s.lapi.HeartBeat.Ping(pingCtx); err == nil && ok {
		result.LAPIReachable = true
	}

	s.attachBlocklistStats(ctx, result)

	metricsCtx, metricsCancel := context.WithTimeout(ctx, 3*time.Second)
	defer metricsCancel()

	if snapshot, err := scrapeMetrics(metricsCtx, s.cfg.Data.MetricsURL); err == nil {
		result.Metrics = buildMetricsSummary(snapshot)
		result.DataSources.Metrics = true
	} else {
		s.log.Debugf("metrics unavailable: %s", err)
	}

	return result, nil
}

// alertStatsFromAPI is the fallback when the LAPI database is not readable:
// figures then come from the (limited) alert list returned by the API.
func alertStatsFromAPI(alerts []*models.Alert, since time.Duration) alertDBStats {
	stats := alertDBStats{
		Total:    len(alerts),
		Timeline: buildTimeline(alerts, since),
	}

	scenarios := map[string]int{}
	sources := map[string]int{}
	countries := map[string]int{}
	geo := map[[2]float64]*geoPoint{}

	for _, alert := range alerts {
		summary := summarizeAlert(alert)
		stats.Events += int(summary.Events)

		if summary.Scenario != "" {
			scenarios[summary.Scenario]++
		}

		if summary.Country != "" {
			countries[summary.Country]++
		}

		source := summary.SourceIP
		if source == "" {
			source = summary.SourceValue
		}

		if source != "" {
			sources[source]++
		}

		if summary.Latitude != 0 || summary.Longitude != 0 {
			key := [2]float64{math.Round(float64(summary.Latitude)*10) / 10, math.Round(float64(summary.Longitude)*10) / 10}

			point, ok := geo[key]
			if !ok {
				point = &geoPoint{Lat: key[0], Lon: key[1], Country: summary.Country}
				geo[key] = point
			}

			point.Count++
		}
	}

	stats.UniqueSources = len(sources)
	stats.ByScenario = topCounts(scenarios, 10)
	stats.ByCountry = topCounts(countries, 10)

	for _, point := range geo {
		stats.Geo = append(stats.Geo, *point)
	}

	sort.Slice(stats.Geo, func(i, j int) bool { return stats.Geo[i].Count > stats.Geo[j].Count })

	return stats
}

func decisionStatsFromDB(stats *decisionDBStats) decisionStats {
	return decisionStats{
		Total:      stats.Total,
		Simulated:  stats.Simulated,
		ByType:     stats.ByType,
		ByOrigin:   stats.ByOrigin,
		ByScenario: stats.ByScenario,
		ByScope:    stats.ByScope,
	}
}

func summarizeMachines(machines []machineInfo) machinesOverview {
	overview := machinesOverview{Total: len(machines), Items: machines}
	cutoff := time.Now().Add(-5 * time.Minute)

	for _, machine := range machines {
		if machine.LastSeen != nil && machine.LastSeen.After(cutoff) {
			overview.Online++
		}
	}

	return overview
}

func summarizeBouncers(bouncers []bouncerInfo) bouncersOverview {
	overview := bouncersOverview{Total: len(bouncers), Items: bouncers}
	cutoff := time.Now().Add(-5 * time.Minute)

	for _, bouncer := range bouncers {
		if bouncer.LastPull != nil && bouncer.LastPull.After(cutoff) {
			overview.Active++
		}
	}

	return overview
}

func (s *Server) handleInfra(w http.ResponseWriter, r *http.Request) {
	response := map[string]any{
		"machines": []machineInfo{},
		"bouncers": []bouncerInfo{},
		"db":       s.state != nil,
	}

	if s.state == nil {
		writeJSON(w, http.StatusOK, response)
		return
	}

	machines, err := s.state.Machines(r.Context())
	if err != nil {
		s.log.Errorf("listing machines: %s", err)
	}

	bouncers, err := s.state.Bouncers(r.Context())
	if err != nil {
		s.log.Errorf("listing bouncers: %s", err)
	}

	response["machines"] = machines
	response["bouncers"] = bouncers

	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	snapshot, err := scrapeMetrics(ctx, s.cfg.Data.MetricsURL)
	if err != nil {
		writeError(w, http.StatusBadGateway, "could not scrape metrics: %s", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"summary":    buildMetricsSummary(snapshot),
		"fetched_at": snapshot.FetchedAt,
		"samples":    len(snapshot.Samples),
	})
}
