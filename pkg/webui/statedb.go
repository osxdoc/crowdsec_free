package webui

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite" // Register the SQLite driver for database/sql.
)

// StateStore gives read-only access to the LAPI database. It is optional: when
// the database cannot be opened the UI keeps working with the API and metrics
// data only.
type StateStore struct {
	db *sql.DB
}

type machineInfo struct {
	MachineID string     `json:"machine_id"`
	Version   string     `json:"version"`
	OSName    string     `json:"osname"`
	OSFamily  string     `json:"osfamily"`
	OSVersion string     `json:"osversion"`
	Scenarios string     `json:"scenarios"`
	LastSeen  *time.Time `json:"last_heartbeat"`
	Validated bool       `json:"validated"`
	IPAddress string     `json:"ip_address"`
	CreatedAt time.Time  `json:"created_at"`
}

type bouncerInfo struct {
	Name      string     `json:"name"`
	Type      string     `json:"type"`
	Version   string     `json:"version"`
	OSName    string     `json:"osname"`
	OSVersion string     `json:"osversion"`
	IPAddress string     `json:"ip_address"`
	LastPull  *time.Time `json:"last_pull"`
	Revoked   bool       `json:"revoked"`
	CreatedAt time.Time  `json:"created_at"`
}

// geoPoint is an aggregated origin on the world map.
type geoPoint struct {
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	Count   int     `json:"count"`
	Country string  `json:"country,omitempty"`
}

type alertDBStats struct {
	Total         int             `json:"total"`
	Events        int             `json:"events"`
	UniqueSources int             `json:"unique_sources"`
	ByScenario    []namedCount    `json:"by_scenario"`
	ByCountry     []namedCount    `json:"by_country"`
	ByAS          []namedCount    `json:"by_as"`
	ByKind        []namedCount    `json:"by_kind"`
	Geo           []geoPoint      `json:"geo"`
	Timeline      []timelinePoint `json:"timeline"`
	// TimelineScenario lists the scenarios the stacked timeline breaks down by,
	// most frequent first; empty when the breakdown was not computed.
	TimelineScenario []namedCount `json:"timeline_scenarios,omitempty"`
}

type decisionDBStats struct {
	Total      int          `json:"total"`
	Simulated  int          `json:"simulated"`
	ByType     []namedCount `json:"by_type"`
	ByScope    []namedCount `json:"by_scope"`
	ByOrigin   []namedCount `json:"by_origin"`
	ByScenario []namedCount `json:"by_scenario"`
}

// OpenStateStore opens the LAPI SQLite database in read-only mode.
func OpenStateStore(path string) (*StateStore, error) {
	if path == "" {
		return nil, errors.New("no database path")
	}

	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("database %q: %w", path, err)
	}

	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=busy_timeout(3000)", path)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}

	// A single connection avoids locking surprises with a writer running in
	// the engine container.
	db.SetMaxOpenConns(1)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}

	return &StateStore{db: db}, nil
}

// Close closes the database.
func (s *StateStore) Close() error {
	return s.db.Close()
}

// DatabasePath resolves the SQLite path: explicit config first, then
// db_config.db_path from the engine's config.yaml.
func (c *Config) DatabasePath() string {
	if c.Data.DBPath != "" {
		return c.Data.DBPath
	}

	data, err := os.ReadFile(filepath.Join(c.Engine.ConfigDir, "config.yaml"))
	if err != nil {
		return ""
	}

	var engineConfig struct {
		DBConfig struct {
			Type   string `yaml:"type"`
			DBPath string `yaml:"db_path"`
		} `yaml:"db_config"`
	}

	if err := yaml.Unmarshal(data, &engineConfig); err != nil {
		return ""
	}

	if engineConfig.DBConfig.Type != "sqlite" {
		return ""
	}

	return engineConfig.DBConfig.DBPath
}

func parseSQLiteTime(raw sql.NullString) *time.Time {
	if !raw.Valid || raw.String == "" {
		return nil
	}

	// modernc.org/sqlite returns DATETIME columns as time.Time, which
	// database/sql converts to RFC3339Nano when scanning into a string.
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	}

	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, raw.String); err == nil {
			return &parsed
		}
	}

	return nil
}

// Machines returns the registered machines.
func (s *StateStore) Machines(ctx context.Context) ([]machineInfo, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT machine_id, COALESCE(version, ''), COALESCE(osname, ''), COALESCE(osfamily, ''),
		       COALESCE(osversion, ''), COALESCE(scenarios, ''), last_heartbeat, is_validated,
		       COALESCE(ip_address, ''), created_at
		FROM machines
		ORDER BY last_heartbeat DESC`)
	if err != nil {
		return nil, fmt.Errorf("querying machines: %w", err)
	}
	defer rows.Close()

	machines := make([]machineInfo, 0)

	for rows.Next() {
		var (
			m         machineInfo
			lastSeen  sql.NullString
			createdAt sql.NullString
		)

		err := rows.Scan(&m.MachineID, &m.Version, &m.OSName, &m.OSFamily, &m.OSVersion,
			&m.Scenarios, &lastSeen, &m.Validated, &m.IPAddress, &createdAt)
		if err != nil {
			return nil, fmt.Errorf("scanning machine: %w", err)
		}

		m.LastSeen = parseSQLiteTime(lastSeen)

		if parsed := parseSQLiteTime(createdAt); parsed != nil {
			m.CreatedAt = *parsed
		}

		machines = append(machines, m)
	}

	return machines, rows.Err()
}

// Bouncers returns the registered remediation components.
func (s *StateStore) Bouncers(ctx context.Context) ([]bouncerInfo, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT name, COALESCE(type, ''), COALESCE(version, ''), COALESCE(osname, ''),
		       COALESCE(osversion, ''), COALESCE(ip_address, ''), last_pull, revoked, created_at
		FROM bouncers
		ORDER BY last_pull DESC`)
	if err != nil {
		return nil, fmt.Errorf("querying bouncers: %w", err)
	}
	defer rows.Close()

	bouncers := make([]bouncerInfo, 0)

	for rows.Next() {
		var (
			b         bouncerInfo
			lastPull  sql.NullString
			createdAt sql.NullString
		)

		err := rows.Scan(&b.Name, &b.Type, &b.Version, &b.OSName, &b.OSVersion,
			&b.IPAddress, &lastPull, &b.Revoked, &createdAt)
		if err != nil {
			return nil, fmt.Errorf("scanning bouncer: %w", err)
		}

		b.LastPull = parseSQLiteTime(lastPull)

		if parsed := parseSQLiteTime(createdAt); parsed != nil {
			b.CreatedAt = *parsed
		}

		bouncers = append(bouncers, b)
	}

	return bouncers, rows.Err()
}

func queryCounts(ctx context.Context, db *sql.DB, query string, args ...any) (map[string]int, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[string]int{}

	for rows.Next() {
		var (
			key   sql.NullString
			count int
		)

		if err := rows.Scan(&key, &count); err != nil {
			return nil, err
		}

		if key.String != "" {
			counts[key.String] = count
		}
	}

	return counts, rows.Err()
}

// Timestamps are compared through strftime('%s', substr(col,1,19)): the engine
// stores Go's time format ("2026-10-29 19:17:20.97 +0000 UTC"), which strftime()
// rejects as a whole, while the first 19 characters parse in both that and
// RFC3339. Plain CAST(strftime('%s', col) ...) silently matched no rows.
//
// AlertCounts is the cheap aggregate used to compare two windows.
type AlertCounts struct {
	Total         int
	Events        int
	UniqueSources int
}

// AlertCountsInRange counts alerts in [from, to), which is what the dashboard
// needs to show a delta against the previous window.
func (s *StateStore) AlertCountsInRange(ctx context.Context, from, to time.Time) (AlertCounts, error) {
	var counts AlertCounts

	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(SUM(events_count), 0), COUNT(DISTINCT source_ip)
		FROM alerts
		WHERE CAST(strftime('%s', substr(created_at,1,19)) AS INTEGER) >= ?
		  AND CAST(strftime('%s', substr(created_at,1,19)) AS INTEGER) < ?`,
		from.Unix(), to.Unix()).Scan(&counts.Total, &counts.Events, &counts.UniqueSources)
	if err != nil {
		return counts, fmt.Errorf("counting alerts in range: %w", err)
	}

	return counts, nil
}

// AlertStats aggregates alerts since the given time.
func (s *StateStore) AlertStats(ctx context.Context, since time.Time) (*alertDBStats, error) {
	stats := &alertDBStats{}

	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(SUM(events_count), 0), COUNT(DISTINCT source_ip)
		FROM alerts WHERE CAST(strftime('%s', substr(created_at,1,19)) AS INTEGER) >= ?`, since.Unix()).
		Scan(&stats.Total, &stats.Events, &stats.UniqueSources)
	if err != nil {
		return nil, fmt.Errorf("counting alerts: %w", err)
	}

	byScenario, err := queryCounts(ctx, s.db,
		`SELECT scenario, COUNT(*) FROM alerts WHERE CAST(strftime('%s', substr(created_at,1,19)) AS INTEGER) >= ? GROUP BY scenario`, since.Unix())
	if err != nil {
		return nil, fmt.Errorf("alerts by scenario: %w", err)
	}

	byCountry, err := queryCounts(ctx, s.db,
		`SELECT source_country, COUNT(*) FROM alerts
		 WHERE CAST(strftime('%s', substr(created_at,1,19)) AS INTEGER) >= ? AND source_country IS NOT NULL AND source_country != ''
		 GROUP BY source_country`, since.Unix())
	if err != nil {
		return nil, fmt.Errorf("alerts by country: %w", err)
	}

	byAS, err := queryCounts(ctx, s.db,
		`SELECT source_as_name, COUNT(*) FROM alerts
		 WHERE CAST(strftime('%s', substr(created_at,1,19)) AS INTEGER) >= ? AND source_as_name IS NOT NULL AND source_as_name != ''
		 GROUP BY source_as_name`, since.Unix())
	if err != nil {
		return nil, fmt.Errorf("alerts by as: %w", err)
	}

	byKind, err := queryCounts(ctx, s.db,
		`SELECT kind, COUNT(*) FROM alerts WHERE CAST(strftime('%s', substr(created_at,1,19)) AS INTEGER) >= ? GROUP BY kind`, since.Unix())
	if err != nil {
		return nil, fmt.Errorf("alerts by kind: %w", err)
	}

	stats.ByScenario = topCounts(byScenario, 10)
	stats.ByCountry = topCounts(byCountry, 10)
	stats.ByAS = topCounts(byAS, 10)
	stats.ByKind = topCounts(byKind, 10)

	timeline, err := s.alertTimeline(ctx, since)
	if err != nil {
		return nil, err
	}

	stats.Timeline = timeline

	stacked, scenarios, err := s.alertTimelineByScenario(ctx, since, timeline)
	if err != nil {
		return nil, err
	}

	stats.Timeline = stacked
	stats.TimelineScenario = scenarios

	geo, err := s.alertGeo(ctx, since)
	if err != nil {
		return nil, err
	}

	stats.Geo = geo

	return stats, nil
}

// alertGeo clusters alert origins for the world map. One decimal degree is
// roughly 11 km, which keeps the payload small without hiding hot spots.
func (s *StateStore) alertGeo(ctx context.Context, since time.Time) ([]geoPoint, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT ROUND(source_latitude, 1), ROUND(source_longitude, 1),
		       COALESCE(source_country, ''), COUNT(*)
		FROM alerts
		WHERE CAST(strftime('%s', substr(created_at,1,19)) AS INTEGER) >= ?
		  AND source_latitude IS NOT NULL AND source_longitude IS NOT NULL
		GROUP BY ROUND(source_latitude, 1), ROUND(source_longitude, 1)
		ORDER BY COUNT(*) DESC
		LIMIT 500`, since.Unix())
	if err != nil {
		return nil, fmt.Errorf("alert geo: %w", err)
	}
	defer rows.Close()

	points := make([]geoPoint, 0)

	for rows.Next() {
		var point geoPoint

		if err := rows.Scan(&point.Lat, &point.Lon, &point.Country, &point.Count); err != nil {
			return nil, fmt.Errorf("scanning geo point: %w", err)
		}

		points = append(points, point)
	}

	return points, rows.Err()
}

func (s *StateStore) alertTimeline(ctx context.Context, since time.Time) ([]timelinePoint, error) {
	duration := time.Since(since)
	step := time.Hour

	if duration > 72*time.Hour {
		step = 24 * time.Hour
	}

	stepSeconds := int64(step.Seconds())

	rows, err := s.db.QueryContext(ctx, `
		SELECT (CAST(strftime('%s', substr(created_at,1,19)) AS INTEGER) / ?) * ? AS bucket, COUNT(*)
		FROM alerts
		WHERE CAST(strftime('%s', substr(created_at,1,19)) AS INTEGER) >= ?
		GROUP BY bucket
		ORDER BY bucket`, stepSeconds, stepSeconds, since.Unix())
	if err != nil {
		return nil, fmt.Errorf("alert timeline: %w", err)
	}
	defer rows.Close()

	counts := map[int64]int{}

	for rows.Next() {
		var (
			bucket sql.NullInt64
			count  int
		)

		if err := rows.Scan(&bucket, &count); err != nil {
			return nil, fmt.Errorf("scanning timeline: %w", err)
		}

		if bucket.Valid {
			counts[bucket.Int64] = count
		}
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	start := since.Truncate(step)
	now := time.Now().Truncate(step)
	points := make([]timelinePoint, 0)

	for t := start; !t.After(now); t = t.Add(step) {
		points = append(points, timelinePoint{Time: t, Count: counts[t.Unix()]})
	}

	return points, nil
}

// alertTimelineByScenario fills each timeline bucket with a per-scenario
// breakdown. Only the busiest scenarios get their own band; the rest fold into
// "other", and the bucket total stays authoritative even when a scenario is
// truncated - the sum of the bands never exceeds count.
func (s *StateStore) alertTimelineByScenario(ctx context.Context, since time.Time, timeline []timelinePoint) ([]timelinePoint, []namedCount, error) {
	if len(timeline) == 0 {
		return timeline, nil, nil
	}

	duration := time.Since(since)
	step := time.Hour

	if duration > 72*time.Hour {
		step = 24 * time.Hour
	}

	stepSeconds := int64(step.Seconds())

	rows, err := s.db.QueryContext(ctx, `
		SELECT (CAST(strftime('%s', substr(created_at,1,19)) AS INTEGER) / ?) * ? AS bucket,
		       COALESCE(NULLIF(scenario, ''), 'unknown') AS scenario,
		       COUNT(*)
		FROM alerts
		WHERE CAST(strftime('%s', substr(created_at,1,19)) AS INTEGER) >= ?
		GROUP BY bucket, scenario
		ORDER BY bucket`, stepSeconds, stepSeconds, since.Unix())
	if err != nil {
		return nil, nil, fmt.Errorf("alert timeline by scenario: %w", err)
	}
	defer rows.Close()

	type bucketKey struct {
		bucket   int64
		scenario string
	}

	counts := map[bucketKey]int{}
	totals := map[string]int{}

	for rows.Next() {
		var (
			bucket   sql.NullInt64
			scenario sql.NullString
			count    int
		)

		if err := rows.Scan(&bucket, &scenario, &count); err != nil {
			return nil, nil, fmt.Errorf("scanning timeline by scenario: %w", err)
		}

		if !bucket.Valid {
			continue
		}

		counts[bucketKey{bucket.Int64, scenario.String}] += count
		totals[scenario.String] += count
	}

	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

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

	bands := ranked
	truncated := false

	if len(bands) > bandLimit {
		bands = bands[:bandLimit]
		truncated = true
	}

	keep := make(map[string]bool, len(bands))

	for _, band := range bands {
		keep[band.Name] = true
	}

	result := make([]timelinePoint, len(timeline))

	for i, point := range timeline {
		point.Breakdown = map[string]int{}

		var counted int

		for _, band := range bands {
			count := counts[bucketKey{point.Time.Unix(), band.Name}]
			if count > 0 {
				point.Breakdown[band.Name] = count
				counted += count
			}
		}

		// Anything outside the top bands, and any bucket/scenario pair the
		// grouping rounded differently, lands in "other".
		if point.Count > counted {
			point.Breakdown["other"] = point.Count - counted
			truncated = true
		}

		result[i] = point
	}

	labels := bands
	if truncated {
		labels = append(labels, namedCount{Name: "other"})
	}

	return result, labels, nil
}

// DecisionStats aggregates the currently active decisions.
func (s *StateStore) DecisionStats(ctx context.Context) (*decisionDBStats, error) {
	stats := &decisionDBStats{}

	active := `until IS NULL OR CAST(strftime('%s', substr(until,1,19)) AS INTEGER) > CAST(strftime('%s', 'now') AS INTEGER)`

	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(simulated), 0) FROM decisions WHERE `+active).
		Scan(&stats.Total, &stats.Simulated)
	if err != nil {
		return nil, fmt.Errorf("counting decisions: %w", err)
	}

	byType, err := queryCounts(ctx, s.db, `SELECT type, COUNT(*) FROM decisions WHERE `+active+` GROUP BY type`)
	if err != nil {
		return nil, fmt.Errorf("decisions by type: %w", err)
	}

	byScope, err := queryCounts(ctx, s.db, `SELECT scope, COUNT(*) FROM decisions WHERE `+active+` GROUP BY scope`)
	if err != nil {
		return nil, fmt.Errorf("decisions by scope: %w", err)
	}

	byOrigin, err := queryCounts(ctx, s.db, `SELECT origin, COUNT(*) FROM decisions WHERE `+active+` GROUP BY origin`)
	if err != nil {
		return nil, fmt.Errorf("decisions by origin: %w", err)
	}

	byScenario, err := queryCounts(ctx, s.db, `SELECT scenario, COUNT(*) FROM decisions WHERE `+active+` GROUP BY scenario`)
	if err != nil {
		return nil, fmt.Errorf("decisions by scenario: %w", err)
	}

	stats.ByType = topCounts(byType, 10)
	stats.ByScope = topCounts(byScope, 10)
	stats.ByOrigin = topCounts(byOrigin, 10)
	stats.ByScenario = topCounts(byScenario, 10)

	return stats, nil
}
