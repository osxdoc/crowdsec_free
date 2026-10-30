package webui

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

const testSchema = `
CREATE TABLE machines (
	id integer PRIMARY KEY AUTOINCREMENT,
	created_at datetime NOT NULL,
	updated_at datetime NOT NULL,
	last_push datetime NULL,
	last_heartbeat datetime NULL,
	machine_id text NOT NULL,
	password text NOT NULL,
	ip_address text NOT NULL,
	scenarios text NULL,
	version text NULL,
	is_validated bool NOT NULL DEFAULT (false),
	auth_type text NOT NULL DEFAULT ('password'),
	osname text NULL,
	osfamily text NULL,
	osversion text NULL
);

CREATE TABLE bouncers (
	id integer PRIMARY KEY AUTOINCREMENT,
	created_at datetime NOT NULL,
	updated_at datetime NOT NULL,
	name text NOT NULL,
	api_key text NOT NULL,
	revoked bool NOT NULL,
	ip_address text NULL DEFAULT (''),
	type text NULL,
	version text NULL,
	last_pull datetime NULL,
	stream_cursor integer NOT NULL DEFAULT (0),
	auth_type text NOT NULL DEFAULT ('api-key'),
	osname text NULL,
	osfamily text NULL,
	osversion text NULL,
	auto_created bool NOT NULL DEFAULT (false)
);

CREATE TABLE alerts (
	id integer PRIMARY KEY AUTOINCREMENT,
	created_at datetime NOT NULL,
	updated_at datetime NOT NULL,
	scenario text NOT NULL,
	message text NULL DEFAULT '',
	events_count integer NULL DEFAULT (0),
	source_ip text NULL,
	source_range text NULL,
	source_as_number text NULL,
	source_as_name text NULL,
	source_country text NULL,
	source_latitude real NULL,
	source_longitude real NULL,
	source_scope text NULL,
	source_value text NULL,
	kind text NULL
);

CREATE TABLE decisions (
	id integer PRIMARY KEY AUTOINCREMENT,
	created_at datetime NOT NULL,
	updated_at datetime NOT NULL,
	until datetime NULL,
	scenario text NOT NULL,
	type text NOT NULL,
	scope text NOT NULL,
	value text NOT NULL,
	origin text NOT NULL,
	simulated bool NOT NULL DEFAULT (false)
);
`

func newTestStateStore(t *testing.T) *StateStore {
	t.Helper()

	path := filepath.Join(t.TempDir(), "lapi.db")

	db, err := sql.Open("sqlite", "file:"+path)
	require.NoError(t, err)
	defer db.Close()

	require.NoError(t, db.Ping())
	_, err = db.Exec(testSchema)
	require.NoError(t, err)

	now := time.Now().UTC()

	exec := func(query string, args ...any) {
		_, err := db.Exec(query, args...)
		require.NoError(t, err)
	}

	exec(`INSERT INTO machines (created_at, updated_at, last_heartbeat, machine_id, password, ip_address, scenarios, version, is_validated, osname)
	      VALUES (?, ?, ?, 'agent-1', 'x', '172.28.0.5', 'crowdsecurity/linux','v1.8.2', 1, 'debian')`,
		now.String(), now.String(), now.String())
	exec(`INSERT INTO machines (created_at, updated_at, machine_id, password, ip_address, scenarios, version, is_validated)
	      VALUES (?, ?, 'ui-1', 'x', '172.28.0.6', '', 'v1.8.2', 1)`,
		now.String(), now.String())

	exec(`INSERT INTO bouncers (created_at, updated_at, name, api_key, revoked, ip_address, type, version, last_pull)
	      VALUES (?, ?, 'fw-1', 'k', 0, '172.28.0.9', 'crowdsec-firewall-bouncer', 'v0.0.30', ?)`,
		now.String(), now.String(), now.Add(-time.Minute).String())

	// Two recent alerts, one old one outside the range.
	exec(`INSERT INTO alerts (created_at, updated_at, scenario, events_count, source_ip, source_country, source_as_name, source_latitude, source_longitude, kind)
	      VALUES (?, ?, 'crowdsecurity/ssh-bf', 5, '185.220.101.45', 'DE', 'Hetzner', 52.52, 13.40, 'crowdsec')`,
		now.Add(-2*time.Minute).String(), now.String())
	exec(`INSERT INTO alerts (created_at, updated_at, scenario, events_count, source_ip, source_country, source_as_name, source_latitude, source_longitude, kind)
	      VALUES (?, ?, 'crowdsecurity/http-probing', 3, '1.2.3.4', 'FR', 'OVH', 48.85, 2.35, 'crowdsec')`,
		now.Add(-3*time.Minute).String(), now.String())
	exec(`INSERT INTO alerts (created_at, updated_at, scenario, events_count, source_ip, kind)
	      VALUES (?, ?, 'crowdsecurity/ssh-bf', 100, '9.9.9.9', 'crowdsec')`,
		now.Add(-72*time.Hour).String(), now.String())

	exec(`INSERT INTO decisions (created_at, updated_at, until, scenario, type, scope, value, origin, simulated)
	      VALUES (?, ?, ?, 'crowdsecurity/ssh-bf', 'ban', 'Ip', '185.220.101.45', 'crowdsec', 0)`,
		now.String(), now.String(), now.Add(time.Hour).String())
	exec(`INSERT INTO decisions (created_at, updated_at, until, scenario, type, scope, value, origin, simulated)
	      VALUES (?, ?, ?, 'manual', 'ban', 'Range', '203.0.113.0/24', 'cscli', 0)`,
		now.String(), now.String(), now.Add(time.Hour).String())
	exec(`INSERT INTO decisions (created_at, updated_at, until, scenario, type, scope, value, origin, simulated)
	      VALUES (?, ?, ?, 'manual', 'captcha', 'Ip', '5.6.7.8', 'cscli', 1)`,
		now.String(), now.String(), now.Add(time.Hour).String())
	// Expired: must not be counted as active.
	exec(`INSERT INTO decisions (created_at, updated_at, until, scenario, type, scope, value, origin, simulated)
	      VALUES (?, ?, ?, 'manual', 'ban', 'Ip', '7.7.7.7', 'cscli', 0)`,
		now.String(), now.String(), now.Add(-time.Hour).String())

	store, err := OpenStateStore(path)
	require.NoError(t, err)

	t.Cleanup(func() { _ = store.Close() })

	return store
}

func TestStateStoreMachines(t *testing.T) {
	store := newTestStateStore(t)

	machines, err := store.Machines(t.Context())
	require.NoError(t, err)
	require.Len(t, machines, 2)

	byID := map[string]machineInfo{}

	for _, machine := range machines {
		byID[machine.MachineID] = machine
	}

	require.Equal(t, "v1.8.2", byID["agent-1"].Version)
	require.Equal(t, "debian", byID["agent-1"].OSName)
	require.True(t, byID["agent-1"].Validated)
	require.NotNil(t, byID["agent-1"].LastSeen)
	require.False(t, byID["agent-1"].CreatedAt.IsZero())
}

func TestStateStoreBouncers(t *testing.T) {
	store := newTestStateStore(t)

	bouncers, err := store.Bouncers(t.Context())
	require.NoError(t, err)
	require.Len(t, bouncers, 1)
	require.Equal(t, "fw-1", bouncers[0].Name)
	require.Equal(t, "crowdsec-firewall-bouncer", bouncers[0].Type)
	require.NotNil(t, bouncers[0].LastPull)
	require.False(t, bouncers[0].Revoked)
}

func TestStateStoreAlertStats(t *testing.T) {
	store := newTestStateStore(t)

	stats, err := store.AlertStats(t.Context(), time.Now().Add(-24*time.Hour))
	require.NoError(t, err)

	require.Equal(t, 2, stats.Total)
	require.Equal(t, 8, stats.Events)
	require.Equal(t, 2, stats.UniqueSources)
	scenarios := map[string]bool{}
	for _, item := range stats.ByScenario {
		scenarios[item.Name] = true
	}
	require.True(t, scenarios["crowdsecurity/ssh-bf"])
	require.True(t, scenarios["crowdsecurity/http-probing"])
	require.Equal(t, "DE", stats.ByCountry[0].Name)
	require.Equal(t, "Hetzner", stats.ByAS[0].Name)

	geoCounts := 0
	for _, point := range stats.Geo {
		geoCounts += point.Count
		require.NotZero(t, point.Lat)
	}

	require.Equal(t, 2, geoCounts)
	require.Len(t, stats.Geo, 2)

	nonzero := 0

	for _, point := range stats.Timeline {
		nonzero += point.Count
	}

	require.Equal(t, 2, nonzero)
}

func TestAlertTimelineBreaksDownByScenario(t *testing.T) {
	store := newTestStateStore(t)

	stats, err := store.AlertStats(context.Background(), time.Now().Add(-24*time.Hour))
	require.NoError(t, err)

	require.NotEmpty(t, stats.Timeline)
	require.NotEmpty(t, stats.TimelineScenario)

	// Every bucket's bands must add up to the bucket total: the stacked chart
	// reads the bands, the tooltip reads the total, and they may not disagree.
	for _, point := range stats.Timeline {
		sum := 0
		for _, count := range point.Breakdown {
			sum += count
		}

		require.Equal(t, point.Count, sum, "breakdown must sum to the bucket total")
	}

	bucketTotal := 0
	for _, point := range stats.Timeline {
		bucketTotal += point.Count
	}

	bandTotal := 0
	for _, band := range stats.TimelineScenario {
		bandTotal += band.Count
	}

	require.Equal(t, bucketTotal, bandTotal, "every counted alert belongs to a band")

	names := map[string]bool{}
	for _, band := range stats.TimelineScenario {
		names[band.Name] = true
	}

	require.True(t, names["crowdsecurity/ssh-bf"])
	require.True(t, names["crowdsecurity/http-probing"])
}

func TestAlertTimelineFoldsRareScenariosIntoOther(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lapi.db")

	db, err := sql.Open("sqlite", "file:"+path)
	require.NoError(t, err)
	require.NoError(t, db.Ping())
	_, err = db.Exec(testSchema)
	require.NoError(t, err)

	now := time.Now().UTC()

	// Seven scenarios: the five busiest get bands, the rest must land in "other".
	for i := 0; i < 7; i++ {
		repeats := 7 - i
		for j := 0; j < repeats; j++ {
			_, err = db.Exec(`INSERT INTO alerts (created_at, updated_at, scenario, events_count, source_ip, kind)
				VALUES (?, ?, ?, 1, ?, 'crowdsec')`,
				now.Add(-time.Duration(i+1)*time.Minute).String(), now.String(),
				fmt.Sprintf("scenario-%d", i), fmt.Sprintf("10.0.0.%d", i))
			require.NoError(t, err)
		}
	}

	store, err := OpenStateStore(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })

	stats, err := store.AlertStats(context.Background(), now.Add(-time.Hour))
	require.NoError(t, err)

	labels := map[string]bool{}
	for _, band := range stats.TimelineScenario {
		labels[band.Name] = true
	}

	require.Len(t, stats.TimelineScenario, 6, "five bands plus the folded remainder")
	require.True(t, labels["other"])

	for _, point := range stats.Timeline {
		sum := 0
		for _, count := range point.Breakdown {
			sum += count
		}

		require.Equal(t, point.Count, sum)
	}
}

func TestStateStoreCountsBothTimestampFormats(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lapi.db")

	db, err := sql.Open("sqlite", "file:"+path)
	require.NoError(t, err)
	require.NoError(t, db.Ping())
	_, err = db.Exec(testSchema)
	require.NoError(t, err)

	now := time.Now().UTC()

	// The engine writes Go's time format; older rows may be RFC3339. Both have
	// to count, otherwise the dashboard silently shows zeros on a real database.
	for _, created := range []string{
		now.Add(-2 * time.Minute).String(),
		now.Add(-time.Minute).Format(time.RFC3339Nano),
	} {
		_, err = db.Exec(`INSERT INTO alerts (created_at, updated_at, scenario, events_count, source_ip, kind)
			VALUES (?, ?, 'crowdsecurity/ssh-bf', 1, '203.0.113.9', 'crowdsec')`, created, now.String())
		require.NoError(t, err)
	}

	require.NoError(t, db.Close())

	store, err := OpenStateStore(path)
	require.NoError(t, err)

	t.Cleanup(func() { _ = store.Close() })

	stats, err := store.AlertStats(t.Context(), now.Add(-24*time.Hour))
	require.NoError(t, err)
	require.Equal(t, 2, stats.Total)
}

func TestStateStoreDecisionStats(t *testing.T) {
	store := newTestStateStore(t)

	stats, err := store.DecisionStats(t.Context())
	require.NoError(t, err)

	// The expired decision is excluded.
	require.Equal(t, 3, stats.Total)
	require.Equal(t, 1, stats.Simulated)
	require.Len(t, stats.ByType, 2)
	require.Len(t, stats.ByScope, 2)
}

func TestDatabasePathResolution(t *testing.T) {
	dir := t.TempDir()

	cfg := &Config{}
	cfg.Engine.ConfigDir = dir
	require.Empty(t, cfg.DatabasePath())

	engineConfig := "db_config:\n  type: sqlite\n  db_path: /var/lib/crowdsec/data/crowdsec.db\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(engineConfig), 0o600))
	require.Equal(t, "/var/lib/crowdsec/data/crowdsec.db", cfg.DatabasePath())

	cfg.Data.DBPath = "/custom/lapi.db"
	require.Equal(t, "/custom/lapi.db", cfg.DatabasePath())

	cfg2 := &Config{}
	cfg2.Engine.ConfigDir = dir
	cfg2.Data.DBPath = ""
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"),
		[]byte(fmt.Sprintf("db_config:\n  type: mysql\n  db_path: %s\n", "/x")), 0o600))
	require.Empty(t, cfg2.DatabasePath())
}

func TestAPITimelineBreaksDownLikeTheDatabaseTimeline(t *testing.T) {
	now := time.Now().UTC()

	alerts := []*models.Alert{}
	for i, scenario := range []string{"a/one", "a/one", "b/two", "c/three"} {
		name := scenario
		alerts = append(alerts, &models.Alert{
			Scenario:  &name,
			CreatedAt: now.Add(-time.Duration(i+1) * time.Minute).Format(time.RFC3339),
		})
	}

	points := buildTimeline(alerts, 24*time.Hour)
	require.NotEmpty(t, points)

	// The API path is the fallback when no SQLite database is readable; it has
	// to feed the same stacked chart, not silently drop the breakdown.
	scenarios := timelineScenarios(points)
	names := map[string]int{}
	for _, scenario := range scenarios {
		names[scenario.Name] = scenario.Count
	}

	require.Equal(t, 2, names["a/one"])
	require.Equal(t, 1, names["b/two"])

	for _, point := range points {
		sum := 0
		for _, count := range point.Breakdown {
			sum += count
		}

		require.Equal(t, point.Count, sum, "bands must sum to the bucket total")
	}
}
