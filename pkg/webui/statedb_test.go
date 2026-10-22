package webui

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

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
		now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	exec(`INSERT INTO machines (created_at, updated_at, machine_id, password, ip_address, scenarios, version, is_validated)
	      VALUES (?, ?, 'ui-1', 'x', '172.28.0.6', '', 'v1.8.2', 1)`,
		now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))

	exec(`INSERT INTO bouncers (created_at, updated_at, name, api_key, revoked, ip_address, type, version, last_pull)
	      VALUES (?, ?, 'fw-1', 'k', 0, '172.28.0.9', 'crowdsec-firewall-bouncer', 'v0.0.30', ?)`,
		now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Add(-time.Minute).Format(time.RFC3339Nano))

	// Two recent alerts, one old one outside the range.
	exec(`INSERT INTO alerts (created_at, updated_at, scenario, events_count, source_ip, source_country, source_as_name, source_latitude, source_longitude, kind)
	      VALUES (?, ?, 'crowdsecurity/ssh-bf', 5, '185.220.101.45', 'DE', 'Hetzner', 52.52, 13.40, 'crowdsec')`,
		now.Add(-2*time.Minute).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	exec(`INSERT INTO alerts (created_at, updated_at, scenario, events_count, source_ip, source_country, source_as_name, source_latitude, source_longitude, kind)
	      VALUES (?, ?, 'crowdsecurity/http-probing', 3, '1.2.3.4', 'FR', 'OVH', 48.85, 2.35, 'crowdsec')`,
		now.Add(-3*time.Minute).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	exec(`INSERT INTO alerts (created_at, updated_at, scenario, events_count, source_ip, kind)
	      VALUES (?, ?, 'crowdsecurity/ssh-bf', 100, '9.9.9.9', 'crowdsec')`,
		now.Add(-72*time.Hour).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))

	exec(`INSERT INTO decisions (created_at, updated_at, until, scenario, type, scope, value, origin, simulated)
	      VALUES (?, ?, ?, 'crowdsecurity/ssh-bf', 'ban', 'Ip', '185.220.101.45', 'crowdsec', 0)`,
		now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Add(time.Hour).Format(time.RFC3339Nano))
	exec(`INSERT INTO decisions (created_at, updated_at, until, scenario, type, scope, value, origin, simulated)
	      VALUES (?, ?, ?, 'manual', 'ban', 'Range', '203.0.113.0/24', 'cscli', 0)`,
		now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Add(time.Hour).Format(time.RFC3339Nano))
	exec(`INSERT INTO decisions (created_at, updated_at, until, scenario, type, scope, value, origin, simulated)
	      VALUES (?, ?, ?, 'manual', 'captcha', 'Ip', '5.6.7.8', 'cscli', 1)`,
		now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Add(time.Hour).Format(time.RFC3339Nano))
	// Expired: must not be counted as active.
	exec(`INSERT INTO decisions (created_at, updated_at, until, scenario, type, scope, value, origin, simulated)
	      VALUES (?, ?, ?, 'manual', 'ban', 'Ip', '7.7.7.7', 'cscli', 0)`,
		now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Add(-time.Hour).Format(time.RFC3339Nano))

	store, err := OpenStateStore(path)
	require.NoError(t, err)

	t.Cleanup(func() { _ = store.Close() })

	return store
}

func TestStateStoreMachines(t *testing.T) {
	store := newTestStateStore(t)

	machines, err := store.Machines(context.Background())
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

	bouncers, err := store.Bouncers(context.Background())
	require.NoError(t, err)
	require.Len(t, bouncers, 1)
	require.Equal(t, "fw-1", bouncers[0].Name)
	require.Equal(t, "crowdsec-firewall-bouncer", bouncers[0].Type)
	require.NotNil(t, bouncers[0].LastPull)
	require.False(t, bouncers[0].Revoked)
}

func TestStateStoreAlertStats(t *testing.T) {
	store := newTestStateStore(t)

	stats, err := store.AlertStats(context.Background(), time.Now().Add(-24*time.Hour))
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

func TestStateStoreDecisionStats(t *testing.T) {
	store := newTestStateStore(t)

	stats, err := store.DecisionStats(context.Background())
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
	require.Equal(t, "", cfg.DatabasePath())

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
	require.Equal(t, "", cfg2.DatabasePath())
}
