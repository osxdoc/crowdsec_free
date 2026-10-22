package blocklistserver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// Machine is a registered Security Engine.
type Machine struct {
	ID           int64     `json:"id"`
	MachineID    string    `json:"machine_id"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	LastSeen     time.Time `json:"last_seen"`
	LastIP       string    `json:"last_ip"`
}

// Decision is a blocklist entry.
type Decision struct {
	ID        int64      `json:"id"`
	Value     string     `json:"value"`
	Scope     string     `json:"scope"`
	Type      string     `json:"type"`
	Duration  string     `json:"duration"`
	Scenario  string     `json:"scenario"`
	Origin    string     `json:"origin"`
	Source    string     `json:"source"`
	MachineID string     `json:"machine_id,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	Until     *time.Time `json:"until,omitempty"`
	Deleted   bool       `json:"deleted"`
	Revision  int64      `json:"revision"`
}

// Tombstone is a removed decision, reported to engines as a deletion.
type Tombstone struct {
	Value     string
	Scope     string
	DeletedAt time.Time
	Revision  int64
}

// Stats is a small summary for dashboards.
type Stats struct {
	ActiveDecisions int64            `json:"active_decisions"`
	Machines        int64            `json:"machines"`
	Revision        int64            `json:"revision"`
	ByScenario      map[string]int64 `json:"by_scenario"`
	ByType          map[string]int64 `json:"by_type"`
}

// Store persists machines and decisions in SQLite.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS revision (
	id    INTEGER PRIMARY KEY CHECK (id = 1),
	value INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO revision (id, value) VALUES (1, 0);

CREATE TABLE IF NOT EXISTS machines (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	machine_id    TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	created_at    TEXT NOT NULL,
	last_seen     TEXT,
	last_ip       TEXT
);

CREATE TABLE IF NOT EXISTS decisions (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	value      TEXT NOT NULL,
	scope      TEXT NOT NULL,
	type       TEXT NOT NULL,
	duration   TEXT NOT NULL,
	scenario   TEXT NOT NULL,
	origin     TEXT NOT NULL,
	source     TEXT NOT NULL,
	machine_id TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	until      TEXT,
	revision   INTEGER NOT NULL,
	deleted    INTEGER NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS decisions_active_unique
	ON decisions (value, scope) WHERE deleted = 0;
CREATE INDEX IF NOT EXISTS decisions_revision ON decisions (revision);

CREATE TABLE IF NOT EXISTS machine_cursor (
	machine_id TEXT PRIMARY KEY,
	revision   INTEGER NOT NULL,
	updated_at TEXT NOT NULL
);
`

// OpenStore opens (and migrates) the SQLite database at path.
func OpenStore(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}

	// SQLite allows a single writer; serializing keeps the code simple and
	// avoids "database is locked" under concurrent pushes.
	db.SetMaxOpenConns(1)

	if err := db.Ping(); err != nil {
		db.Close() //nolint:errcheck
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close() //nolint:errcheck
		return nil, fmt.Errorf("migrating %s: %w", path, err)
	}

	return &Store{db: db}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error {
	return s.db.Close()
}

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func scanDecision(row interface{ Scan(...any) error }) (*Decision, error) {
	var (
		d         Decision
		createdAt string
		until     sql.NullString
		deleted   int
	)

	err := row.Scan(&d.ID, &d.Value, &d.Scope, &d.Type, &d.Duration, &d.Scenario,
		&d.Origin, &d.Source, &d.MachineID, &createdAt, &until, &d.Revision, &deleted)
	if err != nil {
		return nil, err
	}

	d.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return nil, fmt.Errorf("parsing created_at: %w", err)
	}

	if until.Valid {
		t, err := time.Parse(time.RFC3339Nano, until.String)
		if err != nil {
			return nil, fmt.Errorf("parsing until: %w", err)
		}

		d.Until = &t
	}

	d.Deleted = deleted != 0

	return &d, nil
}

func nextRevision(tx *sql.Tx) (int64, error) {
	var rev int64

	err := tx.QueryRow(`UPDATE revision SET value = value + 1 WHERE id = 1 RETURNING value`).Scan(&rev)
	if err != nil {
		return 0, fmt.Errorf("allocating revision: %w", err)
	}

	return rev, nil
}

// RegisterMachine creates a machine. It fails if the machine already exists.
func (s *Store) RegisterMachine(ctx context.Context, machineID, passwordHash, ip string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO machines (machine_id, password_hash, created_at, last_seen, last_ip) VALUES (?, ?, ?, ?, ?)`,
		machineID, passwordHash, nowUTC(), nowUTC(), ip)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return fmt.Errorf("machine %q already registered", machineID)
		}

		return fmt.Errorf("registering machine: %w", err)
	}

	return nil
}

// Machine returns a machine by its id.
func (s *Store) Machine(ctx context.Context, machineID string) (*Machine, error) {
	var (
		m         Machine
		createdAt string
		lastSeen  sql.NullString
		lastIP    sql.NullString
	)

	err := s.db.QueryRowContext(ctx,
		`SELECT id, machine_id, password_hash, created_at, last_seen, last_ip FROM machines WHERE machine_id = ?`,
		machineID).Scan(&m.ID, &m.MachineID, &m.PasswordHash, &createdAt, &lastSeen, &lastIP)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("loading machine: %w", err)
	}

	m.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return nil, fmt.Errorf("parsing created_at: %w", err)
	}

	if lastSeen.Valid {
		m.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeen.String)
	}

	m.LastIP = lastIP.String

	return &m, nil
}

// TouchMachine updates the last seen timestamp of a machine.
func (s *Store) TouchMachine(ctx context.Context, machineID, ip string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE machines SET last_seen = ?, last_ip = ? WHERE machine_id = ?`, nowUTC(), ip, machineID)
	if err != nil {
		return fmt.Errorf("updating machine: %w", err)
	}

	return nil
}

// DeleteMachine removes a machine and its cursor.
func (s *Store) DeleteMachine(ctx context.Context, machineID string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM machines WHERE machine_id = ?`, machineID); err != nil {
		return fmt.Errorf("deleting machine: %w", err)
	}

	if _, err := s.db.ExecContext(ctx, `DELETE FROM machine_cursor WHERE machine_id = ?`, machineID); err != nil {
		return fmt.Errorf("deleting machine cursor: %w", err)
	}

	return nil
}

// ListMachines returns all registered machines.
func (s *Store) ListMachines(ctx context.Context) ([]*Machine, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, machine_id, password_hash, created_at, last_seen, last_ip FROM machines ORDER BY machine_id`)
	if err != nil {
		return nil, fmt.Errorf("listing machines: %w", err)
	}
	defer rows.Close()

	machines := make([]*Machine, 0)

	for rows.Next() {
		var (
			m         Machine
			createdAt string
			lastSeen  sql.NullString
			lastIP    sql.NullString
		)

		if err := rows.Scan(&m.ID, &m.MachineID, &m.PasswordHash, &createdAt, &lastSeen, &lastIP); err != nil {
			return nil, fmt.Errorf("scanning machine: %w", err)
		}

		m.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)

		if lastSeen.Valid {
			m.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeen.String)
		}

		m.LastIP = lastIP.String
		machines = append(machines, &m)
	}

	return machines, rows.Err()
}

// UpsertDecision inserts or refreshes a decision and returns it with its id
// and revision filled in. An existing active decision for the same value and
// scope is refreshed instead of duplicated.
func (s *Store) UpsertDecision(ctx context.Context, d *Decision) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starting transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	rev, err := nextRevision(tx)
	if err != nil {
		return err
	}

	d.Revision = rev

	if d.Type == "" {
		d.Type = "ban"
	}

	if d.CreatedAt.IsZero() {
		d.CreatedAt = time.Now().UTC()
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO decisions (value, scope, type, duration, scenario, origin, source, machine_id, created_at, until, revision, deleted)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
		ON CONFLICT (value, scope) WHERE deleted = 0 DO UPDATE SET
			type = excluded.type,
			duration = excluded.duration,
			scenario = excluded.scenario,
			origin = excluded.origin,
			source = excluded.source,
			machine_id = excluded.machine_id,
			until = excluded.until,
			revision = excluded.revision`,
		d.Value, d.Scope, d.Type, d.Duration, d.Scenario, d.Origin, d.Source, d.MachineID,
		nowUTC(), nullableTime(d.Until), rev); err != nil {
		return fmt.Errorf("upserting decision: %w", err)
	}

	if err := tx.QueryRowContext(ctx,
		`SELECT id FROM decisions WHERE value = ? AND scope = ? AND deleted = 0`, d.Value, d.Scope).Scan(&d.ID); err != nil {
		return fmt.Errorf("reading decision id: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	return nil
}

func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}

	return t.UTC().Format(time.RFC3339Nano)
}

// DeleteDecision soft-deletes a decision, so engines see the deletion.
func (s *Store) DeleteDecision(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starting transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	rev, err := nextRevision(tx)
	if err != nil {
		return err
	}

	res, err := tx.ExecContext(ctx,
		`UPDATE decisions SET deleted = 1, revision = ? WHERE id = ? AND deleted = 0`, rev, id)
	if err != nil {
		return fmt.Errorf("deleting decision: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("deleting decision: %w", err)
	}

	if affected == 0 {
		return ErrNotFound
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	return nil
}

// ExpireDecisions marks decisions past their "until" date as deleted.
func (s *Store) ExpireDecisions(ctx context.Context) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("starting transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	rev, err := nextRevision(tx)
	if err != nil {
		return 0, err
	}

	res, err := tx.ExecContext(ctx,
		`UPDATE decisions SET deleted = 1, revision = ?
		 WHERE deleted = 0 AND until IS NOT NULL AND until <= ?`, rev, nowUTC())
	if err != nil {
		return 0, fmt.Errorf("expiring decisions: %w", err)
	}

	affected, _ := res.RowsAffected()

	// Nothing expired: don't burn revisions for no reason.
	if affected == 0 {
		return 0, nil
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("committing transaction: %w", err)
	}

	return affected, nil
}

const decisionColumns = `id, value, scope, type, duration, scenario, origin, source, machine_id, created_at, until, revision, deleted`

func (s *Store) queryDecisions(ctx context.Context, query string, args ...any) ([]*Decision, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying decisions: %w", err)
	}
	defer rows.Close()

	decisions := make([]*Decision, 0)

	for rows.Next() {
		d, err := scanDecision(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning decision: %w", err)
		}

		decisions = append(decisions, d)
	}

	return decisions, rows.Err()
}

// ActiveDecisions returns every non-deleted decision.
func (s *Store) ActiveDecisions(ctx context.Context) ([]*Decision, error) {
	return s.queryDecisions(ctx, `SELECT `+decisionColumns+` FROM decisions WHERE deleted = 0 ORDER BY scenario, scope, value`)
}

// DecisionsAfter returns active decisions changed after rev.
func (s *Store) DecisionsAfter(ctx context.Context, rev int64) ([]*Decision, error) {
	return s.queryDecisions(ctx,
		`SELECT `+decisionColumns+` FROM decisions WHERE deleted = 0 AND revision > ? ORDER BY scenario, scope, value`, rev)
}

// TombstonesAfter returns decisions deleted after rev.
func (s *Store) TombstonesAfter(ctx context.Context, rev int64) ([]*Tombstone, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT value, scope, revision, created_at FROM decisions WHERE deleted = 1 AND revision > ? ORDER BY revision`, rev)
	if err != nil {
		return nil, fmt.Errorf("querying tombstones: %w", err)
	}
	defer rows.Close()

	tombstones := make([]*Tombstone, 0)

	for rows.Next() {
		var (
			t         Tombstone
			createdAt string
		)

		if err := rows.Scan(&t.Value, &t.Scope, &t.Revision, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning tombstone: %w", err)
		}

		t.DeletedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		tombstones = append(tombstones, &t)
	}

	return tombstones, rows.Err()
}

// DecisionFilter narrows down ListDecisions.
type DecisionFilter struct {
	Scenario       string
	Value          string
	IncludeDeleted bool
	Limit          int
	Offset         int
}

// ListDecisions returns decisions for the admin API.
func (s *Store) ListDecisions(ctx context.Context, filter DecisionFilter) ([]*Decision, error) {
	query := `SELECT ` + decisionColumns + ` FROM decisions WHERE 1 = 1`
	args := []any{}

	if !filter.IncludeDeleted {
		query += ` AND deleted = 0`
	}

	if filter.Scenario != "" {
		query += ` AND scenario = ?`
		args = append(args, filter.Scenario)
	}

	if filter.Value != "" {
		query += ` AND value LIKE ?`
		args = append(args, "%"+filter.Value+"%")
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 500
	}

	query += ` ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, filter.Offset)

	return s.queryDecisions(ctx, query, args...)
}

// CurrentRevision returns the latest revision.
func (s *Store) CurrentRevision(ctx context.Context) (int64, error) {
	var rev int64

	if err := s.db.QueryRowContext(ctx, `SELECT value FROM revision WHERE id = 1`).Scan(&rev); err != nil {
		return 0, fmt.Errorf("reading revision: %w", err)
	}

	return rev, nil
}

// Cursor returns the last revision delivered to a machine.
func (s *Store) Cursor(ctx context.Context, machineID string) (int64, error) {
	var rev int64

	err := s.db.QueryRowContext(ctx, `SELECT revision FROM machine_cursor WHERE machine_id = ?`, machineID).Scan(&rev)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}

	if err != nil {
		return 0, fmt.Errorf("reading cursor: %w", err)
	}

	return rev, nil
}

// SetCursor stores the last revision delivered to a machine.
func (s *Store) SetCursor(ctx context.Context, machineID string, rev int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO machine_cursor (machine_id, revision, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT (machine_id) DO UPDATE SET revision = excluded.revision, updated_at = excluded.updated_at`,
		machineID, rev, nowUTC())
	if err != nil {
		return fmt.Errorf("writing cursor: %w", err)
	}

	return nil
}

// Stats returns a summary of the stored data.
func (s *Store) Stats(ctx context.Context) (*Stats, error) {
	stats := &Stats{ByScenario: map[string]int64{}, ByType: map[string]int64{}}

	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM decisions WHERE deleted = 0`).Scan(&stats.ActiveDecisions); err != nil {
		return nil, fmt.Errorf("counting decisions: %w", err)
	}

	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM machines`).Scan(&stats.Machines); err != nil {
		return nil, fmt.Errorf("counting machines: %w", err)
	}

	rev, err := s.CurrentRevision(ctx)
	if err != nil {
		return nil, err
	}

	stats.Revision = rev

	rows, err := s.db.QueryContext(ctx,
		`SELECT scenario, COUNT(*) FROM decisions WHERE deleted = 0 GROUP BY scenario`)
	if err != nil {
		return nil, fmt.Errorf("counting scenarios: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			scenario string
			count    int64
		)

		if err := rows.Scan(&scenario, &count); err != nil {
			return nil, fmt.Errorf("scanning scenario count: %w", err)
		}

		stats.ByScenario[scenario] = count
	}

	rows2, err := s.db.QueryContext(ctx,
		`SELECT type, COUNT(*) FROM decisions WHERE deleted = 0 GROUP BY type`)
	if err != nil {
		return nil, fmt.Errorf("counting types: %w", err)
	}
	defer rows2.Close()

	for rows2.Next() {
		var (
			typ   string
			count int64
		)

		if err := rows2.Scan(&typ, &count); err != nil {
			return nil, fmt.Errorf("scanning type count: %w", err)
		}

		stats.ByType[typ] = count
	}

	return stats, rows2.Err()
}
