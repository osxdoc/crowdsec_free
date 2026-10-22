package blocklistserver

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStatsScenarioIterationError(t *testing.T) {
	want := errors.New("scenario iteration failed")
	db := sql.OpenDB(statsErrorConnector{failure: want})
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	store := &Store{db: db}

	stats, err := store.Stats(t.Context())
	require.ErrorIs(t, err, want)
	require.Nil(t, stats)
}

type statsErrorConnector struct{ failure error }

func (c statsErrorConnector) Connect(context.Context) (driver.Conn, error) {
	return statsErrorConn(c), nil
}

func (statsErrorConnector) Driver() driver.Driver { return nil }

type statsErrorConn struct{ failure error }

func (statsErrorConn) Prepare(string) (driver.Stmt, error) { return nil, errors.ErrUnsupported }
func (statsErrorConn) Begin() (driver.Tx, error)           { return nil, errors.ErrUnsupported }
func (statsErrorConn) Close() error                        { return nil }
func (c statsErrorConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	rows := &statsErrorRows{columns: []string{"count"}}
	if strings.Contains(query, "GROUP BY") {
		rows.columns = []string{"label", "count"}
		rows.done = true
	}
	if strings.Contains(query, "GROUP BY scenario") {
		rows.failure = c.failure
	}
	return rows, nil
}

type statsErrorRows struct {
	columns []string
	failure error
	done    bool
}

func (r *statsErrorRows) Columns() []string { return r.columns }
func (*statsErrorRows) Close() error        { return nil }
func (r *statsErrorRows) Next(values []driver.Value) error {
	if r.failure != nil {
		return r.failure
	}
	if r.done {
		return io.EOF
	}
	r.done = true
	values[0] = int64(0)
	return nil
}
