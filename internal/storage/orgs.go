package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"
)

// DefaultOrgID is KyIdentity's default org: the one org of a single-tenant install.
const DefaultOrgID = "00000000-0000-0000-0000-000000000001"

// ErrTenancyMode: the database was set up in another tenancy mode than this start.
var ErrTenancyMode = errors.New("database tenancy mode differs from the configured mode")

// ensureOrgs records the tenancy mode and the default org. It checks before it writes, so a
// refused start leaves the database as it was. The gated replica opener uses its separate
// immutable multi-mode binding; this single-mode path never converts an installation.
func (s *Store) ensureOrgs() error {
	const mode = "single"
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stored, err := storedTenancyMode(tx)
	if err != nil {
		return err
	}
	if stored != "" && stored != mode {
		return fmt.Errorf("%w: database is %s, this start is %s", ErrTenancyMode, stored, mode)
	}
	if _, err = tx.Exec(`INSERT INTO server_settings(key,value,updated_at) VALUES('tenancy_mode',?,?) ON CONFLICT(key) DO NOTHING`, mode, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	if stored, err = storedTenancyMode(tx); err != nil || stored != mode {
		return errors.Join(err, fmt.Errorf("%w: database is %s, this start is %s", ErrTenancyMode, stored, mode))
	}
	if _, err = tx.Exec(`INSERT INTO orgs(id,status,home_region) VALUES(?,'active','local') ON CONFLICT(id) DO NOTHING`, DefaultOrgID); err != nil {
		return err
	}
	return tx.Commit()
}

// storedTenancyMode is the recorded mode, or single for a database that predates the record
// (it has the default org), or "" for a fresh one.
func storedTenancyMode(tx *sql.Tx) (string, error) {
	var mode string
	err := tx.QueryRow(`SELECT value FROM server_settings WHERE key='tenancy_mode'`).Scan(&mode)
	if !errors.Is(err, sql.ErrNoRows) {
		return mode, err
	}
	var n int
	if err = tx.QueryRow(`SELECT count(*) FROM orgs WHERE id=?`, DefaultOrgID).Scan(&n); err != nil || n == 0 {
		return "", err
	}
	return "single", nil
}

// Tenancy is the install's recorded mode (ensureOrgs), read where a rule differs by mode.
// Region is multi mode's first cell, recorded at the first start as the staff org's cell.
type Tenancy struct{ Mode, StaffOrg, Region string }

func (t Tenancy) Multi() bool { return t.Mode == "multi" }

// Binds reports whether a start with want's mode and staff org serving cells (KY_CELLS) may use
// a database recorded as t: cells may be added or reordered, but must keep the staff org's cell.
func (t Tenancy) Binds(want Tenancy, cells []string) bool {
	return t.Mode == want.Mode && t.StaffOrg == want.StaffOrg && slices.Contains(cells, t.Region)
}

// servedCellKey prefixes one server_settings row per cell this deployment serves (KY_CELLS),
// replaced at every multi-mode start (SetServedCells).
const servedCellKey = "cell:"

// InServedCell is SQL that is true when the orgs row aliased alias is in a served cell (Cells, C5).
func InServedCell(alias string) string {
	return `EXISTS(SELECT 1 FROM server_settings sc WHERE sc.key='` + servedCellKey + `'||` + alias + `.home_region)`
}

// SetServedCells makes cells the cells this deployment serves. Rows are added before others are
// removed, so replicas starting together with one list never collide.
func SetServedCells(ctx context.Context, db *sql.DB, cells []string) error {
	if len(cells) == 0 {
		return errors.New("served cells: none")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	keep := make([]any, len(cells))
	marks := ""
	for i, cell := range cells {
		if _, err := tx.ExecContext(ctx, `INSERT INTO server_settings(key,value,updated_at) VALUES(?,'','') ON CONFLICT(key) DO NOTHING`, servedCellKey+cell); err != nil {
			return err
		}
		keep[i], marks = servedCellKey+cell, marks+",?"
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM server_settings WHERE key LIKE '`+servedCellKey+`%' AND key NOT IN (`+marks[1:]+`)`, keep...); err != nil {
		return err
	}
	return tx.Commit()
}

// TenancyOf reads the recorded mode, staff org and region; a database without the record is
// single-tenant.
func TenancyOf(q interface {
	QueryRow(string, ...any) *sql.Row
}) (Tenancy, error) {
	var t Tenancy
	err := q.QueryRow(tenancyQuery).Scan(&t.Mode, &t.StaffOrg, &t.Region)
	return t, err
}

// OrgServes is SQL that is true when the org named by the column expression col may be served:
// always in single mode; in multi mode only an active, enabled org in a cell this deployment
// serves (tenancy N9, N13, Cells). Credential checks and the workers carry it, so a stopped org
// is refused on the next request and its reminders and blobs wait. After a restore no customer org serves
// until both suite feeds were replayed from zero (RestoreReplayKey).
func OrgServes(col string) string {
	return `(COALESCE((SELECT value FROM server_settings WHERE key='tenancy_mode'),'single')<>'multi' OR EXISTS(SELECT 1 FROM orgs so WHERE so.id=` + col + ` AND so.status='active' AND so.enabled=1 AND ` + InServedCell("so") + ` AND (so.id=(SELECT value FROM server_settings WHERE key='staff_org_id') OR NOT EXISTS(SELECT 1 FROM server_settings WHERE key='` + RestoreReplayKey + `'))))`
}

// RestoreReplayKey is the server_settings row a restore writes and the elected worker deletes
// once the org and erased feeds, read from zero, have nothing more (httpapi.FinishRestoreReplay).
const RestoreReplayKey = "restore_replay"

const tenancyQuery = `SELECT COALESCE(MAX(CASE WHEN key='tenancy_mode' THEN value END),'single'),COALESCE(MAX(CASE WHEN key='staff_org_id' THEN value END),''),COALESCE(MAX(CASE WHEN key='region' THEN value END),'') FROM server_settings WHERE key IN ('tenancy_mode','staff_org_id','region')`

// TenancyOfContext is the same recorded-mode read for cancellable request/worker paths.
func TenancyOfContext(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (Tenancy, error) {
	var t Tenancy
	err := q.QueryRowContext(ctx, tenancyQuery).Scan(&t.Mode, &t.StaffOrg, &t.Region)
	return t, err
}
