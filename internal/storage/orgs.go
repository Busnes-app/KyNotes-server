package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// DefaultOrgID is KyIdentity's default org: the one org of a single-tenant install.
const DefaultOrgID = "00000000-0000-0000-0000-000000000001"

// ErrTenancyMode: the database was set up in another tenancy mode than this start.
var ErrTenancyMode = errors.New("database tenancy mode differs from the configured mode")

// ensureOrgs records the tenancy mode and the default org. It checks before it writes, so a
// refused start leaves the database as it was. This release runs single-tenant only
// (KYNOTES_TENANCY=multi is refused by config until the spec's PR 6).
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
