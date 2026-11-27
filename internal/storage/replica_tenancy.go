package storage

import (
	"context"
	"database/sql"
	"errors"
)

// verifyExistingReplicaTarget checks an existing database's recorded tenancy binding
// before any pending migrations run, so an accidental target pointing at a single-mode
// database or a differently bound multi-tenant database is refused without altering its
// schema. A fresh or unbound empty database proceeds to migration and binding.
func verifyExistingReplicaTarget(ctx context.Context, conn *sql.Conn, want Tenancy) error {
	var hasSettings bool
	if err := conn.QueryRowContext(ctx, `SELECT to_regclass('server_settings') IS NOT NULL`).Scan(&hasSettings); err != nil {
		return err
	}
	if hasSettings {
		var mode string
		err := conn.QueryRowContext(ctx, `SELECT value FROM server_settings WHERE key='tenancy_mode'`).Scan(&mode)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if mode != "" {
			got, err := TenancyOfContext(ctx, conn)
			if err != nil {
				return err
			}
			if got != want {
				return ErrTenancyMode
			}
			return nil
		}
	}
	for _, check := range []struct {
		existsSQL string
		countSQL  string
	}{
		{`SELECT to_regclass('users') IS NOT NULL`, `SELECT count(*) FROM users`},
		{`SELECT to_regclass('orgs') IS NOT NULL`, `SELECT count(*) FROM orgs`},
	} {
		var exists bool
		if err := conn.QueryRowContext(ctx, check.existsSQL).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			continue
		}
		var n int
		if err := conn.QueryRowContext(ctx, check.countSQL).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			return errors.New("replicas: refusing an unbound nonempty database")
		}
	}
	return nil
}

func verifyExistingSingleTarget(ctx context.Context, conn *sql.Conn) error {
	var hasSettings bool
	if err := conn.QueryRowContext(ctx, `SELECT to_regclass('server_settings') IS NOT NULL`).Scan(&hasSettings); err != nil {
		return err
	}
	if !hasSettings {
		return nil
	}
	var mode string
	err := conn.QueryRowContext(ctx, `SELECT value FROM server_settings WHERE key='tenancy_mode'`).Scan(&mode)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if mode != "" && mode != "single" {
		return ErrTenancyMode
	}
	return nil
}

func (s *Store) ensureReplicaTenancy(ctx context.Context, want Tenancy) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	mode, err := storedTenancyMode(tx)
	if err != nil {
		return err
	}
	if mode != "" {
		got, err := TenancyOfContext(ctx, tx)
		if err != nil {
			return err
		}
		if got != want {
			return ErrTenancyMode
		}
		return tx.Commit()
	}
	// Never convert an existing single install or adopt unbound application data.
	var users, orgs int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&users); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM orgs`).Scan(&orgs); err != nil {
		return err
	}
	if users != 0 || orgs != 0 {
		return errors.New("replicas: refusing an unbound nonempty database")
	}
	for key, value := range map[string]string{"tenancy_mode": want.Mode, "staff_org_id": want.StaffOrg, "region": want.Region} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO server_settings(key,value,updated_at) VALUES(?,?,'')`, key, value); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO orgs(id,status,enabled,home_region) VALUES(?,'active',1,?)`, want.StaffOrg, want.Region); err != nil {
		return err
	}
	return tx.Commit()
}
