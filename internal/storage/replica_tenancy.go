package storage

import (
	"context"
	"errors"
)

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
