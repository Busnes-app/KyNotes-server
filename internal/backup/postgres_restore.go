package backup

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// PreparePostgresRestore fences an offline native-PostgreSQL restored target. It does not
// recover bytes, migrate a schema, select a backup transport, or enable multi-mode startup.
func PreparePostgresRestore(ctx context.Context, store *storage.Store) error {
	if !store.Postgres() {
		return errors.New("restore preparation requires PostgreSQL")
	}
	return store.WithTx(ctx, func(tx *sql.Tx) error { return fenceRestoredTx(ctx, tx) })
}

// fenceRestoredTx is the restore fence both PostgreSQL restore paths commit with: credentials
// revoked, orgs stale behind the replay gate, deposits off, audited.
func fenceRestoredTx(ctx context.Context, tx *sql.Tx) error {
	tenancy, err := storage.TenancyOfContext(ctx, tx)
	if err != nil {
		return err
	}
	if !tenancy.Multi() {
		return errors.New("restore preparation requires recorded multi tenancy")
	}
	if err := storage.RevokeRestoredCredentials(ctx, tx); err != nil {
		return err
	}
	if err := storage.ResetTenancyAfterRestore(ctx, tx); err != nil {
		return err
	}
	if err := recoveryclient.SetInterval(restoreSettings{ctx, tx}, 0); err != nil {
		return err
	}
	return storage.RecordAuditOutcomeTx(tx, "", "platform.restore_prepared", "", "", "success", "credentials_revoked,schedule_off,orgs_stale,replay_gated", "pg-restore")
}

// Keep the library's schedule key/validation inside its API while committing with the reset.
type restoreSettings struct {
	ctx context.Context
	tx  *sql.Tx
}

func (s restoreSettings) Get(key string) (string, error) {
	var value string
	err := s.tx.QueryRowContext(s.ctx, `SELECT value FROM server_settings WHERE key=?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		err = recoveryclient.ErrNotFound
	}
	return value, err
}
func (s restoreSettings) Set(key, value string) error {
	_, err := s.tx.ExecContext(s.ctx, `INSERT INTO server_settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`, key, value, time.Now().UTC().Format(time.RFC3339))
	return err
}
func (s restoreSettings) Delete(key string) error {
	_, err := s.tx.ExecContext(s.ctx, `DELETE FROM server_settings WHERE key=?`, key)
	return err
}
