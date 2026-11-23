package storage

import (
	"context"
	"database/sql"
)

// ResetTenancyAfterRestore is the PostgreSQL restore boundary. The restore adapter must call
// it in the same transaction as credential revocation, before any restored server is served.
// The PostgreSQL backup/restore transport is not enabled by this preparation helper.
func ResetTenancyAfterRestore(ctx context.Context, tx *sql.Tx) error {
	tenancy, err := TenancyOf(tx)
	if err != nil || !tenancy.Multi() {
		return err
	} // Single mode retains its existing restore behavior.

	for _, q := range []string{
		`UPDATE orgs SET status='stale',revision=0 WHERE id<>COALESCE((SELECT value FROM server_settings WHERE key='staff_org_id'),'')`,
		`DELETE FROM org_pool`,
		`DELETE FROM replica_logins`,
		`DELETE FROM replica_rates`,
		`DELETE FROM replica_lockouts`,
		`DELETE FROM replica_presence`,
		`UPDATE reminders SET claimed_until=0,claim_token=''`,
		`DELETE FROM server_settings WHERE key IN ('org_poll_revision','erased_poll_revision','replica_config_fingerprint','blob_probe','blob_probe_prev')`,
	} {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}
