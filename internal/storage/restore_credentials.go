package storage

import (
	"context"
	"database/sql"
	"time"
)

// RevokeRestoredCredentials runs inside the restored target's transaction. Keep encryption
// identities and content; old sessions, paired devices, links and pending invitations lose access.
func RevokeRestoredCredentials(ctx context.Context, tx *sql.Tx) error {
	now := time.Now().UTC().Format(time.RFC3339)
	for _, table := range []string{"sessions", "share_links", "sealed_share_links"} {
		if _, err := tx.ExecContext(ctx, `UPDATE `+table+` SET revoked_at=? WHERE revoked_at=''`, now); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE devices SET revoked_at=? WHERE revoked_at='' AND platform<>'identity'`, now); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM invitations WHERE status='pending'`)
	return err
}
