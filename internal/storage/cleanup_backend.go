package storage

import (
	"database/sql"

	"github.com/Busnes-app/kynotes-server/internal/ids"
)

// Cleanup runs the comment and sealed-link cleanup writes for one database. SQLite keeps
// migration 0031's preallocated audit slots and row padding; PostgreSQL has neither (tenancy
// spec, Replica work, item 6), so there a cleanup is a plain update and its audit an ordinary
// audit_events row: the same row SQLite's audit_history shows for a filled slot.
type Cleanup struct{ pg bool }

func CleanupFor(db *sql.DB) Cleanup { return Cleanup{pg: IsPostgres(db)} }

func (c Cleanup) Reserve(tx *sql.Tx, kind, source, container string) error {
	if c.pg {
		return nil
	}
	return ReserveCleanupAuditTx(tx, kind, source, container)
}

func (c Cleanup) AdvanceSeq(tx *sql.Tx, container, now string) (int64, error) {
	if !c.pg {
		return AdvanceCleanupSeqTx(tx, container, now)
	}
	var seq int64
	err := tx.QueryRow(`UPDATE containers SET change_seq=change_seq+1,updated_at=? WHERE id=? AND deleted_at='' RETURNING change_seq`, now, container).Scan(&seq)
	return seq, err
}

func (c Cleanup) TombstoneComment(tx *sql.Tx, id, now string, seq int64) error {
	if !c.pg {
		return TombstoneCommentTx(tx, id, now, seq)
	}
	res, err := tx.Exec(`UPDATE comments SET deleted_at=?,body_ciphertext=X'',change_seq=? WHERE id=? AND deleted_at=''`, now, seq, id)
	if err == nil {
		if n, _ := res.RowsAffected(); n != 1 {
			err = sql.ErrNoRows
		}
	}
	return err
}

func (c Cleanup) RevokeSealedLink(tx *sql.Tx, id, owner, now string) (bool, error) {
	if !c.pg {
		return RevokeSealedLinkTx(tx, id, owner, now)
	}
	res, err := tx.Exec(`UPDATE sealed_share_links SET revoked_at=? WHERE id=? AND owner_user_id=? AND revoked_at=''`, now, id, owner)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// Fill records the cleanup's audit: kind is "comment" or "sealed_share_link".
func (c Cleanup) Fill(tx *sql.Tx, kind, source, container, actor, request, now string) error {
	if !c.pg {
		return FillCleanupAuditTx(tx, kind, source, actor, request, now)
	}
	if len(request) > MaxAuditRequestIDBytes || len(now) != 20 {
		return ErrCleanupInvariant
	}
	event := map[string]string{"comment": "comment.delete", "sealed_share_link": "share_link.revoke"}[kind]
	if event == "" {
		return ErrCleanupInvariant
	}
	id, err := ids.Mint("aud")
	if err != nil {
		return err
	}
	// ponytail: the default org, as every writer in this release; PR 3 names the actor's.
	_, err = tx.Exec(`INSERT INTO audit_events(id,user_id,event,container_id,object_id,created_at,at,outcome,actor_user_id,request_id,org_id) VALUES(?,?,?,?,?,?,?,'success',?,?,?)`, id, actor, event, container, source, now, now, actor, request, DefaultOrgID)
	return err
}
