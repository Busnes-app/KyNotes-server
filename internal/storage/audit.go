package storage

import (
	"database/sql"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"time"
)

type auditWriter interface {
	Exec(string, ...any) (sql.Result, error)
}

// RecordAuditOutcome returns persistence errors so export and backup callers cannot
// claim an audited operation when its audit row was lost. reason must contain no secrets.
func RecordAuditOutcome(db *sql.DB, actor, event, container, object, outcome, reason, requestID string) error {
	return recordAuditOutcome(db, actor, event, container, object, outcome, reason, requestID)
}

// RecordAuditOutcomeTx commits the audit with its owning security mutation.
func RecordAuditOutcomeTx(tx *sql.Tx, actor, event, container, object, outcome, reason, requestID string) error {
	return recordAuditOutcome(tx, actor, event, container, object, outcome, reason, requestID)
}

func recordAuditOutcome(db auditWriter, actor, event, container, object, outcome, reason, requestID string) error {
	id, err := ids.Mint("aud")
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = db.Exec(`INSERT INTO audit_events(id,user_id,event,container_id,object_id,created_at,at,outcome,actor_user_id,request_id,reason_code) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, id, actor, event, container, object, now, now, outcome, actor, requestID, reason)
	return err
}
