package storage

import (
	"database/sql"
	"github.com/Busnes-app/kynotes-server/internal/ids"
	"time"
)

// AuditOrgSQL is an audit row's org_id for the actor bound to its one placeholder. Single mode:
// the default org, always. Multi mode: the actor's org, or NULL (a platform row) for a staff
// account or an actor that is no account ("system"). The mode and staff org are the rows
// ensureOrgs recorded, so every writer and replica decides alike.
const AuditOrgSQL = `(CASE WHEN (SELECT value FROM server_settings WHERE key='tenancy_mode')='multi' THEN (SELECT NULLIF(u.org_id,(SELECT value FROM server_settings WHERE key='staff_org_id')) FROM users u WHERE u.id=?) ELSE '` + DefaultOrgID + `' END)`

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
	_, err = db.Exec(`INSERT INTO audit_events(id,user_id,event,container_id,object_id,created_at,at,outcome,actor_user_id,request_id,reason_code,org_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,`+AuditOrgSQL+`)`, id, actor, event, container, object, now, now, outcome, actor, requestID, reason, actor)
	return err
}
