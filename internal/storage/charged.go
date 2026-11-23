package storage

import (
	"database/sql"
	"time"
)

type rowQuerier interface {
	QueryRow(query string, args ...any) *sql.Row
}

// ChargedBytes sums what the containers in scope (a query of ?1=key) hold or have reserved:
// every page version and conflict, live comments and attachments, live pending uploads (bar
// skip) at their declared size, and each kept preview blob once. Notebook deletion tombstones
// its attachments and cancels pending uploads. Older late uploads that are still live remain
// charged until reclaimed, even when their notebook is deleted. A preview names its blob by org
// and digest: the same ciphertext in two orgs is two blobs (N8).
func ChargedBytes(q rowQuerier, scope, key, skip string) (int64, error) {
	var used int64
	err := q.QueryRow(`SELECT
 (SELECT COALESCE(SUM(v.ciphertext_bytes),0) FROM object_versions v JOIN objects o ON o.id=v.object_id WHERE o.container_id IN (`+scope+`))
+(SELECT COALESCE(SUM(ciphertext_bytes),0) FROM conflicts WHERE container_id IN (`+scope+`))
+(SELECT COALESCE(SUM(length(body_ciphertext)),0) FROM comments WHERE deleted_at='' AND container_id IN (`+scope+`))
+(SELECT COALESCE(SUM(ciphertext_bytes),0) FROM attachments WHERE deleted_at='' AND container_id IN (`+scope+`))
+(SELECT COALESCE(SUM(declared_bytes),0) FROM upload_sessions WHERE status='pending' AND expires_at>?2 AND id<>?3 AND container_id IN (`+scope+`))
+(SELECT COALESCE(SUM(b.size_bytes),0) FROM blobs b WHERE (b.org_id,b.digest) IN (SELECT s.org_id,s.finalized_digest FROM upload_sessions s WHERE s.kind='preview' AND s.finalized_digest<>'' AND s.container_id IN (SELECT id FROM containers WHERE deleted_at='') AND s.container_id IN (`+scope+`)))`, key, time.Now().UTC().Format(time.RFC3339), skip).Scan(&used)
	return used, err
}

// OrgChargedBytes is the org's figure for its storage pool (tenancy N10): its notebooks'
// charged bytes plus its live sealed share links.
func OrgChargedBytes(db *sql.DB, q rowQuerier, org, skip string) (int64, error) {
	var used int64
	var err error
	if IsPostgres(db) {
		err = q.QueryRow(`SELECT COALESCE((SELECT bytes FROM org_usage WHERE org_id=?1),0)
 +(SELECT COALESCE(SUM(declared_bytes),0) FROM upload_sessions WHERE org_id=?1 AND status='pending' AND expires_at>?2 AND id<>?3)
 +(SELECT COALESCE(SUM(b.size_bytes),0) FROM blobs b WHERE b.org_id=?1 AND b.digest IN
   (SELECT s.finalized_digest FROM upload_sessions s JOIN containers c ON c.id=s.container_id WHERE s.org_id=?1 AND s.kind='preview' AND s.finalized_digest<>'' AND c.deleted_at=''))`, org, time.Now().UTC().Format(time.RFC3339), skip).Scan(&used)
	} else {
		used, err = ChargedBytes(q, `SELECT id FROM containers WHERE org_id=?1`, org, skip)
	}
	if err != nil {
		return 0, err
	}
	var links int64
	err = q.QueryRow(`SELECT COALESCE(SUM(length(ciphertext)),0) FROM sealed_share_links WHERE org_id=? AND revoked_at='' AND expires_at>?`, org, time.Now().UTC().Format(time.RFC3339)).Scan(&links)
	return used + links, err
}

// PoolRefuses reports whether n more bytes would leave the org's pool grant (tenancy N10, owner
// decision 14): in multi mode a write that adds bytes passes only while the org's charged bytes
// plus n are at most its grant's ceiling and the grant has not expired. No grant refuses growth.
// Single mode, and a write that adds nothing, always pass.
func PoolRefuses(db *sql.DB, q rowQuerier, org, skip string, n int64) (bool, error) {
	tenancy, err := TenancyOf(q)
	if err != nil || !tenancy.Multi() || n <= 0 {
		return false, err
	}
	// Finalization replaces a live reservation. It adds no bytes up to that reservation,
	// even if the grant expired while chunks were being sent.
	if skip != "" {
		var reserved int64
		if err := q.QueryRow(`SELECT COALESCE(SUM(declared_bytes),0) FROM upload_sessions WHERE id=? AND org_id=? AND status='pending' AND expires_at>?`, skip, org, time.Now().UTC().Format(time.RFC3339)).Scan(&reserved); err != nil {
			return false, err
		}
		if n <= reserved {
			return false, nil
		}
	}
	var ceiling int64
	var expires string
	err = q.QueryRow(`SELECT ceiling_bytes,expires_at FROM org_pool WHERE org_id=?`, org).Scan(&ceiling, &expires)
	if err == sql.ErrNoRows {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if until, perr := time.Parse(time.RFC3339Nano, expires); perr != nil || !time.Now().Before(until) {
		return true, nil
	}
	used, err := OrgChargedBytes(db, q, org, skip)
	return n > ceiling || used > ceiling-n, err
}
