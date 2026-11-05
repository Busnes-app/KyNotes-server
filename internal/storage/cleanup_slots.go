package storage

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/kynotes-server/internal/ids"
)

// MaxAuditRequestIDBytes is enforced by the HTTP diagnostic-ID boundary before auditing.
const MaxAuditRequestIDBytes = 128
const CleanupDatabaseBudget = capsule.MaxExpandedBytes * 9 / 10
const cleanupSchemaVersion = 31

var ErrCleanupCapacity = errors.New("cleanup metadata does not fit the backup budget")
var ErrCleanupInvariant = errors.New("cleanup reservation missing or invalid")

type cleanupQuery interface{ QueryRow(string, ...any) *sql.Row }

// DatabaseBytes counts real allocated pages, excluding pages VACUUM INTO discards.
func DatabaseBytes(q cleanupQuery) (int64, error) {
	var n int64
	err := q.QueryRow(`SELECT (page_count-freelist_count)*page_size FROM pragma_page_count(),pragma_freelist_count(),pragma_page_size()`).Scan(&n)
	return n, err
}

type cleanupRecord struct {
	Actor   string `json:"actor"`
	Request string `json:"request"`
	At      string `json:"at"`
}

func cleanupSlotBytes(q cleanupQuery) (int, error) {
	var actorBytes int64
	if err := q.QueryRow(`SELECT MAX(30,COALESCE(MAX(length(CAST(id AS BLOB))),0)) FROM users`).Scan(&actorBytes); err != nil {
		return 0, err
	}
	empty, _ := json.Marshal(cleanupRecord{At: "2000-01-01T00:00:00Z"})
	// Any input byte needs at most six JSON bytes, including control/HTML escaping and
	// invalid UTF8 replacement. Existing legacy IDs are measured in bytes, not characters.
	n := int64(len(empty)) + 6*(actorBytes+MaxAuditRequestIDBytes)
	n = (n + 63) / 64 * 64
	if n > CleanupDatabaseBudget {
		return 0, ErrCleanupCapacity
	}
	return int(n), nil
}

// ReserveCleanupAuditTx allocates the exact fixed-size future audit now. No mutable
// actor/time index is added later; audit_history merges completed slots at the read boundary.
func ReserveCleanupAuditTx(tx *sql.Tx, kind, source, container string) error {
	size, err := cleanupSlotBytes(tx)
	if err != nil {
		return err
	}
	return reserveCleanupAuditTx(tx, kind, source, container, size)
}
func reserveCleanupAuditTx(tx *sql.Tx, kind, source, container string, size int) error {
	id, err := ids.Mint("aud")
	if err != nil {
		return err
	}
	payload := append([]byte("null"), bytes.Repeat([]byte{' '}, size-4)...)
	_, err = tx.Exec(`INSERT INTO cleanup_audit_slots(source_id,audit_id,kind,container_id,payload) VALUES(?,?,?,?,?)`, source, id, kind, container, payload)
	return err
}

// FillCleanupAuditTx records actual operation metadata in the preallocated slot, once.
// Its fixed-length BLOB and immutable keys preserve the existing record/index sizes.
func FillCleanupAuditTx(tx *sql.Tx, kind, source, actor, request, now string) error {
	if len(request) > MaxAuditRequestIDBytes || len(now) != 20 {
		return ErrCleanupInvariant
	}
	var payload []byte
	if err := tx.QueryRow(`SELECT payload FROM cleanup_audit_slots WHERE source_id=? AND kind=?`, source, kind).Scan(&payload); err != nil {
		return fmt.Errorf("%w: %v", ErrCleanupInvariant, err)
	}
	if !bytes.Equal(bytes.TrimSpace(payload), []byte("null")) {
		return ErrCleanupInvariant
	}
	record, err := json.Marshal(cleanupRecord{Actor: actor, Request: request, At: now})
	if err != nil {
		return err
	}
	if len(record) > len(payload) {
		return ErrCleanupInvariant
	}
	record = append(record, bytes.Repeat([]byte{' '}, len(payload)-len(record))...)
	_, err = tx.Exec(`UPDATE cleanup_audit_slots SET payload=? WHERE source_id=? AND kind=?`, record, source, kind)
	return err
}

// VerifyCleanupReservations checks live-source bindings at migration/restore.
// Ordinary creation reserves its own slot atomically, without a full-history scan.
func VerifyCleanupReservations(q cleanupQuery) error {
	var invalid int
	if err := q.QueryRow(`SELECT EXISTS(SELECT 1 FROM cleanup_audit_slots WHERE length(payload)%64<>0 OR (json_type(CAST(payload AS TEXT))='object' AND (COALESCE(json_type(CAST(payload AS TEXT),'$.actor'),'')<>'text' OR COALESCE(json_type(CAST(payload AS TEXT),'$.request'),'')<>'text' OR COALESCE(json_type(CAST(payload AS TEXT),'$.at'),'')<>'text' OR length(CAST(json_extract(CAST(payload AS TEXT),'$.request') AS BLOB))>128 OR length(CAST(json_extract(CAST(payload AS TEXT),'$.at') AS BLOB))<>20)))`).Scan(&invalid); err != nil {
		return err
	}
	if invalid != 0 {
		return ErrCleanupInvariant
	}
	var missing int
	err := q.QueryRow(`SELECT EXISTS(SELECT 1 FROM comments c LEFT JOIN cleanup_audit_slots s ON s.source_id=c.id AND s.kind='comment' WHERE c.deleted_at='' AND (s.source_id IS NULL OR json_type(CAST(s.payload AS TEXT))<>'null')) OR EXISTS(SELECT 1 FROM sealed_share_links l LEFT JOIN cleanup_audit_slots s ON s.source_id=l.id AND s.kind='sealed_share_link' WHERE l.revoked_at='' AND (s.source_id IS NULL OR json_type(CAST(s.payload AS TEXT))<>'null'))`).Scan(&missing)
	if err != nil {
		return err
	}
	if missing != 0 {
		return ErrCleanupInvariant
	}
	return nil
}

// SQLite stores signed integers using0,1,2,3,4,6 or8 payload bytes.0/1 use serial
// types8/9 with no payload. Non-negative counters have one-byte serial headers.
func counterBytes(n int64) int {
	switch {
	case n == 0 || n == 1:
		return 0
	case n <= 127:
		return 1
	case n <= 32767:
		return 2
	case n <= 8388607:
		return 3
	case n <= 2147483647:
		return 4
	case n <= 140737488355327:
		return 6
	default:
		return 8
	}
}

func AdvanceCleanupSeqTx(tx *sql.Tx, container, now string) (int64, error) {
	var seq int64
	var previous, nowBytes, pad int
	if err := tx.QueryRow(`SELECT change_seq,length(CAST(updated_at AS BLOB)),length(CAST(? AS BLOB)),length(cleanup_padding) FROM containers WHERE id=? AND deleted_at=''`, now, container).Scan(&seq, &previous, &nowBytes, &pad); err != nil {
		return 0, err
	}
	if seq < 0 || seq == math.MaxInt64 {
		return 0, ErrCleanupInvariant
	}
	next := seq + 1
	// Consume only growth. Shrink credits never replenish a future operation's reserve.
	growth := max(0, counterBytes(next)-counterBytes(seq)) + max(0, nowBytes-previous)
	if growth > pad {
		return 0, ErrCleanupInvariant
	}
	padding, err := cleanupRowPaddingTx(tx, "containers", container, map[string]any{"change_seq": next, "updated_at": now}, pad-growth)
	if err != nil {
		return 0, err
	}
	_, err = tx.Exec(`UPDATE containers SET change_seq=?,updated_at=?,cleanup_padding=zeroblob(?) WHERE id=?`, next, now, padding, container)
	return next, err
}

func TombstoneCommentTx(tx *sql.Tx, id, now string, seq int64) error {
	var old int64
	var pad, nowBytes int
	if err := tx.QueryRow(`SELECT change_seq,length(cleanup_padding),length(CAST(? AS BLOB)) FROM comments WHERE id=? AND deleted_at=''`, now, id).Scan(&old, &pad, &nowBytes); err != nil {
		return err
	}
	if old < 0 {
		return ErrCleanupInvariant
	}
	growth := nowBytes + max(0, counterBytes(seq)-counterBytes(old))
	if growth > pad {
		return ErrCleanupInvariant
	}
	padding, err := cleanupRowPaddingTx(tx, "comments", id, map[string]any{"deleted_at": now, "body_ciphertext": []byte{}, "change_seq": seq}, 0)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE comments SET deleted_at=?,body_ciphertext=X'',change_seq=?,cleanup_padding=zeroblob(?) WHERE id=?`, now, seq, padding, id)
	return err
}
func RevokeSealedLinkTx(tx *sql.Tx, id, owner, now string) (bool, error) {
	var pad, nowBytes int
	err := tx.QueryRow(`SELECT length(cleanup_padding),length(CAST(? AS BLOB)) FROM sealed_share_links WHERE id=? AND owner_user_id=? AND revoked_at=''`, now, id, owner).Scan(&pad, &nowBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if nowBytes > pad {
		return false, ErrCleanupInvariant
	}
	padding, err := cleanupRowPaddingTx(tx, "sealed_share_links", id, map[string]any{"revoked_at": now}, pad-nowBytes)
	if err != nil {
		return false, err
	}
	_, err = tx.Exec(`UPDATE sealed_share_links SET revoked_at=?,cleanup_padding=zeroblob(?) WHERE id=?`, now, padding, id)
	return err == nil, err
}

func initializeCleanupSlotsTx(tx *sql.Tx) error {
	size, err := cleanupSlotBytes(tx)
	if err != nil {
		return err
	}
	var comments, links int64
	if err = tx.QueryRow(`SELECT (SELECT count(*) FROM comments WHERE deleted_at=''),(SELECT count(*) FROM sealed_share_links WHERE revoked_at='')`).Scan(&comments, &links); err != nil {
		return err
	}
	// A necessary lower bound rejects un-fundable legacy sets before allocating a huge
	// scratch database. The final decision below uses physical pages, never this estimate.
	if (comments+links)*int64(size) > CleanupDatabaseBudget {
		return fmt.Errorf("%w: %d comments and %d links need at least %d slot bytes; budget%d; reduce pages/notebooks with the old release", ErrCleanupCapacity, comments, links, (comments+links)*int64(size), CleanupDatabaseBudget)
	}
	rows, err := tx.Query(`SELECT id,container_id,'comment' FROM comments WHERE deleted_at='' UNION ALL SELECT id,'','sealed_share_link' FROM sealed_share_links WHERE revoked_at=''`)
	if err != nil {
		return err
	}
	// One connection owns this transaction; gather only bounded IDs before inserting.
	type source struct{ id, container, kind string }
	var sources []source
	for rows.Next() {
		var s source
		if err = rows.Scan(&s.id, &s.container, &s.kind); err != nil {
			rows.Close()
			return err
		}
		sources = append(sources, s)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, s := range sources {
		if err = reserveCleanupAuditTx(tx, s.kind, s.id, s.container, size); err != nil {
			return err
		}
	}
	used, err := DatabaseBytes(tx)
	if err != nil {
		return err
	}
	if used > CleanupDatabaseBudget {
		return fmt.Errorf("%w: staged database%d bytes, budget%d; %d comments and%d links; reduce pages/notebooks with the old release", ErrCleanupCapacity, used, CleanupDatabaseBudget, comments, links)
	}
	return VerifyCleanupReservations(tx)
}

// Operation timestamps use this exact fixed-width format throughout the cleanup path.
func CleanupTime(now time.Time) string { return now.UTC().Format(time.RFC3339) }
