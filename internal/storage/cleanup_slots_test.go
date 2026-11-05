package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/recoveryclient"
)

// Build the actual prior schema, without running this release's migration.
func legacyCleanupDatabase(t *testing.T, path string, comments, actorBytes int) {
	t.Helper()
	s, err := open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows, err := migrationFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range rows {
		if i+1 >= cleanupSchemaVersion {
			break
		}
		b, err := migrationFS.ReadFile("migrations/" + f.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.db.Exec(string(b)); err != nil {
			t.Fatal(err)
		}
		if _, err = s.db.Exec(`INSERT INTO schema_migrations VALUES(?,?)`, i+1, "2026-01-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"usr_00000000000000000000000000", strings.Repeat("x", max(30, actorBytes))} {
		if _, err = tx.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES(?,?, 'opaque','opaque',100000,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`, id, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = tx.Exec(`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at) VALUES('cnt_00000000000000000000000000','workbook','usr_00000000000000000000000000','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`INSERT INTO objects(id,container_id,kind,change_seq,created_at,updated_at) VALUES('obj_00000000000000000000000000','cnt_00000000000000000000000000','note',1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < comments; i++ {
		if _, err = tx.Exec(`INSERT INTO comments(id,container_id,object_id,author_user_id,body_ciphertext,key_generation,change_seq,created_at) VALUES(?,'cnt_00000000000000000000000000','obj_00000000000000000000000000','usr_00000000000000000000000000',X'6374',1,1,'2026-01-01T00:00:00Z')`, fmt.Sprintf("cmt_%026d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = tx.Exec(`INSERT INTO sealed_share_links(id,token_hash,ciphertext,expires_at,created_at,owner_user_id) VALUES('shl_00000000000000000000000000','legacy',X'00000000000000000000000000000000','2099-01-01T00:00:00Z','2026-01-01T00:00:00Z','usr_00000000000000000000000000')`); err != nil {
		t.Fatal(err)
	}
	if err = RecordAuditOutcomeTx(tx, "usr_00000000000000000000000000", "prior.history", "", "", "success", "untouched", "legacy-request"); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupUpgradeFundsAllLegacyRowsAndPreservesHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite")
	legacyCleanupDatabase(t, path, 4, 30)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var slots, history, padding int
	if err = s.db.QueryRow(`SELECT (SELECT count(*) FROM cleanup_audit_slots),(SELECT count(*) FROM audit_history),(SELECT min(length(cleanup_padding)) FROM comments)`).Scan(&slots, &history, &padding); err != nil || slots != 5 || history != 1 || padding != 64 {
		t.Fatalf("slots/history/padding%d/%d/%d %v", slots, history, padding, err)
	}
	if err = VerifyCleanupReservations(s.db); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.db.QueryRow(`SELECT count(*) FROM cleanup_audit_slots`).Scan(&slots); err != nil || slots != 5 {
		t.Fatalf("second open changed slots%d %v", slots, err)
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "snapshot-cleanup-preflight-*"))
	if len(leftovers) != 0 {
		t.Fatalf("preflight scratch kept%v", leftovers)
	}
}

func TestCleanupUpgradeRefusesBeforeChangingTheLegacyDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite")
	legacyCleanupDatabase(t, path, 300, 256<<10)
	if s, err := Open(path); !errors.Is(err, ErrCleanupCapacity) {
		if s != nil {
			s.Close()
		}
		t.Fatalf("upgrade=%v", err)
	}
	s, err := OpenUnmigrated(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var version, slots, column, comments, audits int
	if err = s.db.QueryRow(`SELECT (SELECT MAX(version) FROM schema_migrations),(SELECT count(*) FROM sqlite_schema WHERE name='cleanup_audit_slots'),(SELECT count(*) FROM pragma_table_info('comments') WHERE name='cleanup_padding'),(SELECT count(*) FROM comments WHERE body_ciphertext=X'6374'),(SELECT count(*) FROM audit_events WHERE reason_code='untouched')`).Scan(&version, &slots, &column, &comments, &audits); err != nil || version != cleanupSchemaVersion-1 || slots != 0 || column != 0 || comments != 300 || audits != 1 {
		t.Fatalf("legacy changed%d/%d/%d/%d/%d %v", version, slots, column, comments, audits, err)
	}
}

func TestCleanupSlotFixedOverwriteIsImmutableAfterCommit(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.db.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES('usr_00000000000000000000000000','person','opaque','opaque',100000,'now','now')`); err != nil {
		t.Fatal(err)
	}
	source := "cmt_00000000000000000000000000"
	if err = s.WithTx(context.Background(), func(tx *sql.Tx) error {
		return ReserveCleanupAuditTx(tx, "comment", source, "cnt_00000000000000000000000000")
	}); err != nil {
		t.Fatal(err)
	}
	before, err := DatabaseBytes(s.db)
	if err != nil {
		t.Fatal(err)
	}
	beforeCompact := compactCleanupBytes(t, s.db)
	var size int
	if err = s.db.QueryRow(`SELECT length(payload) FROM cleanup_audit_slots WHERE source_id=?`, source).Scan(&size); err != nil {
		t.Fatal(err)
	}
	if err = s.WithTx(context.Background(), func(tx *sql.Tx) error {
		return FillCleanupAuditTx(tx, "comment", source, "usr_00000000000000000000000000", strings.Repeat("<", 128), "2026-11-05T00:00:00Z")
	}); err != nil {
		t.Fatal(err)
	}
	if afterCompact := compactCleanupBytes(t, s.db); afterCompact != beforeCompact {
		t.Fatalf("compact slot update grew%d/%d", beforeCompact, afterCompact)
	}
	after, err := DatabaseBytes(s.db)
	if err != nil || after != before {
		t.Fatalf("slot update grew DB%d/%d %v", before, after, err)
	}
	for _, q := range []string{`UPDATE cleanup_audit_slots SET payload=payload WHERE source_id=?`, `DELETE FROM cleanup_audit_slots WHERE source_id=?`} {
		if _, err = s.db.Exec(q, source); err == nil {
			t.Fatalf("committed audit was mutable:%s", q)
		}
	}
	var count, gotSize int
	if err = s.db.QueryRow(`SELECT (SELECT count(*) FROM audit_history),(SELECT length(payload) FROM cleanup_audit_slots WHERE source_id=?)`, source).Scan(&count, &gotSize); err != nil || count != 1 || size != gotSize {
		t.Fatalf("history%d size%d/%d %v", count, size, gotSize, err)
	}
}

func TestCleanupPaddingCoversCounterAndTimestampWidths(t *testing.T) {
	for _, initial := range []int64{0, 1, 127, 32767, 8388607, 2147483647, 140737488355327} {
		t.Run(fmt.Sprint(initial), func(t *testing.T) {
			s, err := Open(filepath.Join(t.TempDir(), "db.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if _, err = s.db.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES('usr_00000000000000000000000000','person','opaque','opaque',100000,'now','now')`); err != nil {
				t.Fatal(err)
			}
			if _, err = s.db.Exec(`INSERT INTO containers(id,kind,owner_user_id,change_seq,created_at,updated_at,meta_ciphertext) VALUES('cnt_00000000000000000000000000','workbook','usr_00000000000000000000000000',?,'now','',zeroblob(3800))`, initial); err != nil {
				t.Fatal(err)
			}
			before, err := DatabaseBytes(s.db)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.WithTx(context.Background(), func(tx *sql.Tx) error {
				_, err := AdvanceCleanupSeqTx(tx, "cnt_00000000000000000000000000", "2026-11-05T00:00:00Z")
				return err
			}); err != nil {
				t.Fatal(err)
			}
			after, err := DatabaseBytes(s.db)
			if err != nil || after > before {
				t.Fatalf("counter width allocated%d/%d %v", before, after, err)
			}
		})
	}
}

func compactCleanupBytes(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	path := filepath.Join(t.TempDir(), "snapshot.sqlite")
	if err := recoveryclient.SQLiteSnapshot(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

func TestCleanupTimestampIsExactlyFundedWidth(t *testing.T) {
	if got := CleanupTime(time.Date(2026, 11, 5, 1, 2, 3, 0, time.FixedZone("x", 3600))); len(got) != 20 {
		t.Fatal(got)
	}
}

func TestCleanupHistoryUsesOperationTimeAndSurvivesSourceRemoval(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, source := range []string{"first-created", "last-created", "pending"} {
		if err := s.WithTx(context.Background(), func(tx *sql.Tx) error { return ReserveCleanupAuditTx(tx, "comment", source, "notebook") }); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.db.Exec(`INSERT INTO audit_events(id,user_id,event,container_id,object_id,created_at,at) VALUES('legacy','person','prior.history','','','2026-11-05T00:00:02Z','2026-11-05T00:00:02Z')`); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []struct{ source, at string }{{"first-created", "2026-11-05T00:00:03Z"}, {"last-created", "2026-11-05T00:00:01Z"}} {
		if err := s.WithTx(context.Background(), func(tx *sql.Tx) error {
			return FillCleanupAuditTx(tx, "comment", operation.source, "person", "request", operation.at)
		}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.db.Query(`SELECT object_id FROM audit_history ORDER BY at DESC,id DESC LIMIT 3`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		got = append(got, id)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if fmt.Sprint(got) != "[first-created  last-created]" {
		t.Fatalf("history order/pending visibility: %v", got)
	}
	if _, err = s.db.Exec(`DELETE FROM cleanup_audit_slots WHERE source_id='pending'`); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM audit_history`).Scan(&count); err != nil || count != 3 {
		t.Fatalf("history lost %d %v", count, err)
	}
}
