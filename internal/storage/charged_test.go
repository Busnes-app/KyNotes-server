package storage

import (
	"context"
	"testing"
)

// Compare the trigger total against the independent full sum after each content lifecycle step.
func TestOrgUsageMatchesUsedBytes(t *testing.T) {
	s := requirePostgres(t)
	seedPurgeOrg(t, s, "org_b", "bbb")
	check := func() {
		t.Helper()
		got, err := OrgChargedBytes(s.db, s.db, "org_b", "")
		if err != nil {
			t.Fatal(err)
		}
		want, err := ChargedBytes(s.db, `SELECT id FROM containers WHERE org_id=?1`, "org_b", "")
		if err != nil {
			t.Fatal(err)
		}
		var links int64
		if err := s.db.QueryRow(`SELECT COALESCE(SUM(length(ciphertext)),0) FROM sealed_share_links WHERE org_id='org_b' AND revoked_at='' AND expires_at>'2000'`).Scan(&links); err != nil {
			t.Fatal(err)
		}
		if got != want+links {
			t.Fatalf("trigger total %d, full sum %d", got, want+links)
		}
	}
	check()
	for _, q := range []string{
		`UPDATE comments SET body_ciphertext=X'01020304' WHERE id='cmt_bbb'`,
		`UPDATE comments SET body_ciphertext=X'',deleted_at='now' WHERE id='cmt_bbb'`,
		`UPDATE attachments SET deleted_at='now' WHERE id='att_bbb'`,
		`UPDATE attachments SET deleted_at='' WHERE id='att_bbb'`,
		`DELETE FROM object_versions WHERE object_id='obj_bbb'`,
		`DELETE FROM conflicts WHERE id='cfl_bbb'`,
		`UPDATE upload_sessions SET expires_at='2099',declared_bytes=30 WHERE id='ups_bbb'`,
		`UPDATE upload_sessions SET status='finalized',kind='preview',finalized_digest=(SELECT digest FROM blobs WHERE org_id='org_b') WHERE id='ups_bbb'`,
		`INSERT INTO upload_sessions(id,user_id,container_id,kind,declared_bytes,chunk_bytes,created_at,updated_at,expires_at,status,finalized_digest,org_id) SELECT 'ups_duplicate',user_id,container_id,kind,declared_bytes,chunk_bytes,created_at,updated_at,expires_at,status,finalized_digest,org_id FROM upload_sessions WHERE id='ups_bbb'`,
		`UPDATE sealed_share_links SET revoked_at='now' WHERE org_id='org_b'`,
		`DELETE FROM comments WHERE id='cmt_bbb'`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		check()
	}
	if _, err := s.db.Exec(`UPDATE orgs SET status='deleted' WHERE id='org_b'`); err != nil {
		t.Fatal(err)
	}
	for range 2 { // the second run is past the late-PUT window
		if err := PurgeOrg(context.Background(), s.db, noObjects, "org_b"); err != nil {
			t.Fatal(err)
		}
		endPurgeWindow(t, s)
	}
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM org_usage WHERE org_id='org_b'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("purge usage rows=%d: %v", n, err)
	}
	check()
}

func TestPoolReservationNeedsNoFreshHeadroom(t *testing.T) {
	s := openFresh(t)
	seedPurgeOrg(t, s, "org_b", "bbb")
	for _, q := range []string{
		`UPDATE server_settings SET value='multi' WHERE key='tenancy_mode'`,
		`UPDATE upload_sessions SET declared_bytes=32,expires_at='2099' WHERE id='ups_bbb'`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	// No grant exists. Converting an existing reservation adds no bytes, growth still fails.
	for _, tc := range []struct {
		n      int64
		refuse bool
	}{{0, false}, {32, false}, {33, true}} {
		got, err := PoolRefuses(s.db, s.db, "org_b", "ups_bbb", tc.n)
		if err != nil || got != tc.refuse {
			t.Fatalf("n=%d: refused=%v err=%v", tc.n, got, err)
		}
	}
}

func TestOrgUsageTracksCascadeCommentDelete(t *testing.T) {
	s := requirePostgres(t)
	seedPurgeOrg(t, s, "org_b", "bbb")
	if _, err := s.db.Exec(`DELETE FROM containers WHERE id='cnt_bbb'`); err != nil {
		t.Fatal(err)
	}
	var n int64
	if err := s.db.QueryRow(`SELECT bytes FROM org_usage WHERE org_id='org_b'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("durable usage after notebook cascade=%d: %v", n, err)
	}
}
