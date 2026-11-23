package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestReplicaRestoreResetIsAtomicAndKeepsDeletionFences(t *testing.T) {
	a, _ := sharedReplicas(t)
	ctx := context.Background()
	for _, q := range []string{
		`INSERT INTO orgs(id,status,home_region,revision) VALUES('org_staff','active','local',9),('org_customer','active','local',7)`,
		`INSERT INTO erased_subjects(subject,org_id,revision) VALUES('erased-before-restore','org_customer',3)`,
		`INSERT INTO org_pool(org_id,seq,expires_at) VALUES('org_customer',9,'2099')`,
		`INSERT INTO server_settings(key,value,updated_at) VALUES('org_poll_revision','100','t'),('erased_poll_revision','100','t'),('replica_config_fingerprint','old','t')`,
	} {
		if _, err := a.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := PutLogin(ctx, a, "old-login", []byte("old-proof"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := AllowRate(ctx, a, "login", "old-ip", 1, 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReserveLockout(ctx, a, "login", "old-user", 1, 10, time.Hour); err != nil {
		t.Fatal(err)
	}
	tx, err := a.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ResetTenancyAfterRestore(ctx, tx); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := a.QueryRow(`SELECT count(*) FROM replica_logins`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("failed restore changed PKCE state: %d %v", n, err)
	}
	tx, err = a.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions`); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := ResetTenancyAfterRestore(ctx, tx); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"replica_logins", "replica_rates", "replica_lockouts", "replica_presence", "org_pool"} {
		if err := a.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("restored state survived in %s: %d %v", table, n, err)
		}
	}
	if err := a.QueryRow(`SELECT count(*) FROM erased_subjects WHERE subject='erased-before-restore'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("deletion fence lost: %d %v", n, err)
	}
	if err := a.QueryRow(`SELECT count(*) FROM orgs WHERE id='org_staff' AND status='active' AND revision=9`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("staff org changed: %d %v", n, err)
	}
	var status string
	var revision int64
	if err := a.QueryRow(`SELECT status,revision FROM orgs WHERE id='org_customer'`).Scan(&status, &revision); err != nil || status != "stale" || revision != 0 {
		t.Fatalf("restored customer not fenced: status=%q revision=%d err=%v", status, revision, err)
	}
	if err := a.QueryRow(`SELECT count(*) FROM orgs restored WHERE restored.id='org_customer' AND NOT ` + OrgServes("restored.id")).Scan(&n); err != nil || n != 1 {
		t.Fatalf("unlisted restored org can serve: %d %v", n, err)
	}
	if err := a.QueryRow(`SELECT count(*) FROM server_settings WHERE key IN ('org_poll_revision','erased_poll_revision','replica_config_fingerprint')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("restore retained old cursors/fingerprint: %d %v", n, err)
	}
}

func TestReplicaRestorePreparationLeavesSingleSQLiteUnchanged(t *testing.T) {
	s, err := openSQLite(filepath.Join(t.TempDir(), "single.db"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, q := range []string{
		`INSERT INTO orgs(id,status,home_region,revision) VALUES('org_single_restore','active','local',7)`,
		`INSERT INTO org_pool(org_id,seq,ceiling_bytes,expires_at) VALUES('org_single_restore',9,17,'2099')`,
		`INSERT INTO server_settings(key,value,updated_at) VALUES('org_poll_revision','15','t'),('replica_config_fingerprint','retained','t')`,
	} {
		if _, err := s.DB().Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	tx, err := s.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ResetTenancyAfterRestore(ctx, tx); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var n int
	for _, q := range []string{
		`SELECT count(*) FROM orgs WHERE id='org_single_restore' AND status='active' AND revision=7`,
		`SELECT count(*) FROM org_pool WHERE org_id='org_single_restore' AND seq=9 AND ceiling_bytes=17`,
		`SELECT count(*) FROM server_settings WHERE key='org_poll_revision' AND value='15'`,
		`SELECT count(*) FROM server_settings WHERE key='replica_config_fingerprint' AND value='retained'`,
	} {
		if err := s.DB().QueryRow(q).Scan(&n); err != nil || n != 1 {
			t.Fatalf("single-mode restore state changed: count=%d err=%v", n, err)
		}
	}
	if err := s.DB().QueryRow(`SELECT count(*) FROM sqlite_master WHERE name LIKE 'replica_%'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("shared tables created on SQLite: %d %v", n, err)
	}
}
