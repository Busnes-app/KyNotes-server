package storage

import (
	"context"
	"testing"
	"time"
)

func TestReplicaSessionLockUsesOneConnectionAndExcludesOtherPools(t *testing.T) {
	a, b := sharedReplicas(t)
	a.SetMaxOpenConns(1)
	b.SetMaxOpenConns(1)
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	lease, ok, err := SessionLock(ctx, a, "upload/test", true)
	if err != nil || !ok {
		t.Fatalf("lock: %v %v", ok, err)
	}
	defer lease.Release()
	if other, ok, err := SessionLock(ctx, b, "upload/test", false); err != nil || ok {
		if ok {
			other.Release()
		}
		t.Fatalf("two owners: %v %v", ok, err)
	}
	// Saturated pools still permit the short write on the lock's own connection.
	tx, err := lease.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO server_settings(key,value,updated_at) VALUES('locked-write','1','t')`); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	lease.Release()
	other, ok, err := SessionLock(ctx, b, "upload/test", false)
	if err != nil || !ok {
		t.Fatalf("no takeover: %v %v", ok, err)
	}
	other.Release()
	// Release is idempotent and does not leave a lock re-enterable in its pool.
	lease.Release()
	again, ok, err := SessionLock(ctx, a, "upload/test", false)
	if err != nil || !ok {
		t.Fatalf("released pool stranded: %v %v", ok, err)
	}
	again.Release()
}
