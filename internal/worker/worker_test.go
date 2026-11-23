package worker

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func TestReplicaWorkerExclusionCancellationAndTakeover(t *testing.T) {
	if !storage.OnPostgresTest() {
		t.Skip("needs KYNOTES_TEST_DATABASE_URL")
	}
	first, err := storage.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	var schema string
	if err := first.DB().QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	dsn, err := url.Parse(os.Getenv("KYNOTES_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	q := dsn.Query()
	q.Set("search_path", schema)
	dsn.RawQuery = q.Encode()
	second, err := storage.OpenPostgres(dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	ctx, stop := context.WithTimeout(context.Background(), 8*time.Second)
	defer stop()
	ownerCtx, stopOwner := context.WithCancel(ctx)
	entered := make(chan struct{})
	cancelled := make(chan struct{})
	ownerDone := make(chan struct{})
	standbyDone := make(chan struct{})
	go func() {
		defer close(ownerDone)
		Run(ownerCtx, first.DB(), 10*time.Millisecond, func(owned context.Context, _ time.Time) { close(entered); <-owned.Done(); close(cancelled) })
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("no elected worker")
	}
	var calls atomic.Int32
	go func() {
		defer close(standbyDone)
		Run(ctx, second.DB(), 10*time.Millisecond, func(context.Context, time.Time) { calls.Add(1) })
	}()
	// A separate real connection cannot acquire the current worker's lock.
	if l, ok, err := storage.SessionLock(ctx, second.DB(), "scheduled-worker", false); err != nil || ok {
		if ok {
			l.Release()
		}
		t.Fatalf("worker ownership not exclusive: %v %v", ok, err)
	}
	stopOwner()
	select {
	case <-cancelled:
	case <-ctx.Done():
		t.Fatal("job not cancelled")
	}
	select {
	case <-ownerDone:
	case <-ctx.Done():
		t.Fatal("old worker not drained")
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for calls.Load() == 0 {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("standby never took over")
		}
	}
	stop()
	<-standbyDone
}

// The lock connection's death cancels a running external operation before another tick.
func TestReplicaWorkerCancelsOnLostConnection(t *testing.T) {
	if !storage.OnPostgresTest() {
		t.Skip("needs KYNOTES_TEST_DATABASE_URL")
	}
	s, err := storage.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, stop := context.WithTimeout(context.Background(), 8*time.Second)
	defer stop()
	entered := make(chan context.Context, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		Run(ctx, s.DB(), 10*time.Millisecond, func(owned context.Context, _ time.Time) {
			select {
			case entered <- owned:
			default:
			}
			<-owned.Done()
		})
	}()
	var owned context.Context
	select {
	case owned = <-entered:
	case <-ctx.Done():
		t.Fatal("no worker")
	}
	var schema string
	if err := s.DB().QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	key := sha256.Sum256([]byte("kynotes/session/" + schema + "/scheduled-worker"))
	var pid int
	// Exact schema-specific advisory key: terminate only the session this test elected.
	if err := s.DB().QueryRow(`SELECT pid FROM pg_locks WHERE locktype='advisory' AND granted AND objsubid=1 AND classid::bigint=? AND objid::bigint=? AND database=(SELECT oid FROM pg_database WHERE datname=current_database())`, int64(binary.BigEndian.Uint32(key[:4])), int64(binary.BigEndian.Uint32(key[4:8]))).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().ExecContext(ctx, `SELECT pg_terminate_backend(?)`, pid); err != nil {
		t.Fatal(err)
	}
	select {
	case <-owned.Done():
	case <-ctx.Done():
		t.Fatal("lost connection did not cancel work")
	}
	stop()
	<-done
}
