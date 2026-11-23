package app

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/suitedir"
	"github.com/Busnes-app/kynotes-server/internal/health"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/orgsync"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"github.com/Busnes-app/kynotes-server/internal/webpush"
)

func scheduleReplicas(t *testing.T) (*sql.DB, *sql.DB) {
	t.Helper()
	if !storage.OnPostgresTest() {
		t.Skip("needs KYNOTES_TEST_DATABASE_URL")
	}
	st, err := storage.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	var schema string
	if err := st.DB().QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	dsn, err := url.Parse(os.Getenv("KYNOTES_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	q := dsn.Query()
	q.Set("search_path", schema)
	dsn.RawQuery = q.Encode()
	second, err := sql.Open("kynotespg", dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { second.Close() })
	for _, q := range []string{`UPDATE orgs SET status='stale'`, `UPDATE server_settings SET value='multi' WHERE key='tenancy_mode'`, `INSERT INTO server_settings(key,value,updated_at) VALUES('staff_org_id','org_staff','t'),('region','local','t')`, `INSERT INTO orgs(id,status,home_region) VALUES('org_staff','active','local')`} {
		if _, err := st.DB().Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	return st.DB(), second
}
func testSchedules(t *testing.T, db *sql.DB, polls, gcs, backups, erasures *atomic.Int32) replicaSchedules {
	t.Helper()
	key, err := webpush.LoadKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	push, err := webpush.New(key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		erasures.Add(1)
		_, _ = w.Write([]byte(`{"subjects":[]}`))
	}))
	t.Cleanup(srv.Close)
	return replicaSchedules{db: db, directory: suitedir.Client{Issuer: srv.URL, HTTP: srv.Client()}, orgs: orgsync.New(db, func(context.Context, int64) ([]suitedir.Org, int64, error) { polls.Add(1); return nil, 0, nil }), reports: &orgsync.Reporter{DB: db}, push: push, gcInterval: time.Hour, gc: func(context.Context, time.Time) error { gcs.Add(1); return nil }, backup: func(context.Context, time.Time) error {
		backups.Add(1)
		return errors.New("test destination unavailable")
	}, log: logging.New(io.Discard, "info", "json")}
}
func TestReplicaScheduleCadenceCountsFailedAttempts(t *testing.T) {
	a, _ := scheduleReplicas(t)
	var polls, gcs, backups, erasures atomic.Int32
	s := testSchedules(t, a, &polls, &gcs, &backups, &erasures)
	now := time.Unix(1_800_000_000, 0)
	s.tick(context.Background(), now)
	s.tick(context.Background(), now.Add(59*time.Second))
	if polls.Load() != 1 || gcs.Load() != 1 || backups.Load() != 1 || erasures.Load() != 1 {
		t.Fatalf("failed attempt retried early: polls=%d gc=%d backups=%d", polls.Load(), gcs.Load(), backups.Load())
	}
	s.tick(context.Background(), now.Add(time.Minute))
	if polls.Load() != 2 || gcs.Load() != 1 || backups.Load() != 2 || erasures.Load() != 2 {
		t.Fatal("minute schedule did not retry once")
	}
	s.tick(context.Background(), now.Add(time.Hour))
	if gcs.Load() != 2 {
		t.Fatal("GC interval ignored")
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	s.tick(cancelled, now.Add(2*time.Hour))
	if polls.Load() != 3 || gcs.Load() != 2 || backups.Load() != 3 || erasures.Load() != 3 {
		t.Fatal("cancelled owner ran a scheduled job")
	}
}
func TestReplicaSchedulesHaveOneOwnerAndResumeOnStandby(t *testing.T) {
	a, b := scheduleReplicas(t)
	var polls, gcs, backups, erasures atomic.Int32
	first, second := testSchedules(t, a, &polls, &gcs, &backups, &erasures), testSchedules(t, b, &polls, &gcs, &backups, &erasures)
	ctx, stop := context.WithTimeout(context.Background(), 12*time.Second)
	defer stop()
	owner, cancelOwner := context.WithCancel(ctx)
	ownerDone, standbyDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(ownerDone); runReplicaSchedules(owner, first) }()
	waitCount := func(n int32) {
		t.Helper()
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		for gcs.Load() < n {
			select {
			case <-ctx.Done():
				t.Fatal("scheduler did not progress")
			case <-tick.C:
			}
		}
	}
	waitCount(1)
	go func() { defer close(standbyDone); runReplicaSchedules(ctx, second) }()
	if l, ok, err := storage.SessionLock(ctx, b, "scheduled-worker", false); err != nil || ok {
		if ok {
			l.Release()
		}
		t.Fatalf("two schedulers owned the lock: %v %v", ok, err)
	}
	if polls.Load() != 1 || backups.Load() != 1 {
		t.Fatal("per-replica schedules ran twice")
	}
	cancelOwner()
	<-ownerDone
	waitCount(2)
	stop()
	<-standbyDone
	if polls.Load() != 2 || backups.Load() != 2 || erasures.Load() != 2 {
		t.Fatalf("takeover schedules: polls=%d backups=%d", polls.Load(), backups.Load())
	}
}
func TestReplicaDrainWithdrawsReadinessBeforeClosingHTTP(t *testing.T) {
	ready := &health.Checker{}
	ready.SetReady(true)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ordinary", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	stopped, workerDone, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	start := time.Now()
	go func() {
		done <- drainReplica(ready, func() { close(stopped); close(workerDone) }, workerDone, srv.Config)
	}()
	<-stopped
	if ready.IsReady() {
		t.Fatal("draining replica still ready")
	}
	res, err := srv.Client().Get(srv.URL + "/ordinary")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 204 {
		t.Fatalf("HTTP stopped before proxy delay: %d", res.StatusCode)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < replicaProxyDrain {
		t.Fatal("proxy convergence delay skipped")
	}
	if _, err := srv.Client().Get(srv.URL + "/ordinary"); err == nil {
		t.Fatal("HTTP still accepting after drain")
	}
}
