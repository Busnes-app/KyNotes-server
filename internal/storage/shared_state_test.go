package storage

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Two pools, one schema: no in-process object is shared by the replica clients.
func sharedReplicas(t *testing.T) (*sql.DB, *sql.DB) {
	t.Helper()
	s := requirePostgres(t)
	var schema string
	if err := s.DB().QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	other, err := openPostgres(os.Getenv("KYNOTES_TEST_DATABASE_URL"), schema, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { other.Close() })
	for _, q := range []string{`UPDATE server_settings SET value='multi' WHERE key='tenancy_mode'`, `INSERT INTO server_settings(key,value,updated_at) VALUES('region','local','t'),('staff_org_id','org_staff','t')`} {
		if _, err := s.DB().Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	return s.DB(), other.DB()
}

func TestReplicaSecurityStateIsSharedAndAtomic(t *testing.T) {
	a, b := sharedReplicas(t)
	ctx := context.Background()
	var spent atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(db *sql.DB) {
			defer wg.Done()
			ok, err := AllowRate(ctx, db, "login", "ip\x00secret", 3, 1.0/3600)
			if err != nil {
				t.Error(err)
			}
			if ok {
				spent.Add(1)
			}
		}([]*sql.DB{a, b}[i%2])
	}
	wg.Wait()
	if spent.Load() != 3 {
		t.Fatalf("shared burst spent %d times", spent.Load())
	}
	if ok, err := AllowRate(ctx, b, "challenge", "ip\x00secret", 1, 1); !ok || err != nil {
		t.Fatalf("namespaces interfere: %v %v", ok, err)
	}
	var raw string
	if err := a.QueryRow(`SELECT key_hash FROM replica_rates WHERE key_hash=?`, StateHash("login\x00ip\x00secret")).Scan(&raw); err != nil || len(raw) != 64 {
		t.Fatalf("keys not hashed: %q %v", raw, err)
	}
	spent.Store(0)
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(db *sql.DB) {
			defer wg.Done()
			_, ok, err := ReserveLockout(ctx, db, "login", "user\x00ip", 3, 50000, time.Minute)
			if err != nil {
				t.Error(err)
			}
			if ok {
				spent.Add(1)
			}
		}([]*sql.DB{a, b}[i%2])
	}
	wg.Wait()
	if spent.Load() != 3 {
		t.Fatalf("concurrent guesses outran lockout: %d", spent.Load())
	}
	// A slow successful/refunded attempt cannot clear a newer lockout generation.
	var old string
	if err := a.QueryRow(`SELECT generation FROM replica_lockouts`).Scan(&old); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Exec(`UPDATE replica_lockouts SET locked_until=1`); err != nil {
		t.Fatal(err)
	}
	fresh, ok, err := ReserveLockout(ctx, b, "login", "user\x00ip", 3, 50000, time.Minute)
	if err != nil || !ok || fresh == old {
		t.Fatalf("new generation: %q %v %v", fresh, ok, err)
	}
	for _, success := range []bool{false, true} {
		if err := ReleaseLockout(ctx, a, "login", "user\x00ip", old, 3, success); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := a.QueryRow(`SELECT failures FROM replica_lockouts WHERE generation=?`, fresh).Scan(&n); err != nil || n != 1 {
		t.Fatalf("old release changed fresh window: %d %v", n, err)
	}
	if err := ReleaseLockout(ctx, a, "login", "user\x00ip", fresh, 3, false); err != nil {
		t.Fatal(err)
	}
	if err := a.QueryRow(`SELECT count(*) FROM replica_lockouts`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("refund: %d %v", n, err)
	}
}

func TestReplicaLoginOneUseExpiryAndFloodEviction(t *testing.T) {
	a, b := sharedReplicas(t)
	ctx := context.Background()
	if err := PutLogin(ctx, a, "state", []byte("nonce and verifier"), time.Minute); err != nil {
		t.Fatal(err)
	}
	var taken atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(db *sql.DB) {
			defer wg.Done()
			raw, ok, err := TakeLogin(ctx, db, "state")
			if err != nil {
				t.Error(err)
			}
			if ok {
				taken.Add(1)
				if string(raw) != "nonce and verifier" {
					t.Errorf("bad payload %q", raw)
				}
			}
		}([]*sql.DB{a, b}[i%2])
	}
	wg.Wait()
	if taken.Load() != 1 {
		t.Fatalf("PKCE state consumed %d times", taken.Load())
	}
	if err := PutLogin(ctx, a, "expired", []byte("no"), -time.Second); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := TakeLogin(ctx, b, "expired"); err != nil || ok {
		t.Fatalf("expired login accepted: %v %v", ok, err)
	}
	if err := PutLogin(ctx, a, "oldest", []byte("old"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Exec(`INSERT INTO replica_logins(state_hash,payload,expires_at) SELECT lpad(n::text,64,'0'),X'00',floor(extract(epoch FROM clock_timestamp()))::bigint+120+n FROM generate_series(1,1023) n`); err != nil {
		t.Fatal(err)
	}
	if err := PutLogin(ctx, b, "fresh", []byte("new"), 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := a.QueryRow(`SELECT count(*) FROM replica_logins`).Scan(&n); err != nil || n != 1024 {
		t.Fatalf("capacity %d %v", n, err)
	}
	if _, ok, err := TakeLogin(ctx, a, "oldest"); err != nil || ok {
		t.Fatalf("oldest retained: %v %v", ok, err)
	}
	if _, ok, err := TakeLogin(ctx, a, "fresh"); err != nil || !ok {
		t.Fatalf("fresh missing: %v %v", ok, err)
	}
}

func TestReplicaCoordinationDoesNotWriteSQLite(t *testing.T) {
	s, err := openSQLite(filepath.Join(t.TempDir(), "sqlite.db"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if shared, err := SharedMode(s.DB()); err != nil || shared {
		t.Fatalf("SQLite selected shared state: %v %v", shared, err)
	}
	var n int
	if err := s.DB().QueryRow(`SELECT count(*) FROM sqlite_master WHERE name LIKE 'replica_%'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("replica tables in SQLite: %d %v", n, err)
	}
}
