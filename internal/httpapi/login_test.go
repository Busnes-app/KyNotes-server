package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/auth"
)

func TestDummyVerifierNeverCachesAFailedMint(t *testing.T) {
	dummyMu.Lock()
	oldHash, oldHashSecret := dummyHash, hashDummySecret
	dummyHash = ""
	calls := 0
	hashDummySecret = func(secret string) (string, error) {
		calls++
		if calls == 1 {
			return "", auth.ErrBusy
		}
		return auth.HashAuthSecret(secret)
	}
	dummyMu.Unlock()
	t.Cleanup(func() {
		dummyMu.Lock()
		dummyHash, hashDummySecret = oldHash, oldHashSecret
		dummyMu.Unlock()
	})

	if got, err := dummyVerifier(); !errors.Is(err, auth.ErrBusy) || got != "" {
		t.Fatalf("first dummy verifier = %q, %v; want empty ErrBusy", got, err)
	}
	got, err := dummyVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "$argon2id$") {
		t.Fatalf("dummy verifier = %q, want argon2id PHC", got)
	}
}

func TestLoginRejectPathIsUniformCost(t *testing.T) {
	db, cfg := setupTestDB(t)
	mux := http.NewServeMux()
	AuthRoutes(mux, db, cfg)
	now := time.Now().UTC().Format(time.RFC3339)
	h, _ := auth.HashAuthSecret(strings.Repeat("a", 64))
	if _, err := db.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,status,created_at,updated_at) VALUES('usr_login_cost','login-cost',?,'salt',600000,'user','active',?,?)`, h, now, now); err != nil {
		t.Fatal(err)
	}
	body := func(username string) string {
		return `{"username":"` + username + `","authSecret":"` + strings.Repeat("b", 64) + `"}`
	}
	measure := func(username string) time.Duration {
		var ds []time.Duration
		for i := 0; i < 3; i++ {
			req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(body(username)))
			req.RemoteAddr = "203.0.113.66:44444"
			start := time.Now()
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s login got %d, want 401", username, rec.Code)
			}
			ds = append(ds, time.Since(start))
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		return ds[len(ds)/2]
	}
	known := measure("login-cost")
	unknown := measure("missing-login-cost")
	if unknown < known/2 {
		t.Fatalf("unknown user reject too cheap: unknown=%s known=%s", unknown, known)
	}
}
