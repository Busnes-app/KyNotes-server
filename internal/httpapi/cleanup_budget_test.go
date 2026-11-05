package httpapi

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/logging"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// Real compact snapshots, with live liabilities and repeated cleanup at the full admission
// budget. A private pre-correction probe measured the original audit-growth escape.
func TestCleanupReservationKeepsCompactSnapshotsWithinBudget(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	oid, code := tm.owner.save(t, tm.id, "", 2)
	if code != 200 {
		t.Fatal(code)
	}
	mux := http.NewServeMux()
	CollabRoutes(mux, tm.owner.db, config.Defaults().Limits)
	server := httptest.NewServer(Middleware(logging.New(io.Discard, "info", "json"), 1<<20)(mux))
	defer server.Close()
	caller := *tm.owner
	caller.url = server.URL // Same session, without the unrelated rate bucket.
	budget := func() int64 {
		var bytes int64
		if err := dbTx(tm.owner.db, func(tx *sql.Tx) error { var err error; bytes, err = databaseBudgetBytes(tx); return err }); err != nil {
			t.Fatal(err)
		}
		return bytes
	}
	snap := func(tag string) int64 {
		p := filepath.Join(t.TempDir(), tag+".sqlite")
		if err := recoveryclient.SQLiteSnapshot(context.Background(), tm.owner.db, p); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > databaseWriteBudget || info.Size() > capsule.MaxExpandedBytes {
			t.Fatalf("snapshot%s=%d exceeds budget%d", tag, info.Size(), databaseWriteBudget)
		}
		t.Logf("snapshot%s=%d; accounted=%d", tag, info.Size(), budget())
		return info.Size()
	}
	// Bounded legacy padding puts the real budget near full without millions of requests.
	padding := int64(databaseWriteBudget - (10 << 20))
	if _, err := tm.owner.db.Exec(`INSERT INTO sealed_share_links(id,token_hash,ciphertext,expires_at,created_at,owner_user_id) VALUES('shl_cleanup_padding','cleanup-padding',zeroblob(?),'2099-01-01','now',?)`, padding, pairUser); err != nil {
		t.Fatal(err)
	}
	if err := dbTx(tm.owner.db, func(tx *sql.Tx) error {
		return storage.ReserveCleanupAuditTx(tx, "sealed_share_link", "shl_cleanup_padding", "")
	}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		padding += databaseWriteBudget - (96 << 10) - budget()
		if _, err := tm.owner.db.Exec(`UPDATE sealed_share_links SET ciphertext=zeroblob(?) WHERE id='shl_cleanup_padding'`, padding); err != nil {
			t.Fatal(err)
		}
	}
	snap("before-admission")
	var all []string
	admitUntilFull := func(bodySize int) {
		admitted := 0
		for range 150 {
			code, out := status(t, caller.do(t, http.MethodPost, "/api/v1/objects/"+oid+"/comments", []byte(`{"bodyCiphertext":"`+base64.StdEncoding.EncodeToString(make([]byte, bodySize))+`","keyGeneration":2}`), true, false))
			if code == 507 {
				t.Logf("admitted%d minimal comments; stopped at accounted%d", admitted, budget())
				if admitted == 0 {
					t.Fatal("no cleanup capacity was reusable")
				}
				return
			}
			if code != 200 {
				t.Fatalf("admit=%d %s", code, out)
			}
			var row struct{ ID string }
			if err := json.Unmarshal([]byte(out), &row); err != nil {
				t.Fatal(err)
			}
			all = append(all, row.ID)
			admitted++
		}
		t.Fatal("did not stop admitting at full budget")
	}
	for round := 0; round < 2; round++ {
		if round == 0 {
			admitUntilFull(MaxCommentBytes)
		} else {
			admitUntilFull(0)
		}
		before := snap("full")
		reserved := budget() - before
		// All deletions succeed even though an ordinary creation was refused. Retrying releases
		// nothing twice, and audit growth cannot spend more than the outstanding liabilities.
		for _, id := range all {
			for range 2 {
				if code, out := status(t, caller.do(t, http.MethodDelete, "/api/v1/comments/"+id, nil, true, false)); code != 204 {
					t.Fatalf("cleanup=%d %s", code, out)
				}
			}
		}
		after := snap("cleaned")
		if after-before > reserved {
			t.Fatalf("cleanup growth%d exceeds reserved%d", after-before, reserved)
		}
		all = nil
	}
}
