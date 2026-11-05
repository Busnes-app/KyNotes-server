package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

func TestCapsulePreservesCleanupHistoryAndPendingReservations(t *testing.T) {
	svc, key := fixture(t)
	if err := svc.store.WithTx(context.Background(), func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,created_at,updated_at) VALUES('person','person','opaque','opaque',100000,'now','now'); INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at) VALUES('notebook','workbook','person','now','now'); INSERT INTO objects(id,container_id,kind,change_seq,created_at,updated_at) VALUES('page','notebook','note',1,'now','now')`); err != nil {
			return err
		}
		for _, id := range []string{"removed", "pending"} {
			if _, err := tx.Exec(`INSERT INTO comments(id,container_id,object_id,author_user_id,body_ciphertext,key_generation,change_seq,created_at) VALUES(?,'notebook','page','person',X'6374',1,1,'now')`, id); err != nil {
				return err
			}
			if err := storage.ReserveCleanupAuditTx(tx, "comment", id, "notebook"); err != nil {
				return err
			}
		}
		if err := storage.TombstoneCommentTx(tx, "removed", "2026-11-05T00:00:00Z", 2); err != nil {
			return err
		}
		return storage.FillCleanupAuditTx(tx, "comment", "removed", "person", "request", "2026-11-05T00:00:00Z")
	}); err != nil {
		t.Fatal(err)
	}
	result, err := svc.Run(context.Background(), "system", "test")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(result.LocalPath)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "opened")
	manifest, _, err := capsule.Open(raw, key, dir)
	if err != nil {
		t.Fatal(err)
	}
	assertChecks := func(m capsule.Manifest, want bool) {
		t.Helper()
		passed := true
		checks := Checks(dir, m)
		for _, c := range checks {
			passed = passed && c.Passed
		}
		if passed != want {
			t.Fatalf("checks passed=%t want%t: %+v", passed, want, checks)
		}
	}
	assertChecks(manifest, true)
	encoded, _ := json.Marshal(manifest.VerificationRecipe)
	var recipe Recipe
	if err = json.Unmarshal(encoded, &recipe); err != nil {
		t.Fatal(err)
	}
	if recipe.Counts["cleanup_audit_slots"] != 2 {
		t.Fatalf("missing slots from recipe: %v", recipe.Counts)
	}
	delete(recipe.Counts, "cleanup_audit_slots")
	encoded, _ = json.Marshal(recipe)
	bad := manifest
	bad.VerificationRecipe = nil
	if err = json.Unmarshal(encoded, &bad.VerificationRecipe); err != nil {
		t.Fatal(err)
	}
	assertChecks(bad, false)
	snap, err := storage.OpenCurrent(filepath.Join(dir, "kynotes.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	var count int
	if err = snap.DB().QueryRow(`SELECT count(*) FROM audit_history WHERE event='comment.delete' AND object_id='removed'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("cleanup history %d %v", count, err)
	}
	if _, err = snap.DB().Exec(`DELETE FROM cleanup_audit_slots WHERE source_id='pending'`); err != nil {
		t.Fatal(err)
	}
	assertChecks(manifest, false)
}
