package httpapi

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommentDeletionDoesNotGrowAtSQLiteOverflowCliff(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	db := p.db
	var err error
	uid := pairUser
	oid := "obj_00000000000000000000000000"
	id := "cmt_00000000000000000000000000"
	cid := strings.Repeat("c", 3800)
	for _, c := range []string{cid, "cnt_00000000000000000000000000"} {
		if _, err = db.Exec(`INSERT INTO containers(id,kind,owner_user_id,change_seq,created_at,updated_at) VALUES(?,'workbook',?,1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`, c, uid); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec(`INSERT INTO objects(id,container_id,kind,change_seq,created_at,updated_at) VALUES(?,?,'note',1,'now','now')`, oid, cid); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO comments(id,container_id,object_id,author_user_id,body_ciphertext,key_generation,change_seq,created_at) VALUES(?,?,?,?,X'63',2,1,'2026-01-01T00:00:00Z')`, id, cid, oid, uid); err != nil {
		t.Fatal(err)
	}
	var payload int
	if err = db.QueryRow(`SELECT max(mx_payload) FROM dbstat WHERE name='comments' AND pagetype='leaf'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	cid = strings.Repeat("c", 3800+4062-payload)
	if _, err = db.Exec(`INSERT INTO containers(id,kind,owner_user_id,change_seq,created_at,updated_at) VALUES(?,'workbook',?,1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`, cid, uid); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE objects SET container_id=? WHERE id=?`, cid, oid); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE comments SET container_id=? WHERE id=?`, cid, id); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 8; i++ {
		if _, err = db.Exec(`INSERT INTO comments(id,container_id,object_id,author_user_id,body_ciphertext,key_generation,change_seq,created_at) VALUES(?,'cnt_00000000000000000000000000',?,?,X'63',2,1,'2026-01-01T00:00:00Z')`, fmt.Sprintf("cmt_%026d", i), oid, uid); err != nil {
			t.Fatal(err)
		}
	}
	if err = dbTx(db, func(tx *sql.Tx) error {
		for i := 0; i <= 8; i++ {
			c := "cnt_00000000000000000000000000"
			if i == 0 {
				c = cid
			}
			if err := storage.ReserveCleanupAuditTx(tx, "comment", fmt.Sprintf("cmt_%026d", i), c); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	snap := func(tag string) int64 {
		p := filepath.Join(t.TempDir(), tag)
		if err := recoveryclient.SQLiteSnapshot(context.Background(), db, p); err != nil {
			t.Fatal(err)
		}
		i, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		return i.Size()
	}
	if _, err = db.Exec(`INSERT INTO memberships(container_id,user_id,role,created_at) VALUES(?,?,'owner','now')`, cid, uid); err != nil {
		t.Fatal(err)
	}
	before := snap("before")
	physicalBefore, _ := storage.DatabaseBytes(db)
	if code, out := status(t, p.do(t, http.MethodDelete, "/api/v1/comments/"+id, nil, true, false)); code != 204 {
		t.Fatalf("authenticated DELETE=%d %s", code, out)
	}
	after := snap("after")
	physicalAfter, _ := storage.DatabaseBytes(db)
	t.Logf("authenticated DELETE204: CIDbytes%d; compact%d->%d (%+d); physical%d->%d (%+d)", len(cid), before, after, after-before, physicalBefore, physicalAfter, physicalAfter-physicalBefore)
	if after > before || physicalAfter > physicalBefore {
		t.Fatal("authenticated cleanup increased compact/allocated bytes despite prepaid slot")
	}
}
