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

func TestNativeUTF16CleanupIsAuthorizedAuditedAndSizeStable(t *testing.T) {
	for _, encoding := range []string{"UTF-16le", "UTF-16be"} {
		t.Run(encoding, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "db.sqlite")
			seed, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = seed.Exec(`PRAGMA encoding='` + encoding + `'; CREATE TABLE fixture_encoding(data TEXT)`); err != nil {
				t.Fatal(err)
			}
			var actual string
			if err = seed.QueryRow(`PRAGMA encoding`).Scan(&actual); err != nil || actual != encoding {
				t.Fatalf("encoding%s want%s: %v", actual, encoding, err)
			}
			seed.Close()
			p := newPairClientIn(t, strings.Repeat("p", 32), root)
			admin := p.addAdmin(t, "audit-admin")
			cid, oid, id, link := "cnt_00000000000000000000000000", "obj_00000000000000000000000000", "cmt_00000000000000000000000000", "shl_00000000000000000000000000"
			if err = dbTx(p.db, func(tx *sql.Tx) error {
				for _, q := range []string{
					`INSERT INTO containers(id,kind,owner_user_id,change_seq,created_at,updated_at) VALUES(?1,'workbook',?2,127,'now','now')`,
					`INSERT INTO memberships(container_id,user_id,role,created_at) VALUES(?1,?2,'owner','now')`,
					`INSERT INTO objects(id,container_id,kind,change_seq,created_at,updated_at) VALUES(?3,?1,'note',1,'now','now')`,
					`INSERT INTO comments(id,container_id,object_id,author_user_id,body_ciphertext,key_generation,change_seq,created_at) VALUES(?4,?1,?3,?2,X'63',1,1,'now')`,
					`INSERT INTO sealed_share_links(id,token_hash,ciphertext,expires_at,created_at,owner_user_id) VALUES(?5,'token',X'63','2099-01-01T00:00:00Z','now',?2)`,
				} {
					if _, err := tx.Exec(q, cid, pairUser, oid, id, link); err != nil {
						return err
					}
				}
				if err := storage.ReserveCleanupAuditTx(tx, "comment", id, cid); err != nil {
					return err
				}
				return storage.ReserveCleanupAuditTx(tx, "sealed_share_link", link, "")
			}); err != nil {
				t.Fatal(err)
			}
			if err = storage.VerifyCleanupReservations(p.db); err != nil {
				t.Fatal(err)
			}
			snap := func(tag string) int64 {
				f := filepath.Join(t.TempDir(), tag)
				if err := recoveryclient.SQLiteSnapshot(context.Background(), p.db, f); err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(f)
				if err != nil {
					t.Fatal(err)
				}
				return info.Size()
			}
			before, err := storage.DatabaseBytes(p.db)
			if err != nil {
				t.Fatal(err)
			}
			compactBefore := snap("before")
			for _, path := range []string{"/api/v1/comments/" + id, "/api/v1/share-links/" + link} {
				if code, out := status(t, p.do(t, http.MethodDelete, path, nil, true, false)); code != 204 {
					t.Fatalf("DELETE%s=%d %s", path, code, out)
				}
			}
			after, err := storage.DatabaseBytes(p.db)
			if err != nil {
				t.Fatal(err)
			}
			compactAfter := snap("after")
			if after > before || compactAfter > compactBefore {
				t.Fatalf("cleanup grew allocated%d->%d, compact%d->%d", before, after, compactBefore, compactAfter)
			}
			if err = storage.VerifyCleanupReservations(p.db); err != nil {
				t.Fatal(err)
			}
			code, out := status(t, admin.do(t, http.MethodGet, "/api/v1/admin/audit", nil, false, false))
			if code != 200 || !strings.Contains(out, "comment.delete") || !strings.Contains(out, "share_link.revoke") {
				t.Fatalf("audit read%d %s", code, out)
			}
		})
	}
}
