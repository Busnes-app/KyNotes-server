package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/storage"
)

// erase runs a member's Delete everything as the user.erased event and then the worker do.
func erase(t *testing.T, db *sql.DB, user string) {
	t.Helper()
	if err := dbTx(db, func(tx *sql.Tx) error { return eraseMemberTx(tx, user) }); err != nil {
		t.Fatal(err)
	}
	if err := storage.EraseMembers(context.Background(), db); err != nil {
		t.Fatal(err)
	}
}

// An erased owner's team notebook passes to its longest-standing approved admin, and the rest
// of the team still reads every page; the notebook the owner alone held is deleted, an
// invitation it sent no longer opens, and the account is scrubbed (spec, A member erases).
func TestEraseKeepsSharedNotebookAndDeletesSoleOnes(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	page, code := tm.owner.save(t, tm.id, "", 2)
	if code != http.StatusOK {
		t.Fatalf("save=%d", code)
	}
	comment, code := tm.owner.comment(t, page, 2)
	if code != http.StatusOK {
		t.Fatalf("comment=%d", code)
	}
	secondComment, code := tm.owner.comment(t, page, 2)
	if code != http.StatusOK {
		t.Fatalf("second comment=%d", code)
	}
	sole := seedContainer(t, tm.owner, "workbook", "", map[string]string{pairUser: "owner"})
	outsider := tm.owner.addUser(t, "outsider")
	_, body := status(t, tm.owner.do(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/invitations", []byte(`{"inviteeID":`+quote(outsider.id)+`,"role":"viewer"}`), true, false))
	var inv struct{ ID, Token string }
	if err := json.Unmarshal([]byte(body), &inv); err != nil || inv.ID == "" {
		t.Fatalf("invite: %s", body)
	}
	var cursor int64 // the rest of the team has synced everything so far
	if err := tm.owner.db.QueryRow(`SELECT change_seq FROM containers WHERE id=?`, tm.id).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	toMultiMode(t, tm.owner.db, "org_staff")
	erase(t, tm.owner.db, pairUser)

	var owner string
	if err := tm.owner.db.QueryRow(`SELECT owner_user_id FROM containers WHERE id=?`, tm.id).Scan(&owner); err != nil || owner != tm.admin.id {
		t.Fatalf("the team passed to %q, want the admin %q (%v)", owner, tm.admin.id, err)
	}
	for name, m := range map[string]member{"admin": tm.admin, "editor": tm.editor} {
		if code, out := status(t, m.do(t, http.MethodGet, "/api/v1/objects/"+page, nil, false, false)); code != http.StatusOK {
			t.Fatalf("%s reading the kept page: %d %s", name, code, out)
		}
	}
	if code, _ := status(t, outsider.do(t, http.MethodPost, "/api/v1/invitations/"+inv.ID+"/accept", []byte(`{"token":`+quote(inv.Token)+`}`), true, false)); code != http.StatusNotFound {
		t.Fatalf("the erased member's invitation: %d, want 404", code)
	}
	var soles int
	if err := tm.owner.db.QueryRow(`SELECT count(*) FROM containers WHERE id=?`, sole).Scan(&soles); err != nil || soles != 0 {
		t.Fatalf("after the erase: %d sole notebooks (%v)", soles, err)
	}
	// Owner decision 12: its comment in the kept notebook is a tombstone, and its account row is
	// kept with nothing but its random ID.
	var deleted string
	var ciphertext []byte
	if err := tm.owner.db.QueryRow(`SELECT deleted_at,body_ciphertext FROM comments WHERE id=?`, comment).Scan(&deleted, &ciphertext); err != nil || deleted == "" || len(ciphertext) != 0 {
		t.Fatalf("the erased member's comment: deleted_at=%q body=%d bytes (%v)", deleted, len(ciphertext), err)
	}
	// Page one change at a time: tombstones must have separate fresh sequences or a cursor
	// would skip the second deletion, even if a full sync happened to return both.
	seen := map[string]bool{}
	for {
		code, out := status(t, tm.admin.do(t, http.MethodGet, "/api/v1/containers/"+tm.id+"/changes?since="+fmt.Sprint(cursor)+"&limit=1", nil, false, false))
		if code != http.StatusOK {
			t.Fatalf("sync after erasure: %d %s", code, out)
		}
		var changes struct {
			Changes []struct {
				ID      string
				Deleted bool
			}
			NextCursor string
			HasMore    bool
		}
		if err := json.Unmarshal([]byte(out), &changes); err != nil {
			t.Fatalf("changes: %s", out)
		}
		for _, c := range changes.Changes {
			seen[c.ID] = c.Deleted
		}
		if !changes.HasMore {
			break
		}
		var next int64
		if _, err := fmt.Sscan(changes.NextCursor, &next); err != nil || next <= cursor {
			t.Fatalf("sync did not advance: %s", out)
		}
		cursor = next
	}
	if !seen[comment] || !seen[secondComment] {
		t.Fatalf("incremental sync missed comment tombstones: %v", seen)
	}
	var username, secret, salt string
	if err := tm.owner.db.QueryRow(`SELECT username,auth_secret_hash,login_salt FROM users WHERE id=?`, pairUser).Scan(&username, &secret, &salt); err != nil || username != pairUser || secret != "" || salt != "" {
		t.Fatalf("the erased account was not scrubbed: %q %q %q (%v)", username, secret, salt, err)
	}
}

// A notebook whose only other approved member is a viewer passes to that viewer; one whose only
// other member is unapproved is the erased member's alone, and is deleted.
func TestEraseSuccessorIsAnyApprovedMember(t *testing.T) {
	p := newPairClient(t, "pppppppppppppppppppppppppppppppp")
	viewer, waiting := p.addUser(t, "viewer"), p.addUser(t, "waiting")
	toViewer := seedContainer(t, p, "team", "", map[string]string{pairUser: "owner", viewer.id: "viewer"})
	unapproved := seedContainer(t, p, "team", "", map[string]string{pairUser: "owner"})
	if _, err := p.db.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at,approved,pending_role) VALUES(?,?,?,'viewer','now',0,'editor')`, mint(t, "mem"), unapproved, waiting.id); err != nil {
		t.Fatal(err)
	}
	toMultiMode(t, p.db, "org_staff")
	erase(t, p.db, pairUser)
	var owner string
	if err := p.db.QueryRow(`SELECT owner_user_id FROM containers WHERE id=?`, toViewer).Scan(&owner); err != nil || owner != viewer.id {
		t.Fatalf("passed to %q, want the viewer (%v)", owner, err)
	}
	var n int
	if err := p.db.QueryRow(`SELECT count(*) FROM containers WHERE id=?`, unapproved).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a notebook with only an unapproved member survived: %d %v", n, err)
	}
}
