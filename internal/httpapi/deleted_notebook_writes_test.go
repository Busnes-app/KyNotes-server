package httpapi

import (
	"crypto/rand"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDeletedNotebookRefusesContentKeysAndInvitations(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	outsider := tm.owner.addUser(t, "deleted-invitee")
	oid, code := tm.owner.save(t, tm.id, "", 2)
	if code != 200 {
		t.Fatal(code)
	}
	if code, out := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id, nil, true, false)); code != 204 {
		t.Fatalf("delete=%d %s", code, out)
	}
	for _, c := range []struct {
		name, method, path string
		body               []byte
	}{
		{"page", http.MethodPost, "/api/v1/containers/" + tm.id + "/objects", []byte(`{"kind":"note"}`)},
		{"comment", http.MethodPost, "/api/v1/objects/" + oid + "/comments", []byte(`{"bodyCiphertext":"Y3Q=","keyGeneration":2}`)},
		{"name", http.MethodPatch, "/api/v1/containers/" + tm.id, []byte(`{"metaCiphertext":"Y3Q=","baseVersion":0,"keyGeneration":2}`)},
		{"rotation", http.MethodPost, "/api/v1/containers/" + tm.id + "/key-rotations", rotationBody(2, envJSON(tm.ownerID, 3, 1))},
		{"envelope", http.MethodPut, "/api/v1/containers/" + tm.id + "/envelopes", envelopesBody(envJSON(tm.ownerID, 2, 1))},
		{"invitation", http.MethodPost, "/api/v1/containers/" + tm.id + "/invitations", []byte(`{"inviteeID":"` + outsider.id + `","role":"viewer"}`)},
		{"child invitation", http.MethodPost, "/api/v1/containers/" + tm.child + "/invitations", []byte(`{"inviteeID":"` + outsider.id + `","role":"viewer"}`)},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, out := status(t, tm.owner.do(t, c.method, c.path, c.body, true, false))
			if code != 404 {
				t.Fatalf("deleted notebook write=%d %s", code, out)
			}
		})
	}
	if _, code := tm.owner.save(t, tm.id, oid, 2); code != 404 {
		t.Fatalf("existing-page PUT=%d", code)
	}
	var stored int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM invitations WHERE container_id IN (?,?)`, tm.id, tm.child).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("invitations=%d %v", stored, err)
	}
}

func TestInvitationRacingNotebookDeletionIsRefused(t *testing.T) {
	tm := newTeam(t)
	outsider := tm.owner.addUser(t, "racing-invitee")
	code, out := tm.owner.sendRacing(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/invitations", map[string]string{"Content-Type": "application/json"}, []byte(`{"inviteeID":"`+outsider.id+`","role":"viewer"}`), func() {
		if code, out := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id, nil, true, false)); code != 204 {
			t.Fatalf("delete=%d %s", code, out)
		}
	})
	if code != 404 || !strings.Contains(out, "not_found") {
		t.Fatalf("late invitation=%d %s", code, out)
	}
}

func TestNewPageRacingNotebookDeletionIsRefused(t *testing.T) {
	tm := newTeam(t)
	code, out := tm.owner.sendRacing(t, http.MethodPost, "/api/v1/containers/"+tm.id+"/objects", map[string]string{"Content-Type": "application/json"}, []byte(`{"kind":"note"}`), func() {
		if code, out := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id, nil, true, false)); code != 204 {
			t.Fatalf("delete=%d %s", code, out)
		}
	})
	if code != 404 || !strings.Contains(out, "not_found") {
		t.Fatalf("late page=%d %s", code, out)
	}
	var objects int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM objects WHERE container_id=?`, tm.id).Scan(&objects); err != nil || objects != 0 {
		t.Fatalf("objects=%d %v", objects, err)
	}
}

// No parallel tests: the reader pauses only the second 16-byte read, the child ID
// minted after the real router's request ID and successful parent precheck.
// Subsequent reads (including the actual DELETE's request/audit IDs) keep working.
type childMintPause struct {
	io.Reader
	reads           atomic.Int32
	reached, resume chan struct{}
}

func (p *childMintPause) Read(b []byte) (int, error) {
	if len(b) == 16 && p.reads.Add(1) == 2 {
		close(p.reached)
		<-p.resume
	}
	return p.Reader.Read(b)
}

func TestChildCreationRacingParentDeletionIsRefused(t *testing.T) {
	tm := newTeam(t)
	original := rand.Reader
	pause := &childMintPause{Reader: original, reached: make(chan struct{}), resume: make(chan struct{})}
	rand.Reader = pause
	var release sync.Once
	done := make(chan struct{})
	var code int
	var err error
	defer func() {
		release.Do(func() { close(pause.resume) })
		<-done
		rand.Reader = original
	}()
	go func() {
		defer close(done)
		code, err = tm.admin.send(http.MethodPost, "/api/v1/containers", []byte(`{"kind":"workbook","teamId":"`+tm.id+`"}`))
	}()
	select {
	case <-pause.reached:
	case <-done:
		t.Fatalf("child returned before pause: %d %v", code, err)
	case <-time.After(30 * time.Second):
		t.Fatal("child did not reach the ID mint after parent precheck")
	}
	if code, out := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id, nil, true, false)); code != 204 {
		t.Fatalf("parent delete=%d %s", code, out)
	}
	release.Do(func() { close(pause.resume) })
	<-done
	if err != nil || code != 404 {
		t.Errorf("late child creation=%d %v, want 404", code, err)
	}
	var live int
	if err := tm.owner.db.QueryRow(`SELECT COUNT(*) FROM containers WHERE team_id=? AND deleted_at=''`, tm.id).Scan(&live); err != nil || live != 0 {
		t.Fatalf("live children after parent deletion=%d %v", live, err)
	}
}

func TestHistoricalOrphanRefusesObjectsAndInvitations(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	outsider := p.addUser(t, "orphan-invitee")
	for _, parentState := range []string{"deleted", "missing"} {
		t.Run(parentState, func(t *testing.T) {
			parent := mint(t, "cnt")
			if parentState == "deleted" {
				parent = seedContainer(t, p, "team", "", map[string]string{pairUser: "owner"})
				if code, out := status(t, p.do(t, http.MethodDelete, "/api/v1/containers/"+parent, nil, true, false)); code != 204 {
					t.Fatalf("parent delete=%d %s", code, out)
				}
			}
			// Represent a child left by the historical precheck/insert race.
			child := seedContainer(t, p, "workbook", parent, map[string]string{pairUser: "owner"})
			for _, kind := range []string{"note", "folder"} {
				if code, out := status(t, p.do(t, http.MethodPost, "/api/v1/containers/"+child+"/objects", []byte(`{"kind":"`+kind+`"}`), true, false)); code != 404 {
					t.Errorf("orphan %s=%d %s", kind, code, out)
				}
			}
			if code, out := status(t, p.do(t, http.MethodPost, "/api/v1/containers/"+child+"/invitations", []byte(`{"inviteeID":"`+outsider.id+`","role":"viewer"}`), true, false)); code != 404 {
				t.Errorf("orphan invitation=%d %s", code, out)
			}
			var stored int
			if err := p.db.QueryRow(`SELECT (SELECT COUNT(*) FROM objects WHERE container_id=?)+(SELECT COUNT(*) FROM invitations WHERE container_id=?)`, child, child).Scan(&stored); err != nil || stored != 0 {
				t.Errorf("orphan mutations=%d %v", stored, err)
			}
		})
	}
}
