package httpapi

import (
	"net/http"
	"strings"
	"testing"
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
