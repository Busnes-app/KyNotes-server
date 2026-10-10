package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestAdminTeamCreationTakesNoNameAndCreatesOwner(t *testing.T) {
	f := newShareFixture(t)
	if _, err := f.db.Exec(`UPDATE users SET role='admin' WHERE id='usr_share'`); err != nil {
		t.Fatal(err)
	}
	ciphertext := base64.StdEncoding.EncodeToString([]byte("encrypted-team-name"))
	req, _ := http.NewRequest(http.MethodPost, f.server.URL+"/api/v1/admin/teams", strings.NewReader(`{"metaCiphertext":"`+ciphertext+`"}`))
	f.csrf(req)
	res, err := f.client.Do(req)
	if err != nil || res.StatusCode != http.StatusBadRequest {
		t.Fatalf("create named team err=%v status=%d", err, res.StatusCode)
	}
	res.Body.Close()
	req, _ = http.NewRequest(http.MethodPost, f.server.URL+"/api/v1/admin/teams", strings.NewReader(`{}`))
	f.csrf(req)
	res, err = f.client.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("create team err=%v status=%d", err, res.StatusCode)
	}
	var team struct {
		ID    string `json:"id"`
		Kind  string `json:"kind"`
		Owner string `json:"ownerUserId"`
	}
	_ = json.NewDecoder(res.Body).Decode(&team)
	res.Body.Close()
	if team.ID == "" || team.Kind != "team" || team.Owner != "usr_share" {
		t.Fatalf("unexpected team response: %+v", team)
	}
	var stored []byte
	if err := f.db.QueryRow(`SELECT meta_ciphertext FROM containers WHERE id=?`, team.ID).Scan(&stored); err != nil || len(stored) != 0 {
		t.Fatalf("stored team metadata must be empty: %q err=%v", stored, err)
	}
	var role string
	if err := f.db.QueryRow(`SELECT role FROM memberships WHERE container_id=? AND user_id=?`, team.ID, "usr_share").Scan(&role); err != nil || role != "owner" {
		t.Fatalf("owner membership role=%q err=%v", role, err)
	}
	var count int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='admin.team.create' AND container_id=?`, team.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("team audit count=%d err=%v", count, err)
	}
}
