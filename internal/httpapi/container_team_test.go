package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestTeamCanCreateMultipleChildWorkspaces(t *testing.T) {
	f := newShareFixture(t)
	if _, err := f.db.Exec(`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at) VALUES('cnt_team','team','usr_share','now','now')`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES('mem_team','cnt_team','usr_share','owner','now')`); err != nil {
		t.Fatal(err)
	}
	create := func() string {
		req, _ := http.NewRequest(http.MethodPost, f.server.URL+"/api/v1/containers", strings.NewReader(`{"kind":"workbook","metaCiphertext":"","teamId":"cnt_team"}`))
		f.csrf(req)
		res, err := f.client.Do(req)
		if err != nil || res.StatusCode != http.StatusOK {
			t.Fatalf("create workspace err=%v status=%d", err, res.StatusCode)
		}
		defer res.Body.Close()
		var result struct{ ID, TeamID string }
		if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		if result.TeamID != "cnt_team" {
			t.Fatalf("team id=%q", result.TeamID)
		}
		return result.ID
	}
	first, second := create(), create()
	if first == second {
		t.Fatal("team workspace IDs are not unique")
	}
	var count int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM containers WHERE team_id='cnt_team' AND deleted_at=''`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("child workspace count=%d err=%v", count, err)
	}
	var membershipCount int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM memberships WHERE container_id IN (?,?) AND user_id='usr_share' AND revoked_at=''`, first, second).Scan(&membershipCount); err != nil || membershipCount != 2 {
		t.Fatalf("child membership count=%d err=%v", membershipCount, err)
	}
}

// A row the list cannot read fails the request: a 200 is always the complete list, which the
// browser relies on before it offers to discard edits for notebooks missing from it.
func TestContainerListFailsRatherThanReturningPartialList(t *testing.T) {
	f := newShareFixture(t)
	if _, err := f.db.Exec(`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at,key_generation) VALUES('cnt_bad','workbook','usr_share','now','now','not a number')`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES('mem_bad','cnt_bad','usr_share','owner','now')`); err != nil {
		t.Fatal(err)
	}
	res, err := f.client.Get(f.server.URL + "/api/v1/containers")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", res.StatusCode)
	}
}

func TestTeamNotebookCopiesEachMember(t *testing.T) {
	f := newShareFixture(t)
	for _, q := range []string{
		`INSERT INTO users(id,username,auth_secret_hash,login_salt,login_iterations,role,created_at,updated_at) VALUES('usr_other','other','x','salt',100000,'user','now','now')`,
		`INSERT INTO containers(id,kind,owner_user_id,created_at,updated_at) VALUES('cnt_team','team','usr_share','now','now')`,
		`INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES('mem_t1','cnt_team','usr_share','owner','now')`,
		`INSERT INTO memberships(id,container_id,user_id,role,created_at) VALUES('mem_t2','cnt_team','usr_other','member','now')`,
	} {
		if _, err := f.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, f.server.URL+"/api/v1/containers", strings.NewReader(`{"kind":"workbook","metaCiphertext":"","teamId":"cnt_team"}`))
	f.csrf(req)
	res, err := f.client.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("create err=%v status=%d", err, res.StatusCode)
	}
	defer res.Body.Close()
	var result struct{ ID string }
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	rows, err := f.db.Query(`SELECT user_id,role FROM memberships WHERE container_id=? AND revoked_at=''`, result.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]string{}
	for rows.Next() {
		var u, r string
		if err := rows.Scan(&u, &r); err != nil {
			t.Fatal(err)
		}
		got[u] = r
	}
	if len(got) != 2 || got["usr_share"] != "owner" || got["usr_other"] != "member" {
		t.Fatalf("memberships=%v", got)
	}
}
