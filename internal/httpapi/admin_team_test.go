package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestAdminCreatesATeamForAnEverydayOwner(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	admin := p.addAdmin(t, "server-admin")
	admin.stepUp(t) // Task 4 puts team creation behind the admin step-up
	other := p.addAdmin(t, "other-admin")
	create := func(body string) (int, string) {
		return status(t, admin.do(t, http.MethodPost, "/api/v1/admin/teams", []byte(body), true, false))
	}
	for _, body := range []string{`{}`, `{"ownerUserId":"nope"}`, `{"metaCiphertext":"eA=="}`} {
		if code, out := create(body); code != http.StatusBadRequest {
			t.Fatalf("%s=%d %s", body, code, out)
		}
	}
	disabled := p.addUser(t, "gone")
	if _, err := p.db.Exec(`UPDATE users SET status='disabled' WHERE id=?`, disabled.id); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{other.id, disabled.id, mint(t, "usr")} {
		if code, out := create(`{"ownerUserId":` + quote(id) + `}`); code != http.StatusNotFound {
			t.Fatalf("owner %s=%d %s", id, code, out)
		}
	}
	// pairUser's fixture ID is not a minted ID, so the owner is a fresh everyday account.
	owner := p.addUser(t, "owner").id
	code, out := create(`{"ownerUserId":` + quote(owner) + `}`)
	var team struct {
		ID    string `json:"id"`
		Owner string `json:"ownerUserId"`
	}
	if code != http.StatusOK || json.Unmarshal([]byte(out), &team) != nil || team.Owner != owner {
		t.Fatalf("create=%d %s", code, out)
	}
	var stored string
	var adminRows, audits int
	if err := p.db.QueryRow(`SELECT owner_user_id FROM containers WHERE id=?`, team.ID).Scan(&stored); err != nil || stored != owner {
		t.Fatal("container owner", stored, err)
	}
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM memberships WHERE container_id=? AND user_id=?`, team.ID, admin.id).Scan(&adminRows); err != nil || adminRows != 0 {
		t.Fatal("the administrator holds a membership", adminRows, err)
	}
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='admin.team.create' AND container_id=? AND object_id=? AND actor_user_id=?`, team.ID, owner, admin.id).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("audit", audits, err)
	}
}
