package httpapi

import (
	"net/http"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/config"
)

// Q4: deleting a notebook purges its stored data and its child notebooks', so GC can reclaim
// the blobs and the owner's quota frees.
func TestDeletingANotebookReleasesItsStorage(t *testing.T) {
	tm := newTeam(t)
	tm.rotate(t, tm.id, 1)
	tm.rotate(t, tm.child, 1)
	for _, cid := range []string{tm.id, tm.child} {
		if _, code := tm.owner.save(t, cid, "", 2); code != http.StatusOK {
			t.Fatalf("save=%d", code)
		}
	}
	var used int64
	if err := tm.owner.db.QueryRow(`SELECT COALESCE(SUM(ciphertext_bytes),0) FROM object_versions`).Scan(&used); err != nil || used == 0 {
		t.Fatalf("nothing stored: %d %v", used, err)
	}
	limits := config.Limits{UserQuotaBytes: used}
	if over, err := quotaExceeded(tm.owner.db, limits, tm.id, "", 1); err != nil || !over {
		t.Fatalf("quota before delete over=%v %v", over, err)
	}
	if code, out := status(t, tm.owner.do(t, http.MethodDelete, "/api/v1/containers/"+tm.id, nil, true, false)); code != http.StatusNoContent {
		t.Fatalf("delete=%d %s", code, out)
	}
	var live, versions, pages int
	if err := tm.owner.db.QueryRow(`SELECT (SELECT COUNT(*) FROM containers WHERE id IN (?1,?2) AND deleted_at=''),(SELECT COUNT(*) FROM object_versions),(SELECT COUNT(*) FROM objects WHERE deleted_at='')`, tm.id, tm.child).Scan(&live, &versions, &pages); err != nil {
		t.Fatal(err)
	}
	if live != 0 || versions != 0 || pages != 0 {
		t.Fatalf("after delete: %d live notebooks, %d versions, %d live pages", live, versions, pages)
	}
	if over, err := quotaExceeded(tm.owner.db, limits, tm.id, "", 1); err != nil || over {
		t.Fatalf("quota after delete over=%v %v", over, err)
	}
}
