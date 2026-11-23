package httpapi

import (
	"io"
	"net/http"
	"testing"
)

// GET /objects/{id}?version= picks a version; empty means the current one. The query is one
// SQL text for SQLite and PostgreSQL, so each form must answer the same on both.
func TestObjectReadSelectsTheVersion(t *testing.T) {
	p := newPairClient(t, "pppppppppppppppppppppppppppppppp")
	cid := seedContainer(t, p, "workbook", "", map[string]string{pairUser: "owner"})
	generation := keyForTest(t, p.db, cid, pairUser)
	oid, code := p.save(t, cid, "", generation)
	if code != http.StatusOK {
		t.Fatalf("first save=%d", code)
	}
	if _, code = p.save(t, cid, oid, generation); code != http.StatusOK {
		t.Fatalf("second save=%d", code)
	}
	for query, want := range map[string]int{"": 200, "?version=": 200, "?version=1": 200, "?version=2": 200, "?version=02": 200, "?version=3": 404, "?version=abc": 404} {
		res := p.do(t, http.MethodGet, "/api/v1/objects/"+oid+query, nil, false, false)
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if res.StatusCode != want {
			t.Errorf("%q: %d, want %d", query, res.StatusCode, want)
		}
		if want == 200 {
			got := res.Header.Get("X-Kynotes-Version")
			expect := map[string]string{"": "2", "?version=": "2", "?version=1": "1", "?version=2": "2", "?version=02": "2"}[query]
			if got != expect {
				t.Errorf("%q: version header %s, want %s", query, got, expect)
			}
		}
	}
}
