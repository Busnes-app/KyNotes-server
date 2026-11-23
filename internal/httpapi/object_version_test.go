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
	// SQLite's comparison read numeric text as a number: "2.0", " 2", "+2" and "1e0" select a
	// version; "1abc", "1.9", "0x1" and "Inf" select none.
	cases := map[string]int{"": 200, "?version=": 200, "?version=1": 200, "?version=2": 200, "?version=02": 200, "?version=3": 404, "?version=abc": 404,
		"?version=1abc": 404, "?version=1.9": 404, "?version=2.0": 200, "?version=%202": 200, "?version=%2B2": 200, "?version=1e0": 200, "?version=0x1": 404, "?version=Inf": 404, "?version=-1": 404}
	for query, want := range cases {
		res := p.do(t, http.MethodGet, "/api/v1/objects/"+oid+query, nil, false, false)
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if res.StatusCode != want {
			t.Errorf("%q: %d, want %d", query, res.StatusCode, want)
		}
		if want == 200 {
			got := res.Header.Get("X-Kynotes-Version")
			expect := map[string]string{"": "2", "?version=": "2", "?version=1": "1", "?version=2": "2", "?version=02": "2", "?version=2.0": "2", "?version=%202": "2", "?version=%2B2": "2", "?version=1e0": "1"}[query]
			if got != expect {
				t.Errorf("%q: version header %s, want %s", query, got, expect)
			}
		}
	}
}
