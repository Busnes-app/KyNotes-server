package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRefuseSessionKeepsKindsApart(t *testing.T) {
	for _, tc := range []struct {
		s    Session
		kind string
		want int
	}{
		{Session{AccountKind: KindEveryday}, KindEveryday, 0},
		{Session{AccountKind: KindAdmin}, KindEveryday, http.StatusForbidden},
		{Session{AccountKind: KindEveryday}, KindAdmin, http.StatusForbidden},
		{Session{AccountKind: ""}, KindEveryday, http.StatusForbidden},
		{Session{AccountKind: KindEveryday, PasswordChangeRequired: true}, KindEveryday, http.StatusConflict},
		{Session{AccountKind: KindAdmin, PasswordChangeRequired: true}, KindAdmin, http.StatusConflict},
	} {
		rec := httptest.NewRecorder()
		refused := refuseSession(rec, tc.s, tc.kind)
		if refused != (tc.want != 0) || (refused && rec.Code != tc.want) {
			t.Errorf("%+v for %s: refused=%v code=%d", tc.s, tc.kind, refused, rec.Code)
		}
	}
}
