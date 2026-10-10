package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRefuseSessionKeepsKindsApart(t *testing.T) {
	for _, tc := range []struct {
		s    Session
		kind string
		want int
		code string
	}{
		{Session{AccountKind: KindEveryday}, KindEveryday, 0, ""},
		{Session{AccountKind: KindAdmin}, KindEveryday, http.StatusForbidden, "admin_account"},
		{Session{AccountKind: KindEveryday}, KindAdmin, http.StatusForbidden, "forbidden"},
		{Session{AccountKind: ""}, KindEveryday, http.StatusForbidden, "admin_account"},
		{Session{AccountKind: KindEveryday, PasswordChangeRequired: true}, KindEveryday, http.StatusConflict, "password_change_required"},
		{Session{AccountKind: KindAdmin, PasswordChangeRequired: true}, KindAdmin, http.StatusConflict, "password_change_required"},
		// The kind is refused before the fence: the wrong kind never learns its password is flagged.
		{Session{AccountKind: KindAdmin, PasswordChangeRequired: true}, KindEveryday, http.StatusForbidden, "admin_account"},
		{Session{AccountKind: KindEveryday, PasswordChangeRequired: true}, KindAdmin, http.StatusForbidden, "forbidden"},
	} {
		rec := httptest.NewRecorder()
		refused := refuseSession(rec, tc.s, tc.kind)
		if refused != (tc.want != 0) || (refused && (rec.Code != tc.want || !strings.Contains(rec.Body.String(), `"`+tc.code+`"`))) {
			t.Errorf("%+v for %s: refused=%v code=%d", tc.s, tc.kind, refused, rec.Code)
		}
	}
}
