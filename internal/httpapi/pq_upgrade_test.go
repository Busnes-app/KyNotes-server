package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/teamkeys"
)

func TestPQUpgrade(t *testing.T) {
	p := newPairClient(t, strings.Repeat("p", 32))
	did := p.createIdentity(t)
	// Fixture legacy identity must be the public key belonging to the retained scalar.
	old := bytes.Repeat([]byte{7}, 32)
	private, public, err := teamkeys.GeneratePQIdentity(old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(`UPDATE devices SET public_key=? WHERE id=?`, b64(public[1:33]), did); err != nil {
		t.Fatal(err)
	}
	cid := seedContainer(t, p, "personal", "", map[string]string{pairUser: "owner"})
	keyForTest(t, p.db, cid, pairUser)
	body := map[string]string{"deviceID": did, "publicKey": b64(public), "wrapAlg": identityWrapAlg, "wrappedPrivateKey": b64(bytes.Repeat([]byte{5}, teamkeys.PQWrappedIdentityBytes)), "recoveryKey": b64(bytes.Repeat([]byte{6}, teamkeys.PQRecoveryBytes))}
	send := func(v map[string]string, csrf bool) (int, string) {
		raw, _ := json.Marshal(v)
		return status(t, p.do(t, http.MethodPost, "/api/v1/me/identity/pq-upgrade", raw, csrf, false))
	}
	if code, _ := send(body, false); code != 403 {
		t.Fatal("CSRF", code)
	}
	original := body["deviceID"]
	body["deviceID"] = "dev_00000000000000000000000000"
	if code, _ := send(body, true); code != 409 {
		t.Fatal("foreign identity", code)
	}
	body["deviceID"] = original
	wrong := bytes.Clone(public)
	wrong[1] ^= 1
	body["publicKey"] = b64(wrong)
	if code, _ := send(body, true); code != 409 {
		t.Fatal("lost legacy key", code)
	}
	body["publicKey"] = b64(public)
	if code, b := send(body, true); code != 200 {
		t.Fatal(code, b)
	}
	var pub string
	var rows, audits int
	if err := p.db.QueryRow(`SELECT public_key FROM devices WHERE id=?`, did).Scan(&pub); err != nil || pub != base64.StdEncoding.EncodeToString(public) {
		t.Fatal("public", err)
	}
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM key_envelopes WHERE container_id=?`, cid).Scan(&rows); err != nil || rows != 1 {
		t.Fatal("history removed", rows, err)
	}
	gen, _ := generationOf(t, p, cid)
	if gen != 2 {
		t.Fatal("future keys not retired", gen)
	}
	if code, b := send(body, true); code != 200 {
		t.Fatal("retry", code, b)
	}
	gen, _ = generationOf(t, p, cid)
	if gen != 2 {
		t.Fatal("retry retired twice", gen)
	}
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event='identity.pq_upgrade'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("audit", audits, err)
	}
	if pub, err := teamkeys.IdentityPublic(private); err != nil || !bytes.Equal(pub, public) {
		t.Fatal(err)
	}
}
