package teamkeys

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

const pqVectorFile = "../../testdata/protocol/pq_vectors.json"

type pqVectors struct {
	SenderPrivate, SenderPublic, RecipientPrivate, RecipientPublic, Envelope, OrgID, ContainerID, RecipientID, SenderID string
	Generation                                                                                                          uint32
}

func TestPQEnvelope(t *testing.T) {
	v := pqVectors{OrgID: "org_test", ContainerID: "cnt_00000000000000000000000000", RecipientID: "dev_00000000000000000000000000", SenderID: "dev_11111111111111111111111111", Generation: 7}
	if *update {
		sp, su, err := GeneratePQIdentity(nil)
		if err != nil {
			t.Fatal(err)
		}
		rp, ru, err := GeneratePQIdentity(nil)
		if err != nil {
			t.Fatal(err)
		}
		env, err := SealPQEnvelope(bytes.Repeat([]byte{42}, 32), ru, v.OrgID, v.ContainerID, v.Generation, v.RecipientID, sp, v.SenderID)
		if err != nil {
			t.Fatal(err)
		}
		v.SenderPrivate = hex.EncodeToString(sp)
		v.SenderPublic = hex.EncodeToString(su)
		v.RecipientPrivate = hex.EncodeToString(rp)
		v.RecipientPublic = hex.EncodeToString(ru)
		v.Envelope = hex.EncodeToString(env)
		raw, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pqVectorFile, append(raw, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(pqVectorFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	sp, su, rp, ru, env := unhex(t, v.SenderPrivate), unhex(t, v.SenderPublic), unhex(t, v.RecipientPrivate), unhex(t, v.RecipientPublic), unhex(t, v.Envelope)
	if len(env) != PQEnvelopeBytes {
		t.Fatal(len(env))
	}
	for _, p := range [][]byte{sp, rp} {
		pub, err := IdentityPublic(p)
		if err != nil || ValidatePublicIdentity(pub) != nil {
			t.Fatal("identity", err)
		}
	}
	open := func(env []byte, org, cid string, g uint32, did string, pub []byte) ([]byte, error) {
		return OpenIdentityEnvelope(PQEnvelopeAlg, env, rp, org, cid, g, did, pub)
	}
	key, err := open(env, v.OrgID, v.ContainerID, v.Generation, v.RecipientID, su)
	if err != nil || !bytes.Equal(key, bytes.Repeat([]byte{42}, 32)) {
		t.Fatal("open", err)
	}
	for _, at := range []int{0, 1, 31, 32, 100, 1152, PQEnvelopeBytes - 65, PQEnvelopeBytes - 1} {
		bad := bytes.Clone(env)
		bad[at] ^= 1
		if _, err := open(bad, v.OrgID, v.ContainerID, v.Generation, v.RecipientID, su); err == nil {
			t.Fatalf("tamper %d", at)
		}
	}
	for _, test := range []struct {
		org, cid, did string
		g             uint32
		pub           []byte
	}{{"other", v.ContainerID, v.RecipientID, 7, su}, {v.OrgID, "cnt_00000000000000000000000001", v.RecipientID, 7, su}, {v.OrgID, v.ContainerID, "dev_00000000000000000000000001", 7, su}, {v.OrgID, v.ContainerID, v.RecipientID, 8, su}, {v.OrgID, v.ContainerID, v.RecipientID, 7, ru}} {
		if _, err := open(env, test.org, test.cid, test.g, test.did, test.pub); err == nil {
			t.Fatal("binding")
		}
	}
	fresh, err := SealPQEnvelope(key, ru, v.OrgID, v.ContainerID, v.Generation, v.RecipientID, sp, v.SenderID)
	if err != nil || bytes.Equal(fresh, env) {
		t.Fatal("fresh seal", err)
	}
	if _, err := OpenIdentityEnvelope(EnvelopeAlg, env, rp, v.OrgID, v.ContainerID, 7, v.RecipientID, su); err == nil {
		t.Fatal("downgraded v4")
	}
}
func TestPQIdentityKeepsLegacyReaders(t *testing.T) {
	for _, v := range loadVectors(t).Envelopes {
		priv, pub, err := GeneratePQIdentity(unhex(t, v.RecipientPrivateKey))
		if err != nil {
			t.Fatal(err)
		}
		_, sender, err := GeneratePQIdentity(unhex(t, v.SenderPrivateKey))
		if err != nil {
			t.Fatal(err)
		}
		key, err := OpenIdentityEnvelope(LegacyEnvelopeAlg, unhex(t, v.Envelope), priv, "org_test", v.ContainerID, v.KeyGeneration, v.RecipientDeviceID, sender)
		if err != nil || hex.EncodeToString(key) != v.ContentKey {
			t.Fatal("v2", err)
		}
		if !bytes.Equal(pub[1:33], unhex(t, v.RecipientPublicKey)) {
			t.Fatal("legacy key lost")
		}
	}
	for _, v := range loadVectors(t).HPKEEnvelopes {
		priv, _, _ := GeneratePQIdentity(unhex(t, v.RecipientPrivateKey))
		_, sender, _ := GeneratePQIdentity(unhex(t, v.SenderPrivateKey))
		key, err := OpenIdentityEnvelope(EnvelopeAlg, unhex(t, v.Envelope), priv, "org_test", v.ContainerID, v.KeyGeneration, v.RecipientDeviceID, sender)
		if err != nil || hex.EncodeToString(key) != v.ContentKey {
			t.Fatal("v3", err)
		}
	}
}
