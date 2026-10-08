package teamkeys

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestOpenEnvelopeAgreesWithVectors(t *testing.T) {
	raw, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil || len(v.Envelopes) == 0 {
		t.Fatalf("vectors: %v", err)
	}
	for _, e := range v.Envelopes {
		priv, err := ecdh.X25519().NewPrivateKey(unhex(t, e.RecipientPrivateKey))
		if err != nil {
			t.Fatal(err)
		}
		ck, err := OpenEnvelope(unhex(t, e.Envelope), priv, e.ContainerID, e.KeyGeneration, e.RecipientDeviceID)
		if err != nil || hex.EncodeToString(ck) != e.ContentKey {
			t.Fatalf("vector did not open: %v", err)
		}
		if _, err := OpenEnvelope(unhex(t, e.Envelope), priv, e.ContainerID, e.KeyGeneration+1, e.RecipientDeviceID); err == nil {
			t.Fatal("opened at another generation")
		}
	}
}

func TestSealEnvelopeRoundTrip(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ck := bytes.Repeat([]byte{5}, 32)
	cid, did := "cnt_0123456789abcdefghjkmnpqrs", "dev_0123456789abcdefghjkmnpqrs"
	env, err := SealEnvelope(ck, priv.PublicKey().Bytes(), cid, 7, did)
	if err != nil || len(env) != EnvelopeBytes {
		t.Fatalf("seal: %d %v", len(env), err)
	}
	if got, err := OpenEnvelope(env, priv, cid, 7, did); err != nil || !bytes.Equal(got, ck) {
		t.Fatalf("open: %v", err)
	}
	if _, err := SealEnvelope(ck, priv.PublicKey().Bytes(), cid, 7, "dev_short"); err == nil {
		t.Fatal("sealed with a malformed device ID")
	}
}
