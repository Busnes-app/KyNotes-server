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
		env, senderPub := unhex(t, e.Envelope), unhex(t, e.SenderPublicKey)
		if sender, err := EnvelopeSender(env); err != nil || sender != e.SenderDeviceID {
			t.Fatalf("sender %q: %v", sender, err)
		}
		ck, err := OpenEnvelope(env, priv, e.ContainerID, e.KeyGeneration, e.RecipientDeviceID, senderPub)
		if err != nil || hex.EncodeToString(ck) != e.ContentKey {
			t.Fatalf("vector did not open: %v", err)
		}
		if _, err := OpenEnvelope(env, priv, e.ContainerID, e.KeyGeneration+1, e.RecipientDeviceID, senderPub); err == nil {
			t.Fatal("opened at another generation")
		}
		if _, err := OpenEnvelope(env, priv, e.ContainerID, e.KeyGeneration, e.RecipientDeviceID, unhex(t, e.RecipientPublicKey)); err == nil {
			t.Fatal("opened with another sender key")
		}
		if _, err := OpenEnvelope(env, priv, e.ContainerID, e.KeyGeneration, e.RecipientDeviceID, make([]byte, 32)); err == nil {
			t.Fatal("opened with an all-zero sender shared secret")
		}
		swapped := bytes.Clone(env)
		copy(swapped[1:31], "dev_00000000000000000000000009")
		if _, err := OpenEnvelope(swapped, priv, e.ContainerID, e.KeyGeneration, e.RecipientDeviceID, senderPub); err == nil {
			t.Fatal("opened with a relabelled sender device")
		}
	}
}

func TestSealEnvelopeRoundTrip(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ck := bytes.Repeat([]byte{5}, 32)
	cid, did, sid := "cnt_0123456789abcdefghjkmnpqrs", "dev_0123456789abcdefghjkmnpqrs", "dev_zyxwvtsrqpnmkjhgfedcba9876"
	env, err := SealEnvelope(ck, priv.PublicKey().Bytes(), cid, 7, did, sender, sid)
	if err != nil || len(env) != EnvelopeBytes {
		t.Fatalf("seal: %d %v", len(env), err)
	}
	if got, err := OpenEnvelope(env, priv, cid, 7, did, sender.PublicKey().Bytes()); err != nil || !bytes.Equal(got, ck) {
		t.Fatalf("open: %v", err)
	}
	if _, err := SealEnvelope(ck, priv.PublicKey().Bytes(), cid, 7, "dev_short", sender, sid); err == nil {
		t.Fatal("sealed with a malformed device ID")
	}
	if _, err := SealEnvelope(ck, priv.PublicKey().Bytes(), cid, 7, did, sender, "dev_short"); err == nil {
		t.Fatal("sealed with a malformed sender device ID")
	}
	if _, err := EnvelopeSender(append([]byte{0x01}, env[1:]...)); err == nil {
		t.Fatal("accepted a v1 envelope")
	}
}
