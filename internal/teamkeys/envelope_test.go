package teamkeys

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func loadVectors(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil || len(v.Envelopes) == 0 || len(v.HPKEEnvelopes) == 0 {
		t.Fatalf("vectors: %v", err)
	}
	return v
}

func privKey(t *testing.T, raw string) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().NewPrivateKey(unhex(t, raw))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestSealEnvelopeMatchesVectors: SealEnvelope's bytes for a fixed ephemeral seed are the
// circl-direct vector bytes, which web/src/teamKeys.ts must reproduce too.
func TestSealEnvelopeMatchesVectors(t *testing.T) {
	for _, e := range loadVectors(t).HPKEEnvelopes {
		got, err := sealEnvelope(bytes.NewReader(unhex(t, e.EphemeralSeed)), unhex(t, e.ContentKey), unhex(t, e.RecipientPublicKey), e.ContainerID, e.KeyGeneration, e.RecipientDeviceID, privKey(t, e.SenderPrivateKey), e.SenderDeviceID)
		if err != nil || hex.EncodeToString(got) != e.Envelope || len(got) != EnvelopeBytes {
			t.Fatalf("seal: %x %v", got, err)
		}
	}
}

func TestOpenEnvelopeAgreesWithVectors(t *testing.T) {
	for _, e := range loadVectors(t).HPKEEnvelopes {
		priv := privKey(t, e.RecipientPrivateKey)
		env, senderPub := unhex(t, e.Envelope), unhex(t, e.SenderPublicKey)
		open := func(env []byte, alg, container string, generation uint32, recipient string, sender []byte) error {
			ck, err := OpenEnvelope(alg, env, priv, container, generation, recipient, sender)
			if err == nil && hex.EncodeToString(ck) != e.ContentKey {
				t.Fatal("opened to another key")
			}
			return err
		}
		if sender, err := EnvelopeSender(EnvelopeAlg, env); err != nil || sender != e.SenderDeviceID {
			t.Fatalf("sender %q: %v", sender, err)
		}
		if err := open(env, EnvelopeAlg, e.ContainerID, e.KeyGeneration, e.RecipientDeviceID, senderPub); err != nil {
			t.Fatalf("vector did not open: %v", err)
		}
		refused := map[string]error{
			"another container":   open(env, EnvelopeAlg, "cnt_00000000000000000000000001", e.KeyGeneration, e.RecipientDeviceID, senderPub),
			"another generation":  open(env, EnvelopeAlg, e.ContainerID, e.KeyGeneration^2, e.RecipientDeviceID, senderPub),
			"another recipient":   open(env, EnvelopeAlg, e.ContainerID, e.KeyGeneration, "dev_00000000000000000000000009", senderPub),
			"another sender key":  open(env, EnvelopeAlg, e.ContainerID, e.KeyGeneration, e.RecipientDeviceID, unhex(t, e.RecipientPublicKey)),
			"a zero sender key":   open(env, EnvelopeAlg, e.ContainerID, e.KeyGeneration, e.RecipientDeviceID, make([]byte, 32)),
			"the legacy alg":      open(env, LegacyEnvelopeAlg, e.ContainerID, e.KeyGeneration, e.RecipientDeviceID, senderPub),
			"an unknown alg":      open(env, "hpke-base-x25519", e.ContainerID, e.KeyGeneration, e.RecipientDeviceID, senderPub),
			"a v2 version byte":   open(append([]byte{0x02}, env[1:]...), EnvelopeAlg, e.ContainerID, e.KeyGeneration, e.RecipientDeviceID, senderPub),
			"a truncated body":    open(env[:EnvelopeBytes-1], EnvelopeAlg, e.ContainerID, e.KeyGeneration, e.RecipientDeviceID, senderPub),
			"a relabelled sender": open(append(append([]byte{0x03}, "dev_00000000000000000000000009"...), env[31:]...), EnvelopeAlg, e.ContainerID, e.KeyGeneration, e.RecipientDeviceID, senderPub),
		}
		for _, at := range []int{0, 1, 30, 31, 62, 63, EnvelopeBytes - 1} {
			bad := bytes.Clone(env)
			bad[at] ^= 1
			refused[fmt.Sprint("a flipped byte ", at)] = open(bad, EnvelopeAlg, e.ContainerID, e.KeyGeneration, e.RecipientDeviceID, senderPub)
		}
		for what, err := range refused {
			if err == nil {
				t.Errorf("opened with %s", what)
			}
		}
	}
}

// TestSenderAuthentication: anyone holding only the recipient's public key (the server)
// cannot seal an envelope that opens as from the claimed sender.
func TestSenderAuthentication(t *testing.T) {
	e := loadVectors(t).HPKEEnvelopes[0]
	forger, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := SealEnvelope(unhex(t, e.ContentKey), unhex(t, e.RecipientPublicKey), e.ContainerID, e.KeyGeneration, e.RecipientDeviceID, forger, e.SenderDeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenEnvelope(EnvelopeAlg, forged, privKey(t, e.RecipientPrivateKey), e.ContainerID, e.KeyGeneration, e.RecipientDeviceID, unhex(t, e.SenderPublicKey)); err == nil {
		t.Fatal("opened an envelope the claimed sender never sealed")
	}
}

// TestOpenLegacyEnvelopeVectors: stored v2 envelopes open unchanged, and only as v2.
func TestOpenLegacyEnvelopeVectors(t *testing.T) {
	for _, e := range loadVectors(t).Envelopes {
		priv := privKey(t, e.RecipientPrivateKey)
		env, senderPub := unhex(t, e.Envelope), unhex(t, e.SenderPublicKey)
		if sender, err := EnvelopeSender(LegacyEnvelopeAlg, env); err != nil || sender != e.SenderDeviceID {
			t.Fatalf("sender %q: %v", sender, err)
		}
		ck, err := OpenEnvelope(LegacyEnvelopeAlg, env, priv, e.ContainerID, e.KeyGeneration, e.RecipientDeviceID, senderPub)
		if err != nil || hex.EncodeToString(ck) != e.ContentKey {
			t.Fatalf("vector did not open: %v", err)
		}
		if _, err := OpenEnvelope(EnvelopeAlg, env, priv, e.ContainerID, e.KeyGeneration, e.RecipientDeviceID, senderPub); err == nil {
			t.Fatal("opened a v2 envelope as v3")
		}
		if _, err := OpenEnvelope(LegacyEnvelopeAlg, env, priv, e.ContainerID, e.KeyGeneration+1, e.RecipientDeviceID, senderPub); err == nil {
			t.Fatal("opened at another generation")
		}
		if _, err := OpenEnvelope(LegacyEnvelopeAlg, env, priv, e.ContainerID, e.KeyGeneration, e.RecipientDeviceID, unhex(t, e.RecipientPublicKey)); err == nil {
			t.Fatal("opened with another sender key")
		}
		if _, err := OpenEnvelope(LegacyEnvelopeAlg, env, priv, e.ContainerID, e.KeyGeneration, e.RecipientDeviceID, make([]byte, 32)); err == nil {
			t.Fatal("opened with an all-zero sender shared secret")
		}
		swapped := bytes.Clone(env)
		copy(swapped[1:31], "dev_00000000000000000000000009")
		if _, err := OpenEnvelope(LegacyEnvelopeAlg, swapped, priv, e.ContainerID, e.KeyGeneration, e.RecipientDeviceID, senderPub); err == nil {
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
	if err != nil || len(env) != EnvelopeBytes || env[0] != 0x03 {
		t.Fatalf("seal: %d %v", len(env), err)
	}
	if got, err := OpenEnvelope(EnvelopeAlg, env, priv, cid, 7, did, sender.PublicKey().Bytes()); err != nil || !bytes.Equal(got, ck) {
		t.Fatalf("open: %v", err)
	}
	again, err := SealEnvelope(ck, priv.PublicKey().Bytes(), cid, 7, did, sender, sid)
	if err != nil || bytes.Equal(again, env) {
		t.Fatal("two seals share an ephemeral key")
	}
	if _, err := SealEnvelope(ck, priv.PublicKey().Bytes(), cid, 7, "dev_short", sender, sid); err == nil {
		t.Fatal("sealed with a malformed device ID")
	}
	if _, err := SealEnvelope(ck, priv.PublicKey().Bytes(), cid, 7, did, sender, "dev_short"); err == nil {
		t.Fatal("sealed with a malformed sender device ID")
	}
	if _, err := SealEnvelope(ck, priv.PublicKey().Bytes(), cid, 0, did, sender, sid); err == nil {
		t.Fatal("sealed at generation 0")
	}
	if _, err := SealEnvelope(ck[:31], priv.PublicKey().Bytes(), cid, 7, did, sender, sid); err == nil {
		t.Fatal("sealed a short content key")
	}
	if _, err := EnvelopeSender(EnvelopeAlg, append([]byte{0x01}, env[1:]...)); err == nil {
		t.Fatal("accepted a v1 envelope")
	}
}
