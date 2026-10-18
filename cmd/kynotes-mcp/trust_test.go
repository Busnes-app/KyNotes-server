package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Busnes-app/kynotes-server/internal/ids"
	"github.com/Busnes-app/kynotes-server/internal/teamkeys"
)

type person struct {
	userID, deviceID string
	key              *ecdh.PrivateKey
}

func newPerson(t *testing.T) person {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := ids.Mint("usr")
	d, _ := ids.Mint("dev")
	return person{u, d, key}
}

func (p person) pub() string { return base64.StdEncoding.EncodeToString(p.key.PublicKey().Bytes()) }

func (p person) as(role string) member {
	return member{UserID: p.userID, Username: "name-" + role, Role: role, identity: &publicIdentity{p.deviceID, p.pub()}}
}

// seal is a browser at sender wrapping contentKey for to at generation.
func seal(t *testing.T, cid string, generation int64, contentKey []byte, sender, to person) envelopeRow {
	t.Helper()
	env, err := teamkeys.SealEnvelope(contentKey, to.key.PublicKey().Bytes(), cid, uint32(generation), to.deviceID, sender.key, sender.deviceID)
	if err != nil {
		t.Fatal(err)
	}
	return envelopeRow{DeviceID: to.deviceID, KeyGeneration: generation, Alg: envelopeAlg, Envelope: base64.StdEncoding.EncodeToString(env)}
}

func randomKey() []byte {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return k
}

func TestTrustRules(t *testing.T) {
	cid, _ := ids.Mint("cnt")
	agent, owner, editor, stranger := newPerson(t), newPerson(t), newPerson(t), newPerson(t)
	me := self{agent.userID, agent.deviceID, agent.key}
	k1, k2 := randomKey(), randomKey()
	members := []member{agent.as("editor"), owner.as("owner"), editor.as("editor")}

	t.Run("own identity", func(t *testing.T) {
		got, err := openKeyring(cid, []envelopeRow{seal(t, cid, 2, k2, agent, agent)}, me, members, nil, keyState{})
		if err != nil || !bytes.Equal(got.ring[2], k2) || got.known.Mark != 2 || len(got.fresh) != 0 {
			t.Fatalf("%+v %v", got, err)
		}
	})
	t.Run("unpinned owner is pinned on first contact", func(t *testing.T) {
		got, err := openKeyring(cid, []envelopeRow{seal(t, cid, 2, k2, owner, agent)}, me, members, map[string]string{}, keyState{})
		if err != nil || !bytes.Equal(got.ring[2], k2) || len(got.fresh) != 1 || got.fresh[0].UserID != owner.userID {
			t.Fatalf("%+v %v", got, err)
		}
	})
	t.Run("pinned owner", func(t *testing.T) {
		got, err := openKeyring(cid, []envelopeRow{seal(t, cid, 2, k2, owner, agent)}, me, members, map[string]string{owner.userID: owner.pub()}, keyState{})
		if err != nil || !bytes.Equal(got.ring[2], k2) || len(got.fresh) != 0 {
			t.Fatalf("%+v %v", got, err)
		}
	})
	t.Run("unpinned non-steward refused", func(t *testing.T) {
		got, err := openKeyring(cid, []envelopeRow{seal(t, cid, 2, k2, editor, agent)}, me, members, map[string]string{}, keyState{})
		if err != nil || len(got.ring) != 0 || len(got.fresh) != 0 {
			t.Fatalf("%+v %v", got, err)
		}
	})
	t.Run("sender that is no member refused", func(t *testing.T) {
		got, err := openKeyring(cid, []envelopeRow{seal(t, cid, 2, k2, stranger, agent)}, me, members, map[string]string{}, keyState{})
		if err != nil || len(got.ring) != 0 {
			t.Fatalf("%+v %v", got, err)
		}
	})
	t.Run("pin mismatch refused", func(t *testing.T) {
		_, err := openKeyring(cid, []envelopeRow{seal(t, cid, 2, k2, owner, agent)}, me, members, map[string]string{owner.userID: stranger.pub()}, keyState{})
		var pin *pinChangedError
		if !errors.As(err, &pin) || pin.userID != owner.userID {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("server-substituted owner key refused", func(t *testing.T) {
		// The server shows the stranger's key as the owner's; the pin still names the real one.
		forged := owner.as("owner")
		forged.identity.PublicKey = stranger.pub()
		_, err := openKeyring(cid, []envelopeRow{seal(t, cid, 2, k2, person{owner.userID, owner.deviceID, stranger.key}, agent)}, me, []member{agent.as("editor"), forged}, map[string]string{owner.userID: owner.pub()}, keyState{})
		var pin *pinChangedError
		if !errors.As(err, &pin) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("a different key for a known generation is refused", func(t *testing.T) {
		first, _ := openKeyring(cid, []envelopeRow{seal(t, cid, 2, k2, owner, agent)}, me, members, map[string]string{owner.userID: owner.pub()}, keyState{})
		got, err := openKeyring(cid, []envelopeRow{seal(t, cid, 2, randomKey(), owner, agent)}, me, members, map[string]string{owner.userID: owner.pub()}, first.known)
		if err != nil || got.ring[2] != nil {
			t.Fatalf("%+v %v", got, err)
		}
	})
	t.Run("demoted steward's history opens below the mark only", func(t *testing.T) {
		pins := map[string]string{editor.userID: editor.pub()} // pinned while it was a steward
		rows := []envelopeRow{seal(t, cid, 1, k1, editor, agent), seal(t, cid, 2, k2, agent, agent), seal(t, cid, 3, randomKey(), editor, agent)}
		got, err := openKeyring(cid, rows, me, members, pins, keyState{})
		if err != nil || !bytes.Equal(got.ring[1], k1) || got.ring[3] != nil || got.known.Mark != 2 {
			t.Fatalf("%+v %v", got, err)
		}
	})
	t.Run("envelope for another device ignored", func(t *testing.T) {
		got, err := openKeyring(cid, []envelopeRow{seal(t, cid, 2, k2, owner, editor)}, me, members, nil, keyState{})
		if err != nil || len(got.ring) != 0 {
			t.Fatalf("%+v %v", got, err)
		}
	})
}

func TestGenerationRollbackRefused(t *testing.T) {
	k := keyState{}
	if err := k.raise(container{KeyGeneration: 3, SharedGeneration: 2}); err != nil || k.Generation != 3 || k.Shared != 2 {
		t.Fatalf("%+v %v", k, err)
	}
	for _, c := range []container{{KeyGeneration: 2, SharedGeneration: 2}, {KeyGeneration: 3, SharedGeneration: 1}} {
		if err := k.raise(c); !errors.Is(err, errRollback) {
			t.Fatalf("%+v: %v", c, err)
		}
	}
	if k.Generation != 3 || k.Shared != 2 {
		t.Fatalf("a refused report lowered the floor: %+v", k)
	}
}

func TestReadKeyOnlyAtOrAboveTheFirstKey(t *testing.T) {
	ring := map[int64][]byte{1: {1}, 2: {2}}
	if readKey(ring, 2, 1) != nil || readKey(ring, 0, 2) != nil || readKey(ring, 2, 3) != nil || readKey(ring, 2, 2) == nil {
		t.Fatal("readKey opened a row it must not")
	}
}

func TestTrustFileIsPrivateAndRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trust.json")
	st, err := loadTrust(path)
	if err != nil {
		t.Fatal(err)
	}
	st.Pins["usr_x"] = "key"
	st.Containers["cnt_x"] = &keyState{Mark: 2, Digests: map[string]string{"2": "d"}}
	if err := st.save(path); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	again, err := loadTrust(path)
	if err != nil || again.Pins["usr_x"] != "key" || again.Containers["cnt_x"].Digests["2"] != "d" {
		t.Fatalf("%+v %v", again, err)
	}
	_ = os.Chmod(path, 0o644)
	if _, err := loadTrust(path); err == nil {
		t.Fatal("a world-readable trust file was accepted")
	}
}
