package teamkeys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"regexp"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

var idPattern = regexp.MustCompile(`^(cnt|dev|usr)_[0-9a-hjkmnp-tv-z]{26}$`)

func mustID(t *testing.T, prefix, id string) {
	t.Helper()
	if !idPattern.MatchString(id) || id[:3] != prefix {
		t.Fatalf("invalid %s id %q", prefix, id)
	}
}

const vectorFile = "../../testdata/protocol/envelope_vectors.json"

var update = flag.Bool("update", false, "rewrite "+vectorFile)

type loginVector struct {
	Password   string `json:"password"`
	LoginSalt  string `json:"loginSalt"`
	Iterations int    `json:"iterations"`
	AuthSecret string `json:"authSecret"`
	UserKEK    string `json:"userKEK"`
}

type identityVector struct {
	UserID     string `json:"userId"`
	UserKEK    string `json:"userKEK"`
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
	Nonce      string `json:"nonce"`
	Wrapped    string `json:"wrapped"`
}

type envelopeVector struct {
	ContainerID         string `json:"containerId"`
	KeyGeneration       uint32 `json:"keyGeneration"`
	RecipientDeviceID   string `json:"recipientDeviceId"`
	RecipientPrivateKey string `json:"recipientPrivateKey"`
	RecipientPublicKey  string `json:"recipientPublicKey"`
	EphemeralPrivateKey string `json:"ephemeralPrivateKey"`
	Nonce               string `json:"nonce"`
	ContentKey          string `json:"contentKey"`
	Envelope            string `json:"envelope"`
}

type vectors struct {
	Login     []loginVector    `json:"login"`
	Identity  []identityVector `json:"identity"`
	Envelopes []envelopeVector `json:"envelopes"`
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hkdf32(t *testing.T, secret, salt []byte, info string) []byte {
	t.Helper()
	out := make([]byte, 32)
	if _, err := hkdf.New(sha256.New, secret, salt, []byte(info)).Read(out); err != nil {
		t.Fatal(err)
	}
	return out
}

func x25519(t *testing.T, scalar, point []byte) []byte {
	t.Helper()
	out, err := curve25519.X25519(scalar, point)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func login(t *testing.T, password, salt string, iterations int) loginVector {
	raw, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		t.Fatal(err)
	}
	stretched := pbkdf2.Key([]byte(password), raw, iterations, 32, sha256.New)
	return loginVector{password, salt, iterations, hex.EncodeToString(hkdf32(t, stretched, nil, "kynotes/auth/v1")), hex.EncodeToString(hkdf32(t, stretched, nil, "kynotes/user-kek/v1"))}
}

func identity(t *testing.T, userID, kek, priv, nonce string) identityVector {
	mustID(t, "usr", userID)
	block, err := aes.NewCipher(unhex(t, kek))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	n := unhex(t, nonce)
	wrapped := gcm.Seal(bytes.Clone(n), n, unhex(t, priv), append([]byte("kynotes/identity/v1"), userID...))
	pub := x25519(t, unhex(t, priv), curve25519.Basepoint)
	return identityVector{userID, kek, priv, hex.EncodeToString(pub), nonce, hex.EncodeToString(wrapped)}
}

func envelope(t *testing.T, containerID string, generation uint32, deviceID, recipientPriv, ephPriv, nonce, contentKey string) envelopeVector {
	mustID(t, "cnt", containerID)
	mustID(t, "dev", deviceID)
	if generation == 0 {
		t.Fatal("key generation must be >= 1")
	}
	recipientPub := x25519(t, unhex(t, recipientPriv), curve25519.Basepoint)
	ephPub := x25519(t, unhex(t, ephPriv), curve25519.Basepoint)
	shared := x25519(t, unhex(t, ephPriv), recipientPub)
	key := hkdf32(t, shared, append(bytes.Clone(ephPub), recipientPub...), "kynotes/envelope/v1")
	aad := append([]byte("kynotes/envelope/v1"), containerID...)
	aad = binary.BigEndian.AppendUint32(aad, generation)
	aad = append(aad, deviceID...)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}
	n := unhex(t, nonce)
	env := append([]byte{0x01}, ephPub...)
	env = append(env, n...)
	env = aead.Seal(env, n, unhex(t, contentKey), aad)
	if len(env) != 93 {
		t.Fatalf("envelope is %d bytes, want 93", len(env))
	}
	// The recipient side must open what the sender side sealed.
	back := hkdf32(t, x25519(t, unhex(t, recipientPriv), ephPub), append(bytes.Clone(ephPub), recipientPub...), "kynotes/envelope/v1")
	open, _ := chacha20poly1305.New(back)
	if pt, err := open.Open(nil, n, env[45:], aad); err != nil || hex.EncodeToString(pt) != contentKey {
		t.Fatalf("round trip failed: %v", err)
	}
	return envelopeVector{containerID, generation, deviceID, recipientPriv, hex.EncodeToString(recipientPub), ephPriv, nonce, contentKey, hex.EncodeToString(env)}
}

// Fixed scalars are the RFC 7748 §6.1 Alice/Bob keys; the password matches
// testdata/protocol/auth_vectors.json so authSecret is pinned twice.
func generate(t *testing.T) vectors {
	alice := "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	bob := "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
	l := login(t, "correct horse battery staple", "MDEyMzQ1Njc4OWFiY2RlZg==", 100000)
	return vectors{
		Login:    []loginVector{l},
		Identity: []identityVector{identity(t, "usr_0123456789abcdefghjkmnpqrs", l.UserKEK, bob, "a0a1a2a3a4a5a6a7a8a9aaab")},
		Envelopes: []envelopeVector{
			envelope(t, "cnt_00000000000000000000000000", 1, "dev_00000000000000000000000000", bob, alice, "000102030405060708090a0b", "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"),
			envelope(t, "cnt_tvwxyz0123456789abcdefghjk", 4294967295, "dev_mnpqrstvwxyz0123456789abcd", alice, bob, "0c0d0e0f1011121314151617", "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f"),
		},
	}
}

func TestEnvelopeVectors(t *testing.T) {
	got, err := json.MarshalIndent(generate(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *update {
		if err := os.WriteFile(vectorFile, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale; run go test ./internal/teamkeys -run TestEnvelopeVectors -update", vectorFile)
	}
}

func TestEnvelopeRejectsLowOrderPoint(t *testing.T) {
	if _, err := curve25519.X25519(unhex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"), make([]byte, 32)); err == nil {
		t.Fatal("all-zero shared secret accepted")
	}
}
