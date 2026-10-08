package teamkeys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

const (
	recoveryVectorFile = "../../testdata/protocol/recovery_vectors.json"
	recoveryCodeLabel  = "kynotes/recovery-code/v1"
	recoveryKEKLabel   = "kynotes/recovery-kek/v1"
	recoveryWrapLabel  = "kynotes/identity-recovery/v1"
	recoveryAlg        = "pbkdf2-sha256-600000/aes-256-gcm"
	recoveryIterations = 600000
	recoveryCopyBytes  = 16 + 12 + 32 + 16
	crockford          = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

type recoveryVector struct {
	Secret     string `json:"secret"`
	Code       string `json:"code"`
	UserID     string `json:"userId"`
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	KEK        string `json:"kek"`
	Wrapped    string `json:"wrapped"`
}

// recoveryInput is a typed form of codes[0]: an alias parses to Code, a reject fails to parse.
type recoveryInput struct {
	Case  string `json:"case"`
	Input string `json:"input"`
	Code  string `json:"code,omitempty"`
}

// recoveryOpenReject is a copy the client must refuse. Reason names the check:
// "alg" (anything but recoveryAlg, so a server cannot lower the iterations), "format"
// (not 76 bytes, so a server cannot shorten the salt), "aead" (wrong code, user, public
// key or tampered bytes) or "public-key" (the opened key does not derive to PublicKey).
type recoveryOpenReject struct {
	Case      string `json:"case"`
	Reason    string `json:"reason"`
	Secret    string `json:"secret"`
	UserID    string `json:"userId"`
	PublicKey string `json:"publicKey"`
	WrapAlg   string `json:"wrapAlg"`
	Wrapped   string `json:"wrapped"`
}

type recoveryVectors struct {
	Codes       []recoveryVector     `json:"codes"`
	Aliases     []recoveryInput      `json:"aliases"`
	Rejects     []recoveryInput      `json:"rejects"`
	OpenRejects []recoveryOpenReject `json:"openRejects"`
}

func recoveryChecksum(secret []byte) uint64 {
	sum := sha256.Sum256(append([]byte(recoveryCodeLabel), secret...))
	return uint64(sum[0])<<2 | uint64(sum[1])>>6
}

// recoveryCode is secret<<10 | checksum as 28 big-endian Crockford symbols, in groups of four.
func recoveryCode(secret []byte) string {
	v := new(big.Int).Lsh(new(big.Int).SetBytes(secret), 10)
	v.Or(v, new(big.Int).SetUint64(recoveryChecksum(secret)))
	out := make([]byte, 28)
	for i := 27; i >= 0; i-- {
		out[i] = crockford[new(big.Int).And(v, big.NewInt(31)).Int64()]
		v.Rsh(v, 5)
	}
	groups := make([]string, 0, 7)
	for i := 0; i < 28; i += 4 {
		groups = append(groups, string(out[i:i+4]))
	}
	return strings.Join(groups, "-")
}

// parseRecoveryCode is the ASCII part of the web parser (the browser adds NFKC first).
func parseRecoveryCode(input string) ([]byte, bool) {
	s := strings.NewReplacer(" ", "", "\t", "", "\n", "", "-", "", "I", "1", "L", "1", "O", "0").Replace(strings.ToUpper(input))
	if len(s) != 28 {
		return nil, false
	}
	v := new(big.Int)
	for _, c := range s {
		d := strings.IndexRune(crockford, c)
		if d < 0 {
			return nil, false
		}
		v.Lsh(v, 5).Or(v, big.NewInt(int64(d)))
	}
	if v.BitLen() > 138 {
		return nil, false
	}
	secret := new(big.Int).Rsh(v, 10).FillBytes(make([]byte, 16))
	if recoveryChecksum(secret) != new(big.Int).And(v, big.NewInt(1023)).Uint64() {
		return nil, false
	}
	return secret, true
}

func recoveryKEK(secret, salt []byte, iterations int) []byte {
	kek, err := pbkdf2.Key(sha256.New, string(secret), append([]byte(recoveryKEKLabel), salt...), iterations, 32)
	if err != nil {
		panic(err)
	}
	return kek
}

func recoveryAAD(userID string, publicKey []byte) []byte {
	return append(append([]byte(recoveryWrapLabel), userID...), publicKey...)
}

func recoveryGCM(kek []byte) cipher.AEAD {
	block, err := aes.NewCipher(kek)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return gcm
}

// sealRecoveryRef seals privateKey with AAD bound to boundPublicKey (its own, except in a reject).
func sealRecoveryRef(secret []byte, userID string, privateKey, boundPublicKey, salt, nonce []byte, iterations int) []byte {
	sealed := recoveryGCM(recoveryKEK(secret, salt, iterations)).Seal(nil, nonce, privateKey, recoveryAAD(userID, boundPublicKey))
	return append(append(append([]byte{}, salt...), nonce...), sealed...)
}

// openRecoveryRef is the reference client check; it returns the private key or the reason it refused.
func openRecoveryRef(secret []byte, wrapAlg string, wrapped []byte, userID string, publicKey []byte) ([]byte, string) {
	if wrapAlg != recoveryAlg {
		return nil, "alg"
	}
	if len(secret) != 16 || len(wrapped) != recoveryCopyBytes || len(publicKey) != 32 {
		return nil, "format"
	}
	privateKey, err := recoveryGCM(recoveryKEK(secret, wrapped[:16], recoveryIterations)).Open(nil, wrapped[16:28], wrapped[28:], recoveryAAD(userID, publicKey))
	if err != nil {
		return nil, "aead"
	}
	derived, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil || subtle.ConstantTimeCompare(derived, publicKey) != 1 {
		return nil, "public-key"
	}
	return privateKey, ""
}

func publicOf(privateKey []byte) []byte {
	pub, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return pub
}

func recoveryVectorFor(secret []byte, userID string, privateKey, salt, nonce []byte) recoveryVector {
	pub := publicOf(privateKey)
	wrapped := sealRecoveryRef(secret, userID, privateKey, pub, salt, nonce, recoveryIterations)
	kek := recoveryKEK(secret, salt, recoveryIterations)
	return recoveryVector{hex.EncodeToString(secret), recoveryCode(secret), userID, hex.EncodeToString(privateKey), hex.EncodeToString(pub), hex.EncodeToString(salt), hex.EncodeToString(nonce), hex.EncodeToString(kek), hex.EncodeToString(wrapped)}
}

func seq(from byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = from + byte(i)
	}
	return out
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func generateRecovery() recoveryVectors {
	codes := []recoveryVector{
		recoveryVectorFor(seq(0, 16), "usr_0123456789abcdefghjkmnpqrs", bytes.Repeat([]byte{0x11}, 32), seq(0x20, 16), seq(0x40, 12)),
		recoveryVectorFor(bytes.Repeat([]byte{0xff}, 16), "usr_zyxwvtsrqpnmkjhgfedcba9876", bytes.Repeat([]byte{0x22}, 32), seq(0x60, 16), seq(0x80, 12)),
		recoveryVectorFor(make([]byte, 16), "usr_0123456789abcdefghjkmnpqrs", bytes.Repeat([]byte{0x33}, 32), seq(0xa0, 16), seq(0xc0, 12)),
	}
	base := codes[0].Code
	flat := strings.ReplaceAll(base, "-", "")
	aliases := []recoveryInput{
		{Case: "lowercase", Input: strings.ToLower(base)},
		{Case: "spaces", Input: strings.ReplaceAll(base, "-", " ")},
		{Case: "no-separators", Input: flat},
		{Case: "letters-for-digits", Input: strings.NewReplacer("0", "O", "1", "l").Replace(base)},
		{Case: "surrounding-whitespace", Input: "  " + base + "\n"},
	}
	for i := range aliases {
		aliases[i].Code = base
	}
	// The first single-symbol change and the first adjacent swap the checksum catches (deterministic).
	var typo, swap string
	for i := 0; i < 28 && typo == ""; i++ {
		for _, c := range crockford {
			candidate := flat[:i] + string(c) + flat[i+1:]
			if candidate != flat && candidate[0] < '8' {
				if _, ok := parseRecoveryCode(candidate); !ok {
					typo = candidate
					break
				}
			}
		}
	}
	for i := 0; i < 27 && swap == ""; i++ {
		candidate := flat[:i] + string(flat[i+1]) + string(flat[i]) + flat[i+2:]
		if _, ok := parseRecoveryCode(candidate); candidate != flat && !ok {
			swap = candidate
		}
	}
	// The last symbol carries checksum bits only: any other value keeps the secret and breaks the checksum.
	last := strings.IndexByte(crockford, flat[27])
	badChecksum := flat[:27] + string(crockford[(last+1)%32])
	// codes[0] starts with "0", so short and long carry the same value and checksum: only the
	// length check refuses them. Overflow sets bit 138 alone, which the 16-byte secret drops.
	if flat[0] != '0' {
		panic("codes[0] must start with 0")
	}
	rejects := []recoveryInput{
		{Case: "short", Input: flat[1:]},
		{Case: "long", Input: "0" + flat},
		{Case: "bad-symbol", Input: flat[:5] + "U" + flat[6:]},
		{Case: "overflow", Input: "8" + flat[1:]},
		{Case: "typo", Input: typo},
		{Case: "transposed", Input: swap},
		{Case: "bad-checksum", Input: badChecksum},
	}

	c := codes[0]
	secret, priv, pub := mustHex(c.Secret), mustHex(c.PrivateKey), mustHex(c.PublicKey)
	reject := func(name, reason, userID string, publicKey []byte, wrapAlg string, wrapped []byte) recoveryOpenReject {
		return recoveryOpenReject{name, reason, c.Secret, userID, hex.EncodeToString(publicKey), wrapAlg, hex.EncodeToString(wrapped)}
	}
	tampered := mustHex(c.Wrapped)
	tampered[40] ^= 1
	openRejects := []recoveryOpenReject{
		// Each of these two opens if the client believed the server's label or length.
		reject("low-iterations", "alg", c.UserID, pub, "pbkdf2-sha256-1000/aes-256-gcm", sealRecoveryRef(secret, c.UserID, priv, pub, seq(0x20, 16), seq(0x40, 12), 1000)),
		reject("short-salt", "format", c.UserID, pub, recoveryAlg, sealRecoveryRef(secret, c.UserID, priv, pub, seq(0x20, 8), seq(0x40, 12), recoveryIterations)),
		reject("wrong-code", "aead", c.UserID, pub, recoveryAlg, mustHex(codes[1].Wrapped)),
		reject("wrong-user", "aead", codes[1].UserID, pub, recoveryAlg, mustHex(c.Wrapped)),
		reject("wrong-public-key", "aead", c.UserID, mustHex(codes[1].PublicKey), recoveryAlg, mustHex(c.Wrapped)),
		reject("tamper", "aead", c.UserID, pub, recoveryAlg, tampered),
		// AAD names codes[1]'s public key, but the sealed private key is codes[0]'s.
		reject("key-mismatch", "public-key", c.UserID, mustHex(codes[1].PublicKey), recoveryAlg, sealRecoveryRef(secret, c.UserID, priv, mustHex(codes[1].PublicKey), seq(0x20, 16), seq(0x40, 12), recoveryIterations)),
	}
	return recoveryVectors{Codes: codes, Aliases: aliases, Rejects: rejects, OpenRejects: openRejects}
}

func TestRecoveryVectors(t *testing.T) {
	v := generateRecovery()
	for _, c := range v.Codes {
		secret, ok := parseRecoveryCode(c.Code)
		if !ok || hex.EncodeToString(secret) != c.Secret {
			t.Fatalf("%s does not parse back to %s", c.Code, c.Secret)
		}
		priv, reason := openRecoveryRef(secret, recoveryAlg, mustHex(c.Wrapped), c.UserID, mustHex(c.PublicKey))
		if reason != "" || hex.EncodeToString(priv) != c.PrivateKey {
			t.Fatalf("%s does not open: %s", c.Code, reason)
		}
	}
	for _, a := range v.Aliases {
		if secret, ok := parseRecoveryCode(a.Input); !ok || recoveryCode(secret) != a.Code {
			t.Fatalf("alias %s did not parse", a.Case)
		}
	}
	for _, r := range v.Rejects {
		if r.Input == "" {
			t.Fatalf("reject %s has no input", r.Case)
		}
		if _, ok := parseRecoveryCode(r.Input); ok {
			t.Fatalf("reject %s parsed", r.Case)
		}
	}
	for _, r := range v.OpenRejects {
		if _, reason := openRecoveryRef(mustHex(r.Secret), r.WrapAlg, mustHex(r.Wrapped), r.UserID, mustHex(r.PublicKey)); reason != r.Reason {
			t.Fatalf("open reject %s: got %q, want %q", r.Case, reason, r.Reason)
		}
	}
	got, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *update {
		if err := os.WriteFile(recoveryVectorFile, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(recoveryVectorFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale; run go test ./internal/teamkeys -run TestRecoveryVectors -update", recoveryVectorFile)
	}
}
