package auth

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/password"
)

func contractSalt() string { return base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")) }

func TestDeriveAuthSecretRejectsShortSalt(t *testing.T) {
	if _, err := DeriveAuthSecret("x", base64.StdEncoding.EncodeToString([]byte("short")), MinLoginIterations); err == nil {
		t.Fatal("short salt accepted")
	}
}

func TestDeriveAuthSecretRejectsBadBase64(t *testing.T) {
	if _, err := DeriveAuthSecret("x", "not base64!", MinLoginIterations); err == nil {
		t.Fatal("bad salt accepted")
	}
}

func TestIterationsBelowMinimumRejected(t *testing.T) {
	if _, err := DeriveAuthSecret("x", contractSalt(), MinLoginIterations-1); err == nil {
		t.Fatal("low iteration count accepted")
	}
}

func TestIterationsAboveMaximumRejected(t *testing.T) {
	if _, err := DeriveAuthSecret("x", contractSalt(), MaxLoginIterations+1); err == nil {
		t.Fatal("high iteration count accepted")
	}
}

func TestProductionArgon2idCostIsTheSuiteProfile(t *testing.T) {
	// RFC 9106 second recommended profile: 64 MiB, t=3, p=4, the one answer
	// ky-primitives/password gives every product. A hash minted here must not
	// be considered stale by the library's own policy.
	if p := password.DefaultParams(); p.Memory != 64*1024 || p.Time != 3 || p.Threads != 4 {
		t.Fatalf("suite Argon2id profile changed: %+v", p)
	}
	h, err := HashAuthSecret("secret")
	if err != nil {
		t.Fatal(err)
	}
	if stale, _ := password.NeedsRehash(h); stale {
		t.Fatal("fresh hash reported as needing a rehash")
	}
}

func TestHashVerifyRoundTrip(t *testing.T) {
	h, err := HashAuthSecret(strings.Repeat("a", 64))
	if err != nil || VerifyAuthSecret(strings.Repeat("a", 64), h) != nil {
		t.Fatalf("round trip failed: %v", err)
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	h, err := HashAuthSecret("right")
	if err != nil {
		t.Fatal(err)
	}
	if VerifyAuthSecret("wrong", h) == nil {
		t.Fatal("wrong secret accepted")
	}
}

func TestVerifyParsesStoredCostParameters(t *testing.T) {
	h, err := HashAuthSecret("secret")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(h, "$")
	if len(parts) != 6 || VerifyAuthSecret("secret", strings.Join(parts, "$")) != nil {
		t.Fatal("self-describing verifier was not parsed")
	}
}

func TestPairingTokenExpiresAfter120Seconds(t *testing.T) {
	now := time.Unix(1000, 0)
	token, _, err := MintPairingToken(strings.Repeat("s", 32), "usr_test", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParsePairingToken(strings.Repeat("s", 32), token, "usr_test", now.Add(121*time.Second)); err == nil {
		t.Fatal("expired token accepted")
	}
}

func TestPairingTokenForgedSignatureIsRejected(t *testing.T) {
	token, _, err := MintPairingToken(strings.Repeat("s", 32), "usr_test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Mutate the decoded signature, not the encoded text: base64's final character
	// carries unused bits, so swapping it can decode to the same bytes and test
	// nothing. This asserts the MAC, not the encoder.
	parts := strings.Split(token, ".")
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 0xFF
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(sig)
	if _, err = ParsePairingToken(strings.Repeat("s", 32), forged, "usr_test", time.Now()); err == nil {
		t.Fatal("forged token accepted")
	}
}

// Four encodings of the same signature differ only in the final character's unused
// bits. Accepting them makes a token malleable, so only the canonical form verifies.
func TestPairingTokenRejectsNonCanonicalEncoding(t *testing.T) {
	token, _, err := MintPairingToken(strings.Repeat("s", 32), "usr_test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []byte{'x', 'y', 'z'} {
		mutated := token[:len(token)-1] + string(c)
		if mutated == token {
			continue
		}
		if _, err := ParsePairingToken(strings.Repeat("s", 32), mutated, "usr_test", time.Now()); err == nil {
			t.Fatalf("non-canonical encoding ending %q was accepted", c)
		}
	}
}

func TestPairingTokenWrongPurposeIsRejected(t *testing.T) {
	// Purpose is authenticated as part of the payload; a token minted by this
	// implementation cannot be changed without invalidating its MAC.
	token, _, err := MintPairingToken(strings.Repeat("s", 32), "usr_test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParsePairingToken(strings.Repeat("s", 32), token, "usr_other", time.Now()); err == nil {
		t.Fatal("token for another subject accepted")
	}
}
