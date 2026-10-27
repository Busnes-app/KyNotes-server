package teamkeys

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"golang.org/x/crypto/curve25519"
)

const (
	linkVectorFile = "../../testdata/protocol/link_vectors.json"
	linkLabel      = "kynotes/link/v2"
	linkCommit     = "kynotes/link-commit/v1"
	linkCheck      = "kynotes/link-check/v1"
	linkVersion    = 0x02
	// linkBundleBytes is 0x02 | enc(32) | ChaCha20-Poly1305(identity private key)(48).
	linkBundleBytes = 81
	// frozenV1Bundle is links[0] of the retired v1 format (0x01 | nonce | ct, 61 bytes); v2 refuses it.
	frozenV1Bundle = "01000102030405060708090a0bfbd2108bdfce6af471589de812d1a31dc4e681c6a0312fcc701fe34b50e404040718695a437e49e6dc0583797eed612b"
)

// lowOrderPoints are the seven classic bad X25519 encodings: u = 0, 1, both order-8 points,
// p-1, p and p+1. Each gives an all-zero agreement, which must be refused.
var lowOrderPoints = []struct{ name, hex string }{
	{"zero", "0000000000000000000000000000000000000000000000000000000000000000"},
	{"one", "0100000000000000000000000000000000000000000000000000000000000000"},
	{"order8-a", "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"},
	{"order8-b", "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"},
	{"p-minus-1", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
	{"p", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
	{"p-plus-1", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
}

type linkVector struct {
	UserID             string `json:"userId"`
	RequestID          string `json:"requestId"`
	IdentityDeviceID   string `json:"identityDeviceId"`
	IdentityPrivateKey string `json:"identityPrivateKey"`
	ApproverPrivateKey string `json:"approverPrivateKey"`
	ApproverPublicKey  string `json:"approverPublicKey"`
	NewcomerPrivateKey string `json:"newcomerPrivateKey"`
	NewcomerPublicKey  string `json:"newcomerPublicKey"`
	EphemeralSeed      string `json:"ephemeralSeed"`
	Info               string `json:"info"`
	Commitment         string `json:"commitment"`
	CheckCode          string `json:"checkCode"`
	Bundle             string `json:"bundle"`
}

// linkReject is what a newcomer would be handed after one change to links[0]. Reason names the
// check that must refuse it: "commitment" (H(newcomer key) differs from the one posted at create),
// or the openLink / openLinkBundle reason "format", "newcomer-key", "low-order" or "aead".
type linkReject struct {
	Case               string `json:"case"`
	Reason             string `json:"reason"`
	UserID             string `json:"userId"`
	RequestID          string `json:"requestId"`
	IdentityDeviceID   string `json:"identityDeviceId"`
	ApproverPublicKey  string `json:"approverPublicKey"`
	NewcomerPrivateKey string `json:"newcomerPrivateKey"`
	NewcomerPublicKey  string `json:"newcomerPublicKey"`
	Commitment         string `json:"commitment"`
	Bundle             string `json:"bundle"`
}

type linkVectors struct {
	Links   []linkVector `json:"links"`
	Rejects []linkReject `json:"rejects"`
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// linkInfo is the v2 HPKE info: label | userID | requestID | identityDeviceID | approverKey | newcomerKey.
func linkInfo(userID, requestID, deviceID string, approverPub, newcomerPub []byte) []byte {
	return cat([]byte(linkLabel), []byte(userID), []byte(requestID), []byte(deviceID), approverPub, newcomerPub)
}

// sealLink is the approver side: RFC 9180 HPKE mode_auth from sender (the approver's one-time key)
// to newcomerPub, the envelope v3 suite, ikmE read from seed. A nil sender seals in mode_base,
// which only reject vectors use.
func sealLink(t *testing.T, sender, newcomerPub, info, seed, identityPriv []byte) []byte {
	t.Helper()
	pkR, err := kemScheme.UnmarshalBinaryPublicKey(newcomerPub)
	if err != nil {
		t.Fatal(err)
	}
	s, err := suite.NewSender(pkR, info)
	if err != nil {
		t.Fatal(err)
	}
	var enc []byte
	var sealer interface {
		Seal(pt, aad []byte) ([]byte, error)
	}
	if sender == nil {
		enc, sealer, err = s.Setup(bytes.NewReader(seed))
	} else {
		skS, kerr := kemScheme.UnmarshalBinaryPrivateKey(sender)
		if kerr != nil {
			t.Fatal(kerr)
		}
		enc, sealer, err = s.SetupAuth(bytes.NewReader(seed), skS)
	}
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sealer.Seal(identityPriv, nil)
	if err != nil {
		t.Fatal(err)
	}
	return cat([]byte{linkVersion}, enc, ct)
}

// openLink is the newcomer side. Its error text is the refusal reason web/src/linking.ts reports.
func openLink(userID, requestID, deviceID string, approverPub, newcomerPriv, newcomerPub, bundle []byte) ([]byte, error) {
	if len(bundle) != linkBundleBytes || bundle[0] != linkVersion || len(approverPub) != 32 {
		return nil, errors.New("format")
	}
	own, err := curve25519.X25519(newcomerPriv, curve25519.Basepoint)
	if err != nil || subtle.ConstantTimeCompare(own, newcomerPub) != 1 {
		return nil, errors.New("newcomer-key")
	}
	// HPKE refuses an all-zero agreement too; this names it.
	if _, err := curve25519.X25519(newcomerPriv, approverPub); err != nil {
		return nil, errors.New("low-order")
	}
	aead := errors.New("aead")
	skR, err := kemScheme.UnmarshalBinaryPrivateKey(newcomerPriv)
	if err != nil {
		return nil, aead
	}
	pkS, err := kemScheme.UnmarshalBinaryPublicKey(approverPub)
	if err != nil {
		return nil, aead
	}
	r, err := suite.NewReceiver(skR, linkInfo(userID, requestID, deviceID, approverPub, newcomerPub))
	if err != nil {
		return nil, aead
	}
	opener, err := r.SetupAuth(bundle[1:33], pkS)
	if err != nil {
		return nil, aead
	}
	pt, err := opener.Open(bundle[33:], nil)
	if err != nil {
		return nil, aead
	}
	return pt, nil
}

func commitmentMatches(commitment, newcomerPub []byte) bool {
	want := sha256.Sum256(cat([]byte(linkCommit), newcomerPub))
	return subtle.ConstantTimeCompare(commitment, want[:]) == 1
}

func checkDigits(userID, requestID string, approverPub, newcomerPub []byte) string {
	check := sha256.Sum256(cat([]byte(linkCheck), []byte(userID), []byte(requestID), approverPub, newcomerPub))
	return fmt.Sprintf("%06d", binary.BigEndian.Uint32(check[:4])%1_000_000)
}

// link builds one vector the way web/src/linking.ts must: commitment, check code and a sealed
// bundle the newcomer side opens.
func link(t *testing.T, userID, requestID, deviceID, identityPriv, approverPriv, newcomerPriv, seed string) linkVector {
	mustID(t, "usr", userID)
	mustID(t, "lnk", requestID)
	mustID(t, "dev", deviceID)
	approverPub := x25519(t, unhex(t, approverPriv), curve25519.Basepoint)
	newcomerPub := x25519(t, unhex(t, newcomerPriv), curve25519.Basepoint)
	commitment := sha256.Sum256(cat([]byte(linkCommit), newcomerPub))
	digits := checkDigits(userID, requestID, approverPub, newcomerPub)
	info := linkInfo(userID, requestID, deviceID, approverPub, newcomerPub)
	bundle := sealLink(t, unhex(t, approverPriv), newcomerPub, info, unhex(t, seed), unhex(t, identityPriv))
	if len(bundle) != linkBundleBytes {
		t.Fatalf("bundle is %d bytes, want %d", len(bundle), linkBundleBytes)
	}
	// The newcomer opens it with its own agreement.
	if pt, err := openLink(userID, requestID, deviceID, approverPub, unhex(t, newcomerPriv), newcomerPub, bundle); err != nil || !bytes.Equal(pt, unhex(t, identityPriv)) {
		t.Fatalf("round trip failed: %v", err)
	}
	return linkVector{userID, requestID, deviceID, identityPriv, approverPriv, hex.EncodeToString(approverPub), newcomerPriv, hex.EncodeToString(newcomerPub), seed, hex.EncodeToString(info), hex.EncodeToString(commitment[:]), digits[:3] + " " + digits[3:], hex.EncodeToString(bundle)}
}

// zeroLedRequestID is the first lnk_ ID (counting up from all zeros) whose check code for these
// keys starts with 0, so the vectors pin zero padding.
func zeroLedRequestID(t *testing.T, userID, approverPriv, newcomerPriv string) string {
	const alphabet = "0123456789abcdefghjkmnpqrstvwxyz"
	approverPub := x25519(t, unhex(t, approverPriv), curve25519.Basepoint)
	newcomerPub := x25519(t, unhex(t, newcomerPriv), curve25519.Basepoint)
	for i := 0; i < 32*32*32; i++ {
		id := "lnk_" + "00000000000000000000000" + string(alphabet[i/1024]) + string(alphabet[i/32%32]) + string(alphabet[i%32])
		if checkDigits(userID, id, approverPub, newcomerPub)[0] == '0' {
			return id
		}
	}
	t.Fatal("no zero-led check code found")
	return ""
}

// rejects derives one refused input per change to base and proves openLink refuses it for the
// named reason. other supplies foreign IDs and keys; relayed is base with the relay's key as the
// newcomer's.
func rejects(t *testing.T, base, other, relayed linkVector) []linkReject {
	r := func(name, reason string) linkReject {
		return linkReject{name, reason, base.UserID, base.RequestID, base.IdentityDeviceID, base.ApproverPublicKey, base.NewcomerPrivateKey, base.NewcomerPublicKey, base.Commitment, base.Bundle}
	}
	flip := func(at int) string {
		b := unhex(t, base.Bundle)
		b[at] ^= 1
		return hex.EncodeToString(b)
	}
	var out []linkReject
	add := func(v linkReject) { out = append(out, v) }

	approverPub, newcomerPub := unhex(t, base.ApproverPublicKey), unhex(t, base.NewcomerPublicKey)
	baseInfo := unhex(t, base.Info)
	seed, identityPriv := unhex(t, base.EphemeralSeed), unhex(t, base.IdentityPrivateKey)

	v := r("tampered-ciphertext", "aead")
	v.Bundle = flip(40)
	add(v)
	v = r("tampered-tag", "aead")
	v.Bundle = flip(80)
	add(v)
	v = r("tampered-enc", "aead")
	v.Bundle = flip(1)
	add(v)
	v = r("wrong-version", "format")
	v.Bundle = flip(0)
	add(v)
	v = r("v1-version-v2-length", "format")
	v.Bundle = "01" + base.Bundle[2:]
	add(v)
	v = r("v1-bundle", "format")
	v.Bundle = frozenV1Bundle
	add(v)
	v = r("v2-version-v1-length", "format")
	v.Bundle = "02" + frozenV1Bundle[2:]
	add(v)
	v = r("truncated", "format")
	v.Bundle = base.Bundle[:2*(linkBundleBytes-1)]
	add(v)
	v = r("swapped-keys", "newcomer-key")
	v.ApproverPublicKey, v.NewcomerPublicKey = base.NewcomerPublicKey, base.ApproverPublicKey
	add(v)
	v = r("wrong-newcomer-key", "newcomer-key")
	v.NewcomerPublicKey = relayed.NewcomerPublicKey
	add(v)
	v = r("wrong-newcomer-private-key", "newcomer-key")
	v.NewcomerPrivateKey = relayed.NewcomerPrivateKey
	add(v)
	// A consistent key pair that is not the one sealed to: past every precheck, HPKE refuses.
	v = r("bundle-for-another-newcomer", "aead")
	v.NewcomerPrivateKey, v.NewcomerPublicKey = relayed.NewcomerPrivateKey, relayed.NewcomerPublicKey
	add(v)
	// The keys bound into info in the wrong order: only the key schedule can catch it.
	v = r("keys-reversed-in-binding", "aead")
	v.Bundle = hex.EncodeToString(sealLink(t, unhex(t, base.ApproverPrivateKey), newcomerPub, linkInfo(base.UserID, base.RequestID, base.IdentityDeviceID, newcomerPub, approverPub), seed, identityPriv))
	add(v)
	// The right info but no binding at all past the label.
	v = r("label-only-info", "aead")
	v.Bundle = hex.EncodeToString(sealLink(t, unhex(t, base.ApproverPrivateKey), newcomerPub, []byte(linkLabel), seed, identityPriv))
	add(v)
	// mode_base: anyone (the relay) can seal to the newcomer's key; Auth mode refuses it.
	v = r("unauthenticated-sender", "aead")
	v.Bundle = hex.EncodeToString(sealLink(t, nil, newcomerPub, baseInfo, seed, identityPriv))
	add(v)
	// mode_auth from a key other than the approver's the check code covers.
	v = r("wrong-sender", "aead")
	v.Bundle = hex.EncodeToString(sealLink(t, unhex(t, relayed.NewcomerPrivateKey), newcomerPub, baseInfo, seed, identityPriv))
	add(v)
	v = r("wrong-approver-key", "aead")
	v.ApproverPublicKey = other.ApproverPublicKey
	add(v)
	for _, p := range lowOrderPoints {
		v = r("low-order-approver-key-"+p.name, "low-order")
		v.ApproverPublicKey = p.hex
		add(v)
	}
	v = r("wrong-request", "aead")
	v.RequestID = other.RequestID
	add(v)
	v = r("wrong-user", "aead")
	v.UserID = other.UserID
	add(v)
	v = r("wrong-identity-device", "aead")
	v.IdentityDeviceID = other.IdentityDeviceID
	add(v)
	// The relay swapped in its own newcomer key after create; the approver sealed to it, so the
	// bundle opens for the relay. Only the commitment posted at create catches it.
	v = r("commitment-mismatch", "commitment")
	v.NewcomerPrivateKey, v.NewcomerPublicKey, v.Bundle = relayed.NewcomerPrivateKey, relayed.NewcomerPublicKey, relayed.Bundle
	add(v)

	for _, v := range out {
		_, openErr := openLink(v.UserID, v.RequestID, v.IdentityDeviceID, unhex(t, v.ApproverPublicKey), unhex(t, v.NewcomerPrivateKey), unhex(t, v.NewcomerPublicKey), unhex(t, v.Bundle))
		committed := commitmentMatches(unhex(t, v.Commitment), unhex(t, v.NewcomerPublicKey))
		if v.Reason == "commitment" {
			if committed || openErr != nil {
				t.Fatalf("%s: commitment matched=%v, open err=%v; want only the commitment to refuse", v.Case, committed, openErr)
			}
		} else if openErr == nil || openErr.Error() != v.Reason {
			t.Fatalf("%s: open err=%v, want %q", v.Case, openErr, v.Reason)
		}
	}
	return out
}

func generateLinks(t *testing.T) linkVectors {
	alice := "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	bob := "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
	carol := "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
	dave := "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"
	base := link(t, "usr_0123456789abcdefghjkmnpqrs", "lnk_00000000000000000000000000", "dev_00000000000000000000000000", carol, alice, bob, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	// Same request, but the relay's key (dave) replaced the newcomer's after the commitment.
	relayed := link(t, base.UserID, base.RequestID, base.IdentityDeviceID, carol, alice, dave, base.EphemeralSeed)
	other := link(t, "usr_zyxwvtsrqpnmkjhgfedcba9876", "lnk_tvwxyz0123456789abcdefghjk", "dev_mnpqrstvwxyz0123456789abcd", dave, bob, alice, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	padded := link(t, base.UserID, zeroLedRequestID(t, base.UserID, carol, dave), base.IdentityDeviceID, bob, carol, dave, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")
	if padded.CheckCode[0] != '0' {
		t.Fatalf("padded vector code %q has no leading zero", padded.CheckCode)
	}
	return linkVectors{Links: []linkVector{base, other, padded}, Rejects: rejects(t, base, other, relayed)}
}

func TestLinkVectors(t *testing.T) {
	got, err := json.MarshalIndent(generateLinks(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *update {
		if err := os.WriteFile(linkVectorFile, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(linkVectorFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale; run go test ./internal/teamkeys -run TestLinkVectors -update", linkVectorFile)
	}
}

func TestLinkVectorsCheckCodeBindsKeyOrder(t *testing.T) {
	v := generateLinks(t).Links[0]
	if checkDigits(v.UserID, v.RequestID, unhex(t, v.NewcomerPublicKey), unhex(t, v.ApproverPublicKey)) == v.CheckCode[:3]+v.CheckCode[4:] {
		t.Fatal("check code ignores key order")
	}
}
