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
	"io"
	"os"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	linkVectorFile = "../../testdata/protocol/link_vectors.json"
	linkLabel      = "kynotes/link/v1"
	linkCommit     = "kynotes/link-commit/v1"
	linkCheck      = "kynotes/link-check/v1"
)

type linkVector struct {
	UserID             string `json:"userId"`
	RequestID          string `json:"requestId"`
	IdentityDeviceID   string `json:"identityDeviceId"`
	IdentityPrivateKey string `json:"identityPrivateKey"`
	ApproverPrivateKey string `json:"approverPrivateKey"`
	ApproverPublicKey  string `json:"approverPublicKey"`
	NewcomerPrivateKey string `json:"newcomerPrivateKey"`
	NewcomerPublicKey  string `json:"newcomerPublicKey"`
	Nonce              string `json:"nonce"`
	Commitment         string `json:"commitment"`
	CheckCode          string `json:"checkCode"`
	Bundle             string `json:"bundle"`
}

// linkReject is what a newcomer would be handed after one change to links[0]. Refused names the
// check that must fail: "commitment" (H(newcomer key) differs from the one posted at create) or
// "bundle" (opening must fail).
type linkReject struct {
	Case               string `json:"case"`
	Refused            string `json:"refused"`
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

func linkAAD(userID, requestID, deviceID string, approverPub, newcomerPub []byte) []byte {
	return cat([]byte(linkLabel), []byte(userID), []byte(requestID), []byte(deviceID), approverPub, newcomerPub)
}

// openLink is the newcomer side: the newcomer's own key must be the bound one, and any other
// binding, key or byte fails the AEAD. An all-zero agreement (low-order point) is an error.
func openLink(userID, requestID, deviceID string, approverPub, newcomerPriv, newcomerPub, bundle []byte) ([]byte, error) {
	if len(bundle) != 61 || bundle[0] != 0x01 || len(approverPub) != 32 {
		return nil, errors.New("unsupported link bundle")
	}
	own, err := curve25519.X25519(newcomerPriv, curve25519.Basepoint)
	if err != nil || subtle.ConstantTimeCompare(own, newcomerPub) != 1 {
		return nil, errors.New("not this newcomer's key")
	}
	shared, err := curve25519.X25519(newcomerPriv, approverPub)
	if err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, cat(approverPub, newcomerPub), []byte(linkLabel)), key); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, bundle[1:13], bundle[13:], linkAAD(userID, requestID, deviceID, approverPub, newcomerPub))
}

func commitmentMatches(commitment, newcomerPub []byte) bool {
	want := sha256.Sum256(cat([]byte(linkCommit), newcomerPub))
	return subtle.ConstantTimeCompare(commitment, want[:]) == 1
}

// link builds one vector the way web/src/linking.ts must: commitment, check code and a sealed
// bundle the newcomer side opens.
func link(t *testing.T, userID, requestID, deviceID, identityPriv, approverPriv, newcomerPriv, nonce string) linkVector {
	mustID(t, "usr", userID)
	mustID(t, "lnk", requestID)
	mustID(t, "dev", deviceID)
	approverPub := x25519(t, unhex(t, approverPriv), curve25519.Basepoint)
	newcomerPub := x25519(t, unhex(t, newcomerPriv), curve25519.Basepoint)
	commitment := sha256.Sum256(cat([]byte(linkCommit), newcomerPub))
	check := sha256.Sum256(cat([]byte(linkCheck), []byte(userID), []byte(requestID), approverPub, newcomerPub))
	digits := fmt.Sprintf("%06d", binary.BigEndian.Uint32(check[:4])%1_000_000)
	aead, err := chacha20poly1305.New(hkdf32(t, x25519(t, unhex(t, approverPriv), newcomerPub), cat(approverPub, newcomerPub), linkLabel))
	if err != nil {
		t.Fatal(err)
	}
	n := unhex(t, nonce)
	bundle := aead.Seal(cat([]byte{0x01}, n), n, unhex(t, identityPriv), linkAAD(userID, requestID, deviceID, approverPub, newcomerPub))
	if len(bundle) != 61 {
		t.Fatalf("bundle is %d bytes, want 61", len(bundle))
	}
	// The newcomer opens it with its own agreement.
	if pt, err := openLink(userID, requestID, deviceID, approverPub, unhex(t, newcomerPriv), newcomerPub, bundle); err != nil || !bytes.Equal(pt, unhex(t, identityPriv)) {
		t.Fatalf("round trip failed: %v", err)
	}
	return linkVector{userID, requestID, deviceID, identityPriv, approverPriv, hex.EncodeToString(approverPub), newcomerPriv, hex.EncodeToString(newcomerPub), nonce, hex.EncodeToString(commitment[:]), digits[:3] + " " + digits[3:], hex.EncodeToString(bundle)}
}

// rejects derives one refused input per change to base and proves the named check refuses it.
// other supplies foreign IDs and keys; relayed is base with the relay's key as the newcomer's.
func rejects(t *testing.T, base, other, relayed linkVector) []linkReject {
	r := func(name, refused string) linkReject {
		return linkReject{name, refused, base.UserID, base.RequestID, base.IdentityDeviceID, base.ApproverPublicKey, base.NewcomerPrivateKey, base.NewcomerPublicKey, base.Commitment, base.Bundle}
	}
	flip := func(at int) string {
		b := unhex(t, base.Bundle)
		b[at] ^= 1
		return hex.EncodeToString(b)
	}
	var out []linkReject
	add := func(v linkReject) { out = append(out, v) }

	v := r("tampered-ciphertext", "bundle")
	v.Bundle = flip(20)
	add(v)
	v = r("tampered-tag", "bundle")
	v.Bundle = flip(60)
	add(v)
	v = r("tampered-nonce", "bundle")
	v.Bundle = flip(1)
	add(v)
	v = r("wrong-version", "bundle")
	v.Bundle = flip(0)
	add(v)
	v = r("truncated", "bundle")
	v.Bundle = base.Bundle[:120]
	add(v)
	v = r("swapped-keys", "bundle")
	v.ApproverPublicKey, v.NewcomerPublicKey = base.NewcomerPublicKey, base.ApproverPublicKey
	add(v)
	v = r("wrong-approver-key", "bundle")
	v.ApproverPublicKey = other.ApproverPublicKey
	add(v)
	v = r("low-order-approver-key", "bundle")
	v.ApproverPublicKey = hex.EncodeToString(make([]byte, 32))
	add(v)
	v = r("wrong-request", "bundle")
	v.RequestID = other.RequestID
	add(v)
	v = r("wrong-user", "bundle")
	v.UserID = other.UserID
	add(v)
	v = r("wrong-identity-device", "bundle")
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
		switch v.Refused {
		case "bundle":
			if openErr == nil {
				t.Fatalf("%s: bundle opened", v.Case)
			}
		case "commitment":
			if committed || openErr != nil {
				t.Fatalf("%s: commitment matched=%v, open err=%v; want only the commitment to refuse", v.Case, committed, openErr)
			}
		}
	}
	return out
}

func generateLinks(t *testing.T) linkVectors {
	alice := "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	bob := "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
	carol := "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
	dave := "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"
	base := link(t, "usr_0123456789abcdefghjkmnpqrs", "lnk_00000000000000000000000000", "dev_00000000000000000000000000", carol, alice, bob, "000102030405060708090a0b")
	// Same request, but the relay's key (dave) replaced the newcomer's after the commitment.
	relayed := link(t, base.UserID, base.RequestID, base.IdentityDeviceID, carol, alice, dave, base.Nonce)
	other := link(t, "usr_zyxwvtsrqpnmkjhgfedcba9876", "lnk_tvwxyz0123456789abcdefghjk", "dev_mnpqrstvwxyz0123456789abcd", dave, bob, alice, "0c0d0e0f1011121314151617")
	return linkVectors{Links: []linkVector{base, other}, Rejects: rejects(t, base, other, relayed)}
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
	swapped := sha256.Sum256(cat([]byte(linkCheck), []byte(v.UserID), []byte(v.RequestID), unhex(t, v.NewcomerPublicKey), unhex(t, v.ApproverPublicKey)))
	if fmt.Sprintf("%06d", binary.BigEndian.Uint32(swapped[:4])%1_000_000) == v.CheckCode[:3]+v.CheckCode[4:] {
		t.Fatal("check code ignores key order")
	}
}
