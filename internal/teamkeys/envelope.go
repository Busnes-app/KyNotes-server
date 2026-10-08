package teamkeys

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"regexp"

	"golang.org/x/crypto/chacha20poly1305"
)

// EnvelopeBytes is the sealed size of a 32-byte content key:
// 0x02 | senderDeviceID(30) | ephPub(32) | nonce(12) | ct+tag(48).
const EnvelopeBytes = 123

const (
	envelopeLabel   = "kynotes/envelope/v2"
	envelopeVersion = 0x02
	idLen           = 30
)

var aadID = regexp.MustCompile(`^(cnt|dev|usr)_[0-9a-hjkmnp-tv-z]{26}$`)

func validID(prefix, id string) bool { return aadID.MatchString(id) && id[:3] == prefix }

func envelopeAAD(containerID string, generation uint32, recipientDeviceID, senderDeviceID string) ([]byte, error) {
	if !validID("cnt", containerID) || !validID("dev", recipientDeviceID) || !validID("dev", senderDeviceID) || generation == 0 {
		return nil, errors.New("teamkeys: invalid envelope binding")
	}
	aad := append([]byte(envelopeLabel), containerID...)
	aad = binary.BigEndian.AppendUint32(aad, generation)
	aad = append(aad, recipientDeviceID...)
	return append(aad, senderDeviceID...), nil
}

// envelopeAEAD keys the envelope from both the ephemeral and the sender's
// static identity agreement, so only the sender (or the recipient) can seal it.
func envelopeAEAD(ephShared, staticShared, ephPub, recipientPub, senderPub []byte) (cipher.AEAD, error) {
	salt := append(append(bytes.Clone(ephPub), recipientPub...), senderPub...)
	key, err := hkdf.Key(sha256.New, append(bytes.Clone(ephShared), staticShared...), salt, envelopeLabel, 32)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.New(key)
}

// SealEnvelope wraps contentKey for recipientPub (raw X25519), authenticated by
// the sender's identity key and bound to the container, generation and both
// devices. Same bytes as web/src/teamKeys.ts.
func SealEnvelope(contentKey, recipientPub []byte, containerID string, generation uint32, recipientDeviceID string, sender *ecdh.PrivateKey, senderDeviceID string) ([]byte, error) {
	aad, err := envelopeAAD(containerID, generation, recipientDeviceID, senderDeviceID)
	if err != nil || len(contentKey) != 32 {
		return nil, errors.New("teamkeys: invalid envelope input")
	}
	recipient, err := ecdh.X25519().NewPublicKey(recipientPub)
	if err != nil {
		return nil, err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ephShared, err := eph.ECDH(recipient)
	if err != nil {
		return nil, err
	}
	staticShared, err := sender.ECDH(recipient)
	if err != nil {
		return nil, err
	}
	aead, err := envelopeAEAD(ephShared, staticShared, eph.PublicKey().Bytes(), recipientPub, sender.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte{envelopeVersion}, senderDeviceID...)
	out = append(out, eph.PublicKey().Bytes()...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, contentKey, aad), nil
}

// EnvelopeSender returns the sender device ID the envelope claims. It is
// unauthenticated until OpenEnvelope succeeds with that device's identity key.
func EnvelopeSender(envelope []byte) (string, error) {
	if len(envelope) != EnvelopeBytes || envelope[0] != envelopeVersion || !validID("dev", string(envelope[1:1+idLen])) {
		return "", errors.New("teamkeys: malformed envelope")
	}
	return string(envelope[1 : 1+idLen]), nil
}

// OpenEnvelope returns the content key sealed by SealEnvelope. senderPub is the
// identity key the caller resolved for EnvelopeSender(envelope).
func OpenEnvelope(envelope []byte, recipient *ecdh.PrivateKey, containerID string, generation uint32, recipientDeviceID string, senderPub []byte) ([]byte, error) {
	senderDeviceID, err := EnvelopeSender(envelope)
	if err != nil {
		return nil, err
	}
	aad, err := envelopeAAD(containerID, generation, recipientDeviceID, senderDeviceID)
	if err != nil {
		return nil, err
	}
	ephPub, nonce, sealed := envelope[1+idLen:63], envelope[63:75], envelope[75:]
	eph, err := ecdh.X25519().NewPublicKey(ephPub)
	if err != nil {
		return nil, err
	}
	sender, err := ecdh.X25519().NewPublicKey(senderPub)
	if err != nil {
		return nil, err
	}
	ephShared, err := recipient.ECDH(eph)
	if err != nil {
		return nil, err
	}
	staticShared, err := recipient.ECDH(sender)
	if err != nil {
		return nil, err
	}
	aead, err := envelopeAEAD(ephShared, staticShared, ephPub, recipient.PublicKey().Bytes(), senderPub)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, sealed, aad)
}
