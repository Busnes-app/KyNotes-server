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

// EnvelopeBytes is the sealed size of a 32-byte content key.
const EnvelopeBytes = 93

const envelopeLabel = "kynotes/envelope/v1"

var aadID = regexp.MustCompile(`^(cnt|dev)_[0-9a-hjkmnp-tv-z]{26}$`)

func envelopeAAD(containerID string, generation uint32, deviceID string) ([]byte, error) {
	if !aadID.MatchString(containerID) || containerID[:3] != "cnt" || !aadID.MatchString(deviceID) || deviceID[:3] != "dev" || generation == 0 {
		return nil, errors.New("teamkeys: invalid envelope binding")
	}
	aad := append([]byte(envelopeLabel), containerID...)
	aad = binary.BigEndian.AppendUint32(aad, generation)
	return append(aad, deviceID...), nil
}

func envelopeAEAD(shared, ephPub, recipientPub []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, shared, append(bytes.Clone(ephPub), recipientPub...), envelopeLabel, 32)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.New(key)
}

// SealEnvelope wraps contentKey for recipientPub (raw X25519) bound to the
// container, generation and recipient device. Same bytes as web/src/teamKeys.ts.
func SealEnvelope(contentKey, recipientPub []byte, containerID string, generation uint32, deviceID string) ([]byte, error) {
	aad, err := envelopeAAD(containerID, generation, deviceID)
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
	shared, err := eph.ECDH(recipient)
	if err != nil {
		return nil, err
	}
	aead, err := envelopeAEAD(shared, eph.PublicKey().Bytes(), recipientPub)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte{0x01}, eph.PublicKey().Bytes()...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, contentKey, aad), nil
}

// OpenEnvelope returns the content key sealed by SealEnvelope.
func OpenEnvelope(envelope []byte, recipient *ecdh.PrivateKey, containerID string, generation uint32, deviceID string) ([]byte, error) {
	aad, err := envelopeAAD(containerID, generation, deviceID)
	if err != nil {
		return nil, err
	}
	if len(envelope) != EnvelopeBytes || envelope[0] != 0x01 {
		return nil, errors.New("teamkeys: malformed envelope")
	}
	eph, err := ecdh.X25519().NewPublicKey(envelope[1:33])
	if err != nil {
		return nil, err
	}
	shared, err := recipient.ECDH(eph)
	if err != nil {
		return nil, err
	}
	aead, err := envelopeAEAD(shared, envelope[1:33], recipient.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, envelope[33:45], envelope[45:], aad)
}
