package teamkeys

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	legacyEnvelopeLabel   = "kynotes/envelope/v2"
	legacyEnvelopeVersion = 0x02
)

// openLegacyEnvelope opens a stored v2 envelope. Nothing seals v2 any more.
// Key = HKDF-SHA256(DH(eph,R) || DH(senderStatic,R), salt = ephPub||recipientPub||senderPub,
// info = label); AAD = envelopeContext with the v2 label.
func openLegacyEnvelope(envelope []byte, recipient *ecdh.PrivateKey, containerID string, generation uint32, recipientDeviceID, senderDeviceID string, senderPub []byte) ([]byte, error) {
	aad, err := envelopeContext(legacyEnvelopeLabel, containerID, generation, recipientDeviceID, senderDeviceID)
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
	salt := append(append(bytes.Clone(ephPub), recipient.PublicKey().Bytes()...), senderPub...)
	key, err := hkdf.Key(sha256.New, append(ephShared, staticShared...), salt, legacyEnvelopeLabel, 32)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, sealed, aad)
}
