package teamkeys

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"regexp"

	"github.com/cloudflare/circl/hpke"
)

// Envelope v3 is RFC 9180 HPKE in mode_auth, suite DHKEM(X25519, HKDF-SHA256) /
// HKDF-SHA256 / ChaCha20Poly1305, single-shot over the 32-byte content key:
// 0x03 | senderDeviceID(30) | enc(32) | ct+tag(48). Every new envelope is v3.
const (
	EnvelopeAlg   = "hpke-auth-x25519-hkdfsha256-chacha20poly1305"
	EnvelopeBytes = 111
)

// Envelope v2 is the earlier custom construction, opened for stored rows only:
// 0x02 | senderDeviceID(30) | ephPub(32) | nonce(12) | ct+tag(48).
const (
	LegacyEnvelopeAlg   = "x25519-hkdf-sha256-chacha20poly1305"
	LegacyEnvelopeBytes = 123
)

const (
	envelopeLabel   = "kynotes/envelope/v3"
	envelopeVersion = 0x03
	idLen           = 30
)

var (
	suite     = hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305)
	kemScheme = hpke.KEM_X25519_HKDF_SHA256.Scheme()
	aadID     = regexp.MustCompile(`^(cnt|dev|usr)_[0-9a-hjkmnp-tv-z]{26}$`)
)

func validID(prefix, id string) bool { return aadID.MatchString(id) && id[:3] == prefix }

// envelopeContext is label | containerID | generation (u32 BE) | recipientDeviceID |
// senderDeviceID: the v3 HPKE info and, with the v2 label, the v2 AAD.
func envelopeContext(label, containerID string, generation uint32, recipientDeviceID, senderDeviceID string) ([]byte, error) {
	if !validID("cnt", containerID) || !validID("dev", recipientDeviceID) || !validID("dev", senderDeviceID) || generation == 0 {
		return nil, errors.New("teamkeys: invalid envelope binding")
	}
	ctx := append([]byte(label), containerID...)
	ctx = binary.BigEndian.AppendUint32(ctx, generation)
	ctx = append(ctx, recipientDeviceID...)
	return append(ctx, senderDeviceID...), nil
}

// SealEnvelope wraps contentKey for recipientPub (raw X25519) as a v3 envelope,
// authenticated by the sender's identity key and bound to the container,
// generation and both devices. Same bytes as web/src/teamKeys.ts.
func SealEnvelope(contentKey, recipientPub []byte, containerID string, generation uint32, recipientDeviceID string, sender *ecdh.PrivateKey, senderDeviceID string) ([]byte, error) {
	return sealEnvelope(rand.Reader, contentKey, recipientPub, containerID, generation, recipientDeviceID, sender, senderDeviceID)
}

// sealEnvelope reads the HPKE ephemeral seed (ikmE) from rnd; tests pass a fixed one.
func sealEnvelope(rnd io.Reader, contentKey, recipientPub []byte, containerID string, generation uint32, recipientDeviceID string, sender *ecdh.PrivateKey, senderDeviceID string) ([]byte, error) {
	info, err := envelopeContext(envelopeLabel, containerID, generation, recipientDeviceID, senderDeviceID)
	if err != nil || len(contentKey) != 32 {
		return nil, errors.New("teamkeys: invalid envelope input")
	}
	pkR, err := kemScheme.UnmarshalBinaryPublicKey(recipientPub)
	if err != nil {
		return nil, err
	}
	skS, err := kemScheme.UnmarshalBinaryPrivateKey(sender.Bytes())
	if err != nil {
		return nil, err
	}
	s, err := suite.NewSender(pkR, info)
	if err != nil {
		return nil, err
	}
	enc, sealer, err := s.SetupAuth(rnd, skS)
	if err != nil {
		return nil, err
	}
	ct, err := sealer.Seal(contentKey, nil)
	if err != nil {
		return nil, err
	}
	out := append([]byte{envelopeVersion}, senderDeviceID...)
	return append(append(out, enc...), ct...), nil
}

// EnvelopeSender returns the sender device ID an envelope of the given alg
// claims. It is unauthenticated until OpenEnvelope succeeds with that device's
// identity key. The alg, version byte and length must agree.
func EnvelopeSender(alg string, envelope []byte) (string, error) {
	version, size := byte(envelopeVersion), EnvelopeBytes
	if alg == LegacyEnvelopeAlg {
		version, size = legacyEnvelopeVersion, LegacyEnvelopeBytes
	} else if alg != EnvelopeAlg {
		return "", errors.New("teamkeys: unsupported envelope alg")
	}
	if len(envelope) != size || envelope[0] != version || !validID("dev", string(envelope[1:1+idLen])) {
		return "", errors.New("teamkeys: malformed envelope")
	}
	return string(envelope[1 : 1+idLen]), nil
}

// OpenEnvelope returns the content key of a v3 or v2 envelope, selected by alg.
// senderPub is the identity key the caller resolved for EnvelopeSender.
func OpenEnvelope(alg string, envelope []byte, recipient *ecdh.PrivateKey, containerID string, generation uint32, recipientDeviceID string, senderPub []byte) ([]byte, error) {
	senderDeviceID, err := EnvelopeSender(alg, envelope)
	if err != nil {
		return nil, err
	}
	if alg == LegacyEnvelopeAlg {
		return openLegacyEnvelope(envelope, recipient, containerID, generation, recipientDeviceID, senderDeviceID, senderPub)
	}
	info, err := envelopeContext(envelopeLabel, containerID, generation, recipientDeviceID, senderDeviceID)
	if err != nil {
		return nil, err
	}
	skR, err := kemScheme.UnmarshalBinaryPrivateKey(recipient.Bytes())
	if err != nil {
		return nil, err
	}
	pkS, err := kemScheme.UnmarshalBinaryPublicKey(senderPub)
	if err != nil {
		return nil, err
	}
	r, err := suite.NewReceiver(skR, info)
	if err != nil {
		return nil, err
	}
	opener, err := r.SetupAuth(envelope[1+idLen:1+idLen+32], pkS)
	if err != nil {
		return nil, err
	}
	return opener.Open(envelope[1+idLen+32:], nil)
}
