// Package keyprotocol owns public identity encodings and envelope framing.
// It contains no private-key operations; the server stores private copies opaque.
package keyprotocol

import (
	"crypto/ecdh"
	"errors"
	"regexp"

	"github.com/Busnes-app/ky-primitives/hybridsig"
	"github.com/Busnes-app/ky-primitives/xwing"
)

const (
	PQEnvelopeAlg          = "hpke-base-xwing-647a-hkdfsha256-aes256gcm-hybridsig"
	PQEnvelopeBytes        = 31 + xwing.Overhead + 32 + hybridsig.SignatureBytes
	PQPublicBytes          = 1 + 32 + xwing.PublicKeyBytes + hybridsig.PublicKeyBytes
	PQPrivateBytes         = 129 + PQPublicBytes
	PQWrappedIdentityBytes = 28 + PQPrivateBytes
	PQRecoveryBytes        = 44 + PQPrivateBytes
)

var idPattern = regexp.MustCompile(`^(cnt|dev|usr)_[0-9a-hjkmnp-tv-z]{26}$`)

func ValidID(prefix, id string) bool { return idPattern.MatchString(id) && id[:3] == prefix }
func ValidatePublicIdentity(public []byte) error {
	if len(public) == 32 {
		_, err := ecdh.X25519().NewPublicKey(public)
		return err
	}
	if len(public) != PQPublicBytes || public[0] != 4 {
		return errors.New("keyprotocol: invalid public identity")
	}
	if _, err := xwing.ParsePublicKey(public[33 : 33+xwing.PublicKeyBytes]); err != nil {
		return err
	}
	_, err := hybridsig.ParsePublicKey(public[33+xwing.PublicKeyBytes:])
	return err
}

// EnvelopeSender validates v4 framing only. The claim is untrusted until the
// recipient verifies the HybridSig proof; the server cannot open the envelope.
func EnvelopeSender(alg string, envelope []byte) (string, error) {
	if alg != PQEnvelopeAlg || len(envelope) != PQEnvelopeBytes || envelope[0] != 4 || !ValidID("dev", string(envelope[1:31])) {
		return "", errors.New("keyprotocol: invalid envelope")
	}
	return string(envelope[1:31]), nil
}
