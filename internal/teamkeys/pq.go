package teamkeys

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"

	"github.com/Busnes-app/ky-primitives/hybridsig"
	"github.com/Busnes-app/ky-primitives/xwing"
	"github.com/Busnes-app/kynotes-server/internal/keyprotocol"
)

const (
	PQEnvelopeAlg          = keyprotocol.PQEnvelopeAlg
	PQEnvelopeBytes        = keyprotocol.PQEnvelopeBytes
	PQPublicBytes          = keyprotocol.PQPublicBytes
	PQPrivateBytes         = keyprotocol.PQPrivateBytes
	PQWrappedIdentityBytes = keyprotocol.PQWrappedIdentityBytes
	PQRecoveryBytes        = keyprotocol.PQRecoveryBytes
	pqLabel                = "kynotes/envelope/v4"
	pqSignLabel            = "kynotes/envelope/v4/sender"
)

// PQ identity encodings retain the classical key solely to read stored v2/v3 rows.
// Public: 4 | legacyPublic(32) | X-Wing(1216) | HybridSig public.
// Private: 4 | legacyPrivate(32) | X-Wing seed(32) | ML-DSA seed(32) |
// Ed25519 seed(32) | public encoding. The public encoding lets pqwasm clients
// validate and recover the pair without a second implementation of key derivation.
func GeneratePQIdentity(legacy []byte) (private, public []byte, err error) {
	if legacy == nil {
		k, e := ecdh.X25519().GenerateKey(rand.Reader)
		if e != nil {
			return nil, nil, e
		}
		legacy = k.Bytes()
	}
	old, err := ecdh.X25519().NewPrivateKey(legacy)
	if err != nil {
		return nil, nil, err
	}
	x, err := xwing.Generate()
	if err != nil {
		return nil, nil, err
	}
	s, err := hybridsig.Generate()
	if err != nil {
		return nil, nil, err
	}
	public = append([]byte{4}, old.PublicKey().Bytes()...)
	public = append(public, x.Public().Bytes()...)
	public = append(public, s.Public().Bytes()...)
	m, e := s.Seeds()
	private = append([]byte{4}, legacy...)
	private = append(private, x.Seed()...)
	private = append(private, m...)
	private = append(private, e...)
	private = append(private, public...)
	return private, public, nil
}

func ValidatePublicIdentity(public []byte) error { return keyprotocol.ValidatePublicIdentity(public) }

// IdentityPublic validates the entire private/public pair at the storage boundary.
func IdentityPublic(private []byte) ([]byte, error) {
	if len(private) == 32 {
		k, e := ecdh.X25519().NewPrivateKey(private)
		if e != nil {
			return nil, e
		}
		return k.PublicKey().Bytes(), nil
	}
	if len(private) != PQPrivateBytes || private[0] != 4 {
		return nil, errors.New("teamkeys: invalid identity private key")
	}
	old, err := ecdh.X25519().NewPrivateKey(private[1:33])
	if err != nil {
		return nil, err
	}
	x, err := xwing.FromSeed(private[33:65])
	if err != nil {
		return nil, err
	}
	s, err := hybridsig.FromSeeds(private[65:97], private[97:129])
	if err != nil {
		return nil, err
	}
	pub := append([]byte{4}, old.PublicKey().Bytes()...)
	pub = append(pub, x.Public().Bytes()...)
	pub = append(pub, s.Public().Bytes()...)
	if !bytes.Equal(pub, private[129:]) {
		return nil, errors.New("teamkeys: identity key mismatch")
	}
	return pub, nil
}

// PQContext is length-delimited for the optional org and fixed-width elsewhere.
// It binds the version in info, AAD and the signed message; no JSON canonicalization.
func PQContext(orgID, containerID string, generation uint32, recipientID, senderID string) ([]byte, error) {
	if len(orgID) > 255 || strings.IndexByte(orgID, 0) >= 0 {
		return nil, errors.New("teamkeys: invalid org")
	}
	ctx, err := envelopeContext(pqLabel+"\x00", containerID, generation, recipientID, senderID)
	if err != nil {
		return nil, err
	}
	org := binary.BigEndian.AppendUint16(nil, uint16(len(orgID)))
	org = append(org, orgID...)
	return append(ctx, org...), nil
}

func SealPQEnvelope(contentKey, recipientPublic []byte, orgID, containerID string, generation uint32, recipientID string, senderPrivate []byte, senderID string) ([]byte, error) {
	ctx, err := PQContext(orgID, containerID, generation, recipientID, senderID)
	if err != nil {
		return nil, err
	}
	if len(contentKey) != 32 || len(recipientPublic) != PQPublicBytes || len(senderPrivate) != PQPrivateBytes {
		return nil, errors.New("teamkeys: PQ identity required")
	}
	if err := ValidatePublicIdentity(recipientPublic); err != nil {
		return nil, err
	}
	if _, err := IdentityPublic(senderPrivate); err != nil {
		return nil, err
	}
	p, err := xwing.ParsePublicKey(recipientPublic[33 : 33+xwing.PublicKeyBytes])
	if err != nil {
		return nil, err
	}
	sealed, err := xwing.Seal(p, ctx, ctx, contentKey)
	if err != nil {
		return nil, err
	}
	out := append([]byte{4}, senderID...)
	out = append(out, sealed...)
	s, err := hybridsig.FromSeeds(senderPrivate[65:97], senderPrivate[97:129])
	if err != nil {
		return nil, err
	}
	sig, err := s.Sign(pqSignLabel, append(bytes.Clone(ctx), out...))
	if err != nil {
		return nil, err
	}
	return append(out, sig...), nil
}

// OpenIdentityEnvelope selects v4 or the read-only classical paths by algorithm.
func OpenIdentityEnvelope(alg string, envelope, recipientPrivate []byte, orgID, containerID string, generation uint32, recipientID string, senderPublic []byte) ([]byte, error) {
	if alg != PQEnvelopeAlg {
		if len(recipientPrivate) == PQPrivateBytes {
			recipientPrivate = recipientPrivate[1:33]
		}
		if len(senderPublic) == PQPublicBytes {
			senderPublic = senderPublic[1:33]
		}
		k, err := ecdh.X25519().NewPrivateKey(recipientPrivate)
		if err != nil {
			return nil, err
		}
		return OpenEnvelope(alg, envelope, k, containerID, generation, recipientID, senderPublic)
	}
	senderID, err := EnvelopeSender(alg, envelope)
	if err != nil {
		return nil, err
	}
	ctx, err := PQContext(orgID, containerID, generation, recipientID, senderID)
	if err != nil {
		return nil, err
	}
	if len(recipientPrivate) != PQPrivateBytes || len(senderPublic) != PQPublicBytes {
		return nil, errors.New("teamkeys: PQ identity required")
	}
	if err := ValidatePublicIdentity(senderPublic); err != nil {
		return nil, err
	}
	unsigned := envelope[:len(envelope)-hybridsig.SignatureBytes]
	s, err := hybridsig.ParsePublicKey(senderPublic[33+xwing.PublicKeyBytes:])
	if err != nil {
		return nil, err
	}
	if err := s.Verify(pqSignLabel, append(bytes.Clone(ctx), unsigned...), envelope[len(unsigned):]); err != nil {
		return nil, err
	}
	x, err := xwing.FromSeed(recipientPrivate[33:65])
	if err != nil {
		return nil, err
	}
	return xwing.Open(x, ctx, ctx, unsigned[31:])
}

// IdentityKey is a validated local identity, classical for legacy reads or v4.
type IdentityKey struct {
	private []byte
	public  []byte
}
type IdentityPublicKey struct{ public []byte }

func ParseIdentity(private []byte) (*IdentityKey, error) {
	public, err := IdentityPublic(private)
	if err != nil {
		return nil, err
	}
	return &IdentityKey{bytes.Clone(private), public}, nil
}
func NewIdentity() (*IdentityKey, error) {
	private, _, err := GeneratePQIdentity(nil)
	if err != nil {
		return nil, err
	}
	return ParseIdentity(private)
}
func (k *IdentityKey) Bytes() []byte                { return bytes.Clone(k.private) }
func (k *IdentityKey) PublicKey() IdentityPublicKey { return IdentityPublicKey{bytes.Clone(k.public)} }
func (k IdentityPublicKey) Bytes() []byte           { return bytes.Clone(k.public) }
