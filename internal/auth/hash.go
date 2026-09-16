package auth

import (
	"errors"
	"fmt"

	"github.com/Busnes-app/ky-primitives/derive"
	"github.com/Busnes-app/ky-primitives/password"
)

var errInvalidSecret = errors.New("invalid secret")
var ErrBusy = errors.New("auth: derivation budget exhausted")

func normalizeBusy(err error) error {
	if errors.Is(err, password.ErrBusy) || errors.Is(err, derive.ErrBusy) {
		return fmt.Errorf("%w: %v", ErrBusy, err)
	}
	return err
}

// HashAuthSecret stores a login secret or recovery code as an Argon2id PHC string.
func HashAuthSecret(secret string) (string, error) {
	h, err := password.Hash(secret)
	return h, normalizeBusy(err)
}

// VerifyAuthSecret is nil only when secret matches stored. A malformed or
// legacy (scrypt) verifier is an error, never a match.
func VerifyAuthSecret(secret, stored string) error {
	ok, err := password.Verify(secret, stored)
	if err != nil {
		return normalizeBusy(err)
	}
	if !ok {
		return errInvalidSecret
	}
	return nil
}

func DummyVerify() { password.DummyVerify() }
