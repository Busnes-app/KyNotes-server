package auth

import "github.com/Busnes-app/ky-primitives/recoverycode"

// NewRecoveryCode mints one single-use code and the verifier to store for it.
// The code is shown to the operator once; only the hash is kept.
func NewRecoveryCode() (code, hash string, err error) {
	codes, err := recoverycode.Generate(1)
	if err != nil {
		return "", "", err
	}
	hash, err = HashAuthSecret(recoverycode.Normalize(codes[0]))
	return codes[0], hash, err
}

// VerifyRecoveryCode accepts the code as an operator types it: case and
// spacing are normalised the same way the hash was made.
func VerifyRecoveryCode(code, stored string) error {
	return VerifyAuthSecret(recoverycode.Normalize(code), stored)
}
