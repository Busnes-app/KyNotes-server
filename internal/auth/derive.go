package auth

import (
	"github.com/Busnes-app/ky-primitives/derive"
)

const MinLoginIterations = derive.MinIterations
const MaxLoginIterations = derive.MaxIterations

// authLabel is the HKDF domain the browser mirrors in web/src/crypto.ts.
// Change a byte and every user is locked out.
const authLabel = "kynotes/auth/v1"
const saltLabel = "login-salt/v1"

func DeriveAuthSecret(password, salt string, iterations int) (string, error) {
	secret, err := derive.AuthSecret(password, salt, iterations, authLabel)
	return secret, normalizeBusy(err)
}

// SyntheticLoginSalt is the salt handed out for a username that has none, so a
// probe cannot tell registered from unregistered. Config validation guarantees
// key is at least 32 bytes, the library's floor, so the error is unreachable.
func SyntheticLoginSalt(key, username string) string {
	s, _ := derive.SyntheticSalt([]byte(key), saltLabel, username)
	return s
}
