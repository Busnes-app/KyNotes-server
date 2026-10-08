package teamkeys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/Busnes-app/ky-primitives/derive"
)

const identityLabel = "kynotes/identity/v1"

// UserKEK is the key that wraps the identity under the password: the browser's deriveLoginKeys
// (one PBKDF2 pass, HKDF label "kynotes/user-kek/v1"). The server never sees it.
func UserKEK(password, loginSalt string, iterations int) ([]byte, error) {
	secret, err := derive.AuthSecret(password, loginSalt, iterations, "kynotes/user-kek/v1")
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(secret)
}

func identityAEAD(userKEK []byte, userID string) (cipher.AEAD, []byte, error) {
	if len(userKEK) != 32 || !validID("usr", userID) {
		return nil, nil, errors.New("teamkeys: invalid identity input")
	}
	block, err := aes.NewCipher(userKEK)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	return aead, append([]byte(identityLabel), userID...), err
}

func sealIdentity(userKEK, privateKey []byte, userID string, nonce []byte) ([]byte, error) {
	aead, aad, err := identityAEAD(userKEK, userID)
	if err != nil {
		return nil, err
	}
	if len(privateKey) != 32 || len(nonce) != aead.NonceSize() {
		return nil, errors.New("teamkeys: invalid identity input")
	}
	return aead.Seal(append([]byte{}, nonce...), nonce, privateKey, aad), nil
}

// SealIdentity is web/src/teamKeys.ts wrapIdentity: nonce(12) ‖ AES-256-GCM(userKEK, privateKey,
// "kynotes/identity/v1" ‖ userID), 60 bytes.
func SealIdentity(userKEK, privateKey []byte, userID string) ([]byte, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return sealIdentity(userKEK, privateKey, userID, nonce)
}

// OpenIdentity reverses SealIdentity.
func OpenIdentity(userKEK, wrapped []byte, userID string) ([]byte, error) {
	aead, aad, err := identityAEAD(userKEK, userID)
	if err != nil {
		return nil, err
	}
	if len(wrapped) != aead.NonceSize()+32+aead.Overhead() {
		return nil, errors.New("teamkeys: invalid wrapped identity")
	}
	return aead.Open(nil, wrapped[:aead.NonceSize()], wrapped[aead.NonceSize():], aad)
}
