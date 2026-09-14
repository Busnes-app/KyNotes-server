package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type PairingClaims struct {
	Sub       string `json:"sub"`
	Exp       int64  `json:"exp"`
	Nonce     string `json:"nonce"`
	Purpose   string `json:"purpose"`
	SessionID string `json:"session,omitempty"`
}

func MintPairingToken(secret, userID string, now time.Time) (string, PairingClaims, error) {
	return MintSessionPairingToken(secret, userID, "", now)
}

// MintSessionPairingToken binds HTTP-issued pairing to the authorizing browser session.
func MintSessionPairingToken(secret, userID, sessionID string, now time.Time) (string, PairingClaims, error) {
	if len(secret) < 32 {
		return "", PairingClaims{}, errors.New("pairing disabled")
	}
	n := make([]byte, 8)
	if _, e := rand.Read(n); e != nil {
		return "", PairingClaims{}, e
	}
	c := PairingClaims{Sub: userID, Exp: now.Add(120 * time.Second).Unix(), Nonce: hex.EncodeToString(n), Purpose: "device-pair", SessionID: sessionID}
	p, _ := json.Marshal(c)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(p)
	return base64.RawURLEncoding.EncodeToString(p) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), c, nil
}
func ParsePairingToken(secret, token, userID string, now time.Time) (PairingClaims, error) {
	if len(secret) < 32 {
		return PairingClaims{}, errors.New("pairing disabled")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return PairingClaims{}, errors.New("invalid token")
	}
	// Strict rejects non-canonical encodings. Without it the final character's
	// unused bits are discarded, so four distinct token strings decode to the same
	// signature and all verify.
	p, e := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if e != nil {
		return PairingClaims{}, errors.New("invalid token")
	}
	sig, e := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if e != nil {
		return PairingClaims{}, errors.New("invalid token")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(p)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return PairingClaims{}, errors.New("invalid token")
	}
	var c PairingClaims
	if json.Unmarshal(p, &c) != nil || subtle.ConstantTimeCompare([]byte(c.Sub), []byte(userID)) != 1 || c.Purpose != "device-pair" || now.Unix() > c.Exp {
		return PairingClaims{}, errors.New("invalid token")
	}
	return c, nil
}
