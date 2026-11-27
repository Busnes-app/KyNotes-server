package sso

import (
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func signMLDSA65JWT(t *testing.T, priv *mldsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	sig, err := priv.Sign(rand.Reader, []byte(signingInput), nil)
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestVerifyClaimsAndLogoutAcceptMLDSA65(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}

	var issuer string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                issuer,
				"authorization_endpoint":                issuer + "/authorize",
				"token_endpoint":                        issuer + "/token",
				"jwks_uri":                              issuer + "/keys",
				"id_token_signing_alg_values_supported": []string{"ML-DSA-65", "RS256"},
				"backchannel_logout_supported":          true,
				"backchannel_logout_session_supported":  true,
			})
		case "/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []any{
					map[string]any{
						"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "rsa-1",
						"n": base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()), "e": "AQAB",
					},
					map[string]any{
						"kty": "AKP", "use": "sig", "alg": "ML-DSA-65", "kid": "mldsa65-1",
						"pub": base64.RawURLEncoding.EncodeToString(mldsaKey.PublicKey().Bytes()),
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	issuer = srv.URL

	origTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = origTransport })

	store := NewStore(nil)
	settings := SSOSettings{IssuerURL: issuer, ClientID: "kynotes"}
	doc := &DiscoveryDoc{
		Issuer:                            issuer,
		JWKSURI:                           issuer + "/keys",
		BackchannelLogoutSessionSupported: true,
	}

	now := time.Now().UTC()
	idToken := signMLDSA65JWT(t, mldsaKey,
		map[string]any{"alg": "ML-DSA-65", "typ": "JWT", "kid": "mldsa65-1"},
		map[string]any{
			"iss":                issuer,
			"sub":                "user-pqc-1",
			"aud":                "kynotes",
			"nonce":              "nonce-mldsa-1",
			"sid":                "sid-mldsa-1",
			"iat":                now.Unix(),
			"exp":                now.Add(time.Hour).Unix(),
			"email":              "pqc@example.test",
			"email_verified":     true,
			"preferred_username": "pqc-user",
		},
	)

	claims, err := store.VerifyClaims(context.Background(), settings, doc, idToken, "nonce-mldsa-1")
	if err != nil {
		t.Fatalf("VerifyClaims(ML-DSA-65): %v", err)
	}
	if claims.Subject != "user-pqc-1" || claims.SessionID != "sid-mldsa-1" || claims.Email != "pqc@example.test" {
		t.Fatalf("unexpected claims: %+v", claims)
	}

	// Tampered ML-DSA-65 signature must be rejected.
	parts := strings.Split(idToken, ".")
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	sigBytes[0] ^= 0xff
	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sigBytes)
	if _, err := store.VerifyClaims(context.Background(), settings, doc, tampered, "nonce-mldsa-1"); err == nil {
		t.Fatal("VerifyClaims accepted tampered ML-DSA-65 token")
	}

	// Cross-algorithm confusion (ML-DSA-65 header naming the RSA kid) must be rejected.
	confused := signMLDSA65JWT(t, mldsaKey,
		map[string]any{"alg": "ML-DSA-65", "typ": "JWT", "kid": "rsa-1"},
		map[string]any{
			"iss":   issuer,
			"sub":   "user-pqc-1",
			"aud":   "kynotes",
			"nonce": "nonce-mldsa-1",
			"sid":   "sid-mldsa-1",
			"iat":   now.Unix(),
			"exp":   now.Add(time.Hour).Unix(),
		},
	)
	if _, err := store.VerifyClaims(context.Background(), settings, doc, confused, "nonce-mldsa-1"); err == nil {
		t.Fatal("VerifyClaims accepted ML-DSA-65 token targeting RSA kid")
	}

	// Backchannel logout+jwt signed with ML-DSA-65 must verify.
	logoutToken := signMLDSA65JWT(t, mldsaKey,
		map[string]any{"alg": "ML-DSA-65", "typ": "logout+jwt", "kid": "mldsa65-1"},
		map[string]any{
			"iss":    issuer,
			"sub":    "user-pqc-1",
			"aud":    "kynotes",
			"sid":    "sid-mldsa-1",
			"jti":    "jti-mldsa-1",
			"iat":    now.Unix(),
			"exp":    now.Add(5 * time.Minute).Unix(),
			"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
		},
	)
	logoutClaims, err := store.VerifyLogout(context.Background(), settings, logoutToken)
	if err != nil {
		t.Fatalf("VerifyLogout(ML-DSA-65): %v", err)
	}
	if logoutClaims.Subject != "user-pqc-1" || logoutClaims.SessionID != "sid-mldsa-1" {
		t.Fatalf("unexpected logout claims: %+v", logoutClaims)
	}
}
