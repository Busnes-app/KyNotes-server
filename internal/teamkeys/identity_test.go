package teamkeys

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestIdentityWrapAgreesWithVectors(t *testing.T) {
	raw, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	for _, l := range v.Login {
		kek, err := UserKEK(l.Password, l.LoginSalt, l.Iterations)
		if err != nil || hex.EncodeToString(kek) != l.UserKEK {
			t.Fatalf("userKEK=%x err=%v, want %s", kek, err, l.UserKEK)
		}
	}
	for _, i := range v.Identity {
		kek, priv := unhex(t, i.UserKEK), unhex(t, i.PrivateKey)
		sealed, err := sealIdentity(kek, priv, i.UserID, unhex(t, i.Nonce))
		if err != nil || hex.EncodeToString(sealed) != i.Wrapped {
			t.Fatalf("sealed=%x err=%v", sealed, err)
		}
		opened, err := OpenIdentity(kek, unhex(t, i.Wrapped), i.UserID)
		if err != nil || !bytes.Equal(opened, priv) {
			t.Fatalf("opened=%x err=%v", opened, err)
		}
		if _, err := OpenIdentity(kek, unhex(t, i.Wrapped), "usr_zzzzzzzzzzzzzzzzzzzzzzzzzz"); err == nil {
			t.Fatal("opened under another user's AAD")
		}
	}
	wrapped, err := SealIdentity(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), "usr_0123456789abcdefghjkmnpqrs")
	if err != nil || len(wrapped) != 60 {
		t.Fatalf("random-nonce wrap=%d bytes err=%v", len(wrapped), err)
	}
}
