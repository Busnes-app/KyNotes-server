package teamkeys

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/cloudflare/circl/hpke"
)

// rfcVectorFile is RFC 9180 Appendix A.2.3: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
// ChaCha20Poly1305, mode_auth (https://www.rfc-editor.org/rfc/rfc9180#appendix-A.2.3),
// identical to the CFRG draft-irtf-cfrg-hpke test-vectors.json entry. web/src/teamKeys.test.ts
// checks the same file.
const rfcVectorFile = "../../testdata/protocol/rfc9180_a2_3_auth.json"

type rfcVector struct {
	Mode        int    `json:"mode"`
	KEMID       int    `json:"kem_id"`
	KDFID       int    `json:"kdf_id"`
	AEADID      int    `json:"aead_id"`
	Info        string `json:"info"`
	IkmE        string `json:"ikmE"`
	PkEm        string `json:"pkEm"`
	SkEm        string `json:"skEm"`
	IkmR        string `json:"ikmR"`
	PkRm        string `json:"pkRm"`
	SkRm        string `json:"skRm"`
	IkmS        string `json:"ikmS"`
	PkSm        string `json:"pkSm"`
	SkSm        string `json:"skSm"`
	Enc         string `json:"enc"`
	Encryptions []struct {
		Sequence int    `json:"sequence"`
		Aad      string `json:"aad"`
		Ct       string `json:"ct"`
		Pt       string `json:"pt"`
	} `json:"encryptions"`
	Exports []struct {
		ExporterContext string `json:"exporter_context"`
		L               uint   `json:"L"`
		ExportedValue   string `json:"exported_value"`
	} `json:"exports"`
}

func TestHPKEMatchesRFC9180AuthVector(t *testing.T) {
	raw, err := os.ReadFile(rfcVectorFile)
	if err != nil {
		t.Fatal(err)
	}
	var v rfcVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	// The suite and mode the envelope uses: mode_auth = 2, 0x0020 / 0x0001 / 0x0003.
	if v.Mode != 2 || v.KEMID != int(hpke.KEM_X25519_HKDF_SHA256) || v.KDFID != int(hpke.KDF_HKDF_SHA256) || v.AEADID != int(hpke.AEAD_ChaCha20Poly1305) || len(v.Encryptions) != 6 || len(v.Exports) != 3 {
		t.Fatalf("wrong vector: %+v", v)
	}
	derive := func(ikm, wantSk, wantPk string) {
		pk, sk := kemScheme.DeriveKeyPair(unhex(t, ikm))
		gotPk, _ := pk.MarshalBinary()
		gotSk, _ := sk.MarshalBinary()
		if !bytes.Equal(gotPk, unhex(t, wantPk)) || !bytes.Equal(gotSk, unhex(t, wantSk)) {
			t.Fatalf("DeriveKeyPair(%s) mismatch", ikm)
		}
	}
	derive(v.IkmE, v.SkEm, v.PkEm)
	derive(v.IkmR, v.SkRm, v.PkRm)
	derive(v.IkmS, v.SkSm, v.PkSm)
	pkR, err := kemScheme.UnmarshalBinaryPublicKey(unhex(t, v.PkRm))
	if err != nil {
		t.Fatal(err)
	}
	skS, err := kemScheme.UnmarshalBinaryPrivateKey(unhex(t, v.SkSm))
	if err != nil {
		t.Fatal(err)
	}
	s, err := suite.NewSender(pkR, unhex(t, v.Info))
	if err != nil {
		t.Fatal(err)
	}
	enc, sealer, err := s.SetupAuth(bytes.NewReader(unhex(t, v.IkmE)), skS)
	if err != nil || !bytes.Equal(enc, unhex(t, v.Enc)) {
		t.Fatalf("enc mismatch: %x %v", enc, err)
	}
	skR, err := kemScheme.UnmarshalBinaryPrivateKey(unhex(t, v.SkRm))
	if err != nil {
		t.Fatal(err)
	}
	pkS, err := kemScheme.UnmarshalBinaryPublicKey(unhex(t, v.PkSm))
	if err != nil {
		t.Fatal(err)
	}
	r, err := suite.NewReceiver(skR, unhex(t, v.Info))
	if err != nil {
		t.Fatal(err)
	}
	opener, err := r.SetupAuth(enc, pkS)
	if err != nil {
		t.Fatal(err)
	}
	// The exporter secret proves the key schedule (shared_secret, secret) byte for byte.
	for _, e := range v.Exports {
		if got := sealer.Export(unhex(t, e.ExporterContext), e.L); !bytes.Equal(got, unhex(t, e.ExportedValue)) {
			t.Fatalf("sender export %q: %x", e.ExporterContext, got)
		}
		if got := opener.Export(unhex(t, e.ExporterContext), e.L); !bytes.Equal(got, unhex(t, e.ExportedValue)) {
			t.Fatalf("receiver export %q: %x", e.ExporterContext, got)
		}
	}
	// Seal sequence numbers 0..256 in order; the RFC prints 0, 1, 2, 4, 255 and 256.
	want := map[int]int{}
	for i, e := range v.Encryptions {
		want[e.Sequence] = i
	}
	for seq := 0; seq <= 256; seq++ {
		i, printed := want[seq]
		if !printed {
			ct, err := sealer.Seal(nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := opener.Open(ct, nil); err != nil {
				t.Fatalf("seq %d: open %v", seq, err)
			}
			continue
		}
		e := v.Encryptions[i]
		ct, err := sealer.Seal(unhex(t, e.Pt), unhex(t, e.Aad))
		if err != nil || !bytes.Equal(ct, unhex(t, e.Ct)) {
			t.Fatalf("seq %d: ct mismatch %x %v", seq, ct, err)
		}
		pt, err := opener.Open(unhex(t, e.Ct), unhex(t, e.Aad))
		if err != nil || !bytes.Equal(pt, unhex(t, e.Pt)) {
			t.Fatalf("seq %d: open %v", seq, err)
		}
	}
}
