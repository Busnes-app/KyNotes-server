package notecrypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const vectorFile = "../../testdata/protocol/payload_vectors.json"

var update = flag.Bool("update", false, "rewrite "+vectorFile)

const (
	keyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	cntA   = "cnt_00000000000000000000000000"
	cntB   = "cnt_tvwxyz0123456789abcdefghjk"
)

type vector struct {
	ContainerID string `json:"containerId"`
	Key         string `json:"key"`
	Nonce       string `json:"nonce"`
	Sealed      string `json:"sealed"`
}

type objectVector struct {
	vector
	Plaintext string          `json:"plaintext"` // exact JSON bytes sealed, as JSON.stringify writes them
	Payload   json.RawMessage `json:"payload"`   // what OpenObject and parseObjectPayload narrow it to
}

type nameVector struct {
	vector
	Name string `json:"name"`
}

type metaVector struct {
	vector
	Meta AttachmentMeta `json:"meta"`
}

type attachmentVector struct {
	vector
	Plaintext string `json:"plaintext"` // hex
}

type vectors struct {
	Objects        []objectVector     `json:"objects"`
	ContainerNames []nameVector       `json:"containerNames"`
	AttachmentMeta []metaVector       `json:"attachmentMeta"`
	Attachments    []attachmentVector `json:"attachments"`
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sealed(t *testing.T, container, label, nonce string, plaintext []byte) vector {
	t.Helper()
	out, err := sealNonce(unhex(t, keyHex), container, label, unhex(t, nonce), plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return vector{container, keyHex, nonce, hex.EncodeToString(out)}
}

func object(t *testing.T, container, nonce, plaintext string) objectVector {
	v := sealed(t, container, objectLabel, nonce, []byte(plaintext))
	p, err := OpenObject(unhex(t, v.Key), container, unhex(t, v.Sealed))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := marshal(p.wire())
	if err != nil {
		t.Fatal(err)
	}
	return objectVector{v, plaintext, payload}
}

func generate(t *testing.T) vectors {
	var vs vectors
	for _, o := range []struct{ container, nonce, plaintext string }{
		{cntA, "000000000000000000000000", `{"type":"page","title":"Groceries <&> \"quoted\"","body":"[{\"type\":\"paragraph\",\"content\":\"héllo\\n☃ 🦀\"}]","section":"obj_0123456789abcdefghjkmnpqrs","order":"a","level":0}`},
		{cntB, "0c0d0e0f1011121314151617", `{"type":"page","title":"","body":""}`},
		{cntA, "a0a1a2a3a4a5a6a7a8a9aaab", `{"type":"section","title":"Work","color":"teal","order":"h","group":"obj_tvwxyz0123456789abcdefghjk"}`},
		{cntA, "b0b1b2b3b4b5b6b7b8b9babb", `{"type":"group","title":"Projects","color":"orange"}`},
		// Untrusted fields are narrowed: an unknown color, a bad order and a missing title.
		{cntB, "c0c1c2c3c4c5c6c7c8c9cacb", `{"type":"section","color":"pink","order":"a0"}`},
	} {
		vs.Objects = append(vs.Objects, object(t, o.container, o.nonce, o.plaintext))
	}
	for _, n := range []struct{ container, nonce, name string }{
		{cntA, "101112131415161718191a1b", "Team notebook"},
		{cntB, "202122232425262728292a2b", "Ünïcødé & <tags>"},
	} {
		plaintext, _ := marshal(map[string]string{"name": n.name})
		vs.ContainerNames = append(vs.ContainerNames, nameVector{sealed(t, n.container, metaLabel, n.nonce, plaintext), n.name})
	}
	meta := AttachmentMeta{"report <final>.pdf", "application/pdf", 1048576}
	plaintext, _ := marshal(meta)
	vs.AttachmentMeta = []metaVector{{sealed(t, cntA, attachmentLabel, "303132333435363738393a3b", plaintext), meta}}
	for _, a := range []struct{ container, nonce, plaintext string }{
		{cntA, "404142434445464748494a4b", ""},
		{cntB, "505152535455565758595a5b", "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"},
	} {
		vs.Attachments = append(vs.Attachments, attachmentVector{sealed(t, a.container, objectLabel, a.nonce, unhex(t, a.plaintext)), a.plaintext})
	}
	return vs
}

func TestPayloadVectors(t *testing.T) {
	got, err := json.MarshalIndent(generate(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *update {
		if err := os.WriteFile(vectorFile, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale; run go test ./internal/notecrypto -run TestPayloadVectors -update", vectorFile)
	}
}

// The public openers read every vector, and the public sealers write what
// SealObject et al. would with the vector's nonce (the plaintext is canonical).
func TestVectorsOpen(t *testing.T) {
	vs := generate(t)
	for _, v := range vs.Objects {
		p, err := OpenObject(unhex(t, v.Key), v.ContainerID, unhex(t, v.Sealed))
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := marshal(p.wire()); !bytes.Equal(got, v.Payload) {
			t.Fatalf("payload %s, want %s", got, v.Payload)
		}
	}
	page, _ := marshal(Payload{Type: "page", Title: "Groceries <&> \"quoted\"", Body: "[{\"type\":\"paragraph\",\"content\":\"héllo\\n☃ 🦀\"}]", Section: "obj_0123456789abcdefghjkmnpqrs", Order: "a", Level: new(0)}.wire())
	if string(page) != vs.Objects[0].Plaintext {
		t.Fatalf("SealObject writes %s, browser writes %s", page, vs.Objects[0].Plaintext)
	}
	for _, v := range vs.ContainerNames {
		if name, err := OpenContainerName(unhex(t, v.Key), v.ContainerID, unhex(t, v.Sealed)); err != nil || name != v.Name {
			t.Fatalf("name %q, %v", name, err)
		}
	}
	for _, v := range vs.AttachmentMeta {
		if meta, err := OpenAttachmentMeta(unhex(t, v.Key), v.ContainerID, unhex(t, v.Sealed)); err != nil || meta != v.Meta {
			t.Fatalf("meta %+v, %v", meta, err)
		}
	}
	for _, v := range vs.Attachments {
		if pt, err := OpenAttachment(unhex(t, v.Key), v.ContainerID, unhex(t, v.Sealed)); err != nil || hex.EncodeToString(pt) != v.Plaintext {
			t.Fatalf("attachment %x, %v", pt, err)
		}
	}
}

func TestSealRoundTripsWithFreshNonces(t *testing.T) {
	key := unhex(t, keyHex)
	p := Payload{Type: "section", Title: "Inbox", Color: "blue"}
	one, err := SealObject(key, cntA, p)
	if err != nil {
		t.Fatal(err)
	}
	two, _ := SealObject(key, cntA, p)
	if bytes.Equal(one[:nonceSize], two[:nonceSize]) {
		t.Fatal("nonce reused")
	}
	if got, err := OpenObject(key, cntA, two); err != nil || got != p {
		t.Fatalf("%+v, %v", got, err)
	}
	name, _ := SealContainerName(key, cntB, "N")
	if got, err := OpenContainerName(key, cntB, name); err != nil || got != "N" {
		t.Fatalf("%q, %v", got, err)
	}
	meta := AttachmentMeta{"a", "b", 3}
	m, _ := SealAttachmentMeta(key, cntA, meta)
	if got, err := OpenAttachmentMeta(key, cntA, m); err != nil || got != meta {
		t.Fatalf("%+v, %v", got, err)
	}
	a, _ := SealAttachment(key, cntA, []byte{1, 2, 3})
	if got, err := OpenAttachment(key, cntA, a); err != nil || !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatalf("%x, %v", got, err)
	}
}

func TestOpenFailsClosed(t *testing.T) {
	vs := generate(t)
	v := vs.Objects[0]
	key, box := unhex(t, v.Key), unhex(t, v.Sealed)
	openObj := func(k []byte, c string, b []byte) error { _, err := OpenObject(k, c, b); return err }
	for _, at := range []int{0, nonceSize - 1, nonceSize, len(box) / 2, len(box) - 1} {
		bad := bytes.Clone(box)
		bad[at] ^= 1
		if openObj(key, v.ContainerID, bad) == nil {
			t.Fatalf("flipped byte %d opened", at)
		}
	}
	wrongKey := bytes.Clone(key)
	wrongKey[0] ^= 1
	for name, err := range map[string]error{
		"wrong container":     openObj(key, cntB, box),
		"wrong key":           openObj(wrongKey, v.ContainerID, box),
		"truncated":           openObj(key, v.ContainerID, box[:len(box)-1]),
		"too short":           openObj(key, v.ContainerID, box[:minSealed-1]),
		"short key":           openObj(key[:31], v.ContainerID, box),
		"malformed container": openObj(key, "cnt_x", box),
	} {
		if err == nil {
			t.Fatalf("%s opened", name)
		}
	}
	// Each label is its own subkey: a name or attachment never opens as another kind.
	n := vs.ContainerNames[0]
	if openObj(unhex(t, n.Key), n.ContainerID, unhex(t, n.Sealed)) == nil {
		t.Fatal("container name opened as an object")
	}
	if _, err := OpenContainerName(key, v.ContainerID, box); err == nil {
		t.Fatal("object opened as a container name")
	}
	m := vs.AttachmentMeta[0]
	if _, err := OpenAttachment(unhex(t, m.Key), m.ContainerID, unhex(t, m.Sealed)); err == nil {
		t.Fatal("attachment metadata opened as attachment bytes")
	}
	a := vs.Attachments[1]
	if _, err := OpenAttachment(key, cntA, unhex(t, a.Sealed)); err == nil {
		t.Fatal("attachment opened under another container")
	}
}

func TestOpenObjectRejectsNonPayloads(t *testing.T) {
	key := unhex(t, keyHex)
	for _, plaintext := range []string{`[]`, `null`, `"page"`, `{"type":"page","title":"no body"}`, `{"body":3}`, `not json`} {
		box, err := sealNonce(key, cntA, objectLabel, make([]byte, nonceSize), []byte(plaintext))
		if err != nil {
			t.Fatal(err)
		}
		if p, err := OpenObject(key, cntA, box); err == nil {
			t.Fatalf("%s opened as %+v", plaintext, p)
		}
	}
	box, _ := sealNonce(key, cntA, metaLabel, make([]byte, nonceSize), []byte(`{"title":"x"}`))
	if _, err := OpenContainerName(key, cntA, box); err == nil {
		t.Fatal("metadata without a name opened")
	}
}

// Content keys never reach the server: neither client-only crypto package is linked into it.
func TestNotLinkedIntoServer(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/Busnes-app/kynotes-server/cmd/kynotes-server").Output()
	if err != nil {
		t.Fatal(err)
	}
	deps := strings.Fields(string(out))
	if len(deps) == 0 || !strings.Contains(string(out), "kynotes-server/internal/httpapi\n") {
		t.Fatalf("go list returned no server dependencies: %q", out)
	}
	for _, dep := range deps {
		if strings.HasSuffix(dep, "/internal/notecrypto") || strings.HasSuffix(dep, "/internal/teamkeys") {
			t.Fatalf("cmd/kynotes-server depends on %s", dep)
		}
	}
}
