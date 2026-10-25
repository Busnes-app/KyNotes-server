package notecrypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

const vectorFile = "../../testdata/protocol/payload_vectors.json"

var update = flag.Bool("update", false, "rewrite "+vectorFile)

const (
	keyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	cntA   = "cnt_00000000000000000000000000"
	cntB   = "cnt_tvwxyz0123456789abcdefghjk"
	objA   = "obj_0123456789abcdefghjkmnpqrs"
	objB   = "obj_tvwxyz0123456789abcdefghjk"
	cmtA   = "cmt_0123456789abcdefghjkmnpqrs"
	attA   = "att_tvwxyz0123456789abcdefghjk"
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

// v2Vector is one v2 seal of any kind. Plaintext is hex of the exact bytes sealed (JSON as
// JSON.stringify writes it; raw bytes for attachments); AAD is contentAAD's bytes.
type v2Vector struct {
	Kind        string `json:"kind"`
	ContainerID string `json:"containerId"`
	BoundID     string `json:"boundId"`
	Key         string `json:"key"`
	Nonce       string `json:"nonce"`
	AAD         string `json:"aad"`
	Plaintext   string `json:"plaintext"`
	Sealed      string `json:"sealed"`
}

// The v1 sections are the read path for content written before v2; writes are v2 only.
type vectors struct {
	Objects        []objectVector     `json:"objects"`
	ContainerNames []nameVector       `json:"containerNames"`
	AttachmentMeta []metaVector       `json:"attachmentMeta"`
	Attachments    []attachmentVector `json:"attachments"`
	V2             []v2Vector         `json:"v2"`
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// sealV1 is the v1 form, which only these tests still write: nonce ‖ AES-256-GCM(HKDF(label)), no AAD.
func sealV1(t *testing.T, key []byte, container, label string, nonce, plaintext []byte) []byte {
	t.Helper()
	gcm, err := aead(key, container, label)
	if err != nil {
		t.Fatal(err)
	}
	return gcm.Seal(bytes.Clone(nonce), nonce, plaintext, nil)
}

func sealed(t *testing.T, container, label, nonce string, plaintext []byte) vector {
	t.Helper()
	out := sealV1(t, unhex(t, keyHex), container, label, unhex(t, nonce), plaintext)
	return vector{container, keyHex, nonce, hex.EncodeToString(out)}
}

func sealedV2(t *testing.T, kind, container, bound, nonce string, plaintext []byte) v2Vector {
	t.Helper()
	out, err := sealNonce(unhex(t, keyHex), container, bound, kind, unhex(t, nonce), plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return v2Vector{kind, container, bound, keyHex, nonce, hex.EncodeToString(contentAAD(container, bound, kind)), hex.EncodeToString(plaintext), hex.EncodeToString(out)}
}

func object(t *testing.T, container, nonce, plaintext string) objectVector {
	v := sealed(t, container, objectLabel, nonce, []byte(plaintext))
	p, err := OpenObject(unhex(t, v.Key), container, objA, unhex(t, v.Sealed), true)
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
	page, _ := marshal(Payload{Type: "page", Title: "Migrated", Body: "[]", Section: objB, Level: new(1), Legacy: map[string]string{attA: strings.Repeat("ab", 32), cmtA: strings.Repeat("0f", 32)}}.wire())
	fresh, _ := marshal(Payload{Type: "page", Title: "New", Body: "", Legacy: map[string]string{}}.wire())
	section, _ := marshal(Payload{Type: "section", Title: "Work", Color: "teal", Order: "h"}.wire())
	comment, _ := marshal(map[string]string{"body": "Looks good <3", "section": "Intro"})
	named, _ := marshal(metaJSON{Name: "Team notebook"})
	marked, _ := marshal(metaJSON{Name: "Team notebook", Objects: 2})
	for _, v := range []struct {
		kind, container, bound, nonce string
		plaintext                     []byte
	}{
		{kindObject, cntA, objA, "600000000000000000000001", page},
		{kindObject, cntB, objB, "610000000000000000000002", fresh},
		{kindObject, cntA, objB, "620000000000000000000003", section},
		{kindComment, cntA, objA, "630000000000000000000004", comment},
		{kindAttachment, cntA, objA, "640000000000000000000005", unhex(t, "89504e470d0a1a0a")},
		{kindAttachmentMeta, cntA, objA, "650000000000000000000006", plaintext},
		{kindContainerMeta, cntA, cntA, "660000000000000000000007", named},
		{kindContainerMeta, cntB, cntB, "670000000000000000000008", marked},
	} {
		vs.V2 = append(vs.V2, sealedV2(t, v.kind, v.container, v.bound, v.nonce, v.plaintext))
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

// The public openers read every vector (v1 with v1 allowed), and the public sealers write
// what the vectors hold with the vector's nonce (the plaintext is canonical).
func TestVectorsOpen(t *testing.T) {
	vs := generate(t)
	for _, v := range vs.Objects {
		p, err := OpenObject(unhex(t, v.Key), v.ContainerID, objA, unhex(t, v.Sealed), true)
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
		if name, migrated, err := OpenContainerName(unhex(t, v.Key), v.ContainerID, unhex(t, v.Sealed), true); err != nil || name != v.Name || migrated {
			t.Fatalf("name %q %v, %v", name, migrated, err)
		}
	}
	for _, v := range vs.AttachmentMeta {
		if meta, err := OpenAttachmentMeta(unhex(t, v.Key), v.ContainerID, objA, unhex(t, v.Sealed), true); err != nil || meta != v.Meta {
			t.Fatalf("meta %+v, %v", meta, err)
		}
	}
	for _, v := range vs.Attachments {
		if pt, err := OpenAttachment(unhex(t, v.Key), v.ContainerID, objA, unhex(t, v.Sealed), true); err != nil || hex.EncodeToString(pt) != v.Plaintext {
			t.Fatalf("attachment %x, %v", pt, err)
		}
	}
}

// Each v2 vector opens through its public opener with v1 refused, and opens with exactly its AAD.
func TestV2VectorsOpen(t *testing.T) {
	for _, v := range generate(t).V2 {
		key, box, pt := unhex(t, v.Key), unhex(t, v.Sealed), unhex(t, v.Plaintext)
		var got []byte
		var err error
		switch v.Kind {
		case kindObject:
			var p Payload
			if p, err = OpenObject(key, v.ContainerID, v.BoundID, box, false); err == nil {
				got, _ = marshal(p.wire())
			}
		case kindAttachment:
			got, err = OpenAttachment(key, v.ContainerID, v.BoundID, box, false)
		case kindAttachmentMeta:
			var m AttachmentMeta
			if m, err = OpenAttachmentMeta(key, v.ContainerID, v.BoundID, box, false); err == nil {
				got, _ = marshal(m)
			}
		case kindContainerMeta:
			meta := metaJSON{}
			var migrated bool
			if meta.Name, migrated, err = OpenContainerName(key, v.ContainerID, box, false); migrated {
				meta.Objects = 2
			}
			got, _ = marshal(meta)
		default:
			got, _, err = open(key, v.ContainerID, v.BoundID, v.Kind, "", box, false)
		}
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("%s: %s, %v", v.Kind, got, err)
		}
		gcm, _ := aead(key, v.ContainerID, contentLabel)
		if box[0] != version2 || hex.EncodeToString(box[1:1+nonceSize]) != v.Nonce {
			t.Fatalf("%s: header %x", v.Kind, box[:1+nonceSize])
		}
		if _, err := gcm.Open(nil, box[1:1+nonceSize], box[1+nonceSize:], unhex(t, v.AAD)); err != nil {
			t.Fatalf("%s does not open with its AAD", v.Kind)
		}
	}
	// The AAD layout, spelled out once.
	want := "\x00\x12kynotes/content/v2\x00\x1e" + cntA + "\x00\x1e" + cntA + "\x00\x0econtainer-meta"
	if got := string(contentAAD(cntA, cntA, kindContainerMeta)); got != want {
		t.Fatalf("aad %q, want %q", got, want)
	}
}

func TestSealRoundTripsWithFreshNonces(t *testing.T) {
	key := unhex(t, keyHex)
	p := Payload{Type: "section", Title: "Inbox", Color: "blue"}
	one, err := SealObject(key, cntA, objA, p)
	if err != nil {
		t.Fatal(err)
	}
	two, _ := SealObject(key, cntA, objA, p)
	if bytes.Equal(one[:1+nonceSize], two[:1+nonceSize]) {
		t.Fatal("nonce reused")
	}
	if got, err := OpenObject(key, cntA, objA, two, false); err != nil || !reflect.DeepEqual(got, p) {
		t.Fatalf("%+v, %v", got, err)
	}
	name, _ := SealContainerName(key, cntB, "N", true)
	if got, migrated, err := OpenContainerName(key, cntB, name, false); err != nil || got != "N" || !migrated {
		t.Fatalf("%q %v, %v", got, migrated, err)
	}
	meta := AttachmentMeta{"a", "b", 3}
	m, _ := SealAttachmentMeta(key, cntA, objA, meta)
	if got, err := OpenAttachmentMeta(key, cntA, objA, m, false); err != nil || got != meta {
		t.Fatalf("%+v, %v", got, err)
	}
	a, _ := SealAttachment(key, cntA, objA, []byte{1, 2, 3})
	if got, err := OpenAttachment(key, cntA, objA, a, false); err != nil || !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatalf("%x, %v", got, err)
	}
	if _, err := SealObject(key, cntA, "obj_x", p); err == nil {
		t.Fatal("sealed under a malformed object ID")
	}
}

func TestOpenFailsClosed(t *testing.T) {
	vs := generate(t)
	v := vs.Objects[0]
	key, box := unhex(t, v.Key), unhex(t, v.Sealed)
	openObj := func(k []byte, c string, b []byte) error { _, err := OpenObject(k, c, objA, b, true); return err }
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
	// Each v1 label is its own subkey: a name or attachment never opens as another kind.
	n := vs.ContainerNames[0]
	if openObj(unhex(t, n.Key), n.ContainerID, unhex(t, n.Sealed)) == nil {
		t.Fatal("container name opened as an object")
	}
	if _, _, err := OpenContainerName(key, v.ContainerID, box, true); err == nil {
		t.Fatal("object opened as a container name")
	}
	m := vs.AttachmentMeta[0]
	if _, err := OpenAttachment(unhex(t, m.Key), m.ContainerID, objA, unhex(t, m.Sealed), true); err == nil {
		t.Fatal("attachment metadata opened as attachment bytes")
	}
	a := vs.Attachments[1]
	if _, err := OpenAttachment(key, cntA, objA, unhex(t, a.Sealed), true); err == nil {
		t.Fatal("attachment opened under another container")
	}
}

// A server swapping one object's ciphertext for another's, in the same container, is refused.
func TestSwappedObjectIsRejected(t *testing.T) {
	key := unhex(t, keyHex)
	a, _ := SealObject(key, cntA, objA, Payload{Type: "page", Title: "A", Body: "[]", Legacy: map[string]string{}})
	if _, err := OpenObject(key, cntA, objB, a, false); err == nil {
		t.Fatal("page A opened as page B")
	}
	if _, err := OpenObject(key, cntA, objB, a, true); err == nil {
		t.Fatal("page A opened as page B with v1 allowed")
	}
}

// Comments, attachment bytes and metadata never open as an object, nor the other way round,
// even bound to the same page.
func TestCrossKindSwapIsRejected(t *testing.T) {
	key := unhex(t, keyHex)
	page := []byte(`{"type":"page","title":"T","body":"[]"}`)
	obj, _ := sealNonce(key, cntA, objA, kindObject, make([]byte, nonceSize), page)
	cmt, _ := sealNonce(key, cntA, objA, kindComment, make([]byte, nonceSize), page)
	att, _ := SealAttachment(key, cntA, objA, page)
	attMeta, _ := sealNonce(key, cntA, objA, kindAttachmentMeta, make([]byte, nonceSize), []byte(`{"name":"T","type":"page","body":"[]"}`))
	meta, _ := SealContainerName(key, cntA, "T", true)
	for name, box := range map[string][]byte{"comment": cmt, "attachment bytes": att, "attachment metadata": attMeta} {
		if _, err := OpenObject(key, cntA, objA, box, true); err == nil {
			t.Fatalf("%s opened as an object", name)
		}
	}
	if _, err := OpenObject(key, cntA, objA, meta, true); err == nil {
		t.Fatal("container meta opened as an object")
	}
	if _, err := OpenAttachment(key, cntA, objA, obj, true); err == nil {
		t.Fatal("an object opened as attachment bytes")
	}
	if _, err := OpenAttachmentMeta(key, cntA, objA, obj, true); err == nil {
		t.Fatal("an object opened as attachment metadata")
	}
	if _, _, err := OpenContainerName(key, cntA, obj, true); err == nil {
		t.Fatal("an object opened as container meta")
	}
}

// v1 opens only while the caller allows it (before the migration marker), including a v1 blob
// whose random nonce starts with the v2 version byte.
func TestV1OnlyBeforeTheMarker(t *testing.T) {
	key := unhex(t, keyHex)
	for _, nonce := range []string{"000000000000000000000000", "020202020202020202020202"} {
		box := sealV1(t, key, cntA, objectLabel, unhex(t, nonce), []byte(`{"type":"page","title":"Old","body":""}`))
		if p, err := OpenObject(key, cntA, objA, box, true); err != nil || p.Title != "Old" || p.Legacy != nil {
			t.Fatalf("v1 before the marker: %+v, %v", p, err)
		}
		if _, err := OpenObject(key, cntA, objA, box, false); err == nil {
			t.Fatal("v1 object opened after the marker")
		}
	}
	old := sealV1(t, key, cntA, metaLabel, make([]byte, nonceSize), []byte(`{"name":"Old","objects":2}`))
	if _, migrated, err := OpenContainerName(key, cntA, old, true); err != nil || migrated {
		t.Fatalf("a v1 meta's marker counted: %v, %v", migrated, err)
	}
	if _, _, err := OpenContainerName(key, cntA, old, false); err == nil {
		t.Fatal("v1 container meta opened after the marker")
	}
}

// legacy round-trips: {} stays {}, absent stays absent, and only valid pins survive.
func TestLegacyPins(t *testing.T) {
	key := unhex(t, keyHex)
	digest := hex.EncodeToString(sha256.New().Sum(nil))
	for _, p := range []Payload{
		{Type: "page", Body: "[]"},
		{Type: "page", Body: "[]", Legacy: map[string]string{}},
		{Type: "page", Body: "[]", Legacy: map[string]string{cmtA: digest}},
	} {
		box, _ := SealObject(key, cntA, objA, p)
		if got, err := OpenObject(key, cntA, objA, box, false); err != nil || !reflect.DeepEqual(got, p) {
			t.Fatalf("%+v → %+v, %v", p, got, err)
		}
	}
	got, err := parsePayload([]byte(`{"type":"page","body":"","legacy":{"` + cmtA + `":"` + digest + `","obj_0123456789abcdefghjkmnpqrs":"` + digest + `","` + attA + `":"ABC"}}`))
	if err != nil || !reflect.DeepEqual(got.Legacy, map[string]string{cmtA: digest}) {
		t.Fatalf("%+v, %v", got.Legacy, err)
	}
	if got, _ := parsePayload([]byte(`{"type":"page","body":"","legacy":7}`)); got.Legacy == nil || len(got.Legacy) != 0 {
		t.Fatalf("malformed legacy narrowed to %#v, want {}", got.Legacy)
	}
}

func TestOpenObjectRejectsNonPayloads(t *testing.T) {
	key := unhex(t, keyHex)
	for _, plaintext := range []string{`[]`, `null`, `"page"`, `{"type":"page","title":"no body"}`, `{"body":3}`, `not json`} {
		box, err := sealNonce(key, cntA, objA, kindObject, make([]byte, nonceSize), []byte(plaintext))
		if err != nil {
			t.Fatal(err)
		}
		if p, err := OpenObject(key, cntA, objA, box, false); err == nil {
			t.Fatalf("%s opened as %+v", plaintext, p)
		}
	}
	box, _ := sealNonce(key, cntA, cntA, kindContainerMeta, make([]byte, nonceSize), []byte(`{"title":"x"}`))
	if _, _, err := OpenContainerName(key, cntA, box, false); err == nil {
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
		// Client-only code: content crypto, the MCP bridge and its SDK.
		if strings.HasSuffix(dep, "/internal/notecrypto") || strings.HasSuffix(dep, "/internal/teamkeys") ||
			strings.HasSuffix(dep, "/cmd/kynotes-mcp") || strings.HasPrefix(dep, "github.com/modelcontextprotocol/") {
			t.Fatalf("cmd/kynotes-server depends on %s", dep)
		}
	}
	// The names above are real: the bridge itself links them.
	bridge, err := exec.Command("go", "list", "-deps", "github.com/Busnes-app/kynotes-server/cmd/kynotes-mcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/internal/notecrypto\n", "/internal/teamkeys\n", "github.com/modelcontextprotocol/go-sdk/mcp\n"} {
		if !strings.Contains(string(bridge), want) {
			t.Fatalf("cmd/kynotes-mcp does not link %s", want)
		}
	}
}
