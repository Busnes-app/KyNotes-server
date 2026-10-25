// Package notecrypto is the Go port of web/src/crypto.ts content sealing: object
// payloads, container names, attachment metadata and attachment bytes, sealed
// under a 32-byte container key. Writes use v2:
// 0x02 ‖ nonce(12) ‖ AES-256-GCM(subkey, nonce, plaintext, AAD), with
// subkey = HKDF-SHA256(key, salt = containerID, info = "kynotes/content/v2", 32) and
// AAD binding the container, the bound ID and the kind (contentAAD). Reads accept
// the unbound v1 form, nonce(12) ‖ AES-256-GCM(HKDF(..., info = label)) with no AAD,
// only when the caller allows it (before the notebook's migration marker).
// Clients only (the MCP bridge); the server never imports it.
package notecrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
)

const (
	objectLabel     = "kynotes/object/v1" // v1: pages, sections, groups and attachment bytes
	metaLabel       = "kynotes/container-meta/v1"
	attachmentLabel = "kynotes/attachment-meta/v1"
	contentLabel    = "kynotes/content/v2" // v2: one subkey, kinds told apart by the AAD
	version2        = 0x02
	nonceSize       = 12
	minSealed       = nonceSize + 16
)

// v2 kinds, the AAD's last field. The bound ID is the object for objects, the page for
// comments and attachments, and the container itself for container-meta.
const (
	kindObject         = "object"
	kindComment        = "comment" // browser only; here for the shared vectors
	kindAttachment     = "attachment"
	kindAttachmentMeta = "attachment-meta"
	kindContainerMeta  = "container-meta"
)

var (
	containerID = regexp.MustCompile(`^cnt_[0-9a-hjkmnp-tv-z]{26}$`)
	objectID    = regexp.MustCompile(`^obj_[0-9a-hjkmnp-tv-z]{26}$`)
	childID     = regexp.MustCompile(`^(cmt|att)_[0-9a-hjkmnp-tv-z]{26}$`)
	digestHex   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	orderKey    = regexp.MustCompile(`^[0-9a-z]*[1-9a-z]$`)
	colors      = []string{"orange", "blue", "green", "purple", "red", "teal", "yellow", "gray"}

	errOpen = errors.New("notecrypto: unable to decrypt: invalid key, tampered ciphertext or a refused older format")
)

func aead(key []byte, container, label string) (cipher.AEAD, error) {
	if len(key) != 32 || !containerID.MatchString(container) {
		return nil, errors.New("notecrypto: invalid content key or container ID")
	}
	subkey, err := hkdf.Key(sha256.New, key, []byte(container), label, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(subkey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// contentAAD is each field as uint16 big-endian length ‖ UTF-8 bytes: label, container, bound ID, kind.
func contentAAD(container, bound, kind string) []byte {
	var aad []byte
	for _, field := range []string{contentLabel, container, bound, kind} {
		aad = binary.BigEndian.AppendUint16(aad, uint16(len(field)))
		aad = append(aad, field...)
	}
	return aad
}

// checkBound keeps every field short and well formed: an object ID, or the container for its meta.
func checkBound(container, bound, kind string) error {
	if kind == kindContainerMeta && bound == container || kind != kindContainerMeta && objectID.MatchString(bound) {
		return nil
	}
	return errors.New("notecrypto: invalid bound ID")
}

func sealNonce(key []byte, container, bound, kind string, nonce, plaintext []byte) ([]byte, error) {
	gcm, err := aead(key, container, contentLabel)
	if err != nil {
		return nil, err
	}
	if err := checkBound(container, bound, kind); err != nil {
		return nil, err
	}
	return gcm.Seal(append([]byte{version2}, nonce...), nonce, plaintext, contentAAD(container, bound, kind)), nil
}

func seal(key []byte, container, bound, kind string, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return sealNonce(key, container, bound, kind, nonce, plaintext)
}

func openWith(key []byte, container, label string, sealed, aad []byte) ([]byte, error) {
	gcm, err := aead(key, container, label)
	if err != nil {
		return nil, err
	}
	if len(sealed) < minSealed {
		return nil, errOpen
	}
	plaintext, err := gcm.Open(nil, sealed[:nonceSize], sealed[nonceSize:], aad)
	if err != nil {
		return nil, errOpen
	}
	return plaintext, nil
}

// open reads the v2 form bound to (container, bound, kind); with v1 set it falls back to the
// unbound v1 form under label, since a v1 blob's random first byte may be 0x02 too. legacy
// reports a v1 read.
func open(key []byte, container, bound, kind, label string, sealed []byte, v1 bool) (plaintext []byte, legacy bool, err error) {
	if err := checkBound(container, bound, kind); err != nil {
		return nil, false, err
	}
	if len(sealed) > 0 && sealed[0] == version2 {
		plaintext, err := openWith(key, container, contentLabel, sealed[1:], contentAAD(container, bound, kind))
		if err == nil || !v1 {
			return plaintext, false, err
		}
	} else if !v1 {
		return nil, false, errOpen
	}
	plaintext, err = openWith(key, container, label, sealed, nil)
	return plaintext, err == nil, err
}

// marshal matches JSON.stringify for these shapes: no HTML escaping, no newline.
// ponytail: Go still escapes U+2028/U+2029; both sides parse it, only the bytes differ.
func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// Payload is a page, section or group as web/src/pages.ts parseObjectPayload narrows it.
type Payload struct {
	Type    string // "page", "section" or "group"
	Title   string
	Body    string // page: BlockNote JSON
	Section string // page: obj_ ID, "" for Quick Notes
	Level   *int   // page: 0, 1 or 2; nil when unset
	Color   string // section and group
	Group   string // section and group: obj_ ID of the enclosing group
	Order   string // fractional order key, "" when unset
	// Legacy is a migrated page's pins: comment or attachment ID → SHA-256 hex of that v1
	// child's ciphertext. nil when the page has no legacy field; preserve it on every edit.
	Legacy map[string]string
}

type pageJSON struct {
	Type    string            `json:"type"`
	Title   string            `json:"title"`
	Body    string            `json:"body"`
	Section string            `json:"section,omitempty"`
	Order   string            `json:"order,omitempty"`
	Level   *int              `json:"level,omitempty"`
	Legacy  map[string]string `json:"legacy,omitzero"` // {} is written, absent is not
}

type sectionJSON struct {
	Type  string `json:"type"`
	Title string `json:"title"`
	Color string `json:"color"`
	Order string `json:"order,omitempty"`
	Group string `json:"group,omitempty"`
}

func (p Payload) wire() any {
	if p.Type == "section" || p.Type == "group" {
		return sectionJSON{p.Type, p.Title, p.Color, p.Order, p.Group}
	}
	return pageJSON{"page", p.Title, p.Body, p.Section, p.Order, p.Level, p.Legacy}
}

// parsePayload ports parseObjectPayload: untrusted JSON narrowed field by field.
func parsePayload(plaintext []byte) (Payload, error) {
	var v map[string]any
	if err := json.Unmarshal(plaintext, &v); err != nil || v == nil {
		return Payload{}, errors.New("notecrypto: invalid object payload")
	}
	str := func(k string) (string, bool) { s, ok := v[k].(string); return s, ok }
	id := func(k string) string {
		if s, _ := str(k); objectID.MatchString(s) {
			return s
		}
		return ""
	}
	var p Payload
	if s, _ := str("order"); len(s) <= 512 && orderKey.MatchString(s) {
		p.Order = s
	}
	if t, _ := str("type"); t == "section" || t == "group" {
		p.Type, p.Group, p.Color = t, id("group"), "gray"
		if c, _ := str("color"); slices.Contains(colors, c) {
			p.Color = c
		}
		var ok bool
		if p.Title, ok = str("title"); !ok {
			p.Title = "Untitled " + t
		}
		return p, nil
	}
	body, ok := str("body")
	if !ok {
		return Payload{}, errors.New("notecrypto: invalid object payload")
	}
	p.Type, p.Body, p.Section = "page", body, id("section")
	p.Title, _ = str("title")
	if n, ok := v["level"].(float64); ok && (n == 0 || n == 1 || n == 2) {
		level := int(n)
		p.Level = &level
	}
	// Present but malformed is {}: a page with the field never accepts unpinned v1 children.
	if raw, ok := v["legacy"]; ok {
		p.Legacy = map[string]string{}
		pins, _ := raw.(map[string]any)
		for id, d := range pins {
			if s, _ := d.(string); childID.MatchString(id) && digestHex.MatchString(s) {
				p.Legacy[id] = s
			}
		}
	}
	return p, nil
}

// SealObject seals a page, section or group bound to its object ID (crypto.ts encryptNote).
func SealObject(key []byte, container, id string, p Payload) ([]byte, error) {
	plaintext, err := marshal(p.wire())
	if err != nil {
		return nil, err
	}
	return seal(key, container, id, kindObject, plaintext)
}

// OpenObject opens and narrows object id (crypto.ts decryptObject); a payload
// parseObjectPayload would reject is an error. v1 also accepts the unbound older form.
func OpenObject(key []byte, container, id string, sealed []byte, v1 bool) (Payload, error) {
	plaintext, _, err := open(key, container, id, kindObject, objectLabel, sealed, v1)
	if err != nil {
		return Payload{}, err
	}
	return parsePayload(plaintext)
}

type metaJSON struct {
	Name    string `json:"name"`
	Objects int    `json:"objects,omitempty"` // 2: every object is v2; v1 is refused from then on
}

// SealContainerName seals a notebook name (crypto.ts encryptContainerMeta); migrated adds the marker.
func SealContainerName(key []byte, container, name string, migrated bool) ([]byte, error) {
	meta := metaJSON{Name: name}
	if migrated {
		meta.Objects = 2
	}
	plaintext, err := marshal(meta)
	if err != nil {
		return nil, err
	}
	return seal(key, container, container, kindContainerMeta, plaintext)
}

// OpenContainerName opens a notebook name (crypto.ts decryptContainerMeta). migrated is true only
// for a v2 meta carrying the marker.
func OpenContainerName(key []byte, container string, sealed []byte, v1 bool) (name string, migrated bool, err error) {
	plaintext, legacy, err := open(key, container, container, kindContainerMeta, metaLabel, sealed, v1)
	if err != nil {
		return "", false, err
	}
	var meta struct {
		Name    *string `json:"name"`
		Objects any     `json:"objects"`
	}
	if err := json.Unmarshal(plaintext, &meta); err != nil || meta.Name == nil {
		return "", false, errors.New("notecrypto: invalid workspace metadata")
	}
	return *meta.Name, !legacy && meta.Objects == float64(2), nil
}

// AttachmentMeta is an attachment's file name, MIME type and plaintext size.
type AttachmentMeta struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size int64  `json:"size"`
}

// SealAttachmentMeta seals attachment metadata bound to the page it is uploaded for
// (crypto.ts encryptAttachmentMetadata).
func SealAttachmentMeta(key []byte, container, page string, meta AttachmentMeta) ([]byte, error) {
	plaintext, err := marshal(meta)
	if err != nil {
		return nil, err
	}
	return seal(key, container, page, kindAttachmentMeta, plaintext)
}

// OpenAttachmentMeta opens attachment metadata (crypto.ts decryptAttachmentMetadata).
func OpenAttachmentMeta(key []byte, container, page string, sealed []byte, v1 bool) (AttachmentMeta, error) {
	var meta AttachmentMeta
	plaintext, _, err := open(key, container, page, kindAttachmentMeta, attachmentLabel, sealed, v1)
	if err != nil {
		return meta, err
	}
	if err := json.Unmarshal(plaintext, &meta); err != nil {
		return AttachmentMeta{}, errors.New("notecrypto: invalid attachment metadata")
	}
	return meta, nil
}

// SealAttachment seals attachment bytes bound to their page (crypto.ts encryptAttachment).
func SealAttachment(key []byte, container, page string, plaintext []byte) ([]byte, error) {
	return seal(key, container, page, kindAttachment, plaintext)
}

// OpenAttachment opens attachment bytes (crypto.ts decryptAttachment). v1 bytes shared the
// object label.
func OpenAttachment(key []byte, container, page string, sealed []byte, v1 bool) ([]byte, error) {
	plaintext, _, err := open(key, container, page, kindAttachment, objectLabel, sealed, v1)
	return plaintext, err
}
