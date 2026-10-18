// Package notecrypto is the Go port of web/src/crypto.ts content sealing: object
// payloads, container names, attachment metadata and attachment bytes, sealed
// under a 32-byte container key. Sealed form is nonce(12) ‖ AES-256-GCM(subkey)
// with no AAD; the container binding is the HKDF salt:
// subkey = HKDF-SHA256(key, salt = containerID, info = label, 32).
// Clients only (the MCP bridge); the server never imports it.
package notecrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
)

const (
	objectLabel     = "kynotes/object/v1" // pages, sections, groups and attachment bytes
	metaLabel       = "kynotes/container-meta/v1"
	attachmentLabel = "kynotes/attachment-meta/v1"
	nonceSize       = 12
	minSealed       = nonceSize + 16
)

var (
	containerID = regexp.MustCompile(`^cnt_[0-9a-hjkmnp-tv-z]{26}$`)
	objectID    = regexp.MustCompile(`^obj_[0-9a-hjkmnp-tv-z]{26}$`)
	orderKey    = regexp.MustCompile(`^[0-9a-z]*[1-9a-z]$`)
	colors      = []string{"orange", "blue", "green", "purple", "red", "teal", "yellow", "gray"}

	errOpen = errors.New("notecrypto: unable to decrypt: invalid key or tampered ciphertext")
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

func sealNonce(key []byte, container, label string, nonce, plaintext []byte) ([]byte, error) {
	gcm, err := aead(key, container, label)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(bytes.Clone(nonce), nonce, plaintext, nil), nil
}

func seal(key []byte, container, label string, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return sealNonce(key, container, label, nonce, plaintext)
}

func open(key []byte, container, label string, sealed []byte) ([]byte, error) {
	gcm, err := aead(key, container, label)
	if err != nil {
		return nil, err
	}
	if len(sealed) < minSealed {
		return nil, errOpen
	}
	plaintext, err := gcm.Open(nil, sealed[:nonceSize], sealed[nonceSize:], nil)
	if err != nil {
		return nil, errOpen
	}
	return plaintext, nil
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
}

type pageJSON struct {
	Type    string `json:"type"`
	Title   string `json:"title"`
	Body    string `json:"body"`
	Section string `json:"section,omitempty"`
	Order   string `json:"order,omitempty"`
	Level   *int   `json:"level,omitempty"`
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
	return pageJSON{"page", p.Title, p.Body, p.Section, p.Order, p.Level}
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
	return p, nil
}

// SealObject seals a page, section or group (crypto.ts encryptNote).
func SealObject(key []byte, container string, p Payload) ([]byte, error) {
	plaintext, err := marshal(p.wire())
	if err != nil {
		return nil, err
	}
	return seal(key, container, objectLabel, plaintext)
}

// OpenObject opens and narrows an object (crypto.ts decryptObject); a payload
// parseObjectPayload would reject is an error.
func OpenObject(key []byte, container string, sealed []byte) (Payload, error) {
	plaintext, err := open(key, container, objectLabel, sealed)
	if err != nil {
		return Payload{}, err
	}
	return parsePayload(plaintext)
}

// SealContainerName seals a notebook name (crypto.ts encryptContainerMeta).
func SealContainerName(key []byte, container, name string) ([]byte, error) {
	plaintext, err := marshal(struct {
		Name string `json:"name"`
	}{name})
	if err != nil {
		return nil, err
	}
	return seal(key, container, metaLabel, plaintext)
}

// OpenContainerName opens a notebook name (crypto.ts decryptContainerMeta).
func OpenContainerName(key []byte, container string, sealed []byte) (string, error) {
	plaintext, err := open(key, container, metaLabel, sealed)
	if err != nil {
		return "", err
	}
	var meta struct {
		Name *string `json:"name"`
	}
	if err := json.Unmarshal(plaintext, &meta); err != nil || meta.Name == nil {
		return "", errors.New("notecrypto: invalid workspace metadata")
	}
	return *meta.Name, nil
}

// AttachmentMeta is an attachment's file name, MIME type and plaintext size.
type AttachmentMeta struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size int64  `json:"size"`
}

// SealAttachmentMeta seals attachment metadata (crypto.ts encryptAttachmentMetadata).
func SealAttachmentMeta(key []byte, container string, meta AttachmentMeta) ([]byte, error) {
	plaintext, err := marshal(meta)
	if err != nil {
		return nil, err
	}
	return seal(key, container, attachmentLabel, plaintext)
}

// OpenAttachmentMeta opens attachment metadata (crypto.ts decryptAttachmentMetadata).
func OpenAttachmentMeta(key []byte, container string, sealed []byte) (AttachmentMeta, error) {
	var meta AttachmentMeta
	plaintext, err := open(key, container, attachmentLabel, sealed)
	if err != nil {
		return meta, err
	}
	if err := json.Unmarshal(plaintext, &meta); err != nil {
		return AttachmentMeta{}, errors.New("notecrypto: invalid attachment metadata")
	}
	return meta, nil
}

// SealAttachment seals attachment bytes (crypto.ts encryptAttachment). It
// shares the object label, as the browser does.
func SealAttachment(key []byte, container string, plaintext []byte) ([]byte, error) {
	return seal(key, container, objectLabel, plaintext)
}

// OpenAttachment opens attachment bytes (crypto.ts decryptAttachment).
func OpenAttachment(key []byte, container string, sealed []byte) ([]byte, error) {
	return open(key, container, objectLabel, sealed)
}
