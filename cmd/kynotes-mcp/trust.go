package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/Busnes-app/kynotes-server/internal/teamkeys"
)

const envelopeAlg = "x25519-hkdf-sha256-chacha20poly1305"

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

// member is a notebook member as the server lists it, with the identity it shows for them.
type member struct {
	UserID   string `json:"userId"`
	Username string `json:"username"`
	Role     string `json:"role"`
	identity *publicIdentity
}

type publicIdentity struct {
	DeviceID  string `json:"deviceId"`
	PublicKey string `json:"publicKey"`
}

type envelopeRow struct {
	DeviceID      string `json:"deviceId"`
	KeyGeneration int64  `json:"keyGeneration"`
	Alg           string `json:"alg"`
	Envelope      string `json:"envelope"`
}

func isSteward(role string) bool { return role == "owner" || role == "admin" }

// keyState is what the bridge remembers per notebook; every field only rises (keyring.ts KeyState).
type keyState struct {
	Mark       int64             `json:"mark"`       // highest generation accepted from itself or a current steward
	Shared     int64             `json:"shared"`     // highest sharedGeneration seen
	Generation int64             `json:"generation"` // highest keyGeneration seen
	Digests    map[string]string `json:"digests"`    // generation → SHA-256 of the key accepted for it
}

// trustState is state-dir/trust.json: TOFU pins (user ID → identity public key, base64) and key
// state per notebook.
type trustState struct {
	Pins       map[string]string    `json:"pins"`
	Containers map[string]*keyState `json:"containers"`
}

func loadTrust(path string) (*trustState, error) {
	t := &trustState{Pins: map[string]string{}, Containers: map[string]*keyState{}}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return t, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("%s: mode %o, want 600", path, info.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, t); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if t.Pins == nil {
		t.Pins = map[string]string{}
	}
	if t.Containers == nil {
		t.Containers = map[string]*keyState{}
	}
	return t, nil
}

// save replaces the file atomically, 0600.
func (t *trustState) save(path string) error {
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".trust-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(b); err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// errRollback: the server reports an older sharing state than this bridge has seen.
var errRollback = errors.New("the server reports an older notebook key state than this bridge has seen (possible rollback); refusing")

// pinChangedError: a current owner or admin's identity key differs from its pin.
type pinChangedError struct{ userID, username, pinned, now string }

func (e *pinChangedError) Error() string {
	old, _ := base64.StdEncoding.DecodeString(e.pinned)
	cur, _ := base64.StdEncoding.DecodeString(e.now)
	return fmt.Sprintf("the encryption key of %s · %q changed (was %s, now %s). A password reset or account recovery changes it; so would a server substituting its own key. Compare the new fingerprint with that person, then remove their pin from trust.json to accept it",
		clean(e.userID), clean(e.username), fingerprint(old), fingerprint(cur))
}

// raise is keyring.ts guardContainer plus raiseFloor: a server reporting a lower generation
// than this bridge has seen is refused outright, for reads too.
func (k *keyState) raise(c container) error {
	if c.SharedGeneration < k.Shared || c.KeyGeneration < k.Generation {
		return errRollback
	}
	k.Shared, k.Generation = c.SharedGeneration, c.KeyGeneration
	return nil
}

// self is the bridge's own identity.
type self struct {
	userID, deviceID string
	key              *ecdh.PrivateKey
}

type openedRing struct {
	ring  map[int64][]byte
	fresh []member // stewards pinned on first contact
	known keyState
}

// openKeyring ports web/src/keyring.ts openKeyring: a key is accepted only from this identity, a
// current owner or admin whose identity key matches its pin (first contact pins it), or, below
// this bridge's own mark, any identity pinned before this call. The first key per generation
// wins, across runs through the stored digest. A changed steward key is an error, never trusted.
func openKeyring(containerID string, rows []envelopeRow, me self, members []member, pins map[string]string, known keyState) (openedRing, error) {
	out := openedRing{ring: map[int64][]byte{}, known: known}
	out.known.Digests = map[string]string{}
	for g, d := range known.Digests {
		out.known.Digests[g] = d
	}
	var pinnedKeys [][]byte
	for _, k := range pins {
		if raw, err := base64.StdEncoding.DecodeString(k); err == nil && len(raw) == 32 {
			pinnedKeys = append(pinnedKeys, raw)
		}
	}
	accept := func(generation int64, key []byte) bool {
		sum := sha256.Sum256(key)
		digest := hex.EncodeToString(sum[:])
		g := strconv.FormatInt(generation, 10)
		if prior, ok := out.ring[generation]; ok {
			return bytes.Equal(prior, key)
		}
		if stored, ok := out.known.Digests[g]; ok && stored != digest {
			return false
		}
		out.ring[generation], out.known.Digests[g] = key, digest
		return true
	}
	open := func(envelope []byte, generation int64, sender []byte) []byte {
		if generation < 1 || generation > math.MaxUint32 {
			return nil
		}
		key, err := teamkeys.OpenEnvelope(envelope, me.key, containerID, uint32(generation), me.deviceID, sender)
		if err != nil {
			return nil
		}
		return key
	}
	newPins := map[string]string{}
	type row struct {
		envelope   []byte
		generation int64
	}
	var deferred []row
	for _, r := range rows {
		if r.DeviceID != me.deviceID || r.Alg != envelopeAlg {
			continue
		}
		envelope, err := base64.StdEncoding.DecodeString(r.Envelope)
		if err != nil {
			continue
		}
		sender, err := teamkeys.EnvelopeSender(envelope)
		if err != nil {
			continue
		}
		var key []byte
		var steward *member
		if sender == me.deviceID {
			key = open(envelope, r.KeyGeneration, me.key.PublicKey().Bytes())
		} else {
			for i := range members {
				if m := &members[i]; m.identity != nil && m.identity.DeviceID == sender && m.UserID != me.userID && isSteward(m.Role) && userID.MatchString(m.UserID) {
					steward = m
				}
			}
			if steward != nil {
				pub, err := base64.StdEncoding.DecodeString(steward.identity.PublicKey)
				if err != nil || len(pub) != 32 {
					continue
				}
				pinned, ok := pins[steward.UserID]
				if !ok {
					pinned, ok = newPins[steward.UserID]
				}
				if ok && !sameKey(pinned, steward.identity.PublicKey) {
					return openedRing{}, &pinChangedError{steward.UserID, steward.Username, pinned, steward.identity.PublicKey}
				}
				key = open(envelope, r.KeyGeneration, pub)
			}
		}
		if key == nil {
			deferred = append(deferred, row{envelope, r.KeyGeneration})
			continue
		}
		if !accept(r.KeyGeneration, key) {
			continue
		}
		out.known.Mark = max(out.known.Mark, r.KeyGeneration)
		if steward != nil {
			if _, ok := pins[steward.UserID]; !ok {
				if _, ok := newPins[steward.UserID]; !ok {
					newPins[steward.UserID] = steward.identity.PublicKey
					out.fresh = append(out.fresh, *steward)
				}
			}
		}
	}
	// History from identities pinned before this call, strictly below the mark.
	for _, d := range deferred {
		if d.generation >= out.known.Mark {
			continue
		}
		for _, sender := range pinnedKeys {
			if key := open(d.envelope, d.generation, sender); key != nil {
				accept(d.generation, key)
				break
			}
		}
	}
	return out, nil
}

func sameKey(a, b string) bool {
	x, err1 := base64.StdEncoding.DecodeString(a)
	y, err2 := base64.StdEncoding.DecodeString(b)
	return err1 == nil && err2 == nil && len(x) == 32 && bytes.Equal(x, y)
}

// readKey is keyring.ts readKeys: a row opens only with its own generation's key, at or above
// the first keyed generation.
func readKey(ring map[int64][]byte, shared, generation int64) []byte {
	if shared == 0 || generation < shared {
		return nil
	}
	return ring[generation]
}

// userID is the server's user ID format; a member reported with any other ID is never trusted or shown.
var userID = regexp.MustCompile(`^usr_[0-9a-hjkmnp-tv-z]{26}$`)

// clean is pins.ts displayName's sanitizer: one line, no control, bidi or zero-width characters, 64 runes.
func clean(s string) string {
	var out []rune
	space := false
	for _, r := range s {
		if r < 0x20 || r >= 0x7f && r <= 0x9f || r == 0x61c || r >= 0x200b && r <= 0x200f || r >= 0x2028 && r <= 0x202e || r >= 0x2066 && r <= 0x2069 || r == 0xfeff || r == ' ' || r == '\t' {
			space = len(out) > 0
			continue
		}
		if space {
			out = append(out, ' ')
			space = false
		}
		out = append(out, r)
	}
	if len(out) > 64 {
		return string(out[:63]) + "…"
	}
	return string(out)
}
