package backup

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"gopkg.in/yaml.v3"
)

var members = []string{"kynotes.sqlite", "secrets/pairing.key", "secrets/serversalt.key", "recovery.pub", "kynotes.yaml", "blob-inventory.json"}
var tables = []string{"users", "devices", "key_envelopes", "containers", "objects", "object_versions", "attachments", "blobs", "server_settings"}

type Blob struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size_bytes"`
}
type Recipe struct {
	Version       int              `json:"version"`
	RequiredFiles []string         `json:"required_files"`
	SQLitePaths   []string         `json:"sqlite_paths"`
	Counts        map[string]int64 `json:"counts"`
}

func readMember(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, capsule.MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || int64(len(data)) > capsule.MaxFileBytes {
		return nil, errors.New("capsule member empty or exceeds library size limit")
	}
	return data, nil
}
func (s *Service) Collect(ctx context.Context) (recoveryclient.Payload, error) {
	p := recoveryclient.Payload{ServiceName: config.AppName, AppVersion: s.version}
	if len(s.cfg.Secrets.PairingSecret) < 32 || len(s.cfg.Secrets.ServerSaltKey) < 32 {
		return p, errors.New("deployment secrets missing")
	}
	key, err := recoveryclient.LoadRecoveryKey(s.cfg.DataDir, settings{s.store})
	if err != nil {
		return p, err
	}
	scratch, err := os.MkdirTemp(s.cfg.DataDir, "snapshot-")
	if err != nil {
		return p, err
	}
	defer os.RemoveAll(scratch)
	path := filepath.Join(scratch, "kynotes.sqlite")
	if err = recoveryclient.SQLiteSnapshot(ctx, s.store.DB(), path); err != nil {
		return p, err
	}
	data, err := readMember(path)
	if err != nil {
		return p, err
	}
	p.Files = append(p.Files, recoveryclient.File{Path: members[0], Data: data, Mode: 0600})
	snap, err := sql.Open("sqlite", path+"?mode=ro")
	if err != nil {
		return p, err
	}
	defer snap.Close()
	recipe := Recipe{Version: 1, RequiredFiles: slices.Clone(members), SQLitePaths: []string{members[0]}, Counts: map[string]int64{}}
	for _, table := range tables {
		var count int64
		if err = snap.QueryRowContext(ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil {
			return p, err
		}
		recipe.Counts[table] = count
	}
	inventory := []Blob{}
	rows, err := snap.QueryContext(ctx, `SELECT digest,size_bytes FROM blobs ORDER BY digest`)
	if err != nil {
		return p, err
	}
	for rows.Next() {
		var b Blob
		if err = rows.Scan(&b.Digest, &b.Size); err != nil {
			rows.Close()
			return p, err
		}
		inventory = append(inventory, b)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return p, err
	}
	blobJSON, err := json.Marshal(inventory)
	if err != nil {
		return p, err
	}
	cfgYAML, err := yaml.Marshal(s.cfg)
	if err != nil {
		return p, err
	}
	for i, data := range [][]byte{[]byte(base64.StdEncoding.EncodeToString([]byte(s.cfg.Secrets.PairingSecret))), []byte(base64.StdEncoding.EncodeToString([]byte(s.cfg.Secrets.ServerSaltKey))), key.Public.Bytes(), cfgYAML, blobJSON} {
		if int64(len(data)) > capsule.MaxFileBytes {
			return p, errors.New("capsule member exceeds library size limit")
		}
		p.Files = append(p.Files, recoveryclient.File{Path: members[i+1], Data: data, Mode: 0600})
	}
	// Recipe lists only paths and counts. Effective configuration (including secrets)
	// and the blob inventory are members inside the encrypted payload.
	raw, _ := json.Marshal(recipe)
	var recipeMap map[string]any
	_ = json.Unmarshal(raw, &recipeMap)
	p.VerificationRecipe = recipeMap
	p.Dependencies = map[string]any{"ciphertext_blobs": "restore separately from blob mirror"}
	return p, nil
}

// Checks consumes the authenticated, JSON-decoded manifest. Every fixed requirement
// remains mandatory even when the recipe is missing or malformed.
func Checks(dir string, opened capsule.Manifest) []recoveryclient.Check {
	fail := func(message string) []recoveryclient.Check {
		return []recoveryclient.Check{{Name: "KyNotes restore", Passed: false, Message: message}}
	}
	raw, err := json.Marshal(opened.VerificationRecipe)
	if err != nil {
		return fail("invalid recipe")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var recipe Recipe
	if err = decoder.Decode(&recipe); err != nil || recipe.Version != 1 || !slices.Equal(recipe.RequiredFiles, members) || !slices.Equal(recipe.SQLitePaths, []string{members[0]}) || len(recipe.Counts) != len(tables) {
		return fail("missing or malformed required recipe")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fail("scratch unavailable")
	}
	defer root.Close()
	for _, path := range recipe.RequiredFiles {
		if !filepath.IsLocal(path) || filepath.Clean(path) != path {
			return fail("unsafe member path")
		}
		info, err := root.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Mode().Perm()&0077 != 0 {
			return fail("required private member missing or unsafe")
		}
	}
	cfgBytes, err := root.ReadFile("kynotes.yaml")
	if err != nil {
		return fail("configuration missing")
	}
	var cfg config.Config
	if yaml.Unmarshal(cfgBytes, &cfg) != nil || len(cfg.Secrets.PairingSecret) < 32 || len(cfg.Secrets.ServerSaltKey) < 32 {
		return fail("deployment secrets invalid")
	}
	for path, want := range map[string]string{"secrets/pairing.key": cfg.Secrets.PairingSecret, "secrets/serversalt.key": cfg.Secrets.ServerSaltKey} {
		raw, err := root.ReadFile(path)
		if err != nil {
			return fail("secret file missing")
		}
		decoded, err := base64.StdEncoding.DecodeString(string(raw))
		if err != nil || string(decoded) != want {
			return fail("effective deployment secrets mismatch")
		}
	}
	pubBytes, err := root.ReadFile("recovery.pub")
	if err != nil {
		return fail("recovery pin missing")
	}
	pub, err := recoverykey.ParsePublicKey(pubBytes)
	if err != nil {
		return fail("invalid recovery pin")
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "kynotes.sqlite")+"?mode=ro")
	if err != nil {
		return fail("database missing")
	}
	defer db.Close()
	var integrity string
	if err = db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return fail("database integrity failed")
	}
	for _, table := range tables {
		want, ok := recipe.Counts[table]
		if !ok || want < 0 {
			return fail("required table count missing")
		}
		var got int64
		if err = db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&got); err != nil || got != want {
			return fail("restored table count mismatch")
		}
	}
	var admins int
	if err = db.QueryRow(`SELECT count(*) FROM users WHERE role='admin' AND status='active'`).Scan(&admins); err != nil || admins == 0 {
		return fail("no active administrator restored")
	}
	var pin string
	if err = db.QueryRow(`SELECT value FROM server_settings WHERE key='kyrecovery_key_id'`).Scan(&pin); err != nil || pin != pub.ID() {
		return fail("restored pin mismatch")
	}
	var encrypted string
	err = db.QueryRow(`SELECT value FROM server_settings WHERE key='kyrecovery_token_enc'`).Scan(&encrypted)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fail("pairing settings unreadable")
	}
	if encrypted != "" {
		seal, e := recoveryclient.NewAESGCMSealer([]byte(cfg.Secrets.ServerSaltKey), TokenLabel)
		if e != nil {
			return fail("token sealer invalid")
		}
		if _, e = seal.Open(encrypted); e != nil {
			return fail("restored pairing token cannot open")
		}
	}
	invBytes, err := root.ReadFile("blob-inventory.json")
	if err != nil {
		return fail("blob inventory missing")
	}
	var inventory []Blob
	if json.Unmarshal(invBytes, &inventory) != nil || int64(len(inventory)) != recipe.Counts["blobs"] {
		return fail("blob inventory count mismatch")
	}
	rows, err := db.Query(`SELECT digest,size_bytes FROM blobs ORDER BY digest`)
	if err != nil {
		return fail("blob inventory unreadable")
	}
	defer rows.Close()
	i := 0
	for rows.Next() {
		var b Blob
		if rows.Scan(&b.Digest, &b.Size) != nil || i >= len(inventory) || b != inventory[i] {
			return fail("blob inventory mismatch")
		}
		i++
	}
	if rows.Err() != nil || i != len(inventory) {
		return fail("incomplete blob inventory")
	}
	return []recoveryclient.Check{{Name: "KyNotes restore", Passed: true, Message: fmt.Sprintf("database, %d tables, administrator, secrets, pin and blob inventory verified; blob bytes require separate recovery", len(tables))}}
}
