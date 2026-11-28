package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/Busnes-app/ky-primitives/syncauth"
	"github.com/Busnes-app/kynotes-server/internal/blobstore"
	"github.com/Busnes-app/kynotes-server/internal/config"
	"github.com/Busnes-app/kynotes-server/internal/sso"
	"github.com/Busnes-app/kynotes-server/internal/storage"
	"github.com/Busnes-app/kynotes-server/internal/storage/pgdialect"
)

// replicaInputs is the environment-only startup snapshot. The configuration build gate
// decides whether Serve may assemble it; maintenance uses the same shared field map.
type replicaInputs struct {
	DSN                                  string
	Tenancy                              storage.Tenancy
	Cells                                []string // KY_CELLS
	SSO                                  sso.SSOSettings
	VAPID                                *ecdsa.PrivateKey
	BlobEndpoint, BlobBucket, BlobRegion string
}

// readReplicaInputs never reads/mints local keys. Multi replicas take their shared keys only
// from the environment, even when the supplied single-mode config already holds local keys.
func readReplicaInputs(c config.Config) (config.Config, replicaInputs, error) {
	var in replicaInputs
	required := func(name string) (string, error) {
		value := os.Getenv(name)
		if value == "" {
			return "", fmt.Errorf("replicas: %s is required", name)
		}
		return value, nil
	}
	var err error
	if in.DSN, err = required("KYNOTES_DB_DSN"); err != nil {
		return c, in, err
	}
	if _, err := pgdialect.Config(in.DSN); err != nil {
		return c, in, err
	}
	in.Tenancy.Mode = "multi"
	if in.Tenancy.StaffOrg, err = required("KYNOTES_STAFF_ORG_ID"); err != nil {
		return c, in, err
	}
	if in.Cells, err = config.Cells(); err != nil {
		return c, in, fmt.Errorf("replicas: %w", err)
	}
	if _, err := blobstore.OrgPrefix(in.Cells[0], in.Tenancy.StaffOrg); err != nil {
		return c, in, errors.New("replicas: KYNOTES_STAFF_ORG_ID is invalid")
	}
	for name, dst := range map[string]*string{"KYNOTES_SECRETS_PAIRING_SECRET": &c.Secrets.PairingSecret, "KYNOTES_SECRETS_SERVER_SALT_KEY": &c.Secrets.ServerSaltKey} {
		value, err := required(name)
		if err != nil {
			return c, in, err
		}
		if len(value) < 32 {
			return c, in, fmt.Errorf("replicas: %s must contain at least 32 bytes", name)
		}
		*dst = value
	}
	in.SSO.Enabled, in.SSO.AutoProvision = true, true
	for name, dst := range map[string]*string{"KYNOTES_SSO_ISSUER": &in.SSO.IssuerURL, "KYNOTES_SSO_CLIENT_ID": &in.SSO.ClientID, "KYNOTES_SSO_CLIENT_SECRET": &in.SSO.ClientSecret, "KYNOTES_SSO_HMAC_SECRET": &in.SSO.HMACSecret} {
		value, err := required(name)
		if err != nil {
			return c, in, err
		}
		*dst = value
	}
	if !replicaHTTPS(in.SSO.IssuerURL) {
		return c, in, errors.New("replicas: KYNOTES_SSO_ISSUER must be HTTPS without credentials, query or fragment")
	}
	if len(in.SSO.HMACSecret) < syncauth.MinKeyBytes {
		return c, in, errors.New("replicas: KYNOTES_SSO_HMAC_SECRET is too short")
	}
	encoded, err := required("KYNOTES_VAPID_KEY")
	if err != nil {
		return c, in, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(raw) != 32 {
		return c, in, errors.New("replicas: KYNOTES_VAPID_KEY must be a base64 P-256 private key")
	}
	if in.VAPID, err = ecdsa.ParseRawPrivateKey(elliptic.P256(), raw); err != nil {
		return c, in, errors.New("replicas: KYNOTES_VAPID_KEY is not a P-256 private key")
	}
	if os.Getenv("KYNOTES_BLOB_BACKEND") != "object" {
		return c, in, errors.New("replicas: KYNOTES_BLOB_BACKEND must be object; no volume fallback")
	}
	for name, dst := range map[string]*string{"KYNOTES_BLOB_S3_ENDPOINT": &in.BlobEndpoint, "KYNOTES_BLOB_S3_BUCKET": &in.BlobBucket, "KYNOTES_BLOB_S3_REGION": &in.BlobRegion} {
		value, err := required(name)
		if err != nil {
			return c, in, err
		}
		*dst = value
	}
	if !replicaHTTPS(in.BlobEndpoint) {
		return c, in, errors.New("replicas: KYNOTES_BLOB_S3_ENDPOINT must be HTTPS without credentials, query or fragment")
	}
	return c, in, nil
}
func replicaHTTPS(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && !u.ForceQuery && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

// replicaFields enumerates shared behavior, including every security limit and key identity.
// Bind address, proxy peers, local directories/retention and logging stay per host. Object
// credentials never enter the fingerprint; the backend's store-identity check binds the bucket.
func replicaFields(c config.Config, in replicaInputs) map[string]string {
	encode := func(value any) string { raw, _ := json.Marshal(value); return string(raw) }
	server := c.Server
	server.Bind = ""
	server.TrustedProxies = nil
	vapid, _ := in.VAPID.PublicKey.Bytes() // P-256 was validated at the environment boundary.
	backupID := "off"
	if parse(c.Backup.DepositInterval) != 0 {
		backupID = "unavailable"
		if key, err := replicaBackupKey(); err == nil {
			digest := sha256.Sum256(key)
			backupID = hex.EncodeToString(digest[:])
		}
	}
	return map[string]string{
		"pg_backup_key": backupID, "pg_backup_prefix": os.Getenv("KYNOTES_PG_BACKUP_PREFIX"),
		"tenancy_mode": in.Tenancy.Mode, "staff_org_id": in.Tenancy.StaffOrg, "cells": encode(slices.Sorted(slices.Values(in.Cells))),
		"pairing_secret": c.Secrets.PairingSecret, "server_salt_key": c.Secrets.ServerSaltKey,
		"sso": encode(in.SSO), "vapid_key": base64.StdEncoding.EncodeToString(vapid),
		"server": encode(server), "limits": encode(c.Limits), "ratelimit": encode(c.RateLimit), "gc": encode(c.GC),
		"backup_deposit_interval": c.Backup.DepositInterval, "backup_allow_private_recovery": strconv.FormatBool(c.Backup.AllowPrivateRecovery),
		"strong_crypto": strconv.FormatBool(fips140.Enabled()), "blob_backend": "object",
		"blob_endpoint": in.BlobEndpoint, "blob_bucket": in.BlobBucket, "blob_region": in.BlobRegion,
	}
}
