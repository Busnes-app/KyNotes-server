-- Team keys P5: a copy of the identity private key wrapped under a key derived from a one-time
-- recovery code the server never sees (salt | nonce | AES-256-GCM, 76 bytes). recovery_id changes on
-- every set; a set must name the one it replaces (compare-and-swap). Deleted with the identity row.
ALTER TABLE user_identities ADD COLUMN recovery_id TEXT NOT NULL DEFAULT '';
ALTER TABLE user_identities ADD COLUMN recovery_alg TEXT NOT NULL DEFAULT '';
ALTER TABLE user_identities ADD COLUMN recovery_wrapped_key BLOB NOT NULL DEFAULT x'';
ALTER TABLE user_identities ADD COLUMN recovery_updated_at TEXT NOT NULL DEFAULT '';
