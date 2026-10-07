-- A user identity is a devices row with platform 'identity' and an unusable
-- secret_hash; this table holds its private key wrapped under the userKEK.
CREATE TABLE user_identities (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 device_id TEXT NOT NULL UNIQUE REFERENCES devices(id) ON DELETE CASCADE,
 wrapped_private_key BLOB NOT NULL,
 wrap_alg TEXT NOT NULL,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX devices_one_identity ON devices(user_id) WHERE platform='identity';
