ALTER TABLE users ADD COLUMN sso_issuer TEXT NOT NULL DEFAULT '';
UPDATE users SET sso_issuer=coalesce((SELECT value FROM server_settings WHERE key='sso_issuer_url'),'') WHERE sso_subject<>'';
CREATE UNIQUE INDEX users_sso_identity ON users(sso_issuer,sso_subject) WHERE sso_subject<>'';

ALTER TABLE sessions ADD COLUMN sso_issuer TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN sso_client_id TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN sso_subject TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN sso_sid TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN sso_issued_at INTEGER NOT NULL DEFAULT 0;
CREATE INDEX sessions_sso_scope ON sessions(sso_issuer,sso_client_id,sso_sid,sso_subject);
ALTER TABLE devices ADD COLUMN sso_session_id TEXT NOT NULL DEFAULT '';
CREATE INDEX devices_sso_session ON devices(sso_session_id) WHERE sso_session_id<>'';

-- Existing credentials have no trustworthy login origin; preserve all encrypted data.
UPDATE sessions SET revoked_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE revoked_at='' AND user_id IN (SELECT id FROM users WHERE sso_subject<>'');
UPDATE devices SET revoked_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE revoked_at='' AND user_id IN (SELECT id FROM users WHERE sso_subject<>'');

-- Retention covers both signature validity and every still-live login transaction.
CREATE TABLE sso_logout_events (
 issuer TEXT NOT NULL, client_id TEXT NOT NULL, jti TEXT NOT NULL,
 subject TEXT NOT NULL, sid TEXT NOT NULL, issued_at INTEGER NOT NULL,
 retain_until INTEGER NOT NULL,
 PRIMARY KEY(issuer,client_id,jti)
);
CREATE INDEX sso_logout_expiry ON sso_logout_events(retain_until);

INSERT INTO audit_events(id,user_id,event,created_at,at,outcome,reason_code)
SELECT 'aud_'||lower(hex(randomblob(16))), '', 'auth.sso_upgrade',
 strftime('%Y-%m-%dT%H:%M:%SZ','now'), strftime('%Y-%m-%dT%H:%M:%SZ','now'),
 'success', 'legacy_credentials_revoked'
WHERE EXISTS(SELECT 1 FROM users WHERE sso_subject<>'');
