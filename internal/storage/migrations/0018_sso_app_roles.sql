-- Legacy global-role provenance cannot be recovered. Keep an unlinked local admin
-- for upgrade, then resync the explicit app role and sign in again.
ALTER TABLE sessions ADD COLUMN sso_app_admin INTEGER NOT NULL DEFAULT 0 CHECK(sso_app_admin IN (0,1));
INSERT INTO audit_events(id,user_id,actor_user_id,object_id,event,created_at,at,outcome,reason_code)
SELECT 'aud_'||lower(hex(randomblob(16))), id,id,sso_subject,'auth.sso_role_upgrade',
 strftime('%Y-%m-%dT%H:%M:%SZ','now'), strftime('%Y-%m-%dT%H:%M:%SZ','now'),
 'success','legacy_role='||role
FROM users WHERE sso_subject<>'';
UPDATE users SET role='user' WHERE sso_subject<>'' AND role='admin';
UPDATE sessions SET revoked_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE sso_issuer<>'' AND revoked_at='';
