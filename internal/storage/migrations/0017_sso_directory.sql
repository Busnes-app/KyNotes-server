-- Resource high-water marks outlive replay expiry and even local account deletion.
CREATE TABLE sso_directory_state (
 issuer TEXT NOT NULL, subject TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>0), digest TEXT NOT NULL,
 active INTEGER NOT NULL CHECK(active IN (0,1)), event_id TEXT NOT NULL,
 PRIMARY KEY(issuer,subject)
);
ALTER TABLE sso_sync_events ADD COLUMN issuer TEXT NOT NULL DEFAULT '';
ALTER TABLE sso_sync_events ADD COLUMN digest TEXT NOT NULL DEFAULT '';

-- Neither an OIDC auto-provision race nor a local status edit overrides directory denial.
CREATE TRIGGER users_directory_insert BEFORE INSERT ON users
WHEN NEW.status='active' AND EXISTS(SELECT 1 FROM sso_directory_state WHERE issuer=NEW.sso_issuer AND subject=NEW.sso_subject AND active=0)
BEGIN SELECT RAISE(ABORT,'directory account disabled'); END;
CREATE TRIGGER users_directory_update BEFORE UPDATE OF status,sso_issuer,sso_subject ON users
WHEN NEW.status='active' AND EXISTS(SELECT 1 FROM sso_directory_state WHERE issuer=NEW.sso_issuer AND subject=NEW.sso_subject AND active=0)
BEGIN SELECT RAISE(ABORT,'directory account disabled'); END;
