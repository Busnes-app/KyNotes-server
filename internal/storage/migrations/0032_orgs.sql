-- Tenancy, PR 1 (docs/superpowers/specs/2026-11-23-tenancy-design.md, "org_id on every row").
-- Every org-owned row names its org. A single-tenant install has one org, the default org, so
-- every query answers as before. N7's cross-org triggers come with PR 3; the PostgreSQL keys with PR 2.
CREATE TABLE orgs (
 id TEXT PRIMARY KEY,
 status TEXT NOT NULL CHECK(status IN ('active','suspended','deletion_scheduled','deleted','stale')),
 revision INTEGER NOT NULL DEFAULT 0,
 enabled INTEGER NOT NULL DEFAULT 1,
 home_region TEXT NOT NULL,
 seen_at TEXT NOT NULL DEFAULT '',
 purged_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE erased_subjects (subject TEXT PRIMARY KEY, org_id TEXT NOT NULL, revision INTEGER NOT NULL);
-- An install with accounts is an existing one, always single-tenant. A fresh database gets its
-- org from ensureOrgs, which knows the configured mode.
INSERT INTO orgs(id,status,home_region) SELECT '00000000-0000-0000-0000-000000000001','active','local' WHERE EXISTS(SELECT 1 FROM users);

ALTER TABLE users ADD COLUMN org_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE containers ADD COLUMN org_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE blobs ADD COLUMN org_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE blob_containers ADD COLUMN org_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE object_versions ADD COLUMN org_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE conflicts ADD COLUMN org_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE attachments ADD COLUMN org_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE upload_sessions ADD COLUMN org_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE sealed_share_links ADD COLUMN org_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
-- NULL is a platform row. Every writer names the org; no default, so one that forgets cannot
-- land in an org by accident (and the trigger below refuses it for a customer account).
ALTER TABLE audit_events ADD COLUMN org_id TEXT;
-- PostgreSQL keys blobs by (org_id, digest) (N8). This index makes the pair a key here too
-- (implied by the digest key), so a claim's ON CONFLICT(org_id,digest) is one SQL text for both.
CREATE UNIQUE INDEX blobs_org_digest ON blobs(org_id,digest);

-- Cleanup sizes a row from SELECT *, which reports ALTER's virtual default. Store it in every
-- cleanup source row now, so a later cleanup rewrite cannot grow the cell (docs/CLEANUP-CAPACITY.md).
UPDATE containers SET org_id='00000000-0000-0000-0000-000000000001';
UPDATE sealed_share_links SET org_id='00000000-0000-0000-0000-000000000001';
UPDATE audit_events SET org_id='00000000-0000-0000-0000-000000000001' WHERE EXISTS(SELECT 1 FROM orgs);

-- The org must exist.
CREATE TRIGGER users_org_exists BEFORE INSERT ON users WHEN NOT EXISTS(SELECT 1 FROM orgs WHERE id=NEW.org_id) BEGIN SELECT RAISE(ABORT,'org_id names no org'); END;
CREATE TRIGGER containers_org_exists BEFORE INSERT ON containers WHEN NOT EXISTS(SELECT 1 FROM orgs WHERE id=NEW.org_id) BEGIN SELECT RAISE(ABORT,'org_id names no org'); END;
CREATE TRIGGER blobs_org_exists BEFORE INSERT ON blobs WHEN NOT EXISTS(SELECT 1 FROM orgs WHERE id=NEW.org_id) BEGIN SELECT RAISE(ABORT,'org_id names no org'); END;
CREATE TRIGGER blob_containers_org_exists BEFORE INSERT ON blob_containers WHEN NOT EXISTS(SELECT 1 FROM orgs WHERE id=NEW.org_id) BEGIN SELECT RAISE(ABORT,'org_id names no org'); END;
CREATE TRIGGER object_versions_org_exists BEFORE INSERT ON object_versions WHEN NOT EXISTS(SELECT 1 FROM orgs WHERE id=NEW.org_id) BEGIN SELECT RAISE(ABORT,'org_id names no org'); END;
CREATE TRIGGER conflicts_org_exists BEFORE INSERT ON conflicts WHEN NOT EXISTS(SELECT 1 FROM orgs WHERE id=NEW.org_id) BEGIN SELECT RAISE(ABORT,'org_id names no org'); END;
CREATE TRIGGER attachments_org_exists BEFORE INSERT ON attachments WHEN NOT EXISTS(SELECT 1 FROM orgs WHERE id=NEW.org_id) BEGIN SELECT RAISE(ABORT,'org_id names no org'); END;
CREATE TRIGGER upload_sessions_org_exists BEFORE INSERT ON upload_sessions WHEN NOT EXISTS(SELECT 1 FROM orgs WHERE id=NEW.org_id) BEGIN SELECT RAISE(ABORT,'org_id names no org'); END;
CREATE TRIGGER sealed_share_links_org_exists BEFORE INSERT ON sealed_share_links WHEN NOT EXISTS(SELECT 1 FROM orgs WHERE id=NEW.org_id) BEGIN SELECT RAISE(ABORT,'org_id names no org'); END;
CREATE TRIGGER audit_events_org_exists BEFORE INSERT ON audit_events WHEN NEW.org_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM orgs WHERE id=NEW.org_id) BEGIN SELECT RAISE(ABORT,'org_id names no org'); END;
-- A platform row (NULL) may name only a staff account, or none.
CREATE TRIGGER audit_events_org_named BEFORE INSERT ON audit_events WHEN NEW.org_id IS NULL AND EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND org_id IS NOT (SELECT value FROM server_settings WHERE key='staff_org_id')) BEGIN SELECT RAISE(ABORT,'audit row must name the org'); END;

-- A row never moves to another org.
CREATE TRIGGER users_org_fixed BEFORE UPDATE OF org_id ON users WHEN NEW.org_id IS NOT OLD.org_id BEGIN SELECT RAISE(ABORT,'org_id is immutable'); END;
CREATE TRIGGER containers_org_fixed BEFORE UPDATE OF org_id ON containers WHEN NEW.org_id IS NOT OLD.org_id BEGIN SELECT RAISE(ABORT,'org_id is immutable'); END;
CREATE TRIGGER blobs_org_fixed BEFORE UPDATE OF org_id ON blobs WHEN NEW.org_id IS NOT OLD.org_id BEGIN SELECT RAISE(ABORT,'org_id is immutable'); END;
CREATE TRIGGER blob_containers_org_fixed BEFORE UPDATE OF org_id ON blob_containers WHEN NEW.org_id IS NOT OLD.org_id BEGIN SELECT RAISE(ABORT,'org_id is immutable'); END;
CREATE TRIGGER object_versions_org_fixed BEFORE UPDATE OF org_id ON object_versions WHEN NEW.org_id IS NOT OLD.org_id BEGIN SELECT RAISE(ABORT,'org_id is immutable'); END;
CREATE TRIGGER conflicts_org_fixed BEFORE UPDATE OF org_id ON conflicts WHEN NEW.org_id IS NOT OLD.org_id BEGIN SELECT RAISE(ABORT,'org_id is immutable'); END;
CREATE TRIGGER attachments_org_fixed BEFORE UPDATE OF org_id ON attachments WHEN NEW.org_id IS NOT OLD.org_id BEGIN SELECT RAISE(ABORT,'org_id is immutable'); END;
CREATE TRIGGER upload_sessions_org_fixed BEFORE UPDATE OF org_id ON upload_sessions WHEN NEW.org_id IS NOT OLD.org_id BEGIN SELECT RAISE(ABORT,'org_id is immutable'); END;
CREATE TRIGGER sealed_share_links_org_fixed BEFORE UPDATE OF org_id ON sealed_share_links WHEN NEW.org_id IS NOT OLD.org_id BEGIN SELECT RAISE(ABORT,'org_id is immutable'); END;
CREATE TRIGGER audit_events_org_fixed BEFORE UPDATE OF org_id ON audit_events WHEN NEW.org_id IS NOT OLD.org_id BEGIN SELECT RAISE(ABORT,'org_id is immutable'); END;

-- A row is in its parent's org, on insert and on re-point. A missing parent is the FK's
-- business (or, for a historical orphan's team, already refused by memberTx).
CREATE TRIGGER containers_org_parent BEFORE INSERT ON containers WHEN NEW.org_id <> (SELECT org_id FROM users WHERE id=NEW.owner_user_id) OR (NEW.team_id <> '' AND NEW.org_id <> (SELECT org_id FROM containers WHERE id=NEW.team_id)) BEGIN SELECT RAISE(ABORT,'org_id differs from its parent'); END;
CREATE TRIGGER containers_org_parent_move BEFORE UPDATE OF owner_user_id,team_id ON containers WHEN NEW.org_id <> (SELECT org_id FROM users WHERE id=NEW.owner_user_id) OR (NEW.team_id <> '' AND NEW.org_id <> (SELECT org_id FROM containers WHERE id=NEW.team_id)) BEGIN SELECT RAISE(ABORT,'org_id differs from its parent'); END;
CREATE TRIGGER object_versions_org_parent BEFORE INSERT ON object_versions WHEN NEW.org_id <> (SELECT c.org_id FROM objects o JOIN containers c ON c.id=o.container_id WHERE o.id=NEW.object_id) BEGIN SELECT RAISE(ABORT,'org_id differs from its parent'); END;
CREATE TRIGGER object_versions_org_parent_move BEFORE UPDATE OF object_id ON object_versions WHEN NEW.org_id <> (SELECT c.org_id FROM objects o JOIN containers c ON c.id=o.container_id WHERE o.id=NEW.object_id) BEGIN SELECT RAISE(ABORT,'org_id differs from its parent'); END;
CREATE TRIGGER conflicts_org_parent BEFORE INSERT ON conflicts WHEN NEW.org_id <> (SELECT org_id FROM containers WHERE id=NEW.container_id) BEGIN SELECT RAISE(ABORT,'org_id differs from its parent'); END;
CREATE TRIGGER conflicts_org_parent_move BEFORE UPDATE OF container_id ON conflicts WHEN NEW.org_id <> (SELECT org_id FROM containers WHERE id=NEW.container_id) BEGIN SELECT RAISE(ABORT,'org_id differs from its parent'); END;
CREATE TRIGGER attachments_org_parent BEFORE INSERT ON attachments WHEN NEW.org_id <> (SELECT org_id FROM containers WHERE id=NEW.container_id) BEGIN SELECT RAISE(ABORT,'org_id differs from its parent'); END;
CREATE TRIGGER attachments_org_parent_move BEFORE UPDATE OF container_id ON attachments WHEN NEW.org_id <> (SELECT org_id FROM containers WHERE id=NEW.container_id) BEGIN SELECT RAISE(ABORT,'org_id differs from its parent'); END;
CREATE TRIGGER blob_containers_org_parent BEFORE INSERT ON blob_containers WHEN NEW.org_id <> (SELECT org_id FROM containers WHERE id=NEW.container_id) BEGIN SELECT RAISE(ABORT,'org_id differs from its parent'); END;
CREATE TRIGGER blob_containers_org_parent_move BEFORE UPDATE OF container_id ON blob_containers WHEN NEW.org_id <> (SELECT org_id FROM containers WHERE id=NEW.container_id) BEGIN SELECT RAISE(ABORT,'org_id differs from its parent'); END;
CREATE TRIGGER upload_sessions_org_parent BEFORE INSERT ON upload_sessions WHEN NEW.org_id <> (SELECT org_id FROM containers WHERE id=NEW.container_id) BEGIN SELECT RAISE(ABORT,'org_id differs from its parent'); END;
CREATE TRIGGER upload_sessions_org_parent_move BEFORE UPDATE OF container_id ON upload_sessions WHEN NEW.org_id <> (SELECT org_id FROM containers WHERE id=NEW.container_id) BEGIN SELECT RAISE(ABORT,'org_id differs from its parent'); END;
CREATE TRIGGER sealed_share_links_org_parent BEFORE INSERT ON sealed_share_links WHEN NEW.org_id <> (SELECT org_id FROM users WHERE id=NEW.owner_user_id) BEGIN SELECT RAISE(ABORT,'org_id differs from its parent'); END;
CREATE TRIGGER sealed_share_links_org_parent_move BEFORE UPDATE OF owner_user_id ON sealed_share_links WHEN NEW.org_id <> (SELECT org_id FROM users WHERE id=NEW.owner_user_id) BEGIN SELECT RAISE(ABORT,'org_id differs from its parent'); END;
