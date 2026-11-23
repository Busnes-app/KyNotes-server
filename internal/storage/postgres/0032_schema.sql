-- The PostgreSQL schema, equal to SQLite's after migrations 0001 to 0032 (tenancy spec, PR 2).
-- Column types: TEXT stays TEXT, INTEGER is BIGINT, BLOB is BYTEA. Differences on purpose:
-- blobs are keyed by (org_id, digest) (N8); no cleanup_audit_slots, cleanup_padding or
-- blob_replicas (Replica work, item 6, and the blob_replicas Inventory row); audit_history reads
-- audit_events only. A later SQLite migration gets a file here with the same number.
CREATE TABLE schema_migrations (version BIGINT PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE orgs (
 id TEXT PRIMARY KEY,
 status TEXT NOT NULL CHECK(status IN ('active','suspended','deletion_scheduled','deleted','stale')),
 revision BIGINT NOT NULL DEFAULT 0,
 enabled BIGINT NOT NULL DEFAULT 1,
 home_region TEXT NOT NULL,
 seen_at TEXT NOT NULL DEFAULT '',
 purged_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE erased_subjects (subject TEXT PRIMARY KEY, org_id TEXT NOT NULL, revision BIGINT NOT NULL);
CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, auth_secret_hash TEXT NOT NULL, login_salt TEXT NOT NULL, login_iterations BIGINT NOT NULL, recovery_hash TEXT NOT NULL DEFAULT '', recovery_used_at TEXT NOT NULL DEFAULT '', role TEXT NOT NULL DEFAULT 'user', status TEXT NOT NULL DEFAULT 'active', quota_bytes BIGINT NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, sso_subject TEXT NOT NULL DEFAULT '', sso_issuer TEXT NOT NULL DEFAULT '', password_admin_known BIGINT NOT NULL DEFAULT 0, account_kind TEXT NOT NULL DEFAULT 'user' CHECK(account_kind IN ('user','admin')), org_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001');
CREATE TABLE sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, token_hash TEXT NOT NULL UNIQUE, csrf_hash TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, hard_expires_at TEXT NOT NULL, revoked_at TEXT NOT NULL DEFAULT '', stepup_at TEXT NOT NULL DEFAULT '', sso_issuer TEXT NOT NULL DEFAULT '', sso_client_id TEXT NOT NULL DEFAULT '', sso_subject TEXT NOT NULL DEFAULT '', sso_sid TEXT NOT NULL DEFAULT '', sso_issued_at BIGINT NOT NULL DEFAULT 0, sso_app_admin BIGINT NOT NULL DEFAULT 0 CHECK(sso_app_admin IN (0,1)));
CREATE TABLE containers (id TEXT PRIMARY KEY, kind TEXT NOT NULL, owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, team_id TEXT NOT NULL DEFAULT '', key_generation BIGINT NOT NULL DEFAULT 1, change_seq BIGINT NOT NULL DEFAULT 0, meta_ciphertext BYTEA NOT NULL DEFAULT '\x', meta_version BIGINT NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, deleted_at TEXT NOT NULL DEFAULT '', shared_generation BIGINT NOT NULL DEFAULT 0, org_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001');
CREATE TABLE blobs (digest TEXT NOT NULL, size_bytes BIGINT NOT NULL, created_at TEXT NOT NULL, unreferenced_since TEXT NOT NULL DEFAULT '', org_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001', PRIMARY KEY(org_id,digest));
CREATE TABLE blob_containers (digest TEXT NOT NULL, container_id TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE, first_seen_at TEXT NOT NULL, org_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001', PRIMARY KEY(digest,container_id), FOREIGN KEY(org_id,digest) REFERENCES blobs(org_id,digest) ON DELETE CASCADE);
CREATE TABLE objects (id TEXT PRIMARY KEY, container_id TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE, kind TEXT NOT NULL, current_version BIGINT NOT NULL DEFAULT 0, change_seq BIGINT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, deleted_at TEXT NOT NULL DEFAULT '', routing_ciphertext BYTEA NOT NULL DEFAULT '\x');
CREATE TABLE object_versions (object_id TEXT NOT NULL REFERENCES objects(id) ON DELETE CASCADE, version BIGINT NOT NULL, blob_digest TEXT NOT NULL, ciphertext_bytes BIGINT NOT NULL, key_generation BIGINT NOT NULL, author_device_id TEXT NOT NULL DEFAULT '', base_version BIGINT NOT NULL DEFAULT 0, change_seq BIGINT NOT NULL, created_at TEXT NOT NULL, author_user_id TEXT NOT NULL DEFAULT '', org_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001', PRIMARY KEY(object_id,version), FOREIGN KEY(org_id,blob_digest) REFERENCES blobs(org_id,digest));
CREATE TABLE devices (id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,public_key TEXT NOT NULL,fingerprint TEXT NOT NULL,secret_hash TEXT NOT NULL,label_ciphertext BYTEA NOT NULL DEFAULT '\x',platform TEXT NOT NULL DEFAULT 'unknown',created_at TEXT NOT NULL,last_seen_at TEXT NOT NULL DEFAULT '',revoked_at TEXT NOT NULL DEFAULT '', sso_session_id TEXT NOT NULL DEFAULT '');
CREATE UNIQUE INDEX idx_devices_user_fingerprint ON devices(user_id,fingerprint);
CREATE TABLE memberships (id TEXT PRIMARY KEY,container_id TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,role TEXT NOT NULL,created_at TEXT NOT NULL,revoked_at TEXT NOT NULL DEFAULT '', invited_by TEXT NOT NULL DEFAULT '', approved BIGINT NOT NULL DEFAULT 1 CHECK(approved IN (0,1)), pending_role TEXT NOT NULL DEFAULT '');
CREATE UNIQUE INDEX idx_memberships_container_user ON memberships(container_id,user_id);
CREATE TABLE pairing_nonces (nonce TEXT PRIMARY KEY,purpose TEXT NOT NULL,user_id TEXT NOT NULL,used_at TEXT NOT NULL,expires_at TEXT NOT NULL);
CREATE TABLE key_envelopes (id TEXT PRIMARY KEY,container_id TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,key_generation BIGINT NOT NULL,alg TEXT NOT NULL,envelope BYTEA NOT NULL,created_at TEXT NOT NULL);
CREATE UNIQUE INDEX idx_envelopes_container_device_gen ON key_envelopes(container_id,device_id,key_generation);
CREATE TABLE device_containers (device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,container_id TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,selected_at TEXT NOT NULL,PRIMARY KEY(device_id,container_id));
CREATE TABLE conflicts (id TEXT PRIMARY KEY,object_id TEXT NOT NULL REFERENCES objects(id) ON DELETE CASCADE,container_id TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,base_version BIGINT NOT NULL,current_version BIGINT NOT NULL,blob_digest TEXT NOT NULL,ciphertext_bytes BIGINT NOT NULL,key_generation BIGINT NOT NULL,device_id TEXT NOT NULL DEFAULT '',change_seq BIGINT NOT NULL,created_at TEXT NOT NULL,resolved_at TEXT NOT NULL DEFAULT '', org_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001', FOREIGN KEY(org_id,blob_digest) REFERENCES blobs(org_id,digest));
CREATE TABLE attachments (id TEXT PRIMARY KEY,container_id TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,blob_digest TEXT NOT NULL,preview_digest TEXT NOT NULL DEFAULT '',ciphertext_bytes BIGINT NOT NULL,metadata_ciphertext BYTEA NOT NULL,key_generation BIGINT NOT NULL,change_seq BIGINT NOT NULL,created_at TEXT NOT NULL,deleted_at TEXT NOT NULL DEFAULT '', org_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001', FOREIGN KEY(org_id,blob_digest) REFERENCES blobs(org_id,digest));
CREATE UNIQUE INDEX idx_attachments_container_digest ON attachments(container_id,blob_digest);
CREATE TABLE upload_sessions (id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,container_id TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,kind TEXT NOT NULL DEFAULT 'attachment',declared_bytes BIGINT NOT NULL,chunk_bytes BIGINT NOT NULL,expected_digest TEXT NOT NULL DEFAULT '',received_bytes BIGINT NOT NULL DEFAULT 0,next_chunk BIGINT NOT NULL DEFAULT 0,status TEXT NOT NULL DEFAULT 'pending',created_at TEXT NOT NULL,updated_at TEXT NOT NULL,expires_at TEXT NOT NULL,finalized_at TEXT NOT NULL DEFAULT '', finalized_digest TEXT NOT NULL DEFAULT '', org_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001');
CREATE TABLE idempotency (key_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,route TEXT NOT NULL,status BIGINT NOT NULL,resource_id TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE audit_events (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,event TEXT NOT NULL,container_id TEXT NOT NULL DEFAULT '',object_id TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL, at TEXT NOT NULL DEFAULT '', outcome TEXT NOT NULL DEFAULT '', actor_user_id TEXT NOT NULL DEFAULT '', actor_device_id TEXT NOT NULL DEFAULT '', request_id TEXT NOT NULL DEFAULT '', reason_code TEXT NOT NULL DEFAULT '', org_id TEXT);
CREATE TABLE invitations (id TEXT PRIMARY KEY,container_id TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,inviter_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,invitee_id TEXT NOT NULL DEFAULT '',token_hash TEXT NOT NULL UNIQUE,role TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',created_at TEXT NOT NULL,expires_at TEXT NOT NULL,responded_at TEXT NOT NULL DEFAULT '');
CREATE TABLE comments (id TEXT PRIMARY KEY,container_id TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,object_id TEXT NOT NULL REFERENCES objects(id) ON DELETE CASCADE,author_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,body_ciphertext BYTEA NOT NULL,key_generation BIGINT NOT NULL,change_seq BIGINT NOT NULL,created_at TEXT NOT NULL,deleted_at TEXT NOT NULL DEFAULT '');
CREATE TABLE mentions (comment_id TEXT NOT NULL REFERENCES comments(id) ON DELETE CASCADE,mentioned_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,PRIMARY KEY(comment_id,mentioned_user_id));
CREATE TABLE activity (id TEXT PRIMARY KEY,container_id TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,actor_user_id TEXT NOT NULL,event TEXT NOT NULL,object_id TEXT NOT NULL DEFAULT '',detail_ciphertext BYTEA NOT NULL DEFAULT '\x',change_seq BIGINT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE push_registrations (device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,transport TEXT NOT NULL,token TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE attachment_refs (attachment_id TEXT NOT NULL REFERENCES attachments(id) ON DELETE CASCADE,object_id TEXT NOT NULL REFERENCES objects(id) ON DELETE CASCADE,object_version BIGINT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(attachment_id,object_id,object_version));
CREATE INDEX idx_attachment_refs_object ON attachment_refs(object_id);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expiry ON sessions(expires_at);
CREATE INDEX idx_devices_user ON devices(user_id);
CREATE INDEX idx_memberships_user ON memberships(user_id);
CREATE INDEX idx_envelopes_device ON key_envelopes(device_id);
CREATE INDEX idx_objects_container_seq ON objects(container_id,change_seq);
CREATE INDEX idx_object_versions_digest ON object_versions(blob_digest);
CREATE INDEX idx_conflicts_object ON conflicts(object_id);
CREATE INDEX idx_conflicts_digest ON conflicts(blob_digest);
CREATE INDEX idx_attachments_container_seq ON attachments(container_id,change_seq);
CREATE INDEX idx_audit_at ON audit_events(at);
CREATE INDEX idx_audit_actor ON audit_events(actor_user_id,at);
CREATE TABLE idempotency_keys (key TEXT PRIMARY KEY, response_id TEXT NOT NULL, status_code BIGINT NOT NULL, created_at TEXT NOT NULL, object_version BIGINT NOT NULL DEFAULT 0);
CREATE INDEX idx_idempotency_created ON idempotency_keys(created_at);
CREATE INDEX idx_containers_owner ON containers(owner_user_id);
CREATE INDEX idx_containers_team ON containers(team_id);
CREATE INDEX idx_attachments_preview ON attachments(preview_digest);
CREATE INDEX idx_upload_sessions_expiry ON upload_sessions(status,expires_at);
CREATE INDEX idx_upload_sessions_user ON upload_sessions(user_id,status);
CREATE TABLE server_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
INSERT INTO server_settings(key,value,updated_at) VALUES('default_theme','Patina Ky',to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS'));
CREATE TABLE share_links (id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, object_id TEXT NOT NULL REFERENCES objects(id) ON DELETE CASCADE, object_version BIGINT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT NOT NULL DEFAULT '');
CREATE INDEX idx_share_links_expiry ON share_links(expires_at);
CREATE INDEX idx_share_links_object ON share_links(object_id, revoked_at);
CREATE TABLE sealed_share_links (id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, ciphertext BYTEA NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT NOT NULL DEFAULT '', owner_user_id TEXT NOT NULL DEFAULT '', org_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001');
CREATE INDEX idx_sealed_share_links_expiry ON sealed_share_links(expires_at);
CREATE INDEX idx_sealed_share_links_owner ON sealed_share_links(owner_user_id);
CREATE INDEX idx_users_sso_subject ON users(sso_subject);
CREATE TABLE sso_sync_events (event_id TEXT PRIMARY KEY, expires_at BIGINT NOT NULL, issuer TEXT NOT NULL DEFAULT '', digest TEXT NOT NULL DEFAULT '');
CREATE INDEX sso_sync_events_expiry ON sso_sync_events(expires_at);
CREATE UNIQUE INDEX users_sso_identity ON users(sso_issuer,sso_subject) WHERE sso_subject<>'';
CREATE INDEX sessions_sso_scope ON sessions(sso_issuer,sso_client_id,sso_sid,sso_subject);
CREATE INDEX devices_sso_session ON devices(sso_session_id) WHERE sso_session_id<>'';
CREATE TABLE sso_logout_events (issuer TEXT NOT NULL, client_id TEXT NOT NULL, jti TEXT NOT NULL, subject TEXT NOT NULL, sid TEXT NOT NULL, issued_at BIGINT NOT NULL, retain_until BIGINT NOT NULL, PRIMARY KEY(issuer,client_id,jti));
CREATE INDEX sso_logout_expiry ON sso_logout_events(retain_until);
CREATE TABLE sso_directory_state (issuer TEXT NOT NULL, subject TEXT NOT NULL, revision BIGINT NOT NULL CHECK(revision>0), digest TEXT NOT NULL, active BIGINT NOT NULL CHECK(active IN (0,1)), event_id TEXT NOT NULL, revoked_before BIGINT NOT NULL DEFAULT 0, PRIMARY KEY(issuer,subject));
CREATE TABLE sso_stepup (id TEXT PRIMARY KEY, session_id TEXT NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE CASCADE, action TEXT NOT NULL, created_at BIGINT NOT NULL, expires_at BIGINT NOT NULL, started BIGINT NOT NULL DEFAULT 0, verified BIGINT NOT NULL DEFAULT 0, auth_time BIGINT NOT NULL DEFAULT 0, proof_sid TEXT NOT NULL DEFAULT '', proof_iat BIGINT NOT NULL DEFAULT 0, scope TEXT NOT NULL DEFAULT 'admin');
CREATE TABLE sso_login_cutoffs (issuer TEXT NOT NULL, subject TEXT NOT NULL, revoked_before BIGINT NOT NULL, PRIMARY KEY(issuer,subject));
CREATE TABLE user_identities (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, device_id TEXT NOT NULL UNIQUE REFERENCES devices(id) ON DELETE CASCADE, wrapped_private_key BYTEA NOT NULL, wrap_alg TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, recovery_id TEXT NOT NULL DEFAULT '', recovery_alg TEXT NOT NULL DEFAULT '', recovery_wrapped_key BYTEA NOT NULL DEFAULT '\x', recovery_updated_at TEXT NOT NULL DEFAULT '');
CREATE UNIQUE INDEX devices_one_identity ON devices(user_id) WHERE platform='identity';
CREATE TABLE invitation_envelopes (invitation_id TEXT NOT NULL REFERENCES invitations(id) ON DELETE CASCADE, container_id TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE, device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE, key_generation BIGINT NOT NULL, alg TEXT NOT NULL, envelope BYTEA NOT NULL, PRIMARY KEY(invitation_id, container_id));
CREATE INDEX idx_invitation_envelopes_device ON invitation_envelopes(device_id);
CREATE TABLE link_requests (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, newcomer_session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, commitment BYTEA NOT NULL, newcomer_key BYTEA, approver_session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE, approver_key BYTEA, bundle BYTEA, created_at TEXT NOT NULL, expires_at TEXT NOT NULL);
CREATE INDEX idx_link_requests_user ON link_requests(user_id, expires_at);
CREATE TABLE reminders (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, at TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX reminders_at ON reminders(at);
CREATE INDEX reminders_user ON reminders(user_id);
CREATE TABLE web_push_subscriptions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, endpoint TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, last_ok_at TEXT NOT NULL DEFAULT '');
CREATE INDEX web_push_subscriptions_user ON web_push_subscriptions(user_id);
CREATE VIEW audit_history AS SELECT id,user_id,event,container_id,object_id,created_at,at,outcome,actor_user_id,actor_device_id,request_id,reason_code FROM audit_events;

-- Triggers. PostgreSQL allows no subquery in a trigger's WHEN, so each check is a function.
-- Names and messages are SQLite's.
CREATE FUNCTION ky_refuse(msg TEXT) RETURNS void LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION '%', msg USING ERRCODE = 'restrict_violation'; END $$;

CREATE FUNCTION users_directory() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.status='active' AND EXISTS(SELECT 1 FROM sso_directory_state WHERE issuer=NEW.sso_issuer AND subject=NEW.sso_subject AND active=0) THEN PERFORM ky_refuse('directory account disabled'); END IF;
 RETURN NEW; END $$;
CREATE TRIGGER users_directory_insert BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION users_directory();
CREATE TRIGGER users_directory_update BEFORE UPDATE OF status,sso_issuer,sso_subject ON users FOR EACH ROW EXECUTE FUNCTION users_directory();
CREATE FUNCTION users_account_kind() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP='UPDATE' AND NEW.account_kind<>OLD.account_kind THEN PERFORM ky_refuse('account_kind_fixed'); END IF;
 IF NEW.role='admin' AND NEW.account_kind<>'admin' THEN PERFORM ky_refuse('admin_role_needs_admin_account'); END IF;
 RETURN NEW; END $$;
CREATE TRIGGER users_account_kind_fixed BEFORE UPDATE OF account_kind ON users FOR EACH ROW EXECUTE FUNCTION users_account_kind();
CREATE TRIGGER users_admin_role_insert BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION users_account_kind();
CREATE TRIGGER users_admin_role_update BEFORE UPDATE OF role ON users FOR EACH ROW EXECUTE FUNCTION users_account_kind();
-- The row's user_id must be an existing everyday account.
CREATE FUNCTION everyday_user() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND account_kind='user') THEN PERFORM ky_refuse('admin_account_holds_no_content'); END IF;
 RETURN NEW; END $$;
CREATE TRIGGER memberships_everyday_only BEFORE INSERT ON memberships FOR EACH ROW EXECUTE FUNCTION everyday_user();
CREATE TRIGGER memberships_everyday_only_update BEFORE UPDATE OF user_id ON memberships FOR EACH ROW EXECUTE FUNCTION everyday_user();
CREATE TRIGGER devices_everyday_only BEFORE INSERT ON devices FOR EACH ROW EXECUTE FUNCTION everyday_user();
CREATE TRIGGER devices_everyday_only_update BEFORE UPDATE OF user_id ON devices FOR EACH ROW EXECUTE FUNCTION everyday_user();
CREATE TRIGGER reminders_everyday_only BEFORE INSERT ON reminders FOR EACH ROW EXECUTE FUNCTION everyday_user();
CREATE TRIGGER reminders_everyday_only_update BEFORE UPDATE OF user_id ON reminders FOR EACH ROW EXECUTE FUNCTION everyday_user();
CREATE TRIGGER web_push_subscriptions_everyday_only BEFORE INSERT ON web_push_subscriptions FOR EACH ROW EXECUTE FUNCTION everyday_user();
CREATE TRIGGER web_push_subscriptions_everyday_only_update BEFORE UPDATE OF user_id ON web_push_subscriptions FOR EACH ROW EXECUTE FUNCTION everyday_user();
CREATE FUNCTION containers_everyday() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.owner_user_id AND account_kind='user') THEN PERFORM ky_refuse('admin_account_holds_no_content'); END IF;
 RETURN NEW; END $$;
CREATE TRIGGER containers_everyday_owner BEFORE INSERT ON containers FOR EACH ROW EXECUTE FUNCTION containers_everyday();
CREATE TRIGGER containers_everyday_owner_update BEFORE UPDATE OF owner_user_id ON containers FOR EACH ROW EXECUTE FUNCTION containers_everyday();
CREATE FUNCTION user_identities_everyday() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM devices d JOIN users u ON u.id=d.user_id WHERE d.id=NEW.device_id AND d.user_id=NEW.user_id AND u.account_kind='user') THEN PERFORM ky_refuse('admin_account_holds_no_content'); END IF;
 RETURN NEW; END $$;
CREATE TRIGGER user_identities_everyday_only BEFORE INSERT ON user_identities FOR EACH ROW EXECUTE FUNCTION user_identities_everyday();
CREATE TRIGGER user_identities_everyday_only_update BEFORE UPDATE OF user_id,device_id ON user_identities FOR EACH ROW EXECUTE FUNCTION user_identities_everyday();
CREATE FUNCTION memberships_pending() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT ((NEW.approved=1 AND NEW.pending_role='') OR (NEW.approved=0 AND NEW.role='viewer' AND NEW.pending_role IN ('editor','commenter','viewer'))) THEN PERFORM ky_refuse('pending_member_is_viewer'); END IF;
 RETURN NEW; END $$;
CREATE TRIGGER memberships_pending_viewer BEFORE INSERT ON memberships FOR EACH ROW EXECUTE FUNCTION memberships_pending();
CREATE TRIGGER memberships_pending_viewer_update BEFORE UPDATE OF approved,role,pending_role ON memberships FOR EACH ROW EXECUTE FUNCTION memberships_pending();

-- Tenancy (0032).
CREATE FUNCTION org_exists() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.org_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM orgs WHERE id=NEW.org_id) THEN PERFORM ky_refuse('org_id names no org'); END IF;
 RETURN NEW; END $$;
CREATE FUNCTION org_fixed() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.org_id IS DISTINCT FROM OLD.org_id THEN PERFORM ky_refuse('org_id is immutable'); END IF;
 RETURN NEW; END $$;
CREATE FUNCTION org_parent_container() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.org_id <> (SELECT org_id FROM containers WHERE id=NEW.container_id) THEN PERFORM ky_refuse('org_id differs from its parent'); END IF;
 RETURN NEW; END $$;
CREATE FUNCTION org_parent_containers() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.org_id <> (SELECT org_id FROM users WHERE id=NEW.owner_user_id) OR (NEW.team_id <> '' AND NEW.org_id <> (SELECT org_id FROM containers WHERE id=NEW.team_id)) THEN PERFORM ky_refuse('org_id differs from its parent'); END IF;
 RETURN NEW; END $$;
CREATE FUNCTION org_parent_object_versions() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.org_id <> (SELECT c.org_id FROM objects o JOIN containers c ON c.id=o.container_id WHERE o.id=NEW.object_id) THEN PERFORM ky_refuse('org_id differs from its parent'); END IF;
 RETURN NEW; END $$;
CREATE FUNCTION org_parent_sealed_share_links() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.org_id <> (SELECT org_id FROM users WHERE id=NEW.owner_user_id) THEN PERFORM ky_refuse('org_id differs from its parent'); END IF;
 RETURN NEW; END $$;
CREATE FUNCTION audit_events_named() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.org_id IS NULL AND EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND org_id IS DISTINCT FROM (SELECT value FROM server_settings WHERE key='staff_org_id')) THEN PERFORM ky_refuse('audit row must name the org'); END IF;
 RETURN NEW; END $$;
DO $$ DECLARE t TEXT; BEGIN
 FOREACH t IN ARRAY ARRAY['users','containers','blobs','blob_containers','object_versions','conflicts','attachments','upload_sessions','sealed_share_links','audit_events'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE INSERT ON %I FOR EACH ROW EXECUTE FUNCTION org_exists()', t || '_org_exists', t);
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OF org_id ON %I FOR EACH ROW EXECUTE FUNCTION org_fixed()', t || '_org_fixed', t);
 END LOOP;
 FOREACH t IN ARRAY ARRAY['conflicts','attachments','blob_containers','upload_sessions'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE INSERT ON %I FOR EACH ROW EXECUTE FUNCTION org_parent_container()', t || '_org_parent', t);
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OF container_id ON %I FOR EACH ROW EXECUTE FUNCTION org_parent_container()', t || '_org_parent_move', t);
 END LOOP;
END $$;
CREATE TRIGGER containers_org_parent BEFORE INSERT ON containers FOR EACH ROW EXECUTE FUNCTION org_parent_containers();
CREATE TRIGGER containers_org_parent_move BEFORE UPDATE OF owner_user_id,team_id ON containers FOR EACH ROW EXECUTE FUNCTION org_parent_containers();
CREATE TRIGGER object_versions_org_parent BEFORE INSERT ON object_versions FOR EACH ROW EXECUTE FUNCTION org_parent_object_versions();
CREATE TRIGGER object_versions_org_parent_move BEFORE UPDATE OF object_id ON object_versions FOR EACH ROW EXECUTE FUNCTION org_parent_object_versions();
CREATE TRIGGER sealed_share_links_org_parent BEFORE INSERT ON sealed_share_links FOR EACH ROW EXECUTE FUNCTION org_parent_sealed_share_links();
CREATE TRIGGER sealed_share_links_org_parent_move BEFORE UPDATE OF owner_user_id ON sealed_share_links FOR EACH ROW EXECUTE FUNCTION org_parent_sealed_share_links();
CREATE TRIGGER audit_events_org_named BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION audit_events_named();
