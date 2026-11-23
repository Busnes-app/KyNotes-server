-- Tenancy N10 (PR 4e), as SQLite's 0035_org_pool.sql.
CREATE TABLE org_pool (
 org_id TEXT PRIMARY KEY,
 seq BIGINT NOT NULL DEFAULT 0,
 reported_bytes BIGINT NOT NULL DEFAULT 0,
 ceiling_bytes BIGINT NOT NULL DEFAULT 0,
 expires_at TEXT NOT NULL DEFAULT '',
 attempted_at TEXT NOT NULL DEFAULT '',
 pool_bytes BIGINT NOT NULL DEFAULT 0,
 org_used_bytes BIGINT NOT NULL DEFAULT 0,
 over_since BIGINT
);

-- Only PostgreSQL keeps incremental usage. SQLite retains its existing bounded cleanup writes.
CREATE TABLE org_usage (
 org_id TEXT PRIMARY KEY DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES orgs(id),
 bytes BIGINT NOT NULL DEFAULT 0 CHECK(bytes>=0)
);
CREATE SEQUENCE org_storage_report_seq;
INSERT INTO org_usage(org_id) SELECT id FROM orgs;
CREATE FUNCTION init_org_usage() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO org_usage(org_id) VALUES(NEW.id);
 RETURN NEW;
END $$;
CREATE TRIGGER org_usage_init AFTER INSERT ON orgs FOR EACH ROW EXECUTE FUNCTION init_org_usage();

CREATE FUNCTION usage_object_versions() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP <> 'INSERT' THEN
  UPDATE org_usage SET bytes=bytes-(OLD.ciphertext_bytes) WHERE org_id=OLD.org_id;
 END IF;
 IF TG_OP <> 'DELETE' THEN
  UPDATE org_usage SET bytes=bytes+(NEW.ciphertext_bytes) WHERE org_id=NEW.org_id;
 END IF;
 RETURN NULL;
END $$;
CREATE TRIGGER object_versions_usage AFTER INSERT OR UPDATE OR DELETE ON object_versions
 FOR EACH ROW EXECUTE FUNCTION usage_object_versions();

CREATE FUNCTION usage_conflicts() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP <> 'INSERT' THEN
  UPDATE org_usage SET bytes=bytes-(OLD.ciphertext_bytes) WHERE org_id=OLD.org_id;
 END IF;
 IF TG_OP <> 'DELETE' THEN
  UPDATE org_usage SET bytes=bytes+(NEW.ciphertext_bytes) WHERE org_id=NEW.org_id;
 END IF;
 RETURN NULL;
END $$;
CREATE TRIGGER conflicts_usage AFTER INSERT OR UPDATE OR DELETE ON conflicts
 FOR EACH ROW EXECUTE FUNCTION usage_conflicts();

CREATE FUNCTION usage_attachments() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP <> 'INSERT' THEN
  UPDATE org_usage SET bytes=bytes-(CASE WHEN OLD.deleted_at='' THEN OLD.ciphertext_bytes ELSE 0 END) WHERE org_id=OLD.org_id;
 END IF;
 IF TG_OP <> 'DELETE' THEN
  UPDATE org_usage SET bytes=bytes+(CASE WHEN NEW.deleted_at='' THEN NEW.ciphertext_bytes ELSE 0 END) WHERE org_id=NEW.org_id;
 END IF;
 RETURN NULL;
END $$;
CREATE TRIGGER attachments_usage AFTER INSERT OR UPDATE OR DELETE ON attachments
 FOR EACH ROW EXECUTE FUNCTION usage_attachments();

CREATE FUNCTION usage_comments() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP <> 'INSERT' THEN
  UPDATE org_usage SET bytes=bytes-(CASE WHEN OLD.deleted_at='' THEN octet_length(OLD.body_ciphertext) ELSE 0 END) WHERE org_id=(SELECT org_id FROM containers WHERE id=OLD.container_id);
 END IF;
 IF TG_OP <> 'DELETE' THEN
  UPDATE org_usage SET bytes=bytes+(CASE WHEN NEW.deleted_at='' THEN octet_length(NEW.body_ciphertext) ELSE 0 END) WHERE org_id=(SELECT org_id FROM containers WHERE id=NEW.container_id);
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER comments_usage BEFORE INSERT OR UPDATE OR DELETE ON comments
 FOR EACH ROW EXECUTE FUNCTION usage_comments();

UPDATE org_usage u SET bytes=
 (SELECT COALESCE(SUM(ciphertext_bytes),0) FROM object_versions WHERE org_id=u.org_id)
+(SELECT COALESCE(SUM(ciphertext_bytes),0) FROM conflicts WHERE org_id=u.org_id)
+(SELECT COALESCE(SUM(ciphertext_bytes),0) FROM attachments WHERE org_id=u.org_id AND deleted_at='')
+(SELECT COALESCE(SUM(octet_length(m.body_ciphertext)),0) FROM comments m JOIN containers c ON c.id=m.container_id WHERE c.org_id=u.org_id AND m.deleted_at='');
CREATE INDEX upload_sessions_pool ON upload_sessions(org_id,status,expires_at);
CREATE INDEX sealed_share_links_pool ON sealed_share_links(org_id,revoked_at,expires_at);

CREATE TRIGGER org_usage_org_exists BEFORE INSERT ON org_usage FOR EACH ROW EXECUTE FUNCTION org_exists();
CREATE TRIGGER org_usage_org_fixed BEFORE UPDATE OF org_id ON org_usage FOR EACH ROW EXECUTE FUNCTION org_fixed();

-- A cascade runs after the notebook row disappears. Charge its comments down before that,
-- while the ordinary comment trigger can still find an org for every non-cascade deletion.
CREATE FUNCTION usage_container_comments() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE org_usage SET bytes=bytes-(SELECT COALESCE(SUM(octet_length(body_ciphertext)),0)
 FROM comments WHERE container_id=OLD.id AND deleted_at='') WHERE org_id=OLD.org_id;
 RETURN OLD;
END $$;
CREATE TRIGGER containers_comment_usage BEFORE DELETE ON containers
 FOR EACH ROW EXECUTE FUNCTION usage_container_comments();
