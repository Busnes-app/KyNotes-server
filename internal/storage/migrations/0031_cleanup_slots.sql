-- Fund every future deletion audit before admitting the source write.
-- Source padding covers UTF-8 and legacy UTF-16 timestamp/counter growth.
ALTER TABLE comments ADD COLUMN cleanup_padding BLOB NOT NULL DEFAULT X'00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';
ALTER TABLE containers ADD COLUMN cleanup_padding BLOB NOT NULL DEFAULT X'00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';
ALTER TABLE sealed_share_links ADD COLUMN cleanup_padding BLOB NOT NULL DEFAULT X'00000000000000000000000000000000000000000000000000000000000000000000000000000000';
-- Materialize ALTER's virtual defaults on legacy rows before checking physical capacity.
UPDATE comments SET cleanup_padding=zeroblob(64) WHERE deleted_at='';
UPDATE containers SET cleanup_padding=zeroblob(64);
UPDATE sealed_share_links SET cleanup_padding=zeroblob(40) WHERE revoked_at='';
CREATE TABLE cleanup_audit_slots (
 source_id TEXT PRIMARY KEY,
 audit_id TEXT NOT NULL UNIQUE,
 kind TEXT NOT NULL CHECK(kind IN ('comment','sealed_share_link')),
 container_id TEXT NOT NULL,
 payload BLOB NOT NULL CHECK(json_valid(CAST(payload AS TEXT)) AND json_type(CAST(payload AS TEXT)) IN ('null','object'))
);
CREATE TRIGGER cleanup_slot_update BEFORE UPDATE ON cleanup_audit_slots
 WHEN json_type(CAST(OLD.payload AS TEXT))<>'null' OR NEW.source_id<>OLD.source_id OR NEW.audit_id<>OLD.audit_id OR NEW.kind<>OLD.kind OR NEW.container_id<>OLD.container_id OR length(NEW.payload)<>length(OLD.payload)
 BEGIN SELECT RAISE(ABORT,'immutable cleanup audit'); END;
CREATE TRIGGER cleanup_slot_delete BEFORE DELETE ON cleanup_audit_slots
 WHEN json_type(CAST(OLD.payload AS TEXT))<>'null'
 BEGIN SELECT RAISE(ABORT,'immutable cleanup audit'); END;
CREATE TRIGGER cleanup_comment_pending AFTER DELETE ON comments
 BEGIN DELETE FROM cleanup_audit_slots WHERE source_id=OLD.id AND kind='comment' AND json_type(CAST(payload AS TEXT))='null'; END;
CREATE TRIGGER cleanup_link_pending AFTER DELETE ON sealed_share_links
 BEGIN DELETE FROM cleanup_audit_slots WHERE source_id=OLD.id AND kind='sealed_share_link' AND json_type(CAST(payload AS TEXT))='null'; END;
CREATE VIEW audit_history AS
 SELECT id,user_id,event,container_id,object_id,created_at,at,outcome,actor_user_id,actor_device_id,request_id,reason_code FROM audit_events
 UNION ALL
 SELECT audit_id,json_extract(CAST(payload AS TEXT),'$.actor'),CASE kind WHEN 'comment' THEN 'comment.delete' ELSE 'share_link.revoke' END,container_id,source_id,json_extract(CAST(payload AS TEXT),'$.at'),json_extract(CAST(payload AS TEXT),'$.at'),'success',json_extract(CAST(payload AS TEXT),'$.actor'),'',json_extract(CAST(payload AS TEXT),'$.request'),'' FROM cleanup_audit_slots WHERE json_type(CAST(payload AS TEXT))='object';
