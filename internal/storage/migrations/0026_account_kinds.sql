-- Sub-project A: an account is an administrator account or an everyday account, for good.
-- users.role stays the administrator grant, allowed only on an administrator account.
ALTER TABLE users ADD COLUMN account_kind TEXT NOT NULL DEFAULT 'user' CHECK(account_kind IN ('user','admin'));
-- Administrator-added members get no key until a steward of the team approves them.
ALTER TABLE memberships ADD COLUMN approved INTEGER NOT NULL DEFAULT 1 CHECK(approved IN (0,1));

-- A mixed account (the grant plus notes) keeps its notes and loses the grant.
INSERT INTO audit_events(id,user_id,actor_user_id,object_id,event,created_at,at,outcome,reason_code)
SELECT 'aud_'||lower(hex(randomblob(16))), u.id, u.id, u.id, 'account.kind_upgrade',
 strftime('%Y-%m-%dT%H:%M:%SZ','now'), strftime('%Y-%m-%dT%H:%M:%SZ','now'), 'success',
 CASE WHEN EXISTS(SELECT 1 FROM memberships m WHERE m.user_id=u.id)
        OR EXISTS(SELECT 1 FROM user_identities i WHERE i.user_id=u.id)
        OR EXISTS(SELECT 1 FROM containers c WHERE c.owner_user_id=u.id)
      THEN 'kind=user,admin_dropped=true' ELSE 'kind=admin' END
FROM users u WHERE u.role='admin';
UPDATE users SET role='user' WHERE role='admin' AND (
 EXISTS(SELECT 1 FROM memberships m WHERE m.user_id=users.id)
 OR EXISTS(SELECT 1 FROM user_identities i WHERE i.user_id=users.id)
 OR EXISTS(SELECT 1 FROM containers c WHERE c.owner_user_id=users.id));
UPDATE users SET account_kind='admin' WHERE role='admin';
UPDATE devices SET revoked_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')
 WHERE revoked_at='' AND user_id IN (SELECT id FROM users WHERE account_kind='admin');

CREATE TRIGGER users_account_kind_fixed BEFORE UPDATE OF account_kind ON users
 WHEN NEW.account_kind<>OLD.account_kind BEGIN SELECT RAISE(ABORT,'account_kind_fixed'); END;
CREATE TRIGGER users_admin_role_insert BEFORE INSERT ON users
 WHEN NEW.role='admin' AND NEW.account_kind<>'admin' BEGIN SELECT RAISE(ABORT,'admin_role_needs_admin_account'); END;
CREATE TRIGGER users_admin_role_update BEFORE UPDATE OF role ON users
 WHEN NEW.role='admin' AND NEW.account_kind<>'admin' BEGIN SELECT RAISE(ABORT,'admin_role_needs_admin_account'); END;
-- Content rows belong to an existing everyday account, on insert and on any later re-point.
CREATE TRIGGER memberships_everyday_only BEFORE INSERT ON memberships
 WHEN NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND account_kind='user') BEGIN SELECT RAISE(ABORT,'admin_account_holds_no_content'); END;
CREATE TRIGGER memberships_everyday_only_update BEFORE UPDATE OF user_id ON memberships
 WHEN NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND account_kind='user') BEGIN SELECT RAISE(ABORT,'admin_account_holds_no_content'); END;
CREATE TRIGGER containers_everyday_owner BEFORE INSERT ON containers
 WHEN NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.owner_user_id AND account_kind='user') BEGIN SELECT RAISE(ABORT,'admin_account_holds_no_content'); END;
CREATE TRIGGER containers_everyday_owner_update BEFORE UPDATE OF owner_user_id ON containers
 WHEN NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.owner_user_id AND account_kind='user') BEGIN SELECT RAISE(ABORT,'admin_account_holds_no_content'); END;
CREATE TRIGGER devices_everyday_only BEFORE INSERT ON devices
 WHEN NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND account_kind='user') BEGIN SELECT RAISE(ABORT,'admin_account_holds_no_content'); END;
CREATE TRIGGER devices_everyday_only_update BEFORE UPDATE OF user_id ON devices
 WHEN NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND account_kind='user') BEGIN SELECT RAISE(ABORT,'admin_account_holds_no_content'); END;
-- An identity (its password and recovery copies are columns of the same row) belongs to the everyday
-- account that owns its identity device.
CREATE TRIGGER user_identities_everyday_only BEFORE INSERT ON user_identities
 WHEN NOT EXISTS(SELECT 1 FROM devices d JOIN users u ON u.id=d.user_id WHERE d.id=NEW.device_id AND d.user_id=NEW.user_id AND u.account_kind='user') BEGIN SELECT RAISE(ABORT,'admin_account_holds_no_content'); END;
CREATE TRIGGER user_identities_everyday_only_update BEFORE UPDATE OF user_id,device_id ON user_identities
 WHEN NOT EXISTS(SELECT 1 FROM devices d JOIN users u ON u.id=d.user_id WHERE d.id=NEW.device_id AND d.user_id=NEW.user_id AND u.account_kind='user') BEGIN SELECT RAISE(ABORT,'admin_account_holds_no_content'); END;
