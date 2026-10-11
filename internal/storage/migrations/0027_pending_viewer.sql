-- A member the server administrator added holds the viewer role until a steward approves it, so
-- every role check, current or future, refuses it writes and deletes (it holds no key either).
-- pending_role is the role approval grants.
ALTER TABLE memberships ADD COLUMN pending_role TEXT NOT NULL DEFAULT '';
UPDATE memberships SET pending_role=role, role='viewer' WHERE approved=0;

CREATE TRIGGER memberships_pending_viewer BEFORE INSERT ON memberships
 WHEN NOT ((NEW.approved=1 AND NEW.pending_role='') OR (NEW.approved=0 AND NEW.role='viewer' AND NEW.pending_role IN ('editor','commenter','viewer')))
 BEGIN SELECT RAISE(ABORT,'pending_member_is_viewer'); END;
CREATE TRIGGER memberships_pending_viewer_update BEFORE UPDATE OF approved, role, pending_role ON memberships
 WHEN NOT ((NEW.approved=1 AND NEW.pending_role='') OR (NEW.approved=0 AND NEW.role='viewer' AND NEW.pending_role IN ('editor','commenter','viewer')))
 BEGIN SELECT RAISE(ABORT,'pending_member_is_viewer'); END;
