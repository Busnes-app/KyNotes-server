-- The steward whose invitation admitted the current membership; '' for owners,
-- server-admin adds and memberships older than this column (not backfilled: those
-- admins stay removable by owners and server admins only).
ALTER TABLE memberships ADD COLUMN invited_by TEXT NOT NULL DEFAULT '';
