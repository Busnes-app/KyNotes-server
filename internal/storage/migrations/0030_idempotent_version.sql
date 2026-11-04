-- The version an idempotent object save committed, so a retry answers that version rather than
-- whatever the page has reached since (0 on rows written before this migration).
ALTER TABLE idempotency_keys ADD COLUMN object_version INTEGER NOT NULL DEFAULT 0;
