-- A replay acknowledges the version this request committed, not a later writer's version.
-- Older keys have no recoverable version provenance and retain the legacy fallback.
ALTER TABLE idempotency_keys ADD COLUMN object_version INTEGER NOT NULL DEFAULT 0;
