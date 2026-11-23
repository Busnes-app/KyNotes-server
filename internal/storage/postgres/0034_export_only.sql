-- Tenancy N11 (PR 4c), as SQLite's 0034_export_only.sql.
ALTER TABLE sessions ADD COLUMN export_only BIGINT NOT NULL DEFAULT 0 CHECK(export_only IN (0,1));
