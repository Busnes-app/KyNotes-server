-- Tenancy N10 (PR 4e), as SQLite's 0035_org_pool.sql.
CREATE TABLE org_pool (
 org_id TEXT PRIMARY KEY,
 seq BIGINT NOT NULL DEFAULT 0,
 reported_bytes BIGINT NOT NULL DEFAULT 0,
 ceiling_bytes BIGINT NOT NULL DEFAULT 0,
 expires_at TEXT NOT NULL DEFAULT '',
 pool_bytes BIGINT NOT NULL DEFAULT 0
);
