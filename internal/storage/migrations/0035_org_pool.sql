-- Tenancy N10 (PR 4e): each org's storage-pool grant from KyIdentity (POST /api/suite/storage,
-- report-and-grant). Written only in multi mode; a single-tenant install keeps it empty.
CREATE TABLE org_pool (
 org_id TEXT PRIMARY KEY,
 seq INTEGER NOT NULL DEFAULT 0,
 reported_bytes INTEGER NOT NULL DEFAULT 0,
 ceiling_bytes INTEGER NOT NULL DEFAULT 0,
 expires_at TEXT NOT NULL DEFAULT '',
 attempted_at TEXT NOT NULL DEFAULT '',
 pool_bytes INTEGER NOT NULL DEFAULT 0,
 org_used_bytes INTEGER NOT NULL DEFAULT 0,
 over_since INTEGER
);
