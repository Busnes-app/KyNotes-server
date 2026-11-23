-- Tenancy N11 (PR 4c): a session signed in with KyIdentity's export_only claim reaches only the
-- routes the browser export needs (auth.ExportRoutes).
ALTER TABLE sessions ADD COLUMN export_only INTEGER NOT NULL DEFAULT 0 CHECK(export_only IN (0,1));
