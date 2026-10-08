-- What an SSO step-up challenge proves: 'admin' (RequireStepUp: verified kynotes.admin) or
-- 'user' (RequireUserActionStepUp: the session's own account). Rows from before are admin.
ALTER TABLE sso_stepup ADD COLUMN scope TEXT NOT NULL DEFAULT 'admin';

-- Device linking relay (team keys P3c). Public keys, a commitment and one sealed bundle only:
-- nothing the server can open. commitment = SHA-256("kynotes/link-commit/v1" || newcomer_key),
-- posted before the approver's key exists (testdata/protocol/link_vectors.json).
CREATE TABLE link_requests (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 newcomer_session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
 commitment BLOB NOT NULL,
 newcomer_key BLOB,
 approver_session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE,
 approver_key BLOB,
 bundle BLOB,
 created_at TEXT NOT NULL,
 expires_at TEXT NOT NULL
);
CREATE INDEX idx_link_requests_user ON link_requests(user_id, expires_at);
