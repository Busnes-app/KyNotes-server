-- What an SSO step-up challenge proves: 'admin' (RequireStepUp: verified kynotes.admin) or
-- 'user' (RequireUserActionStepUp: the session's own account). Rows from before are admin.
ALTER TABLE sso_stepup ADD COLUMN scope TEXT NOT NULL DEFAULT 'admin';
