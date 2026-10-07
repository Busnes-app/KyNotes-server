-- Role-change proof fence, kept apart from directory revisions: subjects that directory
-- sync never saw (auto-provisioned, apply-setup) still need one.
CREATE TABLE sso_login_cutoffs (
 issuer TEXT NOT NULL, subject TEXT NOT NULL,
 revoked_before INTEGER NOT NULL,
 PRIMARY KEY(issuer,subject)
);
