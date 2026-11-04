-- Sealed share links get an owner, so their bytes count toward the owner's quota and the owner can
-- revoke them. Links made before this have no owner; their expiry is capped at 30 days from now.
ALTER TABLE sealed_share_links ADD COLUMN owner_user_id TEXT NOT NULL DEFAULT '';
CREATE INDEX idx_sealed_share_links_owner ON sealed_share_links(owner_user_id);
UPDATE sealed_share_links SET expires_at=strftime('%Y-%m-%dT%H:%M:%SZ','now','+30 days') WHERE expires_at>strftime('%Y-%m-%dT%H:%M:%SZ','now','+30 days');
