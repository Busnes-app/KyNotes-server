-- Who wrote each version ('' for versions written before team keys phase 2).
ALTER TABLE object_versions ADD COLUMN author_user_id TEXT NOT NULL DEFAULT '';
-- First generation minted by POST /key-rotations; 0 = never rotated (legacy save gate).
ALTER TABLE containers ADD COLUMN shared_generation INTEGER NOT NULL DEFAULT 0;
-- Envelopes wrapped for an invitee's identity, moved into key_envelopes on accept
-- only while the container is still at key_generation.
CREATE TABLE invitation_envelopes (
 invitation_id TEXT NOT NULL REFERENCES invitations(id) ON DELETE CASCADE,
 container_id TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
 device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
 key_generation INTEGER NOT NULL,
 alg TEXT NOT NULL,
 envelope BLOB NOT NULL,
 PRIMARY KEY(invitation_id, container_id)
);
CREATE INDEX idx_invitation_envelopes_device ON invitation_envelopes(device_id);
