CREATE TABLE replica_logins(state_hash TEXT PRIMARY KEY, payload BYTEA NOT NULL, expires_at BIGINT NOT NULL);
CREATE INDEX replica_logins_expiry ON replica_logins(expires_at);
CREATE TABLE replica_rates(key_hash TEXT PRIMARY KEY, tat_us BIGINT NOT NULL);
CREATE INDEX replica_rates_expiry ON replica_rates(tat_us);
CREATE TABLE replica_lockouts(namespace TEXT NOT NULL,key_hash TEXT NOT NULL,failures BIGINT NOT NULL,locked_until BIGINT NOT NULL DEFAULT 0,generation TEXT NOT NULL,PRIMARY KEY(namespace,key_hash));
CREATE INDEX replica_lockouts_expiry ON replica_lockouts(namespace,locked_until);
CREATE TABLE replica_presence(user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,container_id TEXT NOT NULL REFERENCES containers(id) ON DELETE CASCADE,state TEXT NOT NULL,expires_at BIGINT NOT NULL,PRIMARY KEY(user_id,container_id));
CREATE INDEX replica_presence_expiry ON replica_presence(expires_at);
ALTER TABLE reminders ADD COLUMN claimed_until BIGINT NOT NULL DEFAULT 0;
ALTER TABLE reminders ADD COLUMN claim_token TEXT NOT NULL DEFAULT '';
CREATE FUNCTION reminder_release_claim() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 NEW.claimed_until=0; NEW.claim_token=''; RETURN NEW; END $$;
CREATE TRIGGER reminders_release_claim BEFORE UPDATE OF at ON reminders FOR EACH ROW EXECUTE FUNCTION reminder_release_claim();

CREATE FUNCTION replica_presence_org_match() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF (SELECT org_id FROM users WHERE id=NEW.user_id)<>(SELECT org_id FROM containers WHERE id=NEW.container_id) THEN RAISE EXCEPTION 'presence org mismatch'; END IF; RETURN NEW; END $$;
CREATE TRIGGER replica_presence_org_match BEFORE INSERT OR UPDATE ON replica_presence FOR EACH ROW EXECUTE FUNCTION replica_presence_org_match();
