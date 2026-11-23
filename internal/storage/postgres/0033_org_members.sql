-- Tenancy N7 (PR 3), as SQLite's 0033_org_members.sql.
CREATE FUNCTION org_match_user() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF (SELECT org_id FROM users WHERE id=NEW.user_id) <> (SELECT org_id FROM containers WHERE id=NEW.container_id) THEN PERFORM ky_refuse('member in another org'); END IF;
 RETURN NEW; END $$;
CREATE FUNCTION org_match_invitee() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.status='accepted' AND (SELECT org_id FROM users WHERE id=NEW.invitee_id) <> (SELECT org_id FROM containers WHERE id=NEW.container_id) THEN PERFORM ky_refuse('member in another org'); END IF;
 RETURN NEW; END $$;
CREATE FUNCTION org_match_device() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF (SELECT u.org_id FROM devices d JOIN users u ON u.id=d.user_id WHERE d.id=NEW.device_id) <> (SELECT org_id FROM containers WHERE id=NEW.container_id) THEN PERFORM ky_refuse('member in another org'); END IF;
 RETURN NEW; END $$;
CREATE TRIGGER memberships_org_match BEFORE INSERT ON memberships FOR EACH ROW EXECUTE FUNCTION org_match_user();
CREATE TRIGGER memberships_org_match_move BEFORE UPDATE OF user_id,container_id ON memberships FOR EACH ROW EXECUTE FUNCTION org_match_user();
CREATE TRIGGER invitations_org_match BEFORE UPDATE OF status ON invitations FOR EACH ROW EXECUTE FUNCTION org_match_invitee();
DO $$ DECLARE t TEXT; BEGIN
 FOREACH t IN ARRAY ARRAY['key_envelopes','device_containers','invitation_envelopes'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE INSERT ON %I FOR EACH ROW EXECUTE FUNCTION org_match_device()', t || '_org_match', t);
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OF device_id,container_id ON %I FOR EACH ROW EXECUTE FUNCTION org_match_device()', t || '_org_match_move', t);
 END LOOP;
END $$;
