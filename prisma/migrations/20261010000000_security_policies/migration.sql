-- CipherMesh: security policies (Phase 10, CM-T046 to CM-T048; security-policy-profiles.md
-- section 4, data-model 4.16).
-- Hand-written and reviewed. No column, table or grant changes: rooms already store
-- security_profile and policy_version (schema v1), and the policy values themselves are the
-- versioned catalogue in packages/shared, never a table (CM-T046: no database row can change a
-- policy value at runtime).
--
-- Two trigger changes. An upgrade to a stricter profile shortens existing expiry dates to at most
-- the upgrade time plus the new maximum (PC-08, PC-09, PC-06). Files and notes already accept an
-- earlier expiry (their guards refuse only a later or removed one). Two guards made expires_at
-- write-once, and now accept a strictly earlier expiry while the row is still open, and refuse
-- any later one, so neither the API nor a faulty writer can extend a lifetime:
--   secrets       (20261009000000_burn_secrets) while ACTIVE. Every other rule is unchanged:
--                 identity columns and the burn flag stay write-once, REVEALED, EXPIRED and
--                 REVOKED stay final (INV-13), and expires_at is NOT NULL with the 7-day CHECK.
--   invitations   (20261006000000_room_statements) while PENDING_APPROVAL or PENDING. The signed
--                 grant (signature, grantor key, invitee key, role) and the other identity columns
--                 stay write-once; expires_at is not part of the grant statement (ADR-015), and the
--                 CHECK expires_at > created_at still holds for every shortened value.

CREATE OR REPLACE FUNCTION "cm_guard_secret_change"() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.room_id IS DISTINCT FROM OLD.room_id
     OR NEW.sender_id IS DISTINCT FROM OLD.sender_id
     OR NEW.recipient_user_id IS DISTINCT FROM OLD.recipient_user_id
     OR NEW.recipient_key_id IS DISTINCT FROM OLD.recipient_key_id
     OR NEW.burn_after_reading IS DISTINCT FROM OLD.burn_after_reading
     OR NEW.algorithm_suite IS DISTINCT FROM OLD.algorithm_suite
     OR NEW.wrap_algorithm IS DISTINCT FROM OLD.wrap_algorithm
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'secrets identity columns are write-once' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  -- REVEALED, EXPIRED and REVOKED are final: nothing about a destroyed secret changes again, so a
  -- burned secret can never become redeemable (INV-13).
  IF OLD.status <> 'ACTIVE' THEN
    IF ROW(NEW.*) IS DISTINCT FROM ROW(OLD.*) THEN
      RAISE EXCEPTION 'secrets in a final state cannot change' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
  END IF;
  -- Phase 10 (CM-T048): an upgrade shortens the expiry of ACTIVE secrets; nothing extends it.
  IF NEW.expires_at > OLD.expires_at THEN
    RAISE EXCEPTION 'secrets expiry can only move earlier' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  -- revealed_at is the first release and is never moved or cleared.
  IF OLD.revealed_at IS NOT NULL AND NEW.revealed_at IS DISTINCT FROM OLD.revealed_at THEN
    RAISE EXCEPTION 'secrets revealed_at is set once' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.status = 'ACTIVE' THEN
    -- Still redeemable: the ciphertext and the wrapped SEK are exactly what the sender stored.
    IF NEW.wrapped_sek IS DISTINCT FROM OLD.wrapped_sek
       OR NEW.payload_ciphertext IS DISTINCT FROM OLD.payload_ciphertext
       OR NEW.payload_iv IS DISTINCT FROM OLD.payload_iv
       OR NEW.destroyed_at IS DISTINCT FROM OLD.destroyed_at THEN
      RAISE EXCEPTION 'secrets ciphertext of an ACTIVE secret cannot change' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    -- A burn-after-reading secret leaves ACTIVE in the transaction that reveals it.
    IF NEW.burn_after_reading AND NEW.revealed_at IS NOT NULL THEN
      RAISE EXCEPTION 'secrets burn-after-reading cannot stay ACTIVE after a reveal' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
  END IF;
  -- Leaving ACTIVE (CHECKs: material NULL, destroyed_at set, REVEALED needs revealed_at and burn).
  IF NEW.status = 'REVEALED' AND OLD.revealed_at IS NOT NULL THEN
    RAISE EXCEPTION 'secrets are revealed and burned once' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.status IN ('EXPIRED', 'REVOKED') AND NEW.revealed_at IS DISTINCT FROM OLD.revealed_at THEN
    RAISE EXCEPTION 'secrets expiry and revocation do not record a reveal' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$;

-- CREATE OR REPLACE keeps the trigger and the function's privileges; restated for the reviewer.
REVOKE ALL ON FUNCTION "cm_guard_secret_change"() FROM PUBLIC;

CREATE OR REPLACE FUNCTION "cm_reject_invitation_grant_change"() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.room_id IS DISTINCT FROM OLD.room_id
     OR NEW.invitee_user_id IS DISTINCT FROM OLD.invitee_user_id
     OR NEW.invitee_key_id IS DISTINCT FROM OLD.invitee_key_id
     OR NEW.invited_by_id IS DISTINCT FROM OLD.invited_by_id
     OR NEW.role IS DISTINCT FROM OLD.role
     OR NEW.grantor_key_id IS DISTINCT FROM OLD.grantor_key_id
     OR NEW.grant_signature IS DISTINCT FROM OLD.grant_signature
     OR NEW.confirmed_fingerprint IS DISTINCT FROM OLD.confirmed_fingerprint
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'invitations grant columns are write-once' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  -- Phase 10 (CM-T048): an upgrade shortens the validity of open invitations; nothing extends it,
  -- and a closed invitation keeps the expiry it had.
  IF NEW.expires_at IS DISTINCT FROM OLD.expires_at
     AND (NEW.expires_at > OLD.expires_at OR OLD.status NOT IN ('PENDING_APPROVAL', 'PENDING')) THEN
    RAISE EXCEPTION 'invitations expiry can only move earlier while open' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION "cm_reject_invitation_grant_change"() FROM PUBLIC;
