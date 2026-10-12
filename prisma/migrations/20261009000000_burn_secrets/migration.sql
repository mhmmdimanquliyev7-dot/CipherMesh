-- CipherMesh: recipient-bound secrets and burn-after-reading (Phase 9, CM-T043, CM-T044;
-- data-model 4.13 and 5, DF-09, INV-13, INV-14, INV-17).
-- Hand-written and reviewed. No column changes: secrets exists since schema v1 with its sizes,
-- the rule that ACTIVE is exactly "has a wrapped SEK", and the rule that the payload, its IV and
-- the wrapped SEK are removed together. The secret feature adds:
--   payload bound     the secret document is at most 16 KiB (CP-29, D-09-01), so its ciphertext is
--                     17 to 16,400 bytes: the API's body limit is not the only bound.
--   lifetime bound    no secret lives longer than the longest PC-09 lifetime (7 days, STANDARD).
--   burn rule         only a burn-after-reading secret can become REVEALED (PC-10, D-09-02).
--   guard trigger     identity columns, the burn flag and the expiry are write-once; a REVEALED,
--                     EXPIRED or REVOKED secret is final (no resurrection); an ACTIVE secret's
--                     ciphertext and wrapped SEK never change, they can only be removed by leaving
--                     ACTIVE; revealed_at is set at most once, and a burn-after-reading secret
--                     cannot stay ACTIVE once revealed.
-- These constraints check shapes and transitions, not meaning (L-27): the recipient's browser
-- authenticates every secret with RSA-OAEP and AES-GCM before it shows anything. The at-most-once
-- reveal itself is the API's locking transaction (SELECT ... FOR UPDATE, then a conditional UPDATE
-- on status ACTIVE); the trigger makes a second release impossible even for a faulty writer,
-- because a REVEALED row has no ciphertext and cannot become ACTIVE again. No grant changes:
-- cm_api keeps SELECT, INSERT, UPDATE and cm_worker SELECT, UPDATE; nobody can DELETE a secret
-- row (the metadata row stays as a tombstone).

-- Hand-written constraints. No secret row existed before Phase 9, so tightening the bounds cannot
-- fail on existing data.
ALTER TABLE "secrets"
  DROP CONSTRAINT "secrets_payload_length_check",
  ADD CONSTRAINT "secrets_payload_length_check"
    CHECK (payload_ciphertext IS NULL OR octet_length(payload_ciphertext) BETWEEN 17 AND 16400),
  ADD CONSTRAINT "secrets_lifetime_check" CHECK (expires_at <= created_at + interval '7 days'),
  ADD CONSTRAINT "secrets_revealed_needs_burn_check" CHECK (status <> 'REVEALED' OR burn_after_reading);

CREATE FUNCTION "cm_guard_secret_change"() RETURNS trigger
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
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
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

CREATE TRIGGER "secrets_guard"
  BEFORE UPDATE ON "secrets"
  FOR EACH ROW EXECUTE FUNCTION "cm_guard_secret_change"();

-- Trigger functions are not callable by runtime roles (as in 20261002000300_runtime_role_grants).
REVOKE ALL ON FUNCTION "cm_guard_secret_change"() FROM PUBLIC;
