-- CipherMesh: encrypted note lifecycle (Phase 8, CM-T042; data-model 4.12 and 5, DF-12).
-- Hand-written and reviewed. No column changes: encrypted_notes exists since schema v1 with its
-- sizes, NULL rules and the tombstone constraint. The note feature adds:
--   ciphertext bound   the note document is at most 64 KiB (CP-28, D-08-01), so its ciphertext is
--                      17 to 65,552 bytes: the API's body limit is not the only bound.
--   guard trigger      identity columns are write-once; the content (ciphertext, wrapped NEK, IVs,
--                      hash, key version, editor) changes only together with the revision, which
--                      moves by exactly one; the key version never moves back; a tombstone is
--                      final and keeps its revision; an expiry can move earlier but never later or
--                      away (PC-08).
-- These constraints check shapes and transitions, not meaning (L-27): the browser authenticates
-- every note with AES-GCM before it shows anything. The optimistic-concurrency check itself is the
-- conditional UPDATE in the API (stored revision = expected revision); the trigger makes a skipped
-- or repeated revision impossible even for a faulty writer. No grant changes: cm_api keeps
-- SELECT, INSERT, UPDATE and cm_worker SELECT, UPDATE; nobody can DELETE a note row (tombstones).

-- Hand-written constraints. No note row existed before Phase 8, so tightening the bound cannot
-- fail on existing data.
ALTER TABLE "encrypted_notes"
  DROP CONSTRAINT "encrypted_notes_ciphertext_length_check",
  ADD CONSTRAINT "encrypted_notes_ciphertext_length_check"
    CHECK (ciphertext IS NULL OR octet_length(ciphertext) BETWEEN 17 AND 65552);

CREATE FUNCTION "cm_guard_encrypted_note_change"() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
  content_changed boolean;
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.room_id IS DISTINCT FROM OLD.room_id
     OR NEW.author_id IS DISTINCT FROM OLD.author_id
     OR NEW.algorithm_suite IS DISTINCT FROM OLD.algorithm_suite
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'encrypted_notes identity columns are write-once' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  -- A tombstone is final: nothing about a deleted note changes again.
  IF OLD.deleted_at IS NOT NULL THEN
    IF ROW(NEW.*) IS DISTINCT FROM ROW(OLD.*) THEN
      RAISE EXCEPTION 'encrypted_notes tombstones are final' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.expires_at IS NOT NULL AND (NEW.expires_at IS NULL OR NEW.expires_at > OLD.expires_at) THEN
    RAISE EXCEPTION 'encrypted_notes expiry can only move earlier' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  content_changed := NEW.wrapped_dek IS DISTINCT FROM OLD.wrapped_dek
    OR NEW.dek_iv IS DISTINCT FROM OLD.dek_iv
    OR NEW.ciphertext IS DISTINCT FROM OLD.ciphertext
    OR NEW.content_iv IS DISTINCT FROM OLD.content_iv
    OR NEW.ciphertext_sha256 IS DISTINCT FROM OLD.ciphertext_sha256
    OR NEW.key_version IS DISTINCT FROM OLD.key_version
    OR NEW.updated_by_id IS DISTINCT FROM OLD.updated_by_id;
  IF NEW.deleted_at IS NOT NULL THEN
    -- Deletion (crypto-shredding of the live copy): the CHECK requires the ciphertext and the
    -- wrapped NEK to be NULL; everything else that describes the last revision stays as it was.
    IF NEW.revision IS DISTINCT FROM OLD.revision
       OR NEW.key_version IS DISTINCT FROM OLD.key_version
       OR NEW.dek_iv IS DISTINCT FROM OLD.dek_iv
       OR NEW.content_iv IS DISTINCT FROM OLD.content_iv
       OR NEW.ciphertext_sha256 IS DISTINCT FROM OLD.ciphertext_sha256
       OR NEW.updated_by_id IS DISTINCT FROM OLD.updated_by_id THEN
      RAISE EXCEPTION 'encrypted_notes deletion only removes key material and ciphertext' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.revision IS DISTINCT FROM OLD.revision THEN
    -- An edit (DF-12): exactly the next revision, with a new NEK, new IVs and new ciphertext.
    IF NEW.revision <> OLD.revision + 1 THEN
      RAISE EXCEPTION 'encrypted_notes revision must increase by one' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.wrapped_dek = OLD.wrapped_dek OR NEW.dek_iv = OLD.dek_iv
       OR NEW.content_iv = OLD.content_iv OR NEW.ciphertext = OLD.ciphertext THEN
      RAISE EXCEPTION 'encrypted_notes revision needs new key material' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.key_version < OLD.key_version THEN
      RAISE EXCEPTION 'encrypted_notes key version cannot move back' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  ELSIF content_changed THEN
    RAISE EXCEPTION 'encrypted_notes content changes only with a new revision' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "encrypted_notes_guard"
  BEFORE UPDATE ON "encrypted_notes"
  FOR EACH ROW EXECUTE FUNCTION "cm_guard_encrypted_note_change"();

-- Trigger functions are not callable by runtime roles (as in 20261002000300_runtime_role_grants).
REVOKE ALL ON FUNCTION "cm_guard_encrypted_note_change"() FROM PUBLIC;
