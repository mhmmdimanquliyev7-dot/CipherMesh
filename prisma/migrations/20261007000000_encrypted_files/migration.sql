-- CipherMesh: encrypted file lifecycle (Phase 7, CM-T037 to CM-T041; data-model 4.11 and 5, DF-07,
-- DF-08). Hand-written and reviewed; the ALTER TABLE ADD COLUMN and CREATE INDEX statements are the
-- output of `prisma migrate diff`.
--
-- encrypted_files exists since schema v1 with its sizes, NULL rules and tombstone constraints. The
-- file feature adds:
--   object_deleted_at   when the storage object of a DELETED file was removed. A tombstone row
--                       stays for audit (data-model 5); this marker lets the worker retry object
--                       deletion until it succeeded, and lets a room's deletion finish only when no
--                       object is left (CM-T040).
--   object key format   exactly the server-generated form "f/" + 32 random bytes in base64url, so
--                       a key can never carry a file name or a client-chosen path (T-11, INV-16).
--   guard trigger       identity columns are write-once; the wrapped FEK and the manifest can only
--                       be removed, never replaced; the status moves only PENDING_UPLOAD ->
--                       AVAILABLE -> DELETED (or PENDING_UPLOAD -> DELETED) and DELETED is final;
--                       an expiry can move earlier (profile upgrade) but never later or away.
-- These constraints check shapes and transitions, not meaning (L-27): the browser authenticates
-- every file with AES-GCM before it shows anything. No grant changes: cm_api keeps SELECT, INSERT,
-- UPDATE and cm_worker SELECT, UPDATE; nobody can DELETE a file row (tombstones).

-- AlterTable
ALTER TABLE "encrypted_files" ADD COLUMN     "object_deleted_at" TIMESTAMPTZ(3);

-- CreateIndex
CREATE INDEX "encrypted_files_pending_idx" ON "encrypted_files"("created_at") WHERE (status = 'PENDING_UPLOAD');

-- CreateIndex
CREATE INDEX "encrypted_files_object_cleanup_idx" ON "encrypted_files"("deleted_at") WHERE (status = 'DELETED' AND object_deleted_at IS NULL);

-- Hand-written constraints. No file row existed before Phase 7, so tightening the key format
-- cannot fail on existing data.
ALTER TABLE "encrypted_files"
  DROP CONSTRAINT "encrypted_files_object_key_format_check",
  ADD CONSTRAINT "encrypted_files_object_key_format_check" CHECK (object_key ~ '^f/[A-Za-z0-9_-]{43}$'),
  ADD CONSTRAINT "encrypted_files_object_deleted_check" CHECK (object_deleted_at IS NULL OR status = 'DELETED');

CREATE FUNCTION "cm_guard_encrypted_file_change"() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.room_id IS DISTINCT FROM OLD.room_id
     OR NEW.uploader_id IS DISTINCT FROM OLD.uploader_id
     OR NEW.key_version IS DISTINCT FROM OLD.key_version
     OR NEW.algorithm_suite IS DISTINCT FROM OLD.algorithm_suite
     OR NEW.dek_iv IS DISTINCT FROM OLD.dek_iv
     OR NEW.content_iv IS DISTINCT FROM OLD.content_iv
     OR NEW.manifest_iv IS DISTINCT FROM OLD.manifest_iv
     OR NEW.object_key IS DISTINCT FROM OLD.object_key
     OR NEW.ciphertext_size IS DISTINCT FROM OLD.ciphertext_size
     OR NEW.ciphertext_sha256 IS DISTINCT FROM OLD.ciphertext_sha256
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'encrypted_files identity columns are write-once' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  -- Crypto-shredding removes the wrapped FEK and the manifest; nothing may replace them.
  IF (NEW.wrapped_dek IS NOT NULL AND NEW.wrapped_dek IS DISTINCT FROM OLD.wrapped_dek)
     OR (NEW.manifest_ciphertext IS NOT NULL AND NEW.manifest_ciphertext IS DISTINCT FROM OLD.manifest_ciphertext) THEN
    RAISE EXCEPTION 'encrypted_files key material can only be removed' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF (OLD.status = 'DELETED' AND (NEW.status <> 'DELETED' OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at))
     OR (OLD.status = 'AVAILABLE' AND NEW.status = 'PENDING_UPLOAD')
     OR (OLD.uploaded_at IS NOT NULL AND NEW.uploaded_at IS DISTINCT FROM OLD.uploaded_at)
     OR (OLD.object_deleted_at IS NOT NULL AND NEW.object_deleted_at IS DISTINCT FROM OLD.object_deleted_at) THEN
    RAISE EXCEPTION 'encrypted_files status transition not allowed' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.expires_at IS NOT NULL AND (NEW.expires_at IS NULL OR NEW.expires_at > OLD.expires_at) THEN
    RAISE EXCEPTION 'encrypted_files expiry can only move earlier' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "encrypted_files_guard"
  BEFORE UPDATE ON "encrypted_files"
  FOR EACH ROW EXECUTE FUNCTION "cm_guard_encrypted_file_change"();

-- Trigger functions are not callable by runtime roles (as in 20261002000300_runtime_role_grants).
REVOKE ALL ON FUNCTION "cm_guard_encrypted_file_change"() FROM PUBLIC;
