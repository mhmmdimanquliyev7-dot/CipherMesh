-- CipherMesh schema v1: integrity constraints (CM-T013). Hand-written and reviewed, because
-- Prisma cannot express CHECK constraints or triggers. Tested in tests/database/constraints.test.ts.
--
-- These checks are a second layer behind API validation. They make sure that even a buggy or
-- compromised API process cannot store data that breaks the data model, for example a plaintext
-- value in a ciphertext column of the wrong size, or a key pair without its encrypted private key.
-- Byte lengths come from the parameter register (docs/crypto/crypto-decisions.md):
--   AES-256-GCM IV 12 bytes (CP-01); tag 16 bytes; wrapped 32-byte DEK = 32 + 16 = 48 bytes;
--   RSA-OAEP-3072 ciphertext 384 bytes (CP-02); RSA-3072 SPKI (e = 65537) 422 bytes;
--   SHA-256 digests and HMAC-SHA-256 32 bytes (CP-07, CP-12); Argon2id salt 16 bytes (CP-04);
--   Argon2id floor m = 19456 KiB, t = 2, p = 1 (CP-04); 50 MiB plaintext files (CP-19);
--   at most 2^20 DEKs per room key version (CP-16).
-- Identifiers are checked as UUIDv4 (version nibble 4, RFC 4122 variant).

-- users (data-model 4.1)
ALTER TABLE "users"
  ADD CONSTRAINT "users_id_v4_check" CHECK (id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT "users_email_check" CHECK (char_length(email::text) BETWEEN 3 AND 254 AND strpos(email::text, '@') > 1),
  ADD CONSTRAINT "users_display_name_check" CHECK (char_length(btrim(display_name)) >= 1),
  -- INV-11: only an Argon2id PHC string can be stored. A plaintext or encrypted password cannot.
  ADD CONSTRAINT "users_password_hash_argon2id_check" CHECK (starts_with(password_hash, '$argon2id$v=19$')),
  ADD CONSTRAINT "users_failed_login_count_check" CHECK (failed_login_count >= 0),
  ADD CONSTRAINT "users_mfa_last_used_step_check" CHECK (mfa_last_used_step IS NULL OR mfa_last_used_step >= 0),
  ADD CONSTRAINT "users_mfa_secret_key_id_pair_check" CHECK ((mfa_totp_secret_enc IS NULL) = (mfa_totp_key_id IS NULL)),
  ADD CONSTRAINT "users_mfa_enabled_needs_secret_check" CHECK (NOT mfa_enabled OR mfa_totp_secret_enc IS NOT NULL),
  -- IV (12) + 20-byte TOTP secret (CP-09) + tag (16) is the minimum for CP-11 ciphertext.
  ADD CONSTRAINT "users_mfa_secret_enc_length_check" CHECK (mfa_totp_secret_enc IS NULL OR octet_length(mfa_totp_secret_enc) >= 48),
  ADD CONSTRAINT "users_deleted_is_disabled_check" CHECK (deleted_at IS NULL OR status = 'DISABLED');

-- recovery_codes (4.2)
ALTER TABLE "recovery_codes"
  ADD CONSTRAINT "recovery_codes_id_v4_check" CHECK (id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT "recovery_codes_code_digest_length_check" CHECK (octet_length(code_digest) = 32);

-- sessions (4.3)
ALTER TABLE "sessions"
  ADD CONSTRAINT "sessions_id_v4_check" CHECK (id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT "sessions_token_digest_length_check" CHECK (octet_length(token_digest) = 32),
  ADD CONSTRAINT "sessions_idle_within_absolute_check" CHECK (idle_expires_at <= absolute_expires_at),
  ADD CONSTRAINT "sessions_absolute_after_created_check" CHECK (absolute_expires_at > created_at),
  ADD CONSTRAINT "sessions_revocation_pair_check" CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL));

-- login_attempts (4.4): exactly one of the account ID or the identifier HMAC. Never a raw identifier.
ALTER TABLE "login_attempts"
  ADD CONSTRAINT "login_attempts_id_v4_check" CHECK (id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT "login_attempts_subject_check" CHECK (num_nonnulls(user_id, identifier_hmac) = 1),
  ADD CONSTRAINT "login_attempts_identifier_hmac_length_check" CHECK (identifier_hmac IS NULL OR octet_length(identifier_hmac) = 32);

-- user_key_pairs (4.5)
ALTER TABLE "user_key_pairs"
  ADD CONSTRAINT "user_key_pairs_id_v4_check" CHECK (id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT "user_key_pairs_algorithm_suite_check" CHECK (algorithm_suite = 'CM1'),
  ADD CONSTRAINT "user_key_pairs_spki_length_check" CHECK (octet_length(public_key_spki) = 422),
  ADD CONSTRAINT "user_key_pairs_fingerprint_format_check" CHECK (public_key_fingerprint ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT "user_key_pairs_private_key_iv_length_check" CHECK (octet_length(private_key_iv) = 12),
  -- A ciphertext is at least one block plus the 16-byte tag; a PKCS#8 RSA-3072 key is far larger.
  ADD CONSTRAINT "user_key_pairs_encrypted_private_key_length_check" CHECK (encrypted_private_key IS NULL OR octet_length(encrypted_private_key) > 1024),
  ADD CONSTRAINT "user_key_pairs_kdf_algorithm_check" CHECK (kdf_algorithm = 'argon2id'),
  ADD CONSTRAINT "user_key_pairs_kdf_floor_check" CHECK (kdf_memory_kib >= 19456 AND kdf_iterations >= 2 AND kdf_parallelism >= 1),
  ADD CONSTRAINT "user_key_pairs_kdf_salt_length_check" CHECK (octet_length(kdf_salt) = 16),
  -- Only the ACTIVE key keeps its encrypted private key; vault reset and revocation remove it.
  ADD CONSTRAINT "user_key_pairs_private_key_status_check" CHECK ((status = 'ACTIVE') = (encrypted_private_key IS NOT NULL)),
  ADD CONSTRAINT "user_key_pairs_superseded_at_check" CHECK (status <> 'SUPERSEDED' OR superseded_at IS NOT NULL),
  ADD CONSTRAINT "user_key_pairs_revoked_at_check" CHECK (status <> 'REVOKED' OR revoked_at IS NOT NULL);

-- rooms (4.6)
ALTER TABLE "rooms"
  ADD CONSTRAINT "rooms_id_v4_check" CHECK (id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT "rooms_name_check" CHECK (char_length(btrim(name)) >= 1),
  ADD CONSTRAINT "rooms_policy_version_check" CHECK (policy_version >= 1),
  ADD CONSTRAINT "rooms_current_key_version_check" CHECK (current_key_version >= 1),
  ADD CONSTRAINT "rooms_membership_epoch_check" CHECK (membership_epoch >= 0),
  -- INV-07 / ADR-013: a locked room always carries its reasons; an ACTIVE room carries none.
  -- Manual rotation keeps the room ACTIVE, so REKEYING is only reachable from REKEY_REQUIRED.
  ADD CONSTRAINT "rooms_key_state_reasons_check" CHECK (
    (key_state = 'ACTIVE' AND cardinality(rekey_reasons) = 0 AND rekey_required_since IS NULL)
    OR (key_state IN ('REKEY_REQUIRED', 'REKEYING') AND cardinality(rekey_reasons) > 0 AND rekey_required_since IS NOT NULL)
  ),
  ADD CONSTRAINT "rooms_deleted_at_check" CHECK ((status = 'ACTIVE') = (deleted_at IS NULL));

-- room_members (4.7)
ALTER TABLE "room_members"
  ADD CONSTRAINT "room_members_id_v4_check" CHECK (id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT "room_members_first_key_version_check" CHECK (first_key_version >= 1),
  ADD CONSTRAINT "room_members_active_not_removed_check" CHECK (status <> 'ACTIVE' OR (removed_at IS NULL AND removal_reason IS NULL)),
  ADD CONSTRAINT "room_members_departed_has_removal_check" CHECK (status NOT IN ('REMOVED', 'LEFT') OR (removed_at IS NOT NULL AND removal_reason IS NOT NULL));

-- invitations (4.8)
ALTER TABLE "invitations"
  ADD CONSTRAINT "invitations_id_v4_check" CHECK (id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  -- Two-person rule: the approver is never the inviter.
  ADD CONSTRAINT "invitations_approver_not_inviter_check" CHECK (approved_by_id IS NULL OR approved_by_id <> invited_by_id),
  ADD CONSTRAINT "invitations_approval_pair_check" CHECK ((approved_by_id IS NULL) = (approved_at IS NULL)),
  ADD CONSTRAINT "invitations_pending_approval_unapproved_check" CHECK (status <> 'PENDING_APPROVAL' OR approved_by_id IS NULL),
  ADD CONSTRAINT "invitations_fingerprint_format_check" CHECK (confirmed_fingerprint IS NULL OR confirmed_fingerprint ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT "invitations_expiry_check" CHECK (expires_at > created_at);

-- room_key_versions (4.9): the row holds the public commitment only, never key material (INV-04).
ALTER TABLE "room_key_versions"
  ADD CONSTRAINT "room_key_versions_id_v4_check" CHECK (id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT "room_key_versions_version_check" CHECK (version >= 1),
  ADD CONSTRAINT "room_key_versions_commitment_length_check" CHECK (octet_length(commitment) = 32),
  ADD CONSTRAINT "room_key_versions_algorithm_suite_check" CHECK (algorithm_suite = 'CM1'),
  ADD CONSTRAINT "room_key_versions_reasons_check" CHECK (cardinality(reasons) >= 1),
  ADD CONSTRAINT "room_key_versions_wrap_count_check" CHECK (wrap_count BETWEEN 0 AND 1048576),
  ADD CONSTRAINT "room_key_versions_first_has_no_operation_check" CHECK (version <> 1 OR created_by_operation_id IS NULL),
  ADD CONSTRAINT "room_key_versions_active_check" CHECK (status <> 'ACTIVE' OR (retired_at IS NULL AND destroyed_at IS NULL)),
  ADD CONSTRAINT "room_key_versions_retired_check" CHECK (status <> 'RETIRED' OR retired_at IS NOT NULL),
  ADD CONSTRAINT "room_key_versions_destroyed_check" CHECK (status <> 'DESTROYED' OR destroyed_at IS NOT NULL);

-- rekey_operations (4.9.1, ADR-013)
ALTER TABLE "rekey_operations"
  ADD CONSTRAINT "rekey_operations_id_v4_check" CHECK (id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT "rekey_operations_base_version_check" CHECK (base_version >= 1),
  ADD CONSTRAINT "rekey_operations_target_is_next_check" CHECK (target_version = base_version + 1),
  ADD CONSTRAINT "rekey_operations_membership_epoch_check" CHECK (membership_epoch >= 0),
  ADD CONSTRAINT "rekey_operations_recipient_digest_length_check" CHECK (octet_length(recipient_set_digest) = 32),
  ADD CONSTRAINT "rekey_operations_payload_digest_length_check" CHECK (payload_digest IS NULL OR octet_length(payload_digest) = 32),
  ADD CONSTRAINT "rekey_operations_lease_check" CHECK (lease_expires_at > created_at),
  ADD CONSTRAINT "rekey_operations_pending_open_check" CHECK (status <> 'PENDING' OR (completed_at IS NULL AND closed_at IS NULL AND payload_digest IS NULL)),
  ADD CONSTRAINT "rekey_operations_closed_check" CHECK (status = 'PENDING' OR closed_at IS NOT NULL),
  ADD CONSTRAINT "rekey_operations_completed_check" CHECK (status <> 'COMPLETED' OR (completed_at IS NOT NULL AND payload_digest IS NOT NULL));

-- key_envelopes (4.10): RSA-OAEP-3072 of 32-byte room key material only (INV-04, INV-17).
ALTER TABLE "key_envelopes"
  ADD CONSTRAINT "key_envelopes_id_v4_check" CHECK (id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT "key_envelopes_key_version_check" CHECK (key_version >= 1),
  ADD CONSTRAINT "key_envelopes_wrapped_key_length_check" CHECK (octet_length(wrapped_key) = 384),
  ADD CONSTRAINT "key_envelopes_algorithm_check" CHECK (algorithm = 'RSA-OAEP-3072-SHA256'),
  ADD CONSTRAINT "key_envelopes_pending_has_invitation_check" CHECK (status <> 'PENDING' OR invitation_id IS NOT NULL);

-- encrypted_files (4.11): file bytes are never stored here, only the wrapped FEK and the
-- encrypted manifest. Deleting a file removes both (crypto-shredding of the live copy).
ALTER TABLE "encrypted_files"
  ADD CONSTRAINT "encrypted_files_id_v4_check" CHECK (id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT "encrypted_files_key_version_check" CHECK (key_version >= 1),
  ADD CONSTRAINT "encrypted_files_algorithm_suite_check" CHECK (algorithm_suite = 'CM1'),
  ADD CONSTRAINT "encrypted_files_wrapped_dek_length_check" CHECK (wrapped_dek IS NULL OR octet_length(wrapped_dek) = 48),
  ADD CONSTRAINT "encrypted_files_iv_lengths_check" CHECK (octet_length(dek_iv) = 12 AND octet_length(content_iv) = 12 AND octet_length(manifest_iv) = 12),
  ADD CONSTRAINT "encrypted_files_manifest_length_check" CHECK (manifest_ciphertext IS NULL OR octet_length(manifest_ciphertext) > 16),
  ADD CONSTRAINT "encrypted_files_object_key_format_check" CHECK (object_key ~ '^[A-Za-z0-9_/-]{16,128}$'),
  ADD CONSTRAINT "encrypted_files_ciphertext_size_check" CHECK (ciphertext_size BETWEEN 16 AND 52428816),
  ADD CONSTRAINT "encrypted_files_ciphertext_sha256_length_check" CHECK (octet_length(ciphertext_sha256) = 32),
  ADD CONSTRAINT "encrypted_files_deleted_check" CHECK (
    (status = 'DELETED' AND wrapped_dek IS NULL AND manifest_ciphertext IS NULL AND deleted_at IS NOT NULL)
    OR (status <> 'DELETED' AND wrapped_dek IS NOT NULL AND manifest_ciphertext IS NOT NULL AND deleted_at IS NULL)
  ),
  ADD CONSTRAINT "encrypted_files_uploaded_check" CHECK (status <> 'AVAILABLE' OR uploaded_at IS NOT NULL),
  ADD CONSTRAINT "encrypted_files_pending_not_uploaded_check" CHECK (status <> 'PENDING_UPLOAD' OR uploaded_at IS NULL),
  ADD CONSTRAINT "encrypted_files_expiry_check" CHECK (expires_at IS NULL OR expires_at > created_at);

-- encrypted_notes (4.12)
ALTER TABLE "encrypted_notes"
  ADD CONSTRAINT "encrypted_notes_id_v4_check" CHECK (id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT "encrypted_notes_revision_check" CHECK (revision >= 1),
  ADD CONSTRAINT "encrypted_notes_key_version_check" CHECK (key_version >= 1),
  ADD CONSTRAINT "encrypted_notes_algorithm_suite_check" CHECK (algorithm_suite = 'CM1'),
  ADD CONSTRAINT "encrypted_notes_wrapped_dek_length_check" CHECK (wrapped_dek IS NULL OR octet_length(wrapped_dek) = 48),
  ADD CONSTRAINT "encrypted_notes_iv_lengths_check" CHECK (octet_length(dek_iv) = 12 AND octet_length(content_iv) = 12),
  ADD CONSTRAINT "encrypted_notes_ciphertext_length_check" CHECK (ciphertext IS NULL OR octet_length(ciphertext) > 16),
  ADD CONSTRAINT "encrypted_notes_ciphertext_sha256_length_check" CHECK (octet_length(ciphertext_sha256) = 32),
  ADD CONSTRAINT "encrypted_notes_deleted_check" CHECK (
    (deleted_at IS NULL AND ciphertext IS NOT NULL AND wrapped_dek IS NOT NULL)
    OR (deleted_at IS NOT NULL AND ciphertext IS NULL AND wrapped_dek IS NULL)
  ),
  ADD CONSTRAINT "encrypted_notes_expiry_check" CHECK (expires_at IS NULL OR expires_at > created_at);

-- secrets (4.13): the payload is AES-256-GCM under the SEK; only the 32-byte SEK is RSA-wrapped.
ALTER TABLE "secrets"
  ADD CONSTRAINT "secrets_id_v4_check" CHECK (id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT "secrets_algorithm_suite_check" CHECK (algorithm_suite = 'CM1'),
  ADD CONSTRAINT "secrets_wrap_algorithm_check" CHECK (wrap_algorithm = 'RSA-OAEP-3072-SHA256'),
  ADD CONSTRAINT "secrets_wrapped_sek_length_check" CHECK (wrapped_sek IS NULL OR octet_length(wrapped_sek) = 384),
  ADD CONSTRAINT "secrets_payload_iv_length_check" CHECK (payload_iv IS NULL OR octet_length(payload_iv) = 12),
  ADD CONSTRAINT "secrets_payload_length_check" CHECK (payload_ciphertext IS NULL OR octet_length(payload_ciphertext) > 16),
  -- Burn, expiry and revocation remove the wrapped SEK, the payload and its IV together (INV-13).
  ADD CONSTRAINT "secrets_material_together_check" CHECK (
    (wrapped_sek IS NULL) = (payload_ciphertext IS NULL) AND (payload_ciphertext IS NULL) = (payload_iv IS NULL)
  ),
  ADD CONSTRAINT "secrets_active_has_material_check" CHECK ((status = 'ACTIVE') = (wrapped_sek IS NOT NULL)),
  ADD CONSTRAINT "secrets_destroyed_at_check" CHECK ((status = 'ACTIVE') = (destroyed_at IS NULL)),
  ADD CONSTRAINT "secrets_revealed_at_check" CHECK (status <> 'REVEALED' OR revealed_at IS NOT NULL),
  ADD CONSTRAINT "secrets_expiry_check" CHECK (expires_at > created_at);

-- audit_events (4.15). The hash chain itself is computed and verified from Phase 12 (ADR-009).
ALTER TABLE "audit_events"
  ADD CONSTRAINT "audit_events_id_v4_check" CHECK (id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT "audit_events_seq_check" CHECK (seq >= 1),
  ADD CONSTRAINT "audit_events_actor_check" CHECK ((actor_type = 'USER') = (actor_user_id IS NOT NULL)),
  ADD CONSTRAINT "audit_events_action_format_check" CHECK (action ~ '^[A-Z][A-Z0-9_]{1,63}$'),
  ADD CONSTRAINT "audit_events_target_type_format_check" CHECK (target_type IS NULL OR target_type ~ '^[A-Z][A-Z_]{0,31}$'),
  ADD CONSTRAINT "audit_events_details_object_check" CHECK (jsonb_typeof(details) = 'object'),
  ADD CONSTRAINT "audit_events_hash_lengths_check" CHECK (octet_length(prev_hash) = 32 AND octet_length(event_hash) = 32),
  ADD CONSTRAINT "audit_events_hash_version_check" CHECK (hash_version >= 1);

-- Write-once columns. A public identity key never changes after upload (a changed key would let
-- an attacker with API write access substitute a key, T-36), and a key version's commitment is
-- written once at activation (data-model 4.9). Status and timestamp columns stay updatable.
CREATE FUNCTION "cm_reject_user_key_pair_identity_change"() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.user_id IS DISTINCT FROM OLD.user_id
     OR NEW.algorithm_suite IS DISTINCT FROM OLD.algorithm_suite
     OR NEW.public_key_spki IS DISTINCT FROM OLD.public_key_spki
     OR NEW.public_key_fingerprint IS DISTINCT FROM OLD.public_key_fingerprint THEN
    RAISE EXCEPTION 'user_key_pairs identity columns are write-once' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "user_key_pairs_identity_write_once"
  BEFORE UPDATE ON "user_key_pairs"
  FOR EACH ROW EXECUTE FUNCTION "cm_reject_user_key_pair_identity_change"();

CREATE FUNCTION "cm_reject_room_key_version_identity_change"() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.room_id IS DISTINCT FROM OLD.room_id
     OR NEW.version IS DISTINCT FROM OLD.version
     OR NEW.commitment IS DISTINCT FROM OLD.commitment
     OR NEW.algorithm_suite IS DISTINCT FROM OLD.algorithm_suite THEN
    RAISE EXCEPTION 'room_key_versions identity columns are write-once' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "room_key_versions_identity_write_once"
  BEFORE UPDATE ON "room_key_versions"
  FOR EACH ROW EXECUTE FUNCTION "cm_reject_room_key_version_identity_change"();
