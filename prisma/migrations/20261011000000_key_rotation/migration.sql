-- CipherMesh: key rotation (Phase 11, CM-T050 to CM-T053; ADR-013, ADR-015 section 4,
-- key-lifecycle sections 1 and 3, data-model 4.6, 4.7.1, 4.9 and 4.9.1).
-- Hand-written and reviewed. One new table and database-level guards for the rekey state
-- machine. The API enforces every rule first; these make a faulty or compromised writer of the
-- runtime role unable to break the invariants silently (T-36, T-37, INV-07).
--
-- 1. room_member_grants: every signed membership grant ever stored on a membership, append-only.
--    A membership keeps only its latest grant, which an ADMIN promotion, an ownership transfer and
--    now a re-share after a vault reset (AZ-14, CM-T053) replace. Statements signed by the old
--    identity (key versions it created, invitations it granted) still need the grant that gave
--    that identity its authority, so the authority chain served to members reads this history
--    (ADR-015 section 4.1, step 4). A trigger on room_members records each grant; existing grants
--    are copied once below.
-- 2. rekey_operations: identity columns are write-once, a closed operation never changes again,
--    and a PENDING operation is never deleted (ADR-013).
-- 3. room_key_versions: versions are created in sequence with the previous commitment of the
--    version before (the chain clients verify), and statuses only move ACTIVE -> RETIRED ->
--    DESTROYED (key-lifecycle 1.1); wrap_count never decreases (CP-16).
-- 4. rooms: the current version moves only to the next, already ACTIVE version; a locked room is
--    unlocked only together with that move; the membership epoch only increases, and a change
--    of it closes a PENDING rekey operation as STALE and returns a REKEYING room to
--    REKEY_REQUIRED (ADR-013 step 5), whichever code path changed the epoch.
-- 5. A deferred consistency check at commit: a room is REKEYING exactly when it has a PENDING
--    MANDATORY operation, and a PENDING MANUAL operation exists only while the room is ACTIVE.
--    No transaction can commit an unlocked room with a half-closed operation or the reverse.

-- ------------------------------------------------------------------------- 1. grant history

-- CreateTable
CREATE TABLE "room_member_grants" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "room_id" UUID NOT NULL,
    "subject_user_id" UUID NOT NULL,
    "subject_key_id" UUID NOT NULL,
    "role" "RoomRole" NOT NULL,
    "grantor_user_id" UUID NOT NULL,
    "grantor_key_id" UUID NOT NULL,
    "grant_signature" BYTEA NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "room_member_grants_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "room_member_grants_one_per_statement" ON "room_member_grants"("room_id", "subject_user_id", "subject_key_id", "role", "grantor_user_id", "grantor_key_id");

-- CreateIndex
CREATE INDEX "room_member_grants_subject_idx" ON "room_member_grants"("room_id", "subject_user_id", "subject_key_id");

-- AddForeignKey
ALTER TABLE "room_member_grants" ADD CONSTRAINT "room_member_grants_room_id_fkey" FOREIGN KEY ("room_id") REFERENCES "rooms"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "room_member_grants" ADD CONSTRAINT "room_member_grants_subject_key_id_subject_user_id_fkey" FOREIGN KEY ("subject_key_id", "subject_user_id") REFERENCES "user_key_pairs"("id", "user_id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "room_member_grants" ADD CONSTRAINT "room_member_grants_grantor_key_id_grantor_user_id_fkey" FOREIGN KEY ("grantor_key_id", "grantor_user_id") REFERENCES "user_key_pairs"("id", "user_id") ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE "room_member_grants"
  ADD CONSTRAINT "room_member_grants_id_v4_check" CHECK (id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT "room_member_grants_signature_length_check" CHECK (octet_length(grant_signature) = 64);

-- Append-only: a recorded grant is a signed statement and is never changed or removed.
CREATE FUNCTION "cm_reject_grant_history_change"() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION 'room_member_grants is append-only: % is not allowed', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$;
REVOKE ALL ON FUNCTION "cm_reject_grant_history_change"() FROM PUBLIC;

CREATE TRIGGER "room_member_grants_reject_update_delete"
  BEFORE UPDATE OR DELETE ON "room_member_grants"
  FOR EACH ROW EXECUTE FUNCTION "cm_reject_grant_history_change"();

CREATE TRIGGER "room_member_grants_reject_truncate"
  BEFORE TRUNCATE ON "room_member_grants"
  FOR EACH STATEMENT EXECUTE FUNCTION "cm_reject_grant_history_change"();

-- Every grant stored on a membership is recorded. The CHECK on room_members makes the grant
-- columns all-or-nothing, so a non-NULL signature means a complete grant.
CREATE FUNCTION "cm_record_membership_grant"() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF NEW.grant_signature IS NOT NULL
     AND (TG_OP = 'INSERT'
          OR NEW.subject_key_id IS DISTINCT FROM OLD.subject_key_id
          OR NEW.grant_role IS DISTINCT FROM OLD.grant_role
          OR NEW.grantor_user_id IS DISTINCT FROM OLD.grantor_user_id
          OR NEW.grantor_key_id IS DISTINCT FROM OLD.grantor_key_id
          OR NEW.grant_signature IS DISTINCT FROM OLD.grant_signature) THEN
    INSERT INTO public.room_member_grants
      (room_id, subject_user_id, subject_key_id, role, grantor_user_id, grantor_key_id, grant_signature)
    VALUES
      (NEW.room_id, NEW.user_id, NEW.subject_key_id, NEW.grant_role, NEW.grantor_user_id, NEW.grantor_key_id,
       NEW.grant_signature)
    ON CONFLICT DO NOTHING;
  END IF;
  RETURN NULL;
END;
$$;
REVOKE ALL ON FUNCTION "cm_record_membership_grant"() FROM PUBLIC;

CREATE TRIGGER "room_members_record_grant"
  AFTER INSERT OR UPDATE ON "room_members"
  FOR EACH ROW EXECUTE FUNCTION "cm_record_membership_grant"();

INSERT INTO "room_member_grants"
  (room_id, subject_user_id, subject_key_id, role, grantor_user_id, grantor_key_id, grant_signature, created_at)
SELECT room_id, user_id, subject_key_id, grant_role, grantor_user_id, grantor_key_id, grant_signature, joined_at
  FROM "room_members"
 WHERE grant_signature IS NOT NULL
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------- 2. rekey operations

CREATE FUNCTION "cm_guard_rekey_operation_change"() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    -- The worker purges closed operations after 90 days (data-model section 5); a live one stays.
    IF OLD.status = 'PENDING' THEN
      RAISE EXCEPTION 'a PENDING rekey operation cannot be deleted' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN OLD;
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.room_id IS DISTINCT FROM OLD.room_id
     OR NEW.started_by_id IS DISTINCT FROM OLD.started_by_id
     OR NEW.mode IS DISTINCT FROM OLD.mode
     OR NEW.base_version IS DISTINCT FROM OLD.base_version
     OR NEW.target_version IS DISTINCT FROM OLD.target_version
     OR NEW.membership_epoch IS DISTINCT FROM OLD.membership_epoch
     OR NEW.recipient_set_digest IS DISTINCT FROM OLD.recipient_set_digest
     OR NEW.lease_expires_at IS DISTINCT FROM OLD.lease_expires_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'rekey_operations snapshot columns are write-once' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  -- COMPLETED, ABANDONED, SUPERSEDED, CANCELLED and STALE are final (ADR-013): a closed
  -- operation can never be finalized, reopened or given another payload.
  IF OLD.status <> 'PENDING' AND ROW(NEW.*) IS DISTINCT FROM ROW(OLD.*) THEN
    RAISE EXCEPTION 'a closed rekey operation cannot change' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION "cm_guard_rekey_operation_change"() FROM PUBLIC;

CREATE TRIGGER "rekey_operations_guard"
  BEFORE UPDATE OR DELETE ON "rekey_operations"
  FOR EACH ROW EXECUTE FUNCTION "cm_guard_rekey_operation_change"();

-- ------------------------------------------------------------------------- 3. key versions

CREATE FUNCTION "cm_guard_room_key_version_insert"() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
  predecessor bytea;
BEGIN
  -- Version 1 (unique per room) and a missing or malformed previous commitment are decided by
  -- the unique index and the CHECKs, which report their own errors.
  IF NEW.version = 1 OR NEW.previous_commitment IS NULL OR octet_length(NEW.previous_commitment) <> 32 THEN
    RETURN NEW;
  END IF;
  SELECT commitment INTO predecessor FROM public.room_key_versions
   WHERE room_id = NEW.room_id AND version = NEW.version - 1;
  -- The signed previous commitment is the commitment of the version before (ADR-015 4.1, step 7),
  -- and no version number is skipped.
  IF predecessor IS NULL OR NEW.previous_commitment <> predecessor THEN
    RAISE EXCEPTION 'room_key_versions must follow the previous version' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION "cm_guard_room_key_version_insert"() FROM PUBLIC;

CREATE TRIGGER "room_key_versions_sequence"
  BEFORE INSERT ON "room_key_versions"
  FOR EACH ROW EXECUTE FUNCTION "cm_guard_room_key_version_insert"();

CREATE FUNCTION "cm_guard_room_key_version_status"() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF NEW.status IS DISTINCT FROM OLD.status
     AND NOT ((OLD.status = 'ACTIVE' AND NEW.status IN ('RETIRED', 'DESTROYED'))
              OR (OLD.status = 'RETIRED' AND NEW.status = 'DESTROYED')) THEN
    RAISE EXCEPTION 'room_key_versions status can only move ACTIVE -> RETIRED -> DESTROYED'
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.wrap_count < OLD.wrap_count THEN
    RAISE EXCEPTION 'room_key_versions wrap_count never decreases' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION "cm_guard_room_key_version_status"() FROM PUBLIC;

CREATE TRIGGER "room_key_versions_status_guard"
  BEFORE UPDATE ON "room_key_versions"
  FOR EACH ROW EXECUTE FUNCTION "cm_guard_room_key_version_status"();

-- ---------------------------------------------------------------------------------- 4. rooms

CREATE FUNCTION "cm_guard_room_key_state"() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF NEW.membership_epoch < OLD.membership_epoch THEN
    RAISE EXCEPTION 'rooms membership_epoch never decreases' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.current_key_version IS DISTINCT FROM OLD.current_key_version THEN
    IF NEW.current_key_version <> OLD.current_key_version + 1
       OR NOT EXISTS (SELECT 1 FROM public.room_key_versions
                       WHERE room_id = NEW.id AND version = NEW.current_key_version AND status = 'ACTIVE') THEN
      RAISE EXCEPTION 'rooms current_key_version moves only to the next, ACTIVE version' USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  -- INV-07: a write-locked room is unlocked only by activating the next key version.
  IF OLD.key_state <> 'ACTIVE' AND NEW.key_state = 'ACTIVE'
     AND NEW.current_key_version IS NOT DISTINCT FROM OLD.current_key_version THEN
    RAISE EXCEPTION 'rooms are unlocked only by a new key version' USING ERRCODE = 'check_violation';
  END IF;
  -- ADR-013 step 5: a membership or member-key change makes a PENDING operation STALE.
  IF NEW.membership_epoch <> OLD.membership_epoch THEN
    UPDATE public.rekey_operations
       SET status = 'STALE', closed_at = statement_timestamp(), closed_reason = 'MEMBERSHIP_CHANGED'
     WHERE room_id = NEW.id AND status = 'PENDING';
    IF NEW.key_state = 'REKEYING' THEN
      NEW.key_state := 'REKEY_REQUIRED';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION "cm_guard_room_key_state"() FROM PUBLIC;

CREATE TRIGGER "rooms_key_state_guard"
  BEFORE UPDATE ON "rooms"
  FOR EACH ROW EXECUTE FUNCTION "cm_guard_room_key_state"();

-- ------------------------------------------------------------- 5. consistency at commit time

CREATE FUNCTION "cm_check_rekey_consistency"() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
  target uuid;
  state text;
  pending_mode text;
BEGIN
  -- Each assignment is prepared only when it runs, so NEW.room_id is never read on a rooms row.
  IF TG_TABLE_NAME = 'rooms' THEN
    target := NEW.id;
  ELSE
    target := NEW.room_id;
  END IF;
  SELECT key_state::text INTO state FROM public.rooms WHERE id = target;
  SELECT mode::text INTO pending_mode FROM public.rekey_operations WHERE room_id = target AND status = 'PENDING';
  IF (state = 'REKEYING') IS DISTINCT FROM (COALESCE(pending_mode, '') = 'MANDATORY') THEN
    RAISE EXCEPTION 'a room is REKEYING exactly while a MANDATORY rekey operation is PENDING'
      USING ERRCODE = 'check_violation';
  END IF;
  IF pending_mode = 'MANUAL' AND state <> 'ACTIVE' THEN
    RAISE EXCEPTION 'a MANUAL rekey operation is PENDING only while the room is ACTIVE'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END;
$$;
REVOKE ALL ON FUNCTION "cm_check_rekey_consistency"() FROM PUBLIC;

CREATE CONSTRAINT TRIGGER "rooms_rekey_consistency"
  AFTER INSERT OR UPDATE ON "rooms"
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION "cm_check_rekey_consistency"();

CREATE CONSTRAINT TRIGGER "rekey_operations_consistency"
  AFTER INSERT OR UPDATE ON "rekey_operations"
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION "cm_check_rekey_consistency"();

-- ---------------------------------------------------------------------------------- grants

-- The API records grants (through the trigger, as the invoking role) and reads the history for
-- the authority chain; nothing may change or delete a recorded grant. The worker reads it for
-- nothing and gets no grant. The verifier role (Phase 12) has no access.
GRANT SELECT, INSERT ON "room_member_grants" TO cm_api;
