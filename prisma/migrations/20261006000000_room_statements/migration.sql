-- CipherMesh: signed room statements (ADR-015 section 4; CM-T033 to CM-T036). Hand-written and
-- reviewed; the ALTER TABLE and foreign-key statements are the output of `prisma migrate diff`.
--
-- Every room key version, every room and every membership grant becomes verifiable by members:
--   rooms              creator_key_id, genesis_signature      cm.room.genesis by the room creator
--   room_key_versions  created_by_key_id, previous_commitment,
--                      recipient_user_ids, recipient_key_ids,
--                      statement_signature                    cm.room.key-version by its creator
--   invitations        grantor_key_id, grant_signature        cm.room.membership-grant by the inviter
--   room_members       subject_key_id, grant_role, grantor_user_id, grantor_key_id, grant_signature
--                                                             the member's latest signed grant
-- Signatures are ECDSA P-256 in IEEE P1363 form (64 bytes, CP-26). None of these columns holds key
-- material: they are public identifiers, commitments and signatures (data-model section 8). The
-- browser verifies them (packages/crypto/src/room-keys.ts); the API verifies the signatures it
-- stores at write time; these constraints check shapes, not meaning (L-27).
--
-- Rooms created before Phase 6 have no key version and no genesis statement (L-43): the two room
-- columns are nullable for them only, and a NULL creator_key_id leaves the composite foreign key
-- unchecked (MATCH SIMPLE). They are never initialized on the server. The key-version and
-- invitation columns are NOT NULL: no key version or invitation existed before Phase 6, and if one
-- did, this migration would fail rather than invent a signature for it.

-- AlterTable
ALTER TABLE "invitations" ADD COLUMN     "grant_signature" BYTEA NOT NULL,
ADD COLUMN     "grantor_key_id" UUID NOT NULL;

-- AlterTable
ALTER TABLE "room_key_versions" ADD COLUMN     "created_by_key_id" UUID NOT NULL,
ADD COLUMN     "previous_commitment" BYTEA,
ADD COLUMN     "recipient_key_ids" UUID[],
ADD COLUMN     "recipient_user_ids" UUID[],
ADD COLUMN     "statement_signature" BYTEA NOT NULL;

-- AlterTable
ALTER TABLE "room_members" ADD COLUMN     "grant_role" "RoomRole",
ADD COLUMN     "grant_signature" BYTEA,
ADD COLUMN     "grantor_key_id" UUID,
ADD COLUMN     "grantor_user_id" UUID,
ADD COLUMN     "subject_key_id" UUID;

-- AlterTable
ALTER TABLE "rooms" ADD COLUMN     "creator_key_id" UUID,
ADD COLUMN     "genesis_signature" BYTEA;

-- AddForeignKey
ALTER TABLE "rooms" ADD CONSTRAINT "rooms_creator_key_id_created_by_id_fkey" FOREIGN KEY ("creator_key_id", "created_by_id") REFERENCES "user_key_pairs"("id", "user_id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "room_members" ADD CONSTRAINT "room_members_subject_key_id_user_id_fkey" FOREIGN KEY ("subject_key_id", "user_id") REFERENCES "user_key_pairs"("id", "user_id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "room_members" ADD CONSTRAINT "room_members_grantor_key_id_grantor_user_id_fkey" FOREIGN KEY ("grantor_key_id", "grantor_user_id") REFERENCES "user_key_pairs"("id", "user_id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "invitations" ADD CONSTRAINT "invitations_grantor_key_id_invited_by_id_fkey" FOREIGN KEY ("grantor_key_id", "invited_by_id") REFERENCES "user_key_pairs"("id", "user_id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "room_key_versions" ADD CONSTRAINT "room_key_versions_created_by_key_id_created_by_id_fkey" FOREIGN KEY ("created_by_key_id", "created_by_id") REFERENCES "user_key_pairs"("id", "user_id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- ------------------------------------------------------------------------- hand-written checks

-- rooms: the genesis statement is all or nothing.
ALTER TABLE "rooms"
  ADD CONSTRAINT "rooms_genesis_pair_check" CHECK ((creator_key_id IS NULL) = (genesis_signature IS NULL)),
  ADD CONSTRAINT "rooms_genesis_signature_length_check" CHECK (genesis_signature IS NULL OR octet_length(genesis_signature) = 64);

-- room_members: a grant has every field or none. The member whose authority is the genesis
-- statement (the creator) has none, like members added before Phase 6.
ALTER TABLE "room_members"
  ADD CONSTRAINT "room_members_grant_complete_check" CHECK (
    (subject_key_id IS NULL AND grant_role IS NULL AND grantor_user_id IS NULL AND grantor_key_id IS NULL AND grant_signature IS NULL)
    OR (subject_key_id IS NOT NULL AND grant_role IS NOT NULL AND grantor_user_id IS NOT NULL AND grantor_key_id IS NOT NULL AND grant_signature IS NOT NULL)
  ),
  ADD CONSTRAINT "room_members_grant_signature_length_check" CHECK (grant_signature IS NULL OR octet_length(grant_signature) = 64);

ALTER TABLE "invitations"
  ADD CONSTRAINT "invitations_grant_signature_length_check" CHECK (octet_length(grant_signature) = 64);

-- room_key_versions: version 1 has no previous commitment and every later version has one; the
-- signed recipient list has 1 to 100 entries (CP-25) as two parallel arrays without NULLs. Prisma
-- maps scalar lists to nullable columns, so the non-NULL rule is a CHECK.
ALTER TABLE "room_key_versions"
  ADD CONSTRAINT "room_key_versions_previous_commitment_check" CHECK ((version = 1) = (previous_commitment IS NULL)),
  ADD CONSTRAINT "room_key_versions_previous_commitment_length_check" CHECK (previous_commitment IS NULL OR octet_length(previous_commitment) = 32),
  ADD CONSTRAINT "room_key_versions_recipients_check" CHECK (
    recipient_user_ids IS NOT NULL AND recipient_key_ids IS NOT NULL
    AND array_ndims(recipient_user_ids) = 1 AND array_ndims(recipient_key_ids) = 1
    AND cardinality(recipient_user_ids) BETWEEN 1 AND 100
    AND cardinality(recipient_key_ids) = cardinality(recipient_user_ids)
    AND array_position(recipient_user_ids, NULL) IS NULL AND array_position(recipient_key_ids, NULL) IS NULL
  ),
  ADD CONSTRAINT "room_key_versions_statement_signature_length_check" CHECK (octet_length(statement_signature) = 64);

-- ---------------------------------------------------------------------------- write-once rules
-- A signed statement is never replaced in place: a database writer cannot swap a genesis, a key
-- version's signed content or an invitation's grant after the fact (T-36). Status and timestamp
-- columns stay updatable. Membership grants are replaced on purpose when an OWNER grants ADMIN or
-- transfers ownership, so room_members has no such trigger; the new grant is verified by the API.

CREATE OR REPLACE FUNCTION "cm_reject_room_key_version_identity_change"() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.room_id IS DISTINCT FROM OLD.room_id
     OR NEW.version IS DISTINCT FROM OLD.version
     OR NEW.commitment IS DISTINCT FROM OLD.commitment
     OR NEW.algorithm_suite IS DISTINCT FROM OLD.algorithm_suite
     OR NEW.created_by_id IS DISTINCT FROM OLD.created_by_id
     OR NEW.created_by_key_id IS DISTINCT FROM OLD.created_by_key_id
     OR NEW.previous_commitment IS DISTINCT FROM OLD.previous_commitment
     OR NEW.recipient_user_ids IS DISTINCT FROM OLD.recipient_user_ids
     OR NEW.recipient_key_ids IS DISTINCT FROM OLD.recipient_key_ids
     OR NEW.statement_signature IS DISTINCT FROM OLD.statement_signature THEN
    RAISE EXCEPTION 'room_key_versions identity columns are write-once' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "cm_reject_room_genesis_change"() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.created_by_id IS DISTINCT FROM OLD.created_by_id
     OR NEW.creator_key_id IS DISTINCT FROM OLD.creator_key_id
     OR NEW.genesis_signature IS DISTINCT FROM OLD.genesis_signature THEN
    RAISE EXCEPTION 'rooms genesis columns are write-once' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "rooms_genesis_write_once"
  BEFORE UPDATE ON "rooms"
  FOR EACH ROW EXECUTE FUNCTION "cm_reject_room_genesis_change"();

CREATE FUNCTION "cm_reject_invitation_grant_change"() RETURNS trigger
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
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'invitations grant columns are write-once' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "invitations_grant_write_once"
  BEFORE UPDATE ON "invitations"
  FOR EACH ROW EXECUTE FUNCTION "cm_reject_invitation_grant_change"();

-- Trigger functions are not callable by runtime roles (as in 20261002000300_runtime_role_grants).
REVOKE ALL ON FUNCTION "cm_reject_room_genesis_change"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "cm_reject_invitation_grant_change"() FROM PUBLIC;
