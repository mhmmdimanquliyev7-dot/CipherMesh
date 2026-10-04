-- Least-privilege grants for the runtime roles (CM-T014, TB-05). Hand-written and reviewed.
-- The roles are created by provisioning (`pnpm db:bootstrap` locally, the cloud runbook later);
-- this migration fails if they do not exist, so a deployment can never run with missing roles.
--
--   cm_migrator  owns the database objects and runs migrations. Never deployed to the VM.
--   cm_api       API runtime: DML needed by the data model, SELECT and INSERT on audit_events.
--   cm_worker    Worker: expiry cleanup, abandoned rekey operations, retention sweeps (section 5
--                of the data model), SELECT and INSERT on audit_events.
--   cm_verifier  Audit verification: SELECT on audit_events only.
--
-- No runtime role owns a table, holds TRUNCATE, REFERENCES or TRIGGER, or can create objects.
-- DELETE is granted only where the data model deletes rows instead of keeping tombstones.
-- tests/database/privileges.test.ts compares the live grants with an independent copy of this
-- matrix, so an unreviewed grant fails CI. Any change here needs a security review.

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO cm_api, cm_worker, cm_verifier;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM cm_api, cm_worker, cm_verifier;

-- Trigger functions run as triggers only; nobody needs to call them directly.
REVOKE ALL ON FUNCTION "cm_reject_audit_modification"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "cm_reject_user_key_pair_identity_change"() FROM PUBLIC;
REVOKE ALL ON FUNCTION "cm_reject_room_key_version_identity_change"() FROM PUBLIC;

-- Accounts. Users are tombstoned, never deleted.
GRANT SELECT, INSERT, UPDATE ON "users" TO cm_api;
-- Regenerating recovery codes replaces the whole set.
GRANT SELECT, INSERT, UPDATE, DELETE ON "recovery_codes" TO cm_api;
-- Sessions are revoked by the API and deleted 30 days after expiry by the worker.
GRANT SELECT, INSERT, UPDATE ON "sessions" TO cm_api;
GRANT SELECT, DELETE ON "sessions" TO cm_worker;
-- Login attempts are written by the API and aged out after 90 days by the worker.
GRANT SELECT, INSERT ON "login_attempts" TO cm_api;
GRANT SELECT, DELETE ON "login_attempts" TO cm_worker;
GRANT SELECT, INSERT, UPDATE ON "user_key_pairs" TO cm_api;

-- Rooms and membership. The worker returns abandoned rekeys to REKEY_REQUIRED and finishes
-- room deletion.
GRANT SELECT, INSERT, UPDATE ON "rooms" TO cm_api;
GRANT SELECT, UPDATE ON "rooms" TO cm_worker;
GRANT SELECT, INSERT, UPDATE ON "room_members" TO cm_api;
GRANT SELECT ON "room_members" TO cm_worker;
GRANT SELECT, INSERT, UPDATE ON "invitations" TO cm_api;
GRANT SELECT, UPDATE ON "invitations" TO cm_worker;
GRANT SELECT, INSERT, UPDATE ON "room_key_versions" TO cm_api;
GRANT SELECT, UPDATE ON "room_key_versions" TO cm_worker;
GRANT SELECT, INSERT, UPDATE ON "rekey_operations" TO cm_api;
GRANT SELECT, UPDATE, DELETE ON "rekey_operations" TO cm_worker;
-- Envelopes are deleted, not tombstoned (removal, invitation decline, destroyed versions).
GRANT SELECT, INSERT, UPDATE, DELETE ON "key_envelopes" TO cm_api;
GRANT SELECT, DELETE ON "key_envelopes" TO cm_worker;

-- Encrypted content is tombstoned: the worker clears wrapped keys and ciphertext on expiry.
GRANT SELECT, INSERT, UPDATE ON "encrypted_files" TO cm_api;
GRANT SELECT, UPDATE ON "encrypted_files" TO cm_worker;
GRANT SELECT, INSERT, UPDATE ON "encrypted_notes" TO cm_api;
GRANT SELECT, UPDATE ON "encrypted_notes" TO cm_worker;
GRANT SELECT, INSERT, UPDATE ON "secrets" TO cm_api;
GRANT SELECT, UPDATE ON "secrets" TO cm_worker;

-- Audit: append-only for writers, read-only for the verifier (INV-09).
GRANT SELECT, INSERT ON "audit_events" TO cm_api, cm_worker;
GRANT SELECT ON "audit_events" TO cm_verifier;
