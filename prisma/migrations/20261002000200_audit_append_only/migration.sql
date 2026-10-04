-- Append-only protection for audit_events (CM-T014, INV-09, T-20). Hand-written and reviewed.
--
-- Layer 1: runtime roles hold only SELECT and INSERT on audit_events (grant migration).
-- Layer 2: these triggers reject UPDATE, DELETE and TRUNCATE for every role, so a grant mistake
--          alone cannot make the table writable.
-- Limits (docs/security/limitations.md): the table owner (migration role) or a superuser can
-- disable a trigger or drop the table. That is why the ledger is tamper-evident, not
-- tamper-proof: the hash chain and signed external checkpoints (ADR-009, Phase 12) detect such
-- changes up to the last anchored checkpoint; nothing here prevents them.

CREATE FUNCTION "cm_reject_audit_modification"() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only: % is not allowed', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER "audit_events_reject_update_delete"
  BEFORE UPDATE OR DELETE ON "audit_events"
  FOR EACH ROW EXECUTE FUNCTION "cm_reject_audit_modification"();

CREATE TRIGGER "audit_events_reject_truncate"
  BEFORE TRUNCATE ON "audit_events"
  FOR EACH STATEMENT EXECUTE FUNCTION "cm_reject_audit_modification"();
