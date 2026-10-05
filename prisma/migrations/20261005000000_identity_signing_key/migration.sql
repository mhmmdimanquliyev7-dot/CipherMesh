-- CipherMesh: identity signing key (ADR-015, OCD-12; CM-T086, CM-T025). Hand-written and reviewed.
--
-- A user's cryptographic identity becomes a bundle of two key pairs under one key ID:
--   - the RSA-OAEP-3072 encryption key (existing columns public_key_spki, encrypted_private_key,
--     private_key_iv), which receives 32-byte values only (CP-02, INV-17);
--   - an ECDSA P-256 signing key (new columns), which signs canonical statements only (CP-26).
-- public_key_fingerprint keeps its name and now holds the identity fingerprint over both public
-- keys (CP-17 as revised by ADR-015). Both private keys are stored only as AES-256-GCM ciphertext
-- produced in the browser under keys derived from the Vault Passphrase (INV-01, docs/crypto/vault.md).
--
-- The new columns are NOT NULL without defaults on purpose: no identity exists before Phase 4,
-- and if one did, this migration would fail rather than invent a signing key for it.

ALTER TABLE "user_key_pairs"
  ADD COLUMN "signing_public_key_spki" BYTEA NOT NULL,
  ADD COLUMN "identity_signature" BYTEA NOT NULL,
  ADD COLUMN "encrypted_signing_private_key" BYTEA,
  ADD COLUMN "signing_private_key_iv" BYTEA NOT NULL,
  ADD COLUMN "vault_version" INTEGER NOT NULL,
  ADD COLUMN "rewrapped_at" TIMESTAMPTZ(3);

-- Sizes from the parameter register (docs/crypto/crypto-decisions.md): ECDSA P-256 SPKI 91 bytes and
-- P1363 signature 64 bytes (CP-26); AES-GCM IV 12 bytes (CP-01); a wrapped PKCS#8 P-256 key is
-- 138 + 16 bytes in every tested engine, a wrapped PKCS#8 RSA-3072 key 1809 to 1811 bytes. The bounds
-- match WRAPPED_KEY_BYTES in packages/crypto/src/params.ts. They are a second layer behind the API
-- and cannot tell ciphertext from other bytes of the same size (L-27).
ALTER TABLE "user_key_pairs"
  ADD CONSTRAINT "user_key_pairs_signing_spki_length_check" CHECK (octet_length(signing_public_key_spki) = 91),
  ADD CONSTRAINT "user_key_pairs_identity_signature_length_check" CHECK (octet_length(identity_signature) = 64),
  ADD CONSTRAINT "user_key_pairs_signing_private_key_iv_length_check" CHECK (octet_length(signing_private_key_iv) = 12),
  ADD CONSTRAINT "user_key_pairs_encrypted_signing_private_key_length_check" CHECK (
    encrypted_signing_private_key IS NULL OR octet_length(encrypted_signing_private_key) BETWEEN 64 AND 256
  ),
  ADD CONSTRAINT "user_key_pairs_encrypted_private_key_max_length_check" CHECK (
    encrypted_private_key IS NULL OR octet_length(encrypted_private_key) <= 2048
  ),
  ADD CONSTRAINT "user_key_pairs_vault_version_check" CHECK (vault_version = 1),
  -- CP-04 ceiling: a stored record can never make a browser derive with more memory or passes.
  ADD CONSTRAINT "user_key_pairs_kdf_ceiling_check" CHECK (
    kdf_memory_kib <= 262144 AND kdf_iterations <= 10 AND kdf_parallelism <= 4
  ),
  -- Only the ACTIVE identity keeps its encrypted signing key, exactly like the encryption key.
  ADD CONSTRAINT "user_key_pairs_signing_private_key_status_check" CHECK (
    (status = 'ACTIVE') = (encrypted_signing_private_key IS NOT NULL)
  ),
  ADD CONSTRAINT "user_key_pairs_rewrapped_at_check" CHECK (rewrapped_at IS NULL OR rewrapped_at >= created_at);

-- Write-once identity, extended to the signing key and the binding signature (T-25, T-36). A
-- retired identity stays retired: a SUPERSEDED or REVOKED key pair can never become ACTIVE again,
-- so an old and possibly compromised identity cannot be brought back by a database write.
CREATE OR REPLACE FUNCTION "cm_reject_user_key_pair_identity_change"() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.user_id IS DISTINCT FROM OLD.user_id
     OR NEW.algorithm_suite IS DISTINCT FROM OLD.algorithm_suite
     OR NEW.public_key_spki IS DISTINCT FROM OLD.public_key_spki
     OR NEW.public_key_fingerprint IS DISTINCT FROM OLD.public_key_fingerprint
     OR NEW.signing_public_key_spki IS DISTINCT FROM OLD.signing_public_key_spki
     OR NEW.identity_signature IS DISTINCT FROM OLD.identity_signature THEN
    RAISE EXCEPTION 'user_key_pairs identity columns are write-once' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.status <> 'ACTIVE' AND NEW.status IS DISTINCT FROM OLD.status THEN
    RAISE EXCEPTION 'a retired identity cannot change status' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END;
$$;
