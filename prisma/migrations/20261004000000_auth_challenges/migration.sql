-- Pre-authentication challenges for the MFA step of login (CM-T016, CM-T019; Phase 3).
-- Generated part: `prisma migrate diff` against the Phase 2 schema. Hand-written part below:
-- integrity constraints and grants, reviewed with docs/security/authentication-security.md.

-- CreateEnum
CREATE TYPE "AuthChallengePurpose" AS ENUM ('LOGIN_MFA');

-- CreateTable
CREATE TABLE "auth_challenges" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID NOT NULL,
    "token_digest" BYTEA NOT NULL,
    "purpose" "AuthChallengePurpose" NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "consumed_at" TIMESTAMPTZ(3),

    CONSTRAINT "auth_challenges_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "auth_challenges_token_digest_key" ON "auth_challenges"("token_digest");

-- CreateIndex
CREATE INDEX "auth_challenges_user_id_idx" ON "auth_challenges"("user_id");

-- CreateIndex
CREATE INDEX "auth_challenges_expires_at_idx" ON "auth_challenges"("expires_at");

-- AddForeignKey
ALTER TABLE "auth_challenges" ADD CONSTRAINT "auth_challenges_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- Integrity: the challenge is short-lived (5 minutes, session-and-csrf.md section 3), allows at
-- most 5 code attempts, and stores only a SHA-256 digest of its token.
ALTER TABLE "auth_challenges"
  ADD CONSTRAINT "auth_challenges_id_v4_check" CHECK (id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
  ADD CONSTRAINT "auth_challenges_token_digest_length_check" CHECK (octet_length(token_digest) = 32),
  ADD CONSTRAINT "auth_challenges_attempts_check" CHECK (attempts BETWEEN 0 AND 5),
  ADD CONSTRAINT "auth_challenges_lifetime_check" CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes');

-- Least privilege (same rules as 20261002000300_runtime_role_grants): the API creates, reads and
-- consumes challenges; the worker deletes expired ones. Rows are never needed after expiry.
REVOKE ALL ON "auth_challenges" FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON "auth_challenges" TO cm_api;
GRANT SELECT, DELETE ON "auth_challenges" TO cm_worker;
