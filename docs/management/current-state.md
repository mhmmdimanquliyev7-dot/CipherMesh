# Current State (engineering handoff)

Snapshot: 2026-10-04, end of Prompt 05. The source of truth is the repository: CLAUDE.md, the ADRs, the normative docs and the code. This file is a starting point for a new session, not a project report. It contains no secrets; local values live only in the git-ignored `.env`.

## 1. Where the project stands

| Item | State |
|---|---|
| Completed | Prompt 05 / Phase 3, Authentication (CM-T015 to CM-T022): implemented, awaiting project owner approval |
| Next | Prompt 06 / Phase 4, Cryptographic Identity and Vault. Do not start without explicit approval |
| Current branch | `feature/CM-T015-authentication` (head `4b77d00`) |
| Parent branch | `feature/CM-T013-database-prisma` (head `92418c3`) |
| Stacking | Three stacked branches, none merged: `main` (`5945d70`) ← `feature/CM-T006-application-foundation` (`900b664`) ← `feature/CM-T013-database-prisma` ← `feature/CM-T015-authentication`. No GitHub remote exists, so no pull request or CI run has happened. Never rewrite these histories. Create the Prompt 06 branch from `feature/CM-T015-authentication` |

Recent commits (oldest first):

| Commit | Content |
|---|---|
| `cb3b222`, `5945d70` | Phase 0 and 0.5 architecture baseline |
| `900b664` | Phase 1 application foundation (CM-T006 to CM-T012) |
| `50eaabb`, `1952980`, `147f633`, `92418c3` | Phase 2 schema, roles and migrations; API database connection; database tests and CI; docs |
| `1542247`, `5225cff`, `0ecf4fa`, `3b3f0a3`, `4b77d00` | Phase 3 auth_challenges migration; authentication; web screens; tests; docs |

## 2. Architecture implemented so far

- pnpm 12 monorepo, Node 24, TypeScript 6 strict: `apps/api` (Express 5, esbuild bundle), `apps/web` (Next.js 16 static export, strict hashed CSP), `packages/shared`, `packages/validation` (zod 4), `packages/crypto` (**still boundary-only: no crypto code yet**).
- API pipeline: request ID, security headers, request log, same-origin gate (INV-19), JSON gate, body parser, route registry (deny by default, public allowlist of six routes, central session resolution, step-up and platform-admin gates, response projections), error handler.
- Database access only through `apps/api/src/db` (ESLint enforced). Logs are JSON with central redaction.
- Engineering details: `docs/architecture/engineering-baseline.md`.

## 3. Database state

- PostgreSQL 17, Prisma 7.10.0 with the pg adapter. Schema v1: 16 tables, 211 classified fields (`/// class:`), five migrations; the last is `20261004000000_auth_challenges`.
- Roles: `cm_migrator` (owner, never on the VM), `cm_api`, `cm_worker`, `cm_verifier`, with a tested grant matrix. `audit_events` is append-only (grants plus triggers); **the hash chain does not exist yet** (Phase 12).
- About 116 CHECK constraints, including write-once public keys and key-version commitments, and size checks for envelopes, wrapped keys, IVs and digests.
- The vault columns already exist in `user_key_pairs` (SPKI, fingerprint, encrypted private key, IV, KDF parameters, salt) but are unused.
- Commands: `pnpm services:up && pnpm db:bootstrap && pnpm db:migrate`; checks `pnpm db:check-schema`, `pnpm db:drift`. Details: `docs/security/database-security.md`.

## 4. Authentication and sessions (Phase 3)

- Argon2id through Node.js `crypto.argon2` (LIB-04), CP-05 m = 65536 KiB, t = 3, p = 4, with a concurrency limit. CP-06 password policy with a breach blocklist.
- Opaque 256-bit session tokens stored as SHA-256 digests, cookie `__Host-cm_session` (HttpOnly, Secure, SameSite=Strict). 30-minute idle and 12-hour absolute lifetime, rotation, revocation, 10-session limit. No insecure-cookie switch exists; local E2E runs over HTTPS (`tests/e2e/static-server.mjs`).
- Abuse controls: per-address limits, per-account and per-identifier backoff without lockout, and no database writes for refused requests.
- Security events go to the redacted log through `apps/api/src/auth/security-events.ts`, **not** to `audit_events` (INV-09; Phase 12 swaps the sink).
- Full description: `docs/security/authentication-security.md`.

## 5. MFA, recovery codes and step-up

- TOTP (`otpauth`, LIB-06; CP-09), secrets encrypted at rest under `TOTP_ENCRYPTION_KEY` with AAD `cm.srv.totp` (CP-11), replay protection per time step.
- The MFA login step uses `auth_challenges` (5 minutes, 5 attempts, single use, cookie `__Host-cm_preauth`).
- Ten 100-bit recovery codes stored as digests; single use; regeneration needs a step-up.
- Step-up via `POST /auth/step-up` (password, plus TOTP when enabled). Route gates are `requires: { stepUp: 'standard' }` (15 minutes) or `'strict'` (5 minutes). `requireRecentAuthentication` is ready for PC-02.
- PLATFORM_ADMIN only through `pnpm admin:platform-role` (MFA required). It grants no room access.

## 6. Invariants every session must preserve

All of CLAUDE.md section 6 (INV-01 to INV-19). For Prompt 06 especially:
- **INV-01, CD-01:** the Vault Passphrase, vault-derived keys and the private key never reach the server. The account password is never reused for the vault.
- **INV-02, INV-15, CD-14:** fresh 96-bit IVs only inside `packages/crypto`; no caller-supplied IVs; no KDF fallback, so the vault fails closed.
- **INV-17:** RSA-OAEP only on 32-byte values.
- **INV-10:** no keys, passphrases or decrypted data in logs.
- Canonical contexts (CP-15) come only from the builders. No custom cryptography.
- **INV-09:** no unchained rows in `audit_events`.
- Never weaken tests, grants, cookies or authorization to make something pass.

## 7. Documents Prompt 06 must read

- CLAUDE.md; `docs/management/project-roadmap.md` (Phase 4); `docs/management/jira-backlog.md` (CM-T023 to CM-T028 and CM-T086).
- `docs/crypto/` all four files, especially the parameter register CP-01 to CP-04, CP-15 to CP-18; the library register LIB-01, LIB-03, LIB-05; the decision log CD-01, CD-14 to CD-16, CD-22; open decisions OCD-02, OCD-04, OCD-10, OCD-12.
- ADR-002, ADR-003, ADR-007 (Proposed), ADR-010 (Proposed), ADR-008, ADR-011.
- `docs/architecture/data-flow.md` DF-03 and DF-04; `docs/architecture/data-model.md` 4.5; `docs/security/authentication-security.md`; `docs/threat-model/threat-model.md` T-22, T-23, T-25, T-36, sections 8 and 9; `docs/security/limitations.md` L-01, L-07, L-08, L-15, L-17, L-23.

## 8. Test counts (last full run, 2026-10-04)

| Suite | Tests |
|---|---|
| unit | 168 |
| integration | 19 |
| security | 75 |
| auth (`tests/auth`, real API and database) | 186 |
| database (`tests/database`) | 105 |
| **`pnpm test` total** | **553 in 36 files** |
| `pnpm test:e2e` (Chromium, Firefox, WebKit) | 18 |
| `pnpm security:negative-controls` | 10 of 10 defects caught |

The auth, database, E2E and smoke runs need the local database.

## 9. Known limitations and residual risks

- Audit hash chain absent; table owner can bypass append-only (L-26); auth events only in the log (L-33).
- Targeted login delay through backoff (L-30); in-memory rate limits per process (L-32); no Nginx yet.
- No TOTP key rotation tooling (L-31); TOTP is phishable (L-34).
- Registration reveals taken emails (L-35); emails unverified (L-21); static breach list (L-36).
- Argon2id benchmark ran on a 2-CPU container, not the production VM.
- Constraints check shapes, not meaning (L-27); local roles are not cloud IAM (L-28); no local database TLS (L-29).
- Admin-assisted reset (PA-04) is a documented procedure without tooling.
- Full list: `docs/security/limitations.md`.

## 10. Deferred decisions

| Decision | Status |
|---|---|
| **OCD-12 / CM-T086: key-version authentication (T-36)** | **Open. A P0 prerequisite of Phase 4:** decide by ADR before vault work, because it may add a signing key to the identity format |
| OCD-02 / LIB-03, CP-04: browser Argon2id library and parameters | Phase 4 (ADR-010 Proposed) |
| OCD-04 / LIB-05: RFC 8785 implementation | Phase 4; must reproduce the bytes of the server context `cm.srv.totp` (CD-22) |
| OCD-01 / ADR-007: RSA-OAEP-3072 versus HPKE | Before Phase 6 |
| OCD-10: printable vault recovery key | Phase 4 stretch |
| OCD-11: WebAuthn | After Phase 3, stretch |
| Production VM Argon2id benchmark; Nginx limits; secret files; TOTP key rotation | Phase 17 |
| Worker scheduling for `pnpm worker:retention` | Phase 12 |

## 11. Outstanding work outside the repository

- Create the GitHub remote; open pull requests for Phases 1 to 3 in order; run CI.
- Branch protection, plus evidence EV-01-01 (CI run), EV-01-02 and EV-01-03.
- Jira: import the backlog (`docs/management/jira-import-guide.md`); move CM-T006 to CM-T022 through IN PROGRESS, SECURITY REVIEW and TESTING. Nothing is DONE yet.
- Evidence still needing Jira or GitHub: EV-00-05, EV-00-06, EV-00-10, and the roadmap's Jira history items for Phases 2 and 3.
- Captured evidence: `docs/report/evidence/index.md`.

## 12. Scope of Prompt 06 (Phase 4, CM-T023 to CM-T028, after CM-T086)

1. **CM-T086 first:** ADR for OCD-12, then update the identity, envelope and key-version formats as decided.
2. **CM-T023** `packages/crypto`:
   - WebCrypto wrappers: AES-256-GCM with internal IVs, RSA-OAEP with labels, HKDF, SHA-256, base64url.
   - RFC 8785 canonicalization and the context builders.
   - Known-answer and tamper tests; at least 90% coverage.
3. **CM-T024** browser Argon2id: LIB-03 selection, Web Worker, benchmark, final CP-04, ADR-010 accepted.
4. **CM-T025** vault setup (DF-03):
   - Key-pair generation and private-key wrapping in the browser.
   - Upload of the public key and the ciphertext only.
   - API validation of the uploaded key.
5. **CM-T026** vault unlock (DF-04): non-extractable private key, auto-lock (CP-22, logout, tab close, session invalidation), generic error for a wrong passphrase.
6. **CM-T027** public-key directory and fingerprint display (SS-05, CP-17).
7. **CM-T028** passphrase change and re-wrap.
8. Add vault reset to the session invalidation table (it revokes other sessions).
9. Security checkpoint: no passphrase or private key leaves the browser (network capture); no keys in browser storage.

## 13. Prompt 06 must NOT implement

- Secure Rooms, room RBAC or the authorization matrix (Phase 5).
- Room key material, envelopes, rekey, the Room Safety Code (Phase 6 onward).
- File, note or secret encryption; object storage (Phases 7 to 9).
- Security policy engine (Phase 10); audit hash chain or checkpoints (Phase 12); Crypto Inspector or Security Dashboard (Phases 13 and 14).
- Deployment, Nginx or cloud resources (Phase 17 onward).
- Any server-side handling of the Vault Passphrase or private key; any reuse of the account password for the vault.
