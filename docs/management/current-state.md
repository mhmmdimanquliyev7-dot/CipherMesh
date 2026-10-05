# Current State (engineering handoff)

Snapshot: 2026-10-05, end of Prompt 06 (Phase 4). The source of truth is the repository: CLAUDE.md, the ADRs, the normative docs and the code. This file is a starting point for a new session, not a project report. It contains no secrets; local values live only in the git-ignored `.env`.

## 1. Where the project stands

| Item | State |
|---|---|
| Completed | Prompt 06 / Phase 4, Cryptographic Identity and Vault (CM-T086, CM-T023 to CM-T028): implemented, awaiting project owner approval. Traceability: [phase-04-traceability.md](phase-04-traceability.md) |
| Next | Prompt 07 / Phase 5, Secure Rooms and RBAC (CM-T029 to CM-T032). Do not start without explicit approval |
| Baseline branch | `main` on GitHub (`mhmmdimanquliyev7-dot/CipherMesh`) holds Phases 0 to 3 (`f86a2ce`, after pull requests #1, #7, #8 and #9) |
| Phase 4 branch | `feature/CM-T023-cryptographic-vault`, created from `f86a2ce`. Pull request #10: CI passed every job (run 37347479619); GitGuardian waits for a false-positive mark. Merge only after the project owner approves Phase 4, with a normal merge commit |
| Prompt 07 branch | Create it from `main` after the Phase 4 pull request is merged (`git checkout main && git pull --ff-only`) |

## 2. Architecture implemented so far

- pnpm 12 monorepo, Node 24, TypeScript 6 strict: `apps/api` (Express 5, esbuild bundle), `apps/web` (Next.js 16 static export, strict hashed CSP), `packages/shared`, `packages/validation` (zod 4), `packages/crypto` (Phase 4, see section 5).
- API pipeline: request ID, security headers, request log, same-origin gate (INV-19), JSON gate, body parser, route registry (deny by default, public allowlist, central session resolution, step-up and platform-admin gates, response projections), error handler.
- CSP: `script-src 'self' 'wasm-unsafe-eval'` plus inline-script hashes, `form-action 'none'` (since SF-04-01), no `'unsafe-inline'` or `'unsafe-eval'`. Buttons stay disabled until the page has hydrated.
- Database access only through `apps/api/src/db` (ESLint enforced). Logs are JSON with central redaction.
- Engineering details: `docs/architecture/engineering-baseline.md`.

## 3. Database state

- PostgreSQL 17, Prisma 7.10.0 with the pg adapter. 16 tables, 217 classified fields (`/// class:`), six migrations; the last is `20261005000000_identity_signing_key` (Phase 4).
- Roles `cm_migrator` (owner, never on the VM), `cm_api`, `cm_worker`, `cm_verifier`, with a tested grant matrix (unchanged in Phase 4). `audit_events` is append-only; **the hash chain does not exist yet** (Phase 12).
- `user_key_pairs` now holds one identity per row: both SPKIs, the binding signature, the fingerprint, both wrapped private keys and IVs, KDF parameters and salt, the vault format version. CHECKs bound sizes and the KDF floor and ceiling; a trigger keeps identity columns write-once and retired identities retired.
- Commands: `pnpm services:up && pnpm db:bootstrap && pnpm db:migrate`; checks `pnpm db:check-schema`, `pnpm db:drift`. Details: `docs/security/database-security.md` (section 12 for Phase 4).

## 4. Authentication and sessions (Phase 3)

- Argon2id through Node.js `crypto.argon2` (LIB-04), CP-05 m = 65536 KiB, t = 3, p = 4, with a concurrency limit. CP-06 password policy with a breach blocklist.
- Opaque 256-bit session tokens stored as SHA-256 digests, cookie `__Host-cm_session` (HttpOnly, Secure, SameSite=Strict); idle and absolute expiry, rotation, revocation, 10-session limit. Local E2E runs over HTTPS (`tests/e2e/static-server.mjs`).
- TOTP MFA (LIB-06), recovery codes, step-up (`standard` 15 minutes, `strict` 5 minutes). The TOTP AAD is now built by the shared canonical builder (CD-22); Phase 3 ciphertexts still open.
- Security events go to the redacted log through `apps/api/src/auth/security-events.ts`, **not** to `audit_events` (INV-09; Phase 12 swaps the sink). Phase 4 added the vault events.
- Full description: `docs/security/authentication-security.md` (section 16 for Phase 4).

## 5. Cryptography and vault (Phase 4)

- **OCD-12 decided by [ADR-015](../architecture/adr/ADR-015-identity-signing-keys.md)** (accepted 2026-10-05, before implementation): an identity is an RSA-OAEP-3072 encryption key and an ECDSA P-256 signing key under one key ID, with a binding signature and a fingerprint over both keys. Room statements (genesis, membership grants, key versions) are signed from Phase 6; the verification rule and `KEY_AUTHENTICATION_FAILED` are specified in ADR-015 section 4.
- `packages/crypto`: AES-256-GCM with internal IVs, RSA-OAEP (32-byte values only), ECDSA, HKDF, SHA-256, RFC 8785 for the CP-15 subset (in-repo, LIB-05), the context catalogue (`contexts.ts`), identity verification shared with the API (`@ciphermesh/crypto/identity`), the vault format version 1 ([vault.md](../crypto/vault.md)). Known answers from FIPS 180-2, RFC 5869, the GCM specification, Wycheproof, RFC 6979, RFC 8785 and RFC 9106. Coverage 99.5% statements, 91.8% branches (`pnpm test:coverage:crypto`, CI gate).
- Browser Argon2id: `argon2id` 1.0.1 (LIB-03), WebAssembly embedded and checksummed, a fresh Web Worker per derivation, one at a time, 120-second timeout. CP-04 target m = 64 MiB, t = 3, p = 1; floor and ceiling enforced in the browser, the API and the database. ADR-010 accepted. No phone benchmark (L-37).
- Vault flows: setup (standard step-up), unlock in memory with pair checks (keys exist only while the view is unlocked, R-04-01), auto-lock (15 minutes without trusted input, sign-out, `pagehide`, session end), signed passphrase change and upgrade with compare-and-swap, reset (strict step-up, new identity, other sessions revoked), directory lookup (exact address, own vault required, rate-limited).
- API routes: `GET /vault`, `POST /vault`, `POST /vault/rewrap`, `POST /vault/reset`, `POST /directory/lookup`.

## 6. Invariants every session must preserve

All of CLAUDE.md section 6 (INV-01 to INV-19). For Prompt 07 especially:
- **INV-05, INV-06:** authorization only through the central module with membership loaded from the database; room-scoped queries filtered by room ID and membership; non-members get 404.
- **INV-08:** policy controls in the API, never only in the UI.
- **INV-01, INV-04:** the server never receives the Vault Passphrase, private keys or room key material; Phase 5 creates no keys.
- **INV-09:** no unchained rows in `audit_events`.
- Never weaken tests, grants, cookies or authorization to make something pass.

## 7. Documents Prompt 07 must read

- CLAUDE.md; `docs/management/project-roadmap.md` (Phase 5); `docs/management/jira-backlog.md` (CM-T029 to CM-T032).
- `docs/security/authorization-model.md`, `docs/security/security-policy-profiles.md`; `docs/architecture/data-model.md` 4.6 to 4.8 and section 8 (planned signed statements); `docs/architecture/data-flow.md` DF-05 and DF-06; ADR-011 (identifier routing confirmed in Phase 5), ADR-013, ADR-015.
- `docs/threat-model/threat-model.md` T-04 to T-06, T-21, T-37 and section 10; `docs/security/limitations.md`.

## 8. Test counts (last full local runs, 2026-10-05)

| Suite | Tests |
|---|---|
| unit (24 files, including 14 in `packages/crypto` with 124 tests) | 314 |
| integration | 19 |
| security | 76 |
| auth (`tests/auth`, real API and database) | 222 |
| vault (`tests/vault`, real API, real Argon2id and database) | 23 |
| database (`tests/database`) | 118 |
| **`pnpm test` total** | **772 in 53 files** |
| `pnpm test:e2e` (Chromium, Firefox, WebKit) | 54 (52 run, 2 skipped by design: the cross-engine test runs once, from Chromium) |
| `pnpm security:negative-controls` | 27 of 27 defects caught (local run) |

The auth, vault, database, E2E and smoke runs need the local database. CI provides a throwaway PostgreSQL service and random per-run role passwords and authentication keys. Local note: with many other containers running, a parallel E2E run once crashed browser processes for lack of memory; it passed when run alone.

## 9. Known limitations and residual risks

- New in Phase 4: no phone benchmark (L-37); the vault lock is client-side (L-38); a session holder can download the encrypted vault and guess offline (L-39); a passphrase change does not re-key (L-40); the directory reveals which addresses have a vault (L-41).
- T-36 stays open until Phase 6 implements the signed key-version verification (L-23).
- Audit hash chain absent; table owner can bypass append-only (L-26); auth and vault events only in the log (L-33).
- Targeted login delay through backoff (L-30); in-memory rate limits per process (L-32); no Nginx yet.
- No TOTP key rotation tooling (L-31); TOTP is phishable (L-34). Registration reveals taken emails (L-35); emails unverified (L-21).
- Full list: `docs/security/limitations.md`.

## 10. Deferred decisions

| Decision | Status |
|---|---|
| OCD-01 / ADR-007: RSA-OAEP-3072 versus HPKE | Before Phase 6: an envelope created in one engine must open in another |
| ADR-015 section 4: exact room-statement formats and columns | Phase 6 (CM-T033 to CM-T036) and Phase 11 (CM-T050); planned fields in data-model section 8 |
| OCD-06: fingerprint pinning | After Phase 12, stretch |
| OCD-10: user-held vault recovery key | Not implemented; later stretch, never server escrow |
| OCD-11: WebAuthn | Stretch |
| Phone benchmark of CP-04 | Open (L-37) |
| Production VM Argon2id benchmark; Nginx limits; secret files; TOTP key rotation | Phase 17 |

## 11. Outstanding work outside the repository

- GitHub: the Phase 4 pull request awaits review, CI and the project owner's approval; merge only with a normal merge commit.
- Branch protection (CM-T012): the `main` ruleset still lists no required status checks; add the CI jobs (now including the coverage step) as required checks. Then capture EV-01-01 (CI run), EV-01-02 and EV-01-03.
- GitGuardian: mark incident 37892113 on pull request #10 as a false positive in the dashboard (the first 12 bytes of a test ciphertext in an evidence file; classification posted on the pull request). The Wycheproof vectors contain public test keys by design (`packages/crypto/vectors/README.md`); they were not flagged.
- Dependabot pull requests #2 to #6 remain open (see the Phase 3 handoff notes: #2 PostgreSQL 18 needs an ADR; #6 `@types/node` 26 is ahead of Node 24).
- Jira: import the backlog (the CSV now matches ADR-015); move CM-T006 to CM-T028 and CM-T086 through IN PROGRESS, SECURITY REVIEW and TESTING. Create the security finding SF-04-01 (label `security-finding`, fixed in the Phase 4 pull request). Nothing is DONE yet.
- Evidence still needing Jira or GitHub: EV-00-05, EV-00-06, EV-00-10, the Jira history items of Phases 2 to 4, EV-04-13 (CI run).

## 12. Scope of Prompt 07 (Phase 5, CM-T029 to CM-T032)

1. **CM-T029** central authorization module implementing the shared matrix; route-registry enforcement.
2. **CM-T030** room creation, listing, renaming and deletion (room keys arrive in Phase 6: check the backlog item for the key-material boundary).
3. **CM-T031** membership administration: role changes and ownership transfer.
4. **CM-T032** BOLA and IDOR suite for every room-scoped route.
5. Security checkpoint: every route declared and tested; PLATFORM_ADMIN has no room access; non-members receive 404.

## 13. Prompt 07 must NOT implement

- Room key material, envelopes, signed room statements, rekey or the Room Safety Code (Phase 6 onward).
- File, note or secret encryption; object storage (Phases 7 to 9).
- The security policy engine (Phase 10), the audit hash chain (Phase 12), the Crypto Inspector or the Security Dashboard (Phases 13 and 14).
- Deployment, Nginx or cloud resources (Phase 17 onward).
- Any server-side handling of the Vault Passphrase or private keys.
