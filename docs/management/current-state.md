# Current State (engineering handoff)

Snapshot: 2026-10-06, end of Prompt 07C (Phase 5 complete locally: CM-T029 to CM-T032). The source of truth is the repository: CLAUDE.md, the ADRs, the normative docs and the code. This file is a starting point for a new session, not a project report. It contains no secrets; local values live only in the git-ignored `.env`.

## 1. Where the project stands

| Item | State |
|---|---|
| Completed | Phase 4 (CM-T086, CM-T023 to CM-T028), merged through pull request #10; **Phase 5 (CM-T029 to CM-T032)**, merged through pull request #13 (merge commit `bd4d2f6`). Traceability: [phase-04-traceability.md](phase-04-traceability.md), [phase-05-traceability.md](phase-05-traceability.md) |
| Phase 5 | Secure Rooms and RBAC (CM-T029 to CM-T032): **implemented, verified and merged.** Prompt 07A (CM-T029 central authorization and matrix), Prompt 07B (CM-T030 room lifecycle, CM-T031 membership administration and ownership transfer, PA-03 suspension of memberships), Prompt 07C (CM-T032 BOLA and IDOR suite, the `source-map-js` audit fix, evidence EV-05-01 to EV-05-06). No room cryptography exists. Traceability: [phase-05-traceability.md](phase-05-traceability.md) |
| Phase 5 pull request | **#13**, from `feature/CM-T029-secure-rooms-rbac` (created from `main` at `5c1ed32`), merged on 2026-10-06 with a normal merge commit `bd4d2f6` (parents `5c1ed32` and `ae3ea9c`). CI run 37462944884 passed every job and GitGuardian passed (EV-05-06). The branch (head `ae3ea9c`) takes no further commits |
| Next | **Prompt 08: Phase 6, Cryptographic Membership** (CM-T033 to CM-T036, CM-T085): room key version 1 at creation, invitations with envelopes, OWNER approval, acceptance, client unwrap and commitment check, the Room Safety Code, signed room statements (ADR-015). It starts from the updated `main`, never from the Phase 5 branch. Do not start without explicit approval |
| Baseline branch | `main` on GitHub (`mhmmdimanquliyev7-dot/CipherMesh`) holds Phases 0 to 5. It is the baseline for Prompt 08 |

## 2. Architecture implemented so far

- pnpm 12 monorepo, Node 24, TypeScript 6 strict: `apps/api` (Express 5, esbuild bundle), `apps/web` (Next.js 16 static export, strict hashed CSP), `packages/shared`, `packages/validation` (zod 4), `packages/crypto` (Phase 4, see section 5).
- API pipeline: request ID, security headers, request log, same-origin gate (INV-19), JSON gate, body parser, route registry (deny by default, public allowlist, central session resolution, path-parameter, query and body schemas, **central room authorization** (Phase 5), step-up and platform-admin gates, response projections), error handler.
- CSP: `script-src 'self' 'wasm-unsafe-eval'` plus inline-script hashes, `form-action 'none'` (since SF-04-01), no `'unsafe-inline'` or `'unsafe-eval'`. Buttons stay disabled until the page has hydrated.
- Database access only through `apps/api/src/db` (ESLint enforced). Logs are JSON with central redaction.
- Engineering details: `docs/architecture/engineering-baseline.md`.

## 3. Database state

- PostgreSQL 17, Prisma 7.10.0 with the pg adapter. 16 tables, 217 classified fields (`/// class:`), six migrations; the last is `20261005000000_identity_signing_key` (Phase 4). **Prompt 07A changed no schema, migration or grant.**
- Roles `cm_migrator` (owner, never on the VM), `cm_api`, `cm_worker`, `cm_verifier`, with a tested grant matrix. `audit_events` is append-only; **the hash chain does not exist yet** (Phase 12).
- `rooms` and `room_members` exist since Phase 2: one current membership per (room, user) among ACTIVE and SUSPENDED rows, exactly one ACTIVE OWNER per room, removal fields required for REMOVED and LEFT. A room needs no key rows; key versions and envelopes arrive in Phase 6.
- Commands: `pnpm services:up && pnpm db:bootstrap && pnpm db:migrate`; checks `pnpm db:check-schema`, `pnpm db:drift`. Details: `docs/security/database-security.md`.

## 4. Authentication and sessions (Phase 3)

- Argon2id (LIB-04, CP-05), CP-06 password policy with a breach blocklist; opaque 256-bit session tokens as SHA-256 digests in `__Host-cm_session`; idle and absolute expiry, rotation, revocation, 10-session limit; TOTP MFA, recovery codes, step-up (`standard` 15 minutes, `strict` 5 minutes).
- Security events go to the redacted log through `apps/api/src/auth/security-events.ts`, **not** to `audit_events` (INV-09; Phase 12 swaps the sink). Phase 4 added the vault events, Phase 5 `ROOM_ACCESS_DENIED`.
- Full description: `docs/security/authentication-security.md`.

## 5. Cryptography and vault (Phase 4)

- ADR-015 (OCD-12): an identity is an RSA-OAEP-3072 encryption key and an ECDSA P-256 signing key under one key ID, with a binding signature and a fingerprint over both keys. Room statements are signed from Phase 6.
- `packages/crypto`: AES-256-GCM with internal IVs, RSA-OAEP (32-byte values only), ECDSA, HKDF, SHA-256, RFC 8785, the context catalogue, identity verification shared with the API, vault format version 1 ([vault.md](../crypto/vault.md)). Coverage gate `pnpm test:coverage:crypto`.
- Browser Argon2id `argon2id` 1.0.1 (LIB-03) in a Web Worker; vault setup, unlock in memory, auto-lock, signed passphrase change, reset, directory lookup. API routes: `GET /vault`, `POST /vault`, `POST /vault/rewrap`, `POST /vault/reset`, `POST /directory/lookup`.

## 6. Room authorization and rooms (Phase 5, CM-T029 to CM-T032)

| Part | Location |
|---|---|
| Role and action matrix (AZ-01 to AZ-30, PA-01 to PA-05, SS-01 to SS-06), frozen data; room constants (profiles, PC-01 and PC-02 values, page sizes) | `packages/shared/src/authorization.ts`, `packages/shared/src/rooms.ts` |
| Central decision, pure and fail-closed | `decideRoomAction`. The platform role is not an input (PA-05) |
| Membership lookup and target lookup | `apps/api/src/db/room-access-store.ts`: `findActiveMembership(roomId, userId)`, `findTargetMember(roomId, userId, includeSuspended)`, both filtered by room in the query |
| Central authorizer, in-transaction re-authorization | `apps/api/src/authorization/rooms.ts`: `createRoomAuthorizer` (the gate), `reauthorizeRoomAction` (the same decision on locked state), generic 404 or 403, `ROOM_ACCESS_DENIED` |
| Room data access | `apps/api/src/db/room-store.ts`: membership-scoped reads, `lockRoom`, `lockMembership`, conditional writes, `removeMember`, `suspendMemberships`, `transferOwnership`; `room-cleanup.ts` (worker) |
| Room service and routes | `apps/api/src/rooms/service.ts`, `apps/api/src/routes/rooms.ts`; schemas in `packages/validation/src/rooms.ts` |
| Route registry | `apps/api/src/routes/registry.ts` (declarations, `roomOf(ctx)`, `params` schemas) |
| Web client | `apps/web/src/app/rooms/page.tsx` (list, create), `apps/web/src/app/rooms/room/page.tsx` (`/rooms/room?id=`, members, rename, delete, ownership), `apps/web/src/rooms/` (matrix-derived controls, messages) |
| Design record | [authorization-model.md](../security/authorization-model.md) sections 9.5 and 9.6; testing plan section 3.4 |

Routes (9, reviewed list in `tests/security/route-inventory.test.ts`): `POST /rooms` (SS-04), `GET /rooms` (SS-06), `GET /rooms/{roomId}` and `/members` (AZ-01), `POST /rooms/{roomId}/rename` (AZ-02), `/delete` (AZ-04, step-up), `/members/{userId}/role` (AZ-10), `/members/{userId}/remove` (AZ-09), `/members/{userId}/transfer-ownership` (AZ-05, step-up).

Behaviour to know:
- Creation needs an ACTIVE account and vault; CONFIDENTIAL and RESTRICTED need an MFA-verified session (PC-01) and a recent password sign-in (PC-02, 4 and 1 hours). The room has no key version or envelope (L-43).
- Removal and account suspension (PA-03) set the room REKEY_REQUIRED in the same transaction that ends the member's access and deletes their envelopes (INV-07). Re-enabling an account restores no membership (AZ-14, Phase 6, L-44). Nothing creates keys or claims a rekey.
- After a transfer the former OWNER is an ADMIN. Deleting a room makes it DELETING (404 for everyone); `pnpm worker:retention` makes it DELETED only when no envelope or content row is left.
- Every membership change locks the room row, then the memberships, and re-checks authorization on that state; account suspension locks rooms in ID order. A transaction over five seconds fails closed.
- New routes: add them to the reviewed lists (`tests/security/route-inventory.test.ts`) and to the BOLA table (`tests/helpers/bola-cases.ts`); `tests/security/bola-inventory.test.ts` fails until both agree with the registry, and `tests/authz/bola.test.ts` then attacks the route.

Not implemented: invitations, leaving a room (AZ-11, with the rekey machinery), profile changes (AZ-03), the policy gates (PC-03 and the rest, L-42) and everything of Phase 6 onward. No room cryptography exists.

Findings: R-05-01 (fixed in `bef4570`): undecodable percent-encoding in a path parameter reached the error handler as an unhandled 500; it is now the generic 404. Prompts 07B and 07C produced no new security finding; 07B added limitations L-42 to L-45. CM-T032 (`tests/authz/bola.test.ts`, 49 tests, with the table `tests/helpers/bola-cases.ts`) attacks every production room route with identifiers from another room; its controls NC-05-18 to NC-05-22 prove it fails when any layer is removed.

## 7. Invariants every session must preserve

All of CLAUDE.md section 6 (INV-01 to INV-19). For Phase 5 especially:
- **INV-05, INV-06:** authorization only through the central module with membership loaded from the database; room-scoped queries filtered by room ID and membership; non-members get 404.
- **INV-08:** policy controls in the API, never only in the UI.
- **INV-01, INV-04:** the server never receives the Vault Passphrase, private keys or room key material; Phase 5 creates no keys.
- **INV-09:** no unchained rows in `audit_events`.
- Never weaken tests, grants, cookies or authorization to make something pass.

## 8. Documents Prompt 08 must read

- CLAUDE.md; this file; `docs/management/project-roadmap.md` (Phase 6); `docs/management/jira-backlog.md` (CM-T033 to CM-T036, CM-T085).
- `docs/crypto/` (cryptographic-architecture, key-hierarchy, key-lifecycle, crypto-decisions, vault), ADR-007, ADR-012, ADR-013, ADR-015 (section 4: signed room statements), `docs/architecture/data-model.md` (4.9, 4.10 and section 8), `docs/architecture/data-flow.md` (DF-05, DF-06).
- `docs/security/authorization-model.md` (sections 3, 5 and 9), `docs/security/limitations.md` (L-42 to L-45), `docs/threat-model/threat-model.md` (T-25, T-29, T-36 and section 11), [phase-05-traceability.md](phase-05-traceability.md) section 13.

## 9. Test counts

Gates of Prompt 07C on the final Phase 5 code (2026-10-06, local PostgreSQL), recorded in EV-05-05 and phase-05-traceability.md section 12:

| Gate | Result |
|---|---|
| `pnpm test` | 1516 tests in 66 files (Phase 4: 772 in 53). The `authz` project has 131 tests in 7 files, run serially; `bola.test.ts` 49, `bola-inventory.test.ts` 5 |
| `pnpm test:e2e` (three engines, one worker) | 58 passed, 2 skipped by design |
| `pnpm security:negative-controls` | 49 of 49 caught (ten Phase 3, seventeen Phase 4, twenty-two Phase 5), both baselines pass. Run with `NODE_ENV` unset: `.env` sets `development`, which breaks `next build` |
| `pnpm test:coverage:authz` | 97.3% statements, 98.3% branches |
| `pnpm build`, `pnpm smoke:api`, `pnpm sbom:generate`, format, lint, typecheck | Pass |
| `pnpm audit:deps` | **Pass**: no known vulnerabilities. The `source-map-js` advisory was closed by a lockfile-only refresh to 1.2.2 (EV-05-04) |
| `pnpm scan:secrets` (full history) | 44 commits scanned, no leaks |

Local notes: the database suites need the local PostgreSQL container (Docker Desktop stopped several times during Phase 5; restart it and wait for healthy). Run E2E and the negative controls one at a time, E2E with `--workers=1` (parallel browsers ran out of memory). Start the negative controls with `NODE_ENV` unset and only `DATABASE_URL` exported. The `cm_api` connection limit of 40 is shared by all projects; the `authz` project runs its files serially (peak in a full run: 24). Two crypto tests were timing-sensitive and are not security defects: `vault.test.ts` "refuses a second derivation while one is running" (it assumed the first of two concurrent calls always reaches the derivation first; failed in about three of about twelve full runs including one CI run on `main`; now deterministic, see phase-05-traceability.md section 8) and `identity.test.ts` (now with a 30-second limit).

## 10. Known limitations and residual risks

- Phase 4: no phone benchmark (L-37); client-side vault lock (L-38); offline guessing by a session holder (L-39); a passphrase change does not re-key (L-40); the directory reveals which addresses have a vault (L-41).
- T-36 stays open until Phase 6 implements the signed key-version verification (L-23).
- Audit hash chain absent; table owner can bypass append-only (L-26); authentication, vault and room authorization events only in the log (L-33).
- Targeted login delay (L-30); in-memory rate limits per process (L-32); no Nginx yet; no TOTP key rotation tooling (L-31); TOTP is phishable (L-34); registration reveals taken emails (L-35); emails unverified (L-21).
- Phase 5: profile gates not yet checked on every room request (L-42); rooms have no key version until CM-T033 (L-43); a room that loses a member stays REKEY_REQUIRED until the rekey exists, and a re-enabled account gets no membership back (L-44); a reused room ID is refused with 409, and there is no room quota (L-45).
- Full list: `docs/security/limitations.md`.

## 11. Deferred decisions

| Decision | Status |
|---|---|
| Invitation acceptance and the user-row lock | Prompt 08 (Phase 6): acceptance must lock the invitee's user row like room creation, so an account disable cannot miss a membership it creates |
| OCD-01 / ADR-007: RSA-OAEP-3072 versus HPKE | Before Phase 6: an envelope created in one engine must open in another |
| PC-16 scope for AZ-07, AZ-14 and AZ-26 | When they are implemented (Phases 6 and 9) |
| ADR-015 section 4: exact room-statement formats and columns | Phase 6 and Phase 11 |
| OCD-06 fingerprint pinning, OCD-10 vault recovery key, OCD-11 WebAuthn | Stretch |
| Production VM Argon2id benchmark; Nginx limits; secret files; TOTP key rotation | Phase 17 |

## 12. Outstanding work outside the repository

- Branch protection (CM-T012): the `main` ruleset still lists no required status checks; add the CI jobs (now including both coverage steps) as required checks, then capture EV-01-01 to EV-01-03.
- Dependabot pull requests #2 to #6 remain open (#2 PostgreSQL 18 needs an ADR; #6 `@types/node` 26 is ahead of Node 24).
- Jira: import the backlog; move CM-T006 to CM-T032 and CM-T086 through IN PROGRESS, SECURITY REVIEW and TESTING; create SF-04-01 and R-05-01 as `security-finding` items (both fixed in their phase branches). Nothing is DONE yet.
- Evidence still needing Jira or GitHub: EV-00-05, EV-00-06, EV-00-10, the Jira history items of Phases 2 to 5. EV-05-01 to EV-05-06 are in `docs/report/evidence/phase-05/` (EV-05-06 is the CI run of pull request #13).

## 13. Not implemented yet

- Room key material, key envelopes, commitments, signed room statements, rekey and the Room Safety Code (Phase 6 onward). No room cryptography exists: rooms are an authorization and membership structure only (L-43).
- File, note or secret encryption; object storage (Phases 7 to 9).
- The security policy engine (Phase 10), the audit hash chain (Phase 12), the Crypto Inspector or the Security Dashboard (Phases 13 and 14).
- Deployment, Nginx or cloud resources (Phase 17 onward).
- Any server-side handling of the Vault Passphrase or private keys, ever.
