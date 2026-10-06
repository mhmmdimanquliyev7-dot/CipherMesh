# Current State (engineering handoff)

Snapshot: 2026-10-06, end of Prompt 07B (Phase 5, CM-T030 and CM-T031). The source of truth is the repository: CLAUDE.md, the ADRs, the normative docs and the code. This file is a starting point for a new session, not a project report. It contains no secrets; local values live only in the git-ignored `.env`.

## 1. Where the project stands

| Item | State |
|---|---|
| Completed | Phase 4 (CM-T086, CM-T023 to CM-T028), merged into `main` through pull request #10. Traceability: [phase-04-traceability.md](phase-04-traceability.md) |
| In progress | Phase 5, Secure Rooms and RBAC (CM-T029 to CM-T032). **Prompt 07A done** (CM-T029, central authorization module and shared matrix) and **Prompt 07B done** (CM-T030 room lifecycle, CM-T031 membership administration and ownership transfer, and the PA-03 suspension of memberships), all committed on the Phase 5 branch. **CM-T032 (BOLA suite) is pending.** No pull request. Traceability: [phase-05-traceability.md](phase-05-traceability.md) |
| Phase 5 branch | `feature/CM-T029-secure-rooms-rbac`, created from `main` at `5c1ed32`. Prompt 07A head `7190092`; Prompt 07B implementation commit `09ade03`, followed by the handoff commit (`git log` shows the head). Local only; not pushed |
| Next | **Prompt 07C: CM-T032** (the BOLA and IDOR suite over every room route), the final Phase 5 security and evidence gate (EV-05-01 to EV-05-03, the full-history secret scan, the dependency-audit decision below) and the pull request. It continues on `feature/CM-T029-secure-rooms-rbac`, **not from `main`**. Do not start without explicit approval |
| Baseline branch | `main` on GitHub (`mhmmdimanquliyev7-dot/CipherMesh`) holds Phases 0 to 4 (`5c1ed32`) |

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

## 6. Room authorization and rooms (Prompts 07A and 07B, CM-T029 to CM-T031)

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
- New routes: add them to the reviewed list; every room route needs coverage in the BOLA suite (CM-T032).

Not implemented: the BOLA suite (CM-T032), invitations, leaving a room (AZ-11, with the rekey machinery), profile changes (AZ-03), the policy gates (PC-03 and the rest, L-42) and everything of Phase 6 onward. No room cryptography exists.

Findings: R-05-01 (fixed in `bef4570`): undecodable percent-encoding in a path parameter reached the error handler as an unhandled 500; it is now the generic 404. Prompt 07B produced no new security finding and added limitations L-42 to L-45.

## 7. Invariants every session must preserve

All of CLAUDE.md section 6 (INV-01 to INV-19). For Phase 5 especially:
- **INV-05, INV-06:** authorization only through the central module with membership loaded from the database; room-scoped queries filtered by room ID and membership; non-members get 404.
- **INV-08:** policy controls in the API, never only in the UI.
- **INV-01, INV-04:** the server never receives the Vault Passphrase, private keys or room key material; Phase 5 creates no keys.
- **INV-09:** no unchained rows in `audit_events`.
- Never weaken tests, grants, cookies or authorization to make something pass.

## 8. Documents Prompt 07C must read

- CLAUDE.md; this file; [phase-05-traceability.md](phase-05-traceability.md); `docs/management/jira-backlog.md` (CM-T032) and `docs/report/evidence-plan.md` (EV-05-01 to EV-05-03).
- `docs/security/authorization-model.md` (sections 5, 8 and 9), `docs/security/security-testing-plan.md` (`bola`, `route-inventory`, section 3.4), `docs/threat-model/threat-model.md` T-05, T-06 and section 11, `docs/security/limitations.md` (L-42 to L-45).
- `apps/api/src/routes/rooms.ts`, `apps/api/src/rooms/service.ts`, `tests/helpers/rooms.ts` (fixtures, `whileLocked`), `tests/authz/`.

## 9. Test counts

Full gates of Prompt 07B (2026-10-06, local PostgreSQL), details in phase-05-traceability.md section 8:

| Gate | Result |
|---|---|
| `pnpm test` | 1462 tests in 64 files (Phase 4: 772 in 53). Authz project: 82 tests in 6 files, run serially |
| `pnpm test:e2e` (three engines, one worker) | 58 passed, 2 skipped by design |
| `pnpm security:negative-controls` | 44 of 44 caught (ten Phase 3, seventeen Phase 4, seventeen Phase 5), baselines pass. Run with `NODE_ENV` unset: `.env` sets `development`, which breaks `next build` |
| `pnpm test:coverage:authz` | 97.3% statements, 98.3% branches (Prompt 07A) |
| `pnpm build`, `pnpm smoke:api`, `pnpm sbom:generate`, format, lint, typecheck | Pass |
| `pnpm audit:deps` | **Fails** on `source-map-js` below 1.2.2 (high, build-time, transitive of `next`, `postcss` and Tailwind; the same on `main`). Patched 1.2.2 is available. Needs a decision before the Phase 5 pull request |

Intermittent: `packages/crypto/src/vault.test.ts` "refuses a second derivation while one is running" failed once in seven full runs under load (8 of 8 passes in isolation; unchanged by Phase 5; timing-dependent). Local notes: the database suites need the local PostgreSQL container (Docker Desktop stopped twice during Phase 5; restart it and wait for healthy). Run E2E and the negative controls one at a time, E2E with `--workers=1` (parallel browsers ran out of memory). The `cm_api` connection limit of 40 is shared by all projects; the peak in a full run is 24.

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
| Dependency advisory `source-map-js` (build-time) | Prompt 07C or the project owner: a pnpm override to 1.2.2 changes the web build toolchain and needs review and an E2E run |
| Invitation acceptance and the user-row lock | Phase 6: acceptance must lock the invitee's user row like room creation, so an account disable cannot miss a membership it creates |
| OCD-01 / ADR-007: RSA-OAEP-3072 versus HPKE | Before Phase 6: an envelope created in one engine must open in another |
| PC-16 scope for AZ-07, AZ-14 and AZ-26 | When they are implemented (Phases 6 and 9) |
| ADR-015 section 4: exact room-statement formats and columns | Phase 6 and Phase 11 |
| OCD-06 fingerprint pinning, OCD-10 vault recovery key, OCD-11 WebAuthn | Stretch |
| Production VM Argon2id benchmark; Nginx limits; secret files; TOTP key rotation | Phase 17 |

## 12. Outstanding work outside the repository

- Branch protection (CM-T012): the `main` ruleset still lists no required status checks; add the CI jobs (now including both coverage steps) as required checks, then capture EV-01-01 to EV-01-03.
- Dependabot pull requests #2 to #6 remain open (#2 PostgreSQL 18 needs an ADR; #6 `@types/node` 26 is ahead of Node 24).
- Jira: import the backlog; move CM-T006 to CM-T031 and CM-T086 through IN PROGRESS, SECURITY REVIEW and TESTING; create SF-04-01 and R-05-01 as `security-finding` items (both fixed in their phase branches). Nothing is DONE yet.
- Evidence still needing Jira or GitHub: EV-00-05, EV-00-06, EV-00-10, the Jira history items of Phases 2 to 5. EV-05-01 to EV-05-03 are captured in Prompt 07C.

## 13. Phase 5 must NOT implement (Prompt 07C included)

- Room key material, envelopes, signed room statements, rekey or the Room Safety Code (Phase 6 onward).
- File, note or secret encryption; object storage (Phases 7 to 9).
- The security policy engine (Phase 10), the audit hash chain (Phase 12), the Crypto Inspector or the Security Dashboard (Phases 13 and 14).
- Deployment, Nginx or cloud resources (Phase 17 onward).
- Any server-side handling of the Vault Passphrase or private keys.
