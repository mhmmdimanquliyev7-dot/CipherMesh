# Current State (engineering handoff)

Snapshot: 2026-10-06, end of Prompt 07A (Phase 5, CM-T029). The source of truth is the repository: CLAUDE.md, the ADRs, the normative docs and the code. This file is a starting point for a new session, not a project report. It contains no secrets; local values live only in the git-ignored `.env`.

## 1. Where the project stands

| Item | State |
|---|---|
| Completed | Phase 4 (CM-T086, CM-T023 to CM-T028), merged into `main` through pull request #10. Traceability: [phase-04-traceability.md](phase-04-traceability.md) |
| In progress | Phase 5, Secure Rooms and RBAC (CM-T029 to CM-T032). **Prompt 07A done:** CM-T029, the central authorization module and shared matrix, implemented and committed on the Phase 5 branch. No pull request yet. Traceability: [phase-05-traceability.md](phase-05-traceability.md) |
| Phase 5 branch | `feature/CM-T029-secure-rooms-rbac`, created from `main` at `5c1ed32`. Head before this handoff commit: `9da20dd`. Local only; not pushed |
| Next | **Prompt 07B: CM-T030 and CM-T031** (room creation, listing, renaming and deletion; membership administration; ownership transfer). It continues on `feature/CM-T029-secure-rooms-rbac`, **not from `main`**. Then Prompt 07C: CM-T032 (BOLA suite), the full gates, evidence and the pull request. Do not start without explicit approval |
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

## 6. Room authorization (Prompt 07A, CM-T029)

| Part | Location |
|---|---|
| Role and action matrix (AZ-01 to AZ-30, PA-01 to PA-05, SS-01 to SS-05), frozen data | `packages/shared/src/authorization.ts` (`ROOM_ACTIONS`, `ACCOUNT_ACTIONS`) |
| Central decision, pure and fail-closed | `decideRoomAction` in the same file. Inputs: the membership from the database, room state, target facts. The platform role is not an input (PA-05) |
| Membership lookup boundary | `apps/api/src/db/room-access-store.ts`: `findActiveMembership(roomId, userId)`, one query filtered by room, user, ACTIVE membership and ACTIVE room; projection without room name or key material; usable with a transaction client |
| Central authorizer | `apps/api/src/authorization/rooms.ts`: membership, decision, target loader only after the role permits, generic 404 or 403, `ROOM_ACCESS_DENIED` event (action and reason only) |
| Route-registry integration | `apps/api/src/routes/registry.ts`: `access: { kind: 'room', requires?, resource? }`, AZ action, path `/rooms/:roomId/...`, `params` schema, `roomOf(ctx)` in handlers. Startup refuses inconsistent declarations, paths that name a room without room access, missing step-ups (AZ-04, AZ-05, PA-03, PA-04) and missing or superfluous resource loaders |
| Design record | [authorization-model.md](../security/authorization-model.md) section 9; testing plan section 3.4 |

Rules for Prompt 07B:
- Register every room route through the registry with a room action; read the role only from `roomOf(ctx)`; never check membership in a handler. Target-dependent actions (AZ-05, AZ-09, AZ-10) declare a `resource` loader that loads the target by identifier and room ID, for example with `findActiveMembership(room.roomId, targetUserId)`.
- Writes that change membership, roles or ownership re-check the stored actor and target state inside their transaction (conditional update or row lock): the gate decision describes the start of the request.
- Add every new production room route to the reviewed list in `tests/security/route-inventory.test.ts` (currently empty).
- `tests/helpers/db-fixtures.ts` has `insertRoomWithoutKeys`; `startAuthApi({ routes })` accepts test-only routes.

Not implemented in Prompt 07A: any production room route, room CRUD, membership administration, ownership transfer, the BOLA suite, and anything of Phase 6 (no room keys, envelopes, signed statements, rekey or Room Safety Code).

Open items: room listing has no matrix action yet (model section 9.5); PA-03 membership suspension on account disable is still to be implemented (authentication-security.md promises it for Phase 5); the PC-16 key-state lock belongs to CM-T047, but INV-07 applies to the first invitation or content-write route (Phase 6); ADR-011 identifier routing is confirmed with the first room page.

Finding R-05-01 (fixed, commit `bef4570`): undecodable percent-encoding in a path parameter reached the error handler as an unhandled 500; it is now the generic 404 (regression test, NC-05-10).

## 7. Invariants every session must preserve

All of CLAUDE.md section 6 (INV-01 to INV-19). For Phase 5 especially:
- **INV-05, INV-06:** authorization only through the central module with membership loaded from the database; room-scoped queries filtered by room ID and membership; non-members get 404.
- **INV-08:** policy controls in the API, never only in the UI.
- **INV-01, INV-04:** the server never receives the Vault Passphrase, private keys or room key material; Phase 5 creates no keys.
- **INV-09:** no unchained rows in `audit_events`.
- Never weaken tests, grants, cookies or authorization to make something pass.

## 8. Documents Prompt 07B must read

- CLAUDE.md; this file; [phase-05-traceability.md](phase-05-traceability.md); `docs/management/jira-backlog.md` (CM-T030, CM-T031).
- `docs/security/authorization-model.md` (sections 3 to 7 and 9), `docs/security/security-policy-profiles.md` (sections 4 and 6); `docs/architecture/data-model.md` 4.6 and 4.7 and section 5 (room deletion); `docs/architecture/data-flow.md` DF-05; ADR-011, ADR-013.
- `docs/threat-model/threat-model.md` T-04 to T-06, T-21, T-28 and section 11; `docs/security/limitations.md`.

## 9. Test counts

Last full local runs (2026-10-05, end of Phase 4): `pnpm test` 772 tests in 53 files; `pnpm test:e2e` 54 (52 run, 2 skipped by design); `pnpm security:negative-controls` 27 of 27.

Prompt 07A added 554 tests and ten negative controls. Its targeted runs (2026-10-06):

| Run | Result |
|---|---|
| unit: `packages/shared`, `apps/api/src` | 660 passed (decision 428, registry 49, denial mapping 15) |
| security, integration, authz projects | 166 passed (authz-matrix 44, route-inventory 8, malformed-requests 9, membership lookup 8, room access 14) |
| auth: step-up, admin, csrf, logging | 158 passed |
| `pnpm test:coverage:authz` | 97.3% statements, 98.3% branches |
| `negative-controls --only=NC-05` | 10 of 10 caught, baseline passes |

The complete `pnpm test` (projected 1,326 tests), Playwright, the full negative-control run (37), SBOM, audit and the full-history secret scan were not run in Prompt 07A, by instruction; they belong to Prompt 07C. The database suites need the local PostgreSQL container (Docker Desktop); during 07A it stopped once and was restarted. With many other containers running, a parallel E2E run once crashed browser processes for lack of memory (Phase 4); it passed when run alone.

## 10. Known limitations and residual risks

- Phase 4: no phone benchmark (L-37); client-side vault lock (L-38); offline guessing by a session holder (L-39); a passphrase change does not re-key (L-40); the directory reveals which addresses have a vault (L-41).
- T-36 stays open until Phase 6 implements the signed key-version verification (L-23).
- Audit hash chain absent; table owner can bypass append-only (L-26); authentication, vault and room authorization events only in the log (L-33).
- Targeted login delay (L-30); in-memory rate limits per process (L-32); no Nginx yet; no TOTP key rotation tooling (L-31); TOTP is phishable (L-34); registration reveals taken emails (L-35); emails unverified (L-21).
- Full list: `docs/security/limitations.md`.

## 11. Deferred decisions

| Decision | Status |
|---|---|
| Matrix action for listing one's own rooms | Prompt 07B, with a reviewed change to the authorization model |
| OCD-01 / ADR-007: RSA-OAEP-3072 versus HPKE | Before Phase 6: an envelope created in one engine must open in another |
| PC-16 scope for AZ-07, AZ-14 and AZ-26 | When they are implemented (Phases 6 and 9) |
| ADR-015 section 4: exact room-statement formats and columns | Phase 6 and Phase 11 |
| OCD-06 fingerprint pinning, OCD-10 vault recovery key, OCD-11 WebAuthn | Stretch |
| Production VM Argon2id benchmark; Nginx limits; secret files; TOTP key rotation | Phase 17 |

## 12. Outstanding work outside the repository

- Branch protection (CM-T012): the `main` ruleset still lists no required status checks; add the CI jobs (now including both coverage steps) as required checks, then capture EV-01-01 to EV-01-03.
- Dependabot pull requests #2 to #6 remain open (#2 PostgreSQL 18 needs an ADR; #6 `@types/node` 26 is ahead of Node 24).
- Jira: import the backlog; move CM-T006 to CM-T029 and CM-T086 through IN PROGRESS, SECURITY REVIEW and TESTING; create SF-04-01 and R-05-01 as `security-finding` items (both fixed in their phase branches). Nothing is DONE yet.
- Evidence still needing Jira or GitHub: EV-00-05, EV-00-06, EV-00-10, the Jira history items of Phases 2 to 5. EV-05-01 to EV-05-03 are captured in Prompt 07C.

## 13. Phase 5 must NOT implement

- Room key material, envelopes, signed room statements, rekey or the Room Safety Code (Phase 6 onward).
- File, note or secret encryption; object storage (Phases 7 to 9).
- The security policy engine (Phase 10), the audit hash chain (Phase 12), the Crypto Inspector or the Security Dashboard (Phases 13 and 14).
- Deployment, Nginx or cloud resources (Phase 17 onward).
- Any server-side handling of the Vault Passphrase or private keys.
