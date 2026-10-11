# Current State (engineering handoff)

Snapshot: 2026-10-11, end of Prompt 10 (Phase 8 implemented, verified and merged into `main`: CM-T042). Phases 1 to 8 are on `main`. The source of truth is the repository: CLAUDE.md, the ADRs, the normative docs and the code. This file is a starting point for a new session, not a project report. It contains no secrets; local values live only in the git-ignored `.env`.

## 1. Where the project stands

| Item | State |
|---|---|
| Completed on `main` | Phases 1 to 8 (pull requests #1, #7, #8, #10, #13, #22, #24, #26). **Phase 8 (CM-T042) was merged through pull request #26, merge commit `faeb633` (`faeb633a5a2839383a3c6c095c1c34e9c694affe`; parents `111a193` and `44aabf0`).** CI run 38162650065 passed every job on attempt 2 (attempt 1 had one unrelated WebKit vault-creation timeout in a Phase 7 file test, EV-08-07); GitGuardian, the dependency audit and the secret scan passed. Traceability: [phase-08-traceability.md](phase-08-traceability.md) |
| Phase 7 | Encrypted Files: client-side AES-256-GCM files of at most 50 MiB with a per-file FEK wrapped under RWK_v, ciphertext in the S3-compatible bucket through presigned URLs, quotas, expiry, deletion and worker cleanup (section 6b) |
| Phase 8 | Secure Notes (CM-T042): title and body as one AES-256-GCM message under a fresh NEK per revision, the revision bound in both contexts, optimistic concurrency with 409 on stale saves, AZ-19 to AZ-22, text-only rendering (section 6c). Traceability: [phase-08-traceability.md](phase-08-traceability.md) |
| Branch | `feature/CM-T042-encrypted-notes` (head `44aabf0`) is merged and takes no further commits |
| Next | **Prompt 11: Phase 9, Burn Secrets** (CM-T043 to CM-T045; CM-T045 is a stretch item). It starts from the updated `main` after this Phase 8 handoff is merged. Do not start without explicit approval. **Prompt 16.5 (complete UI/UX redesign and visual polish) is an accepted roadmap addition and is not to be started before its turn**; the Notes panel only follows the current style |
| Baseline branch | `main` on GitHub (`mhmmdimanquliyev7-dot/CipherMesh`) holds Phases 0 to 8. After this handoff is merged it is the baseline for Prompt 11 |

## 2. Architecture implemented so far

- pnpm 12 monorepo, Node 24, TypeScript 6 strict: `apps/api` (Express 5, esbuild bundle), `apps/web` (Next.js 16 static export, strict hashed CSP), `packages/shared`, `packages/validation` (zod 4), `packages/crypto` (Phase 4, see section 5).
- API pipeline: request ID, security headers, request log, same-origin gate (INV-19), JSON gate, body parser, route registry (deny by default, public allowlist, central session resolution, path-parameter, query and body schemas, **central room authorization** (Phase 5), step-up and platform-admin gates, response projections), error handler.
- CSP: `script-src 'self' 'wasm-unsafe-eval'` plus inline-script hashes, `form-action 'none'` (since SF-04-01), no `'unsafe-inline'` or `'unsafe-eval'`. Buttons stay disabled until the page has hydrated.
- Database access only through `apps/api/src/db` (ESLint enforced). Logs are JSON with central redaction.
- Engineering details: `docs/architecture/engineering-baseline.md`.

## 3. Database state

- PostgreSQL 17, Prisma 7.10.0 with the pg adapter. 16 tables, 232 classified fields (`/// class:`), nine migrations; the last is `20261008000000_encrypted_notes` (Phase 8: the CP-28 ciphertext bound and the note guard trigger, no column or grant changes).
- Roles `cm_migrator` (owner, never on the VM), `cm_api`, `cm_worker`, `cm_verifier`, with a tested grant matrix. `audit_events` is append-only; **the hash chain does not exist yet** (Phase 12).
- Phase 6 columns: `rooms.creator_key_id` and `genesis_signature` (NULL only for rooms from before Phase 6); `room_key_versions.created_by_key_id`, `previous_commitment`, `recipient_user_ids`, `recipient_key_ids`, `statement_signature`; `invitations.grantor_key_id` and `grant_signature`; `room_members.subject_key_id`, `grant_role`, `grantor_user_id`, `grantor_key_id`, `grant_signature`. Composite foreign keys bind each signing key to its user, CHECKs enforce all-or-nothing grants and sizes, and triggers make the genesis, the key-version statement and the invitation grant write-once.
- `rooms` and `room_members` exist since Phase 2; key versions, envelopes and invitations are written by the API since Phase 6.
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

## 6a. Cryptographic membership (Phase 6, CM-T033 to CM-T036, CM-T085)

| Part | Location |
|---|---|
| Statement builders and signature checks (browser and API, no private keys) | `packages/crypto/src/room-statements.ts`, `recipients.ts`; the API imports the subset `@ciphermesh/crypto/identity` |
| Room key creation, the verification rule, invitation envelopes, grants, Safety Code | `packages/crypto/src/room-keys.ts` (`createInitialRoomKey`, `openRoomKey`, `createInvitationKeys`, `signMembershipGrant`, `computeSafetyCode`) |
| Wire format and bundles from server data | `packages/crypto/src/room-format.ts` |
| Word list (LIB-08, BIP-39 English, generated and checksum-verified) | `packages/crypto/src/safety-code-words.ts`, `scripts/crypto/build-safety-code-words.mjs` |
| API: statements, rooms, invitations, key material | `apps/api/src/rooms/statements.ts`, `service.ts`, `invitations.ts`, `keys.ts`; stores `apps/api/src/db/room-key-store.ts`, `invitation-store.ts`; routes `apps/api/src/routes/rooms.ts`, `invitations.ts` |
| Schemas | `packages/validation/src/room-keys.ts`, `list.ts`; constants `INVITATION_RULES` in `packages/shared/src/rooms.ts`; AZ-31 in the matrix |
| Web | `apps/web/src/rooms/keys.ts` (memory-only room keys, cleared by `vaultController.onKeysDropped`), `key-panel.tsx`, `invitations.tsx`, `messages.ts`; pages `/rooms`, `/rooms/room?id=`, `/invitations` |

Behaviour to know:
- **RKM lifecycle.** RKM_1 is 32 random bytes made in the browser. Raw bytes exist only inside `room-keys.ts` while a key is created, opened or wrapped for an invitee, and are overwritten afterwards. The opened key is a non-extractable HKDF `CryptoKey`; RWK_v is a non-extractable AES-256-GCM key (`wrapKey`, `unwrapKey`). Nothing is stored in the browser, and locking the vault clears every opened room key. A full page load starts without an unlocked vault, so the tests and the UI reopen rooms by navigating inside the app.
- **Commitment and envelope.** RKC_v = HKDF(RKM_v, `cm.room.commitment {roomId, keyVersion}`); envelope = RSA-OAEP(recipient key, RKM_v, label `cm.room.envelope {roomId, keyVersion, recipientUserId, recipientKeyId, suite}`).
- **Statements** (`cm.room.genesis`, `cm.room.membership-grant`, `cm.room.key-version`), the verification rule and the owner-approved clarification for invited members: ADR-015 section 4.1, CD-28. The API verifies the statements it stores, and browsers verify everything again.
- **Invitations.** AZ-06 role ceilings; PC-03 (RESTRICTED step-up), PC-04 (OWNER approval of ADMIN invitations in CONFIDENTIAL and RESTRICTED), PC-05, PC-06 and PC-07 from `INVITATION_RULES`; PC-16 everywhere. PENDING envelopes are never served and become ACTIVE at acceptance. Acceptance locks the user row, the identity row, the room, the invitation and the memberships in that order and re-checks everything, so an account disable cannot miss it.
- **Identity reset.** A vault reset revokes the open invitations addressed to the old identity and deletes their PENDING envelopes. Deleting the old identity's ACTIVE envelopes and re-sharing (AZ-14, reinstatement) are CM-T053 (Phase 11, L-44); Phase 6 does not implement them.
- **Grants** replace each other only when the OWNER grants ADMIN or transfers ownership (`POST .../role`, `.../transfer-ownership` carry a signed grant). They are statements, not revocable credentials (L-46).
- **Routes** (new in Phase 6; reviewed lists in `tests/security/route-inventory.test.ts`, BOLA table `tests/helpers/bola-cases.ts`): `GET /rooms/{roomId}/key-versions` (AZ-15), `/envelopes` (AZ-12), `/members/{userId}/identity` (AZ-01), `/invitations` (AZ-31); `POST /rooms/{roomId}/invitations` (AZ-06), `/invitations/{id}/approve` (AZ-07), `/invitations/{id}/revoke` (AZ-08), `/key-reports` (AZ-29), `/safety-code` (AZ-30); `GET /invitations`, `POST /invitations/{id}/accept`, `/decline` (SS-03). `POST /rooms` requires `keys`.
- **Legacy rooms.** Rooms created before Phase 6 stay keyless and cannot be invited to (L-43); nothing initializes them on the server.
- **Worker.** `pnpm worker:retention` expires invitations and, for rooms being deleted, revokes invitations, deletes envelopes and marks key versions DESTROYED before a room becomes DELETED.
- **Dependency.** `next` 16.3.8 (GHSA-cjq9-62q9-8jv4); no other dependency changed.

## 6b. Encrypted files (Phase 7, CM-T037 to CM-T041)

| Part | Location |
|---|---|
| File format (FEK, manifest, wrap, `encryptFile`, `openFile`), wire layer | `packages/crypto/src/files.ts`, `file-format.ts`; DEK helpers `generateDataKey`, `wrapDataKey`, `unwrapDataKey` in `aead.ts`; constants `FILES` in `params.ts`; error codes `FILE_INTEGRITY_FAILED`, `FILE_FORMAT_UNSUPPORTED` |
| Shared constants | `packages/shared/src/files.ts` (`FILE_LIMITS`, `FILE_QUOTAS`, `FILE_RULES` per profile, `PREVIEWABLE_IMAGE_TYPES`); error codes in `errors.ts` |
| Schemas | `packages/validation/src/files.ts` (strict; no name, type, hash or key field) |
| Object storage | `apps/api/src/storage/object-store.ts` (`aws4fetch`, LIB-09), config `STORAGE_*` in `config/env.ts` (API and worker), `scripts/storage/` (`pnpm storage:bootstrap`), compose identity file and CORS in `infrastructure/docker/compose.dev.yml` |
| API | `apps/api/src/files/service.ts`, `routes/files.ts`, `db/file-store.ts` (part of the room store), worker `db/file-cleanup.ts` via `pnpm worker:retention` |
| Database | migration `20261007000000_encrypted_files` (`object_deleted_at`, indexes, object-key CHECK, guard trigger); 232 classified fields |
| Web | `apps/web/src/rooms/files.ts` (operations, name sanitizing), `file-panel.tsx` (the Files card in the room page); CSP `connect-src` gains the storage origin (`CM_STORAGE_ORIGIN`, default `https://localhost:4174`), `img-src` gains `blob:` |

Routes (reviewed lists in `tests/security/route-inventory.test.ts`, BOLA table `tests/helpers/bola-cases.ts`): `GET /rooms/{roomId}/files` (AZ-17), `POST /rooms/{roomId}/files` (AZ-16), `GET /rooms/{roomId}/files/{fileId}` (AZ-17), `POST .../complete` (AZ-16), `POST .../download-url` (AZ-17), `POST .../delete` (AZ-18).

Behaviour to know:
- **Protocol.** One file is one AES-256-GCM message of at most 50 MiB (CP-19) under a fresh FEK; the manifest (RFC 8785 `{name, sha256, size, type, v}`) is a second message under the same FEK; the FEK is wrapped under RWK_v with `cm.dek.wrap` (itemType `file`, revision 0). No chunks, no resumable upload (L-47). Decrypting needs the key version the file names, so the web client holds every opened version (`roomKeys.version`).
- **Lifecycle.** `PENDING_UPLOAD` (row, presigned PUT for the exact size) to `AVAILABLE` (uploader completes after HEAD confirms the size) to `DELETED` (tombstone: wrapped FEK and manifest NULL, object deleted at once or by the worker). A write-locked room cancels pending uploads. Abandoned uploads are reaped after 15 minutes; expired files are refused at read time.
- **Quotas** (decision D-07-01): 1024 MiB per room, 2048 MiB per account, 5 pending uploads per account.
- **Storage.** Local SeaweedFS with an administrator identity (`S3_*`, bucket creation only) and a runtime identity (`STORAGE_*`) that reads and writes objects of `cm-files` only. After pulling Phase 7, add the new variables of `.env.example` to your `.env`, run `pnpm services:up` (recreates only the storage container; the volume is kept), `pnpm storage:bootstrap` and `pnpm db:migrate`.
- **Finding SF-07-01** (fixed): WebKit sent the session cookie to a storage endpoint on the application's host with another port. Presigned URLs must be on another host (the API refuses to start otherwise); the E2E storage endpoint is `localhost` while the app is `127.0.0.1`, and the proxy refuses any request with a cookie.
- **Not done:** per-address rate limits for the file routes (Nginx, Phase 17), bucket lifecycle rules and versioning (Phase 19), audit rows for file events (Phase 12; events go to the log), a memory measurement of the 50 MiB limit and phone tests (L-47).
- Test helper `tests/helpers/files.ts` (real storage, files encrypted by `packages/crypto`); `startAuthApi` accepts a storage double for failure tests; the `files` Vitest project runs one file at a time. `scripts/db/lib.mjs` now serializes role creation with an advisory lock (the parallel projects raced on `ALTER ROLE`).

## 6c. Encrypted notes (Phase 8, CM-T042)

| Part | Location |
|---|---|
| Note format (NEK per revision, document, wrap, `encryptNote`, `openNote`), wire layer | `packages/crypto/src/notes.ts`, `note-format.ts`; constants `NOTES` in `params.ts`; error codes `NOTE_INTEGRITY_FAILED`, `NOTE_FORMAT_UNSUPPORTED` |
| Shared constants | `packages/shared/src/notes.ts` (`NOTE_LIMITS`, `NOTE_RULES` per profile, `NOTE_LIST_PAGE_SIZE`); error codes `REVISION_CONFLICT`, `NOTE_ID_UNAVAILABLE`, `NOTE_LIMIT_REACHED` |
| Schemas | `packages/validation/src/notes.ts` (strict; no title, body, key, revision, author or editor field) |
| API | `apps/api/src/notes/service.ts`, `routes/notes.ts`, `db/note-store.ts` (part of the room store), worker `db/note-cleanup.ts` via `pnpm worker:retention` (before the room cleanup, which now waits only for live notes) |
| Database | migration `20261008000000_encrypted_notes` (ciphertext 17 to 65,552 bytes, trigger `cm_guard_encrypted_note_change`) |
| Web | `apps/web/src/rooms/notes.ts` (operations, in-memory revision memory for T-32), `note-panel.tsx` (the Notes card in the room page); messages in `messages.ts` |

Routes (reviewed lists in `tests/security/route-inventory.test.ts`, BOLA table `tests/helpers/bola-cases.ts` with `targetsNote`): `GET /rooms/{roomId}/notes` (AZ-20), `POST /rooms/{roomId}/notes` (AZ-19), `GET /rooms/{roomId}/notes/{noteId}` (AZ-20), `POST .../update` (AZ-21), `POST .../delete` (AZ-22).

Behaviour to know:
- **Protocol (CD-31, CP-28).** A revision is one AES-256-GCM message: the RFC 8785 document `{body, title, v: 1}` (at most 64 KiB; title 1 to 200 code units, no control characters) under a fresh NEK, AAD `cm.note.content` {roomId, noteId, revision}; the NEK is wrapped under RWK_v with `cm.dek.wrap` (itemType `note`, itemId the note ID, the same revision). Only canonical documents are accepted. Each save consumes one wrap of the key version (CP-16).
- **Revisions.** Creation stores revision 1. An update names `expectedRevision`; the API locks user, room, membership and note, re-checks AZ-21, requires key state ACTIVE and the current key version, and writes revision expected + 1 only while the stored revision is still expected (409 `REVISION_CONFLICT`). Only the current revision is kept. The browser remembers the highest revision it saw in this tab and flags a lower one (T-32).
- **Lifecycle.** Expiry fixed at creation (PC-08; CONFIDENTIAL and RESTRICTED require one). Deleted and expired notes are refused at read time; deletion is a tombstone (ciphertext and wrapped NEK NULL) and is allowed while the room is REKEY_REQUIRED. At most 1000 live notes per room (D-08-01). Reads are security events at EXTENDED and FULL (PC-13).
- **UI.** A plain-text editor; note text is rendered as text only. A save conflict keeps the editor's text and offers to load the latest revision. Locking the vault discards every decrypted title and body at once.
- **Decisions** D-08-01 to D-08-08 are in the traceability file; no new dependency.

## 7. Invariants every session must preserve

All of CLAUDE.md section 6 (INV-01 to INV-19). For Phases 5 and 6 especially:
- **INV-05, INV-06:** authorization only through the central module with membership loaded from the database; room-scoped queries filtered by room ID and membership; non-members get 404.
- **INV-08:** policy controls in the API, never only in the UI.
- **INV-01, INV-04:** the server never receives the Vault Passphrase, private keys or room key material. Since Phase 6 it stores only commitments, signatures and RSA-OAEP envelopes made in browsers.
- **INV-07, INV-17, INV-18:** invitations and acceptances are refused while a room is REKEY_REQUIRED or REKEYING; RSA-OAEP wraps only the 32-byte room key; the Room Safety Code is computed only in browsers and never sent, stored or logged.
- **INV-09:** no unchained rows in `audit_events`.
- Never weaken tests, grants, cookies or authorization to make something pass.

## 8. Documents Prompt 11 must read

- CLAUDE.md; this file; `docs/management/project-roadmap.md` (Phase 9, CM-T043 to CM-T045); `docs/management/jira-backlog.md` (CM-EPIC-08: CM-T043, CM-T044, CM-T045 stretch); [phase-08-traceability.md](phase-08-traceability.md) (the note protocol and its tests are the pattern for content routes; secrets differ: the SEK is RSA-OAEP-wrapped to the recipient's key, not under RWK_v).
- `docs/crypto/` (cryptographic-architecture 6.3 and section 11, key-hierarchy, key-lifecycle section 2, crypto-decisions CD-06, CD-17, CP-02, CP-09), `docs/architecture/data-model.md` (4.13), `data-flow.md` (DF-09).
- `docs/security/authorization-model.md` (sections 3 and 5: AZ-23 to AZ-26), `security-policy-profiles.md` (PC-09, PC-10, PC-11, PC-16), INV-13, INV-14 and INV-17 in CLAUDE.md, `limitations.md`, `docs/threat-model/threat-model.md` (secret-related threats and section 12).

## 9. Test counts

Gates of Prompt 10 on the final Phase 8 code (2026-10-11, local PostgreSQL and storage), recorded in EV-08-05 and phase-08-traceability.md section 5:

| Gate | Result |
|---|---|
| `pnpm install --frozen-lockfile`, `pnpm format:check`, `pnpm lint`, `pnpm typecheck` | Pass |
| `pnpm test` | 1956 tests in 78 files (Phase 7: 1876 in 75). New suites: `packages/crypto/src/notes.test.ts` (20 tests), `tests/notes` (25: lifecycle 15, access 10); extended: `bola.test.ts` 160 tests over 27 room routes (was 132 over 22), database constraints (note bound and guard trigger), route inventory, BOLA inventory, profile and register drift, export surface |
| `pnpm test:e2e` (three engines, one worker) | 102 passed, 12 skipped by design (single-engine tests); was 83 and 10. `notes.spec.ts`: 7 tests, 19 results, 2 skipped (the cross-engine test runs once from Chromium and drives Firefox and WebKit) |
| `pnpm security:negative-controls` | 79 of 79 caught (ten Phase 3, seventeen Phase 4, twenty-two Phase 5, ten Phase 6, ten Phase 7, ten Phase 8), both baselines pass, 44 source files restored byte for byte |
| `pnpm test:coverage:crypto` | 98.77% statements, 93.85% branches (gate 90%) |
| `pnpm test:coverage:authz` | 97.26% statements, 98.3% branches |
| `pnpm build`, `pnpm smoke:api`, `pnpm sbom:generate`, `db:validate`, `db:check-schema`, `db:drift` | Pass; migrations from zero are exercised by `tests/database/migrations.test.ts` (part of `pnpm test`) |
| `pnpm audit:deps` | Pass (no known vulnerabilities); no dependency added or changed |
| Secret scan (gitleaks) | Staged changes and all commits: see EV-08-05 |

Local notes: the files suites need the local storage (`pnpm services:up && pnpm storage:bootstrap`); the database suites need the local PostgreSQL container (Docker Desktop stops during long pauses; restart it and wait for healthy). Run E2E and the negative controls one at a time, E2E with `--workers=1`. The notes suites need only PostgreSQL (`pnpm test:notes`). The `cm_api` connection limit of 40 is shared by all projects; the `authz` project runs its files serially. The test helper `newAddress()` wraps inside 1..0xfffe (a start near 0xffff once overflowed the IPv6 group and tripped the per-address registration limit). Known timing-sensitive tests are listed in the memory notes: `vault.test.ts` KDF-busy test, the TOTP drift test and the cross-engine vault E2E; on a red CI run rerun the job once, find the mechanism and never loosen assertions.

## 10. Known limitations and residual risks

- Phase 4: no phone benchmark (L-37); client-side vault lock (L-38); offline guessing by a session holder (L-39); a passphrase change does not re-key (L-40); the directory reveals which addresses have a vault (L-41).
- Phase 6: grants are statements, not revocable credentials (L-46); T-36 is mitigated (L-23 updated) but identity substitution (T-25, L-07), an authorized owner colluding with the server (L-22) and served code (L-02) remain.
- Audit hash chain absent; table owner can bypass append-only (L-26); authentication, vault, room and invitation events only in the log (L-33).
- Targeted login delay (L-30); in-memory rate limits per process (L-32); no Nginx yet; no TOTP key rotation tooling (L-31); TOTP is phishable (L-34); registration reveals taken emails (L-35); emails unverified (L-21).
- Phase 7: files are at most 50 MiB, single-shot, no resumable upload, memory and phones not measured (L-47); removal does not take back downloaded files (L-48); backups keep deleted ciphertext (L-49); names and types come from the uploader (L-50).
- Phase 8: note metadata (authors, editors, revision counts, sizes, times) is visible to the server (L-51); only the current revision, no history or merge (L-52); authorship is the server's statement (L-53, L-09); removal does not take back notes already read (L-54); an older revision served under its own number is noticed only if this tab saw a newer one (L-10, T-32).
- Profile gates not yet checked on every room request (L-42); rooms from before Phase 6 stay keyless (L-43); a room that loses a member stays REKEY_REQUIRED until the rekey exists, and neither a re-enabled account nor a reset identity gets rooms back until CM-T053 (L-44); a reused room ID is refused with 409, and there is no room quota (L-45).
- Full list: `docs/security/limitations.md`.

## 11. Deferred decisions

| Decision | Status |
|---|---|
| Rekey, leaving a room, re-sharing and reinstatement (AZ-14), how a former ADMIN's signature is rejected (L-46) | Phase 11 (CM-T050 to CM-T053) |
| PC-16 scope for AZ-26 | When it is implemented (Phase 9) |
| Initialization of rooms created before Phase 6 | Not needed while nothing is deployed; needs an architecture decision before it is built (L-43) |
| OCD-06 fingerprint pinning, OCD-10 vault recovery key, OCD-11 WebAuthn | Stretch |
| Production VM Argon2id benchmark; Nginx limits; secret files; TOTP key rotation | Phase 17 |

## 12. Outstanding work outside the repository

- Branch protection (CM-T012): the `main` ruleset still lists no required status checks; add the CI jobs (now including both coverage steps) as required checks, then capture EV-01-01 to EV-01-03.
- Dependabot pull requests remain open (#2 PostgreSQL 18 needs an ADR; #6 `@types/node` 26 is ahead of Node 24; the `next` update is covered by Phase 6, which pins 16.3.8).
- Jira: import the backlog; move CM-T006 to CM-T042, CM-T085 and CM-T086 through IN PROGRESS, SECURITY REVIEW and TESTING; create SF-04-01, R-05-01 and SF-07-01 as `security-finding` items. Nothing is DONE yet.
- Evidence still needing Jira or GitHub: the Jira history of CM-T042 (EV-08-01 to EV-08-07 are in `docs/report/evidence/phase-08/`; EV-08-07 is the CI run of pull request #26); EV-00-05, EV-00-06, EV-00-10, the Jira history items of Phases 2 to 7. EV-07-01 to EV-07-11 are in `docs/report/evidence/phase-07/` (EV-07-11 is the CI run of pull request #24). EV-06-01 to EV-06-10 are in `docs/report/evidence/phase-06/` (EV-06-10 is the CI run of pull request #22).

## 13. Not implemented yet

- Recipient-bound secrets and burn-after-reading (Phase 9). Files (Phase 7, section 6b) and notes (Phase 8, section 6c) are encrypted. Note version history, collaborative editing and Markdown are not planned for any phase.
- Rekey, key-version retirement, leaving a room, re-sharing keys, the compromised-identity procedure (Phase 11).
- The security policy engine (Phase 10), the audit hash chain (Phase 12), the Crypto Inspector or the Security Dashboard (Phases 13 and 14).
- Deployment, Nginx or cloud resources (Phase 17 onward).
- Any server-side handling of the Vault Passphrase, private keys or room key material, ever.

