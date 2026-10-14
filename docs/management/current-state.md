# Current State (engineering handoff)

Snapshot: 2026-10-14, end of the combined Phase 14 + Prompt 16.5 (security dashboard, complete UI/UX redesign and the Security & Trust Center, CM-T061 and CM-T062) on branch `feature/CM-T061-trust-center-redesign`. Phases 1 to 11 are on `main`; the project owner deferred Phases 12, 13, 15 and 16 on 2026-10-13. The source of truth is the repository: CLAUDE.md, the ADRs, the normative docs and the code. This file is a starting point for a new session, not a project report. It contains no secrets; local values live only in the git-ignored `.env`.

## 1. Where the project stands

| Item | State |
|---|---|
| Completed on `main` | Phases 1 to 11 (pull requests #1, #7, #8, #10, #13, #22, #24, #26, #28, #30, #32). **Phase 11 (CM-T050 to CM-T053) was merged through pull request #32, merge commit `31c31ba` (`31c31ba50ab599f0a9e27c8ac2487337e00601b5`; parents `8a5905d` and `7874614`), merged by the project owner after the automated session was refused permission to merge.** CI run 38392960689 (pull request #32): the dependency audit, GitGuardian, the secret scan and the lint, types, tests, build and E2E job all passed on the first attempt (EV-11-10). Traceability: [phase-11-traceability.md](phase-11-traceability.md). **Phase 10 (CM-T046 to CM-T049) was merged through pull request #30, merge commit `3688722` (`3688722f98b49db857ea5580384aabeb50b251c4`; parents `b6a4da4` and `02c48e5`).** CI run 38236439654 (pull request #30): the dependency audit, GitGuardian and the secret scan passed and every Vitest project passed, but the E2E step failed on three attempts, each time on a different Phase 5 to 9 test (attempt 1: Firefox secrets two-tab, WebKit room-keys, WebKit rooms; 2: WebKit secrets lock-vault; 3: WebKit notes tamper), none in `policies.spec.ts`. `main`'s own run after the Phase 9 merge (38217990916) and the Phase 9 handoff run (38217907402) failed the same way, and the Phase 9 baseline also failed two E2E tests locally; each of these tests passes alone. The project owner merged pull request #30 manually after being told this (EV-10-07). The E2E flakiness is an open item (section 12). Traceability: [phase-10-traceability.md](phase-10-traceability.md). Phase 9 (CM-T043, CM-T044) was merged through pull request #28, merge commit `208cdd9` (`208cdd946b9acac185a1b5d8adc4b6e228d9670d`; parents `e52f554` and `09584e5`).** CI run 38214636993 passed every job on the first attempt; GitGuardian, the dependency audit and the secret scan passed. Traceability: [phase-09-traceability.md](phase-09-traceability.md). Phase 8 (CM-T042) was merged through pull request #26, merge commit `faeb633` (`faeb633a5a2839383a3c6c095c1c34e9c694affe`; parents `111a193` and `44aabf0`).** CI run 38162650065 passed every job on attempt 2 (attempt 1 had one unrelated WebKit vault-creation timeout in a Phase 7 file test, EV-08-07); GitGuardian, the dependency audit and the secret scan passed. Traceability: [phase-08-traceability.md](phase-08-traceability.md) |
| Phase 7 | Encrypted Files: client-side AES-256-GCM files of at most 50 MiB with a per-file FEK wrapped under RWK_v, ciphertext in the S3-compatible bucket through presigned URLs, quotas, expiry, deletion and worker cleanup (section 6b) |
| Phase 8 | Secure Notes (CM-T042): title and body as one AES-256-GCM message under a fresh NEK per revision, the revision bound in both contexts, optimistic concurrency with 409 on stale saves, AZ-19 to AZ-22, text-only rendering (section 6c). Traceability: [phase-08-traceability.md](phase-08-traceability.md) |
| Phase 9 | Burn Secrets (CM-T043, CM-T044): one AES-256-GCM message under a fresh SEK, only the 32-byte SEK RSA-OAEP-wrapped to a recipient key the sender's browser authenticated against the room's signed statements; POST-only reveal in a locking transaction that returns and, with burn-after-reading, destroys the ciphertext in one statement; AZ-23 to AZ-25 and the new AZ-32 (section 6d). CM-T045 (external links, stretch) not built. Traceability: [phase-09-traceability.md](phase-09-traceability.md) |
| Phase 10 | Security Policies (CM-T046 to CM-T049): the versioned, frozen policy catalogue `packages/shared/src/policy.ts` (version 1), PC-01 and PC-02 on every room request and again on the locked room row, PC-03 for every sensitive operation that exists, PC-13 FULL events, profile changes with expiry clamping and revocation (AZ-03), the `policy` test matrix (section 6e). Traceability: [phase-10-traceability.md](phase-10-traceability.md) |
| Phase 11 | Key Rotation (CM-T050 to CM-T053): the rekey state machine and operation API (ADR-013), rekeyed versions made and reviewed in the browser, leaving a room, retirement, destruction, the wrap bound and the PC-14 cryptoperiod through the worker, the vault-reset procedure with the `identityCompromised` flag, re-sharing and reinstatement (AZ-14) and the append-only grant history (section 6f). Engine finding SF-11-01 fixed in `unwrap32` (CD-33). Account deletion does not exist, so R4 has no trigger (L-67). Traceability: [phase-11-traceability.md](phase-11-traceability.md); runbook: [../security/runbook-compromised-identity-key.md](../security/runbook-compromised-identity-key.md) |
| Phase 14 + Prompt 16.5 | Approved by the project owner on 2026-10-13 as a combined phase. `GET /admin/security-dashboard` (PA-01, aggregates only; SD-10, SD-11, SD-12, SD-15 NOT_IMPLEMENTED), a design system and application shell, the Overview, encryption receipts, the Security & Trust Center `/trust` generated from the normative documents, the guided walkthrough and the demonstration guide (section 6g). Traceability: [phase-14-traceability.md](phase-14-traceability.md) |
| Branch | `feature/CM-T061-trust-center-redesign`, from `main` at `42474ac` (Phase 11 handoff, pull request #33). `feature/CM-T050-key-rotation` is merged and takes no further commits |
| Next | **Cloud Deployment + Cloud Security Hardening** (Phases 17 to 19), after the Phase 14 + Prompt 16.5 pull request and its handoff are merged, and only with explicit approval: no cloud resource may be created or paid for without it. Then ISMS evidence, the final report and the live demonstration. Phases 12, 13, 15 and 16 are deferred (owner decision 2026-10-13) and need a new approval |
| Baseline branch | `main` on GitHub (`mhmmdimanquliyev7-dot/CipherMesh`) holds Phases 0 to 11 and, after the merge, Phase 14 + Prompt 16.5 |

## 2. Architecture implemented so far

- pnpm 12 monorepo, Node 24, TypeScript 6 strict: `apps/api` (Express 5, esbuild bundle), `apps/web` (Next.js 16 static export, strict hashed CSP), `packages/shared`, `packages/validation` (zod 4), `packages/crypto` (Phase 4, see section 5).
- API pipeline: request ID, security headers, request log, same-origin gate (INV-19), JSON gate, body parser, route registry (deny by default, public allowlist, central session resolution, path-parameter, query and body schemas, **central room authorization** (Phase 5), step-up and platform-admin gates, response projections), error handler.
- CSP: `script-src 'self' 'wasm-unsafe-eval'` plus inline-script hashes, `form-action 'none'` (since SF-04-01), no `'unsafe-inline'` or `'unsafe-eval'`. Buttons stay disabled until the page has hydrated.
- Database access only through `apps/api/src/db` (ESLint enforced). Logs are JSON with central redaction.
- Engineering details: `docs/architecture/engineering-baseline.md`.

## 3. Database state

- PostgreSQL 17, Prisma 7.10.0 with the pg adapter. 16 tables, 232 classified fields (`/// class:`), eleven migrations; the last is `20261010000000_security_policies` (Phase 10: the secret guard and the invitation grant trigger let an open row's `expires_at` move only earlier, for upgrade clamping; no column or grant changes). Before it, `20261009000000_burn_secrets` (Phase 9: the CP-29 payload bound, the 7-day lifetime bound, REVEALED only with burn, and the secret guard trigger; no column or grant changes).
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
- **Identity reset.** A vault reset revokes the open invitations addressed to the old identity and deletes their PENDING envelopes. Since Phase 11 the reset also deletes every envelope wrapped to the old identity, advances each room's epoch and, with the compromise flag, locks every room of the user; re-sharing and reinstatement (AZ-14) are in section 6f (L-44 resolved).
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

## 6d. Recipient-bound secrets (Phase 9, CM-T043, CM-T044)

| Part | Location |
|---|---|
| Secret format (SEK, document, wrap, `authenticateSecretRecipient`, `encryptSecret`, `openSecret`), wire layer | `packages/crypto/src/secrets.ts`, `secret-format.ts`; `authenticateRoomMember` in `room-keys.ts`; `importDataKey` in `aead.ts`; constants `SECRETS` in `params.ts`; error codes `SECRET_INTEGRITY_FAILED`, `SECRET_FORMAT_UNSUPPORTED` |
| Shared constants | `packages/shared/src/secrets.ts` (`SECRET_LIMITS`, `SECRET_RULES` per profile, `SECRET_LIST_PAGE_SIZE`, `SECRET_STATUSES`); AZ-32 in the matrix; error codes `SECRET_ID_UNAVAILABLE`, `SECRET_RECIPIENT_INVALID`, `BURN_REQUIRED`, `SECRET_LIMIT_REACHED`, `SECRET_UNAVAILABLE` |
| Schemas | `packages/validation/src/secrets.ts` (strict; no text, SEK, sender, status or role field); `memberIdentityResponseSchema` gained `authority` (the member's grant chain) |
| API | `apps/api/src/secrets/service.ts`, `routes/secrets.ts`, `db/secret-store.ts` (part of the room store; `runSecretCleanup` for the worker); revocations in `room-store.ts` (`removeMember`, `suspendMemberships`) and the vault reset (`vault/service.ts`) |
| Database | migration `20261009000000_burn_secrets` (payload 17 to 16,400 bytes, lifetime at most 7 days, REVEALED only with burn, trigger `cm_guard_secret_change`) |
| Web | `apps/web/src/rooms/secrets.ts` (operations), `secret-panel.tsx` (the Secrets card in the room page), `keys.ts` (`roomKeys.secretRecipient`); messages in `messages.ts` |

Routes (reviewed lists in `tests/security/route-inventory.test.ts`, BOLA table `tests/helpers/bola-cases.ts` with `targetsSecret`): `GET /rooms/{roomId}/secrets` (AZ-32), `POST /rooms/{roomId}/secrets` (AZ-23), `POST .../{secretId}/reveal` (AZ-24), `POST .../{secretId}/revoke` (AZ-25). `GET /rooms/{roomId}/members/{userId}/identity` now also returns the member's grant chain.

Behaviour to know:
- **Protocol (CD-32, CP-29).** SEK = 32 CSPRNG bytes; payload = AES-256-GCM over RFC 8785 `{text, v: 1}` (at most 16 KiB), AAD `cm.secret.payload` {roomId, secretId}; wrapped SEK = RSA-OAEP-3072 with label `cm.secret.sek-wrap` {roomId, secretId, recipientUserId, recipientKeyId, suite}. The SEK bytes exist only inside the crypto package and are overwritten after import.
- **Recipient authentication.** The sender's browser fetches the member's identity with the member's grant chain plus the room's key material, and `authenticateSecretRecipient` accepts the key only if the verified statements name that user and key (recipient list or accepted grant). A member who reset their vault has no grant for the new key until CM-T053, so nobody can send them secrets (L-44).
- **Reveal (INV-13).** POST with `{}`. Locks user, room, membership and the secret row (recipient = caller), re-checks AZ-24, refuses non-ACTIVE, expired-now and retired-key secrets (409 `SECRET_UNAVAILABLE`), then one `UPDATE ... RETURNING` returns the old values while writing REVEALED and NULLs. Non-recipients get 404 before anything is touched. Response after commit; a lost response loses the secret (L-57). The browser refuses to send a reveal while the vault is locked.
- **Non-burn secrets** (outside RESTRICTED) stay ACTIVE and can be revealed again until expiry or revocation (D-09-02).
- **Lifecycle.** Expiry 5 minutes to the PC-09 maximum, required. Revocation (AZ-25) of any ACTIVE secret. Removal, suspension or vault reset of the recipient revokes their pending secrets (D-09-06). The worker marks expired secrets EXPIRED and revokes those of DELETING rooms; a room becomes DELETED only when no ACTIVE secret is left. Rows are never deleted.
- **Limits.** 100 ACTIVE secrets sent per account (D-09-04); list pages of 50; no per-route rate limit (Nginx, Phase 17).
- **Events.** `SECRET_CREATED`, `SECRET_REVEALED`, `SECRET_REVEAL_REFUSED`, `SECRET_REVOKED` to the redacted log (identifiers, flags, reason codes).
- **Decisions** D-09-01 to D-09-15 are in the traceability file; no new dependency.
- Test helper `tests/helpers/secrets.ts`; suites `tests/secrets` (lifecycle, concurrency with row-lock barriers and two API instances); `pnpm test:secrets`.

## 6e. Security policies (Phase 10, CM-T046 to CM-T049)

| Part | Location |
|---|---|
| Catalogue (version 1, deep-frozen; `resolveRoomPolicy`, `currentPolicy`, the pure gate decisions, `clampedExpiry`) | `packages/shared/src/policy.ts`; the per-feature constants of Phases 5 to 9 were removed |
| Gates | `apps/api/src/authorization/rooms.ts` (membership 404, then PC-01 and PC-02, matrix, PC-03 when the route declares `requires: { sensitive }`), `apps/api/src/authorization/policy.ts` (`enforceRoomAccess`, `reapplyRoomPolicy` for the locked row, `policyOf`, the responses and `ROOM_ACCESS_DENIED` reasons) |
| Profile change | `POST /rooms/{roomId}/profile` (AZ-03) in `routes/rooms.ts`, `RoomService.changeProfile`, `db/policy-store.ts` (`setRoomProfile`, `applyUpgrade`); schemas `profileChangeRequestSchema`, `profileChangedResponseSchema` |
| Web | `apps/web/src/rooms/profile-panel.tsx` (rules from the catalogue, OWNER change form, downgrade warning); panels take the resolved `policy`; file and secret panels ask the page for a step-up (`onStepUp`) |
| Tests | `tests/policy` (Vitest project `policy`: matrix and profile changes), `tests/security/policy-catalogue.test.ts`, `packages/shared/src/policy.test.ts`, `tests/e2e/policies.spec.ts`, helpers `tests/helpers/policy.ts` (`inRoomLockOrder` forces lock order) |

Behaviour to know:
- **Resolution.** A room's rules come only from its stored `security_profile` and `policy_version`. An unknown version answers 503 `POLICY_UNSUPPORTED` (reason recorded), never a fallback. New rooms and profile changes record version 1.
- **Order.** Membership (404) → PC-01 (403 `MFA_REQUIRED`), PC-02 (401 `REAUTH_REQUIRED`) → matrix (403) → PC-03 (401 `STEP_UP_REQUIRED`) → static step-up of AZ-04 and AZ-05 → handler, which re-applies matrix and gates on the locked room row. A RESTRICTED VIEWER asking for a download URL gets the step-up prompt first, then PC-12.
- **PC-03 routes:** reveal, download URL, invite, approve, remove member, profile change, delete room (pinned in `route-inventory.test.ts`). START_REKEY comes with Phase 11: its route must declare `sensitive: 'START_REKEY'`.
- **Profile change.** OWNER only; `expectedProfile` must equal the stored profile (409 `PROFILE_CHANGED`). Upgrade: the new profile's PC-01 and PC-02, and for RESTRICTED its PC-03; shortens expiry of live files and notes, ACTIVE secrets and open invitations; revokes invitations that skipped approval, lack a required fingerprint or share older versions, and non-burn secrets when burn becomes mandatory; `PROFILE_UPGRADED` with counts. Downgrade: step-up within 5 minutes; nothing extended; `PROFILE_DOWNGRADED` with severity HIGH. Allowed while REKEY_REQUIRED; never changes the key state.
- **Events.** FULL adds `ENVELOPES_FETCHED` and `MEMBER_LIST_VIEWED` (room and count). All to the redacted log until Phase 12.
- **Tests that move session ages** update `sessions.authenticated_at` or `step_up_at` as cm_api; a test that needs a CONFIDENTIAL or RESTRICTED actor must use `mfaPersonWithVault` (and step up in RESTRICTED for the PC-03 operations).
- **Decisions** D-10-01 to D-10-09 are in the traceability file; no new dependency.
- **Not enforced, by plan:** PC-11 (CM-T045). PC-14 has been enforced by the worker since Phase 11 (REKEY_REQUIRED with CRYPTOPERIOD_EXPIRED from `policy.cryptoperiodMs`, section 6f).

## 6f. Key rotation (Phase 11, CM-T050 to CM-T053)

| Part | Location |
|---|---|
| Browser: make, review and open rekeyed versions | `packages/crypto/src/room-keys.ts` (`createRekeyKeys`, `reviewRekeyRecipients`, `openRoomKeys` with the grant history), `room-format.ts` (`rekeyKeysToWire`, `grantsFromWire`) |
| RSA-OAEP fix SF-11-01 | `packages/crypto/src/rsa-oaep.ts` (`unwrap32` left-pads a short result; CD-33) |
| API | `apps/api/src/rooms/rekey.ts` (state machine, leaving, re-sharing), `routes/rekey.ts`, `db/rekey-store.ts`, `db/rekey-cleanup.ts` (worker maintenance, called from `worker/retention.ts`), `vault/service.ts` (`resetVault` with the compromise flag) |
| Schemas and constants | `packages/validation/src/rekey.ts`; `REKEY_RULES`, `REKEY_REASONS` in `packages/shared/src/rooms.ts`; error codes `REKEY_*`, `ROOM_KEY_UNAVAILABLE`, `RESHARE_NOT_NEEDED` |
| Database | migration `20261011000000_key_rotation`: `room_member_grants` (append-only), guards on `rekey_operations`, `room_key_versions` and `rooms`, a deferred consistency check (database-security section 14) |
| Web | `apps/web/src/rooms/rekey-panel.tsx` (state, review, rotate, leave, re-share), `keys.ts`, a compromise checkbox on the vault page |
| Tests | `tests/rekey` (Vitest project `rekey`), `tests/database/rekey-guards.test.ts`, `packages/crypto/src/rekey.test.ts`, `tests/e2e/rekey.spec.ts`, helpers `tests/helpers/rekey.ts` |

Behaviour to know:
- **Who.** OWNER and ADMIN start; only the starter finalizes; the starter or the OWNER cancels. RESTRICTED starts need a step-up. One live operation per room (10-minute lease); 10 starts per room per hour.
- **Lock.** Removal, leaving, suspension, the compromise flag, an expired cryptoperiod and the wrap bound set REKEY_REQUIRED. A mandatory rekey cannot be cancelled into an unlocked room. Any membership change makes a pending operation STALE (API and database).
- **Re-share.** After a vault reset the new identity holds no key until a rekey includes it or an OWNER or ADMIN re-shares (AZ-14, same role ceilings as invitations; nobody re-shares to the OWNER). A locked room refuses a re-share, so the rekey comes first.
- **Trust.** The server checks the set, the signature and the order of versions; members verify the version in the browser. The starter chooses the key (L-63).
- **Line endings.** Scripted edits must keep LF (open files with `newline=''`).

## 6g. Security dashboard, redesign and Trust Center (Phase 14 + Prompt 16.5)

- **Dashboard.** `GET /admin/security-dashboard` (`apps/api/src/routes/admin.ts`, `apps/api/src/db/dashboard-store.ts`, catalogue `packages/shared/src/dashboard.ts`): PLATFORM_ADMIN only (404 otherwise), aggregates only, computed on request. SD-10, SD-11, SD-12 and SD-15 are NOT_IMPLEMENTED until the ledger exists; a value the store did not compute fails the request. The response carries the provider-neutral platform status (`api` and `database` HEALTHY, `object-storage` and `worker` NOT_VERIFIED, `cloud` NOT_CONNECTED), which the cloud workstream connects. Tests: Vitest project `dashboard` (own database).
- **Client.** Design tokens in `globals.css` (`slate` retuned, `accent` teal), `components/` (ui, styles, buttons with the SF-04-01 guard, icons, app-shell, auth-layout), `/overview`, room section navigation, encryption receipts (`rooms/receipts.tsx`), a header Sign out. Sign-in lands on `/overview`.
- **Trust Center.** `/trust`, `/trust/cryptography`, `/trust/infrastructure`, `/trust/governance`, `/trust/evidence`, `/trust/walkthrough`, `/trust/dashboard`. Data in `apps/web/src/trust/generated/` comes from `pnpm trust:generate`; the web build runs `trust:check` and fails on drift, so regenerate after editing the threat model, limitations, ISMS mapping, evidence plan or index, the parameter register, the cloud documents, or after committing evidence files. Curated text in `apps/web/src/trust/*.ts` is checked by `trust-content.test.ts`.
- **Evidence.** EV-14-01 to EV-14-18 in `docs/report/evidence/phase-14/`, captured on demand by `CM_CAPTURE_EVIDENCE=1 pnpm exec playwright test evidence-capture --project chromium` (rebuild and regenerate the Trust Center data afterwards).
- **Demonstration.** [../report/live-demo-guide.md](../report/live-demo-guide.md): Cryptography, then Cloud, then ISMS.

## 7. Invariants every session must preserve

All of CLAUDE.md section 6 (INV-01 to INV-19). For Phases 5 and 6 especially:
- **INV-05, INV-06:** authorization only through the central module with membership loaded from the database; room-scoped queries filtered by room ID and membership; non-members get 404.
- **INV-08:** policy controls in the API, never only in the UI.
- **INV-01, INV-04:** the server never receives the Vault Passphrase, private keys or room key material. Since Phase 6 it stores only commitments, signatures and RSA-OAEP envelopes made in browsers.
- **INV-07, INV-17, INV-18:** invitations, acceptances and new content (files, notes, secrets) are refused while a room is REKEY_REQUIRED or REKEYING; RSA-OAEP wraps only 32-byte values (room keys, SEKs, the pair check); the Room Safety Code is computed only in browsers and never sent, stored or logged.
- **INV-13:** a burn-after-reading secret leaves the server only through the reveal transaction, which destroys it in the same statement; never add a GET or a retry that releases it.
- **INV-09:** no unchained rows in `audit_events`.
- Never weaken tests, grants, cookies or authorization to make something pass.

## 8. Documents the cloud workstream must read

- CLAUDE.md; this file; [phase-14-traceability.md](phase-14-traceability.md) section 12; `docs/management/project-roadmap.md` (Phases 17 to 19); `docs/cloud/` (service models, shared responsibility, deployment architecture with the VM hardening checklist); ADR-006 and the provider-selection ADR to write (ADR-014).
- `apps/web/src/trust/infrastructure.ts` (move controls from Designed to Configured and Verified with scope `cloud` only with captured EV-17 to EV-19 evidence), `packages/shared/src/dashboard.ts` (`PLATFORM_COMPONENTS`, the contract for the provider adapter), `apps/web/src/config/public-env.ts` (`NEXT_PUBLIC_CM_ENVIRONMENT=cloud-demonstration` for the cloud build), `apps/web/scripts/csp-lib.mjs` (the header set Nginx must serve; `CM_STORAGE_ORIGIN`).
- Deferred and still open: ADR-009 and Phase 12 (the ledger), the PC-16 scope question for AZ-26 with CM-T045 (not built).

## 9. Test counts

Gates of Phase 14 + Prompt 16.5 on the final code (2026-10-14, local PostgreSQL and storage):

| Gate | Result |
|---|---|
| `pnpm format:check`, `pnpm lint`, `pnpm typecheck` | Pass |
| `pnpm test` | 2326 tests in 91 files (Phase 11: 2302 in 88). New: `tests/dashboard` (4), `apps/web/scripts/trust-data.test.ts` (9), `apps/web/src/trust/trust-content.test.ts` (10), route-inventory additions |
| `pnpm test:e2e` (three engines) | 169 passed, 0 failed, 20 skipped (16 by design, the on-demand evidence capture in each engine, the skip-link check in WebKit). An earlier full run had two Firefox `page.goto` hangs in second tabs (the known navigation-hang item, section 12); both passed on rerun |
| `pnpm security:negative-controls` | NC-14-01 to NC-14-06: 6 of 6 caught; the older controls on files this phase changed (NC-03-06, NC-04-16 retargeted to `buttons.tsx`, NC-06-10, NC-08-09): 4 of 4 caught; baselines pass; all 121 anchors intact |
| `pnpm test:coverage:crypto` | 98.36% statements, 93.85% branches (gate 90%) |
| `pnpm test:coverage:authz` | 96.92% statements, 97.24% branches |
| `pnpm build`, `pnpm smoke:api`, `db:validate`, `db:check-schema`, `db:drift`, `trust:check` | Pass; CSP for 18 pages, no inline style |
| `pnpm audit:deps` | No known vulnerabilities; no dependency added |
| Secret scan (gitleaks) | 76 commits and the staged changes: no leaks found |

Local note from this phase: a full `pnpm test` run that spans a sleep of the machine reports absurd durations (one test "21720049 ms") and hook timeouts; it is invalid, not a defect. Rerun it awake.

Gates of Prompt 13 on the final Phase 11 code (2026-10-13, local PostgreSQL and storage), recorded in EV-11-09 and phase-11-traceability.md section 5:

| Gate | Result |
|---|---|
| `pnpm format:check`, `pnpm lint`, `pnpm typecheck` | Pass |
| `pnpm test` | 2302 tests in 88 files (Phase 10: 2201 in 84). New: `tests/rekey` (36), `rekey-guards.test.ts`, `packages/crypto/src/rekey.test.ts`, SF-11-01 tests |
| `pnpm test:e2e` (three engines) | 128 passed, 0 failed, 16 skipped by design |
| `pnpm security:negative-controls` | NC-11-01 to NC-11-13: 13 of 13 caught; the 31 older controls on files Phase 11 changed: 31 of 31 caught; baselines pass; all 115 anchors intact. A run of all 115 was not repeated |
| `pnpm test:coverage:crypto` | 98.36% statements, 93.85% branches (gate 90%) |
| `pnpm test:coverage:authz` | 96.92% statements, 97.24% branches |
| `pnpm build`, `pnpm smoke:api`, `db:validate`, `db:check-schema`, `db:drift`, `pnpm sbom:generate` | Pass |
| `pnpm audit:deps` | Pass (no known vulnerabilities); no dependency added or changed |
| Secret scan (gitleaks) | 73 commits and staged changes: no leaks found |

Local notes: `.gitignore` anchors `/secrets/`; if Docker Desktop restarts and the Postgres container cannot bind `127.0.0.1:55432` (Windows reserves port ranges), set another `POSTGRES_PORT` and the same port in the three database URLs of the git-ignored `.env`; the files and policy suites need the local storage (`pnpm services:up && pnpm storage:bootstrap`); the database suites need the local PostgreSQL container. Run E2E and the negative controls one at a time, E2E with `--workers=1`. The `cm_api` connection limit of 40 is shared by all projects; `authz`, `files`, `notes`, `secrets` and `policy` run their files serially. Twice in Prompt 12 a single test reported "timed out in 60000ms" after 10 to 16 minutes: the test process itself stalled (its timer could not fire); reruns passed and a 10-second tick logger showed no stall. A duration far above the timeout means a stall, not a defect, but check with the tick logger. Known timing-sensitive tests are in the memory notes; on a red CI run rerun the job once, find the mechanism and never loosen assertions.

## 10. Known limitations and residual risks

- Phase 4: no phone benchmark (L-37); client-side vault lock (L-38); offline guessing by a session holder (L-39); a passphrase change does not re-key (L-40); the directory reveals which addresses have a vault (L-41).
- Phase 6: grants are statements, not revocable credentials (L-46); T-36 is mitigated (L-23 updated) but identity substitution (T-25, L-07), an authorized owner colluding with the server (L-22) and served code (L-02) remain.
- Audit hash chain absent; table owner can bypass append-only (L-26); authentication, vault, room and invitation events only in the log (L-33).
- Targeted login delay (L-30); in-memory rate limits per process (L-32); no Nginx yet; no TOTP key rotation tooling (L-31); TOTP is phishable (L-34); registration reveals taken emails (L-35); emails unverified (L-21).
- Phase 7: files are at most 50 MiB, single-shot, no resumable upload, memory and phones not measured (L-47); removal does not take back downloaded files (L-48); backups keep deleted ciphertext (L-49); names and types come from the uploader (L-50).
- Phase 8: note metadata (authors, editors, revision counts, sizes, times) is visible to the server (L-51); only the current revision, no history or merge (L-52); authorship is the server's statement (L-53, L-09); removal does not take back notes already read (L-54); an older revision served under its own number is noticed only if this tab saw a newer one (L-10, T-32).
- Phase 9: secret metadata is visible to the server and to OWNER and ADMIN (L-55); the sender of a secret is the server's statement (L-56); burn-after-reading is at most once and proves release, not reading (L-57); revealed text is dropped, not wiped (L-58); with L-03 and L-12.
- Phase 10: reads are judged by the profile at the request's start (L-59); profiles are per room, not per device, and the room list still shows a room to a member who fails its profile (L-60); profile changes do not take back what members obtained (L-61); PC-11 and PC-14 wait for later phases (L-62). L-42 is resolved. Rooms from before Phase 6 stay keyless (L-43); a room that loses a member stays REKEY_REQUIRED until the rekey exists, and neither a re-enabled account nor a reset identity gets rooms back until CM-T053 (L-44); a reused room ID is refused with 409, and there is no room quota (L-45).
- Phase 11: a rekeyed version is trusted to the browser that made it (L-63); the compromise flag is declared, not detected (L-64); re-share and rekey for a reset member rely on a fingerprint check through another channel in STANDARD and CONFIDENTIAL rooms (L-65); cryptoperiods run on the worker's schedule and destruction leaves backups (L-66); account deletion does not exist (L-67). L-44 is resolved; PC-14 is enforced.
- Phase 14: the Trust Center is compiled from the documents and can be only as right as they are (L-68); the live checks observe the serving origin from one browser, not monitoring (L-69); the dashboard has no ledger metrics and a partial platform view (L-70). L-13 now says the ledger is designed, not implemented; ISMS controls 5.33, 8.15 and 8.16 are Partial.
- Full list: `docs/security/limitations.md`.

## 11. Deferred decisions

| Decision | Status |
|---|---|
| Rekey, leaving a room, re-sharing and reinstatement (AZ-14) | Done in Phase 11. A former ADMIN's earlier grants still count as authority for statements they signed (L-46, L-65) |
| Account deletion and its rekey trigger (R4) | No feature exists; implement together (L-67) |
| PC-16 scope for AZ-26 | With CM-T045 (external links, stretch), which Phase 9 did not build |
| Initialization of rooms created before Phase 6 | Not needed while nothing is deployed; needs an architecture decision before it is built (L-43) |
| OCD-06 fingerprint pinning, OCD-10 vault recovery key, OCD-11 WebAuthn | Stretch |
| Production VM Argon2id benchmark; Nginx limits; secret files; TOTP key rotation | Phase 17 |

## 12. Outstanding work outside the repository

- **Evidence index gap (found in Phase 14).** `docs/report/evidence/index.md` has prose for Phase 6 and no rows for Phases 8 to 10, although their files are committed. The Trust Center counts the committed files, so the statuses are right, but the index should get rows with captions in the ISMS workstream. EV-10-05 and EV-10-07 are still missing.

- **E2E flakiness (found in Prompt 12, not caused by Phase 10).** The browser E2E step of CI fails intermittently on a different Phase 5 to 9 test every run, mostly WebKit and Firefox (see section 1 for the runs); the Vitest jobs are green. Unresolved: find the mechanism (a hang under load is suspected, unproven) before a later prompt relies on a green E2E. The Phase 11 local runs (three engines, default workers) had no intermittent failure: one deterministic failure was a stale assertion (fixed) and the final full run passed 128 of 128, and never loosen assertions or drop an engine. The same section's required-checks item below matters here: until the CI jobs are required checks, a red E2E does not block a merge.
- Branch protection (CM-T012): the `main` ruleset still lists no required status checks; add the CI jobs (now including both coverage steps) as required checks, then capture EV-01-01 to EV-01-03.
- Dependabot pull requests remain open (#2 PostgreSQL 18 needs an ADR; #6 `@types/node` 26 is ahead of Node 24; the `next` update is covered by Phase 6, which pins 16.3.8).
- Jira: import the backlog; move CM-T006 to CM-T044, CM-T085 and CM-T086 through IN PROGRESS, SECURITY REVIEW and TESTING; create SF-04-01, R-05-01 and SF-07-01 as `security-finding` items. Nothing is DONE yet.
- Evidence still needing Jira or GitHub: the Jira history of CM-T043 and CM-T044 (EV-09-01 to EV-09-09 are in `docs/report/evidence/phase-09/`; EV-09-08 is the CI run of pull request #28); the Jira history of CM-T042 (EV-08-01 to EV-08-07 are in `docs/report/evidence/phase-08/`; EV-08-07 is the CI run of pull request #26); EV-00-05, EV-00-06, EV-00-10, the Jira history items of Phases 2 to 7. EV-07-01 to EV-07-11 are in `docs/report/evidence/phase-07/` (EV-07-11 is the CI run of pull request #24). EV-06-01 to EV-06-10 are in `docs/report/evidence/phase-06/` (EV-06-10 is the CI run of pull request #22).

## 13. Not implemented yet

- External one-time secret links (CM-T045, stretch). Files (Phase 7), notes (Phase 8) and recipient-bound secrets (Phase 9, section 6d) are implemented. Note version history, collaborative editing and Markdown are not planned for any phase. Secrets are not signed by their sender (L-56).
- Account deletion (key-lifecycle R4, L-67).
- The audit hash chain (Phase 12) and the standalone Crypto Inspector (Phase 13): deferred by the project owner. The Security Dashboard exists (Phase 14) without the ledger metrics.
- API hardening (Phase 15) and the consolidated test automation (Phase 16): deferred.
- Deployment, Nginx or cloud resources (Phase 17 onward).
- Any server-side handling of the Vault Passphrase, private keys or room key material, ever.

