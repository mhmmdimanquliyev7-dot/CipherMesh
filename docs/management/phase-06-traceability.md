# Phase 6 Traceability

Status: implemented on 2026-10-06 to 2026-10-11 (Prompt 08): CM-T033 to CM-T036 and CM-T085 are implemented, verified and merged into `main` through pull request #22 (merge commit `b3e9dd5`, CI run 38126199518, EV-06-10). Branch `feature/CM-T033-cryptographic-membership` was created from `main` at `aaaaf99`. Backlog items: [jira-backlog.md](jira-backlog.md) (CM-EPIC-06). Specification: [../architecture/adr/ADR-015-identity-signing-keys.md](../architecture/adr/ADR-015-identity-signing-keys.md) section 4.1, [../crypto/cryptographic-architecture.md](../crypto/cryptographic-architecture.md) section 7, [../architecture/data-flow.md](../architecture/data-flow.md) DF-05 and DF-06, [../security/authorization-model.md](../security/authorization-model.md) section 9.7.

## 1. Work items

| Item | Requirement (acceptance criterion) | Implementation | Tests | Evidence | Result |
|---|---|---|---|---|---|
| CM-T033 Initial room-key version | A room cannot be created without valid key data; the API checks envelope length, that the recipient key is the caller's ACTIVE key, and the commitment length; everything is stored in one transaction | `createInitialRoomKey` (`packages/crypto/src/room-keys.ts`); `POST /rooms` requires `keys`; `RoomService.createRoom` verifies both signatures under the creator's ACTIVE identity, locks the user and identity rows, and `insertRoomWithOwner` writes room, OWNER membership, version 1 and envelope together | `room-keys.test.ts`, `tests/authz/room-keys.test.ts`, `rooms-lifecycle.test.ts`, `rooms.spec.ts`; NC-06-08 | EV-06-01 | Met |
| | Request schemas contain no field that could carry raw key material | `roomCreationKeysSchema`: five strict fields with exact sizes; any other field is rejected | `rooms.test.ts` (schemas), `rooms-lifecycle.test.ts` | | Met |
| | The commitment is written once and never changes | Database trigger extended to the new columns | `constraints.test.ts` | | Met |
| | Unsigned or wrongly signed genesis and key-version statements are refused | 422 `ROOM_STATEMENT_INVALID`, event `ROOM_STATEMENT_REJECTED`, nothing stored | `tests/authz/room-keys.test.ts`; NC-06-08 | | Met |
| | E2E: create a room, lock and unlock the vault, reopen the room | The key panel verifies the key after the vault unlocks; locking clears it | `room-keys.spec.ts` (three engines) | | Met (the room is reopened inside the app; a full page load starts without the unlocked vault by design, CP-22) |
| CM-T034 Invitations with pre-wrapped envelopes | Role ceiling, history rule (PC-07), fingerprint confirmation (PC-05), server-set validity (PC-06), PENDING envelopes, revocation (AZ-08), invalidation when the invitee's key changes | `createInvitationService` (`apps/api/src/rooms/invitations.ts`), `invitation-store.ts`; the inviter's browser wraps the key and signs the grant (`createInvitationKeys`); a vault reset revokes invitations for the old key | `invitations.test.ts`, `invitation-concurrency.test.ts`, `profile-requirements.test.ts`; NC-06-04, NC-06-06 | EV-06-02 | Met |
| | Every invitation carries a membership grant signed by the inviter, or by the OWNER for ADMIN grants (`cm.room.membership-grant`) | Invitation stores `grantor_key_id` and `grant_signature`; ADMIN promotion and ownership transfer carry the OWNER's signed grant | `invitations.test.ts`, `membership-admin.test.ts`, `room-keys.test.ts`; NC-06-05 | | Met |
| | Invitations are rejected while the room is REKEY_REQUIRED or REKEYING | PC-16 in creation, approval and acceptance, checked on locked state | `invitations.test.ts`, `invitation-concurrency.test.ts` | | Met |
| | Envelope sets are validated: the current version is required, older versions only where allowed | `ENVELOPE_SET_INVALID` | `invitations.test.ts` | | Met |
| | RESTRICTED invitations require a confirmed fingerprint equal to the invitee's current key | `FINGERPRINT_REQUIRED`, `FINGERPRINT_MISMATCH`; the UI computes the fingerprint locally | `invitations.test.ts`, `room-keys.spec.ts` | EV-06-02 | Met |
| CM-T035 Acceptance, OWNER approval, delivery | OWNER approval of ADMIN-created invitations in CONFIDENTIAL and RESTRICTED rooms (PC-04), approver differs from inviter | `approveInvitation`; database CHECK `invitations_approver_not_inviter_check` | `invitations.test.ts` | | Met |
| | Accept and decline; expiry job; envelope activation; own-envelope fetch (AZ-12, OL-05) | `acceptInvitation` (lock order: user, identity, room, invitation, memberships), `declineInvitation`, `expireInvitations` in `pnpm worker:retention`, `GET /rooms/{roomId}/envelopes` | `invitations.test.ts`, `invitation-concurrency.test.ts`; NC-06-06, NC-06-07 | | Met |
| | PENDING envelopes are never served; expired or revoked invitations cannot be accepted | Envelope fetch selects ACTIVE envelopes of the caller; status and expiry re-checked under lock | `invitations.test.ts` | | Met |
| Phase 5 handoff | Acceptance locks and re-checks the invitee's user row; a disable never misses a concurrently accepted membership | `lockActiveUser` first in the acceptance transaction | `invitation-concurrency.test.ts` (account disable against acceptance, with and without a forced overlap); NC-06-07 | | Met |
| CM-T036 Client-side unwrap, commitment check | Envelope decryption, commitment check, reuse check, RWK derivation, in-memory cache cleared on lock; the verification rule of ADR-015 section 4; `KEY_AUTHENTICATION_FAILED` and a security alert; mismatch reporting (AZ-29) | `openRoomKey`, `openRoomKeys`, `apps/web/src/rooms/keys.ts` (cache cleared by `onKeysDropped`), `POST /rooms/{roomId}/key-reports` | `room-keys.test.ts`, `room-format.test.ts`, `room-keys.spec.ts`; NC-06-01 to NC-06-03 | EV-06-03 | Met |
| | A tampered envelope or a key that does not match the commitment is rejected and reported | `KEY_COMMITMENT_MISMATCH`, report with version and kind only | `room-keys.test.ts`, `tests/authz/room-keys.test.ts` | EV-06-03 | Met |
| | A test documents the limit: a harness that serves a different commitment with a matching envelope passes the check; the Safety Code covers it | Split-view tests (Node and browser) | `room-keys.test.ts`, `room-keys.spec.ts` | EV-06-06 | Met |
| | The cross-browser suite passes in Chromium, Firefox and WebKit; ADR-007 Accepted or revised | Envelopes made in Chromium open in Firefox and WebKit; ADR-007 Accepted | `room-keys.spec.ts` | EV-06-04 | Met |
| | The `key-injection` suite; a negative control removes the verification | Unsigned, forged, wrongly attributed and unauthorized versions, mismatch, missing recipient | `room-keys.test.ts`; NC-06-01 | | Met |
| CM-T085 Room Safety Code | HKDF derivation (CP-24), six words with the key version and a numeric alternative, word list (LIB-08) | `computeSafetyCode`, `safety-code-words.ts` (BIP-39 English, checksum-verified), `key-panel.tsx` | `room-keys.test.ts`, `room-keys.spec.ts`; NC-06-09 | EV-06-05 | Met |
| | Known-answer vectors pass in all three engines | Vector "knee want dad also trust siege" for RKM 00..1f | `room-keys.spec.ts` (known answers) | EV-06-04 | Met |
| | The code changes with key, version and room, and never appears in requests, logs or storage | Request, URL, storage and log inspection | `room-keys.spec.ts`, `tests/authz/room-keys.test.ts`, `room-keys.test.ts`; NC-06-10 | | Met |
| | A two-browser harness with different keys shows different codes while the commitment check alone does not catch it | Split-view harness | `room-keys.spec.ts` | EV-06-06 | Met |
| | UI wording states the limits (L-22) | `SAFETY_CODE_EXPLANATION`, `SAFETY_CODE_MISMATCH`; profile reminders are advisory | `room-keys.spec.ts` | EV-06-05 | Met |
| | Optional comparison records and mismatch reports carry only the key version (AZ-30) | `POST /rooms/{roomId}/safety-code`; no code field exists | `rooms.test.ts` (schemas), `tests/authz/room-keys.test.ts` | | Met |

## 2. Architecture-conflict review

I compared the Jira acceptance criteria, `cryptographic-architecture.md`, `key-hierarchy.md`, `key-lifecycle.md`, `data-model.md`, DF-05, DF-06, ADR-007, ADR-012, ADR-013, ADR-015 and `authorization-model.md` before writing crypto code. One material disagreement was found and resolved by the project owner before it was built:

- **Recipient authorization of invited members.** ADR-015 section 4.5 requires "the client's own identity is in the signed recipient list" of the key-version statement, while DF-05 signs version 1 once, at creation, with only the creator as a recipient, and DF-06 has invitations wrap existing versions for new members. Read literally, no invited member could verify a key. The owner approved (2026-10-06): a client is an authorized recipient if it is named in the signed list **or** is the subject of a verified membership grant whose grantor's authority chains back to the genesis statement. No statement field was added. Recorded in ADR-015 section 4.1 and CD-28.

Other questions were settled by reading the documents: the commitment (HKDF over `cm.room.commitment`, CP-03), the envelope label (`cm.room.envelope`), the Safety Code (CP-24) and the statement fields (ADR-015 section 4, with the recipient list as sorted `{userId, keyId}` objects and `previousCommitment` as `null` exactly for version 1) have one definition each.

## 3. Decisions and deviations

| Decision | Reason |
|---|---|
| Migration `20261006000000_room_statements`: signed columns, composite foreign keys, CHECKs, write-once triggers | data-model section 8 listed what has to be stored; the exact columns are decided here |
| AZ-31 (view the room's invitations) added to the matrix | OL-11 gave OWNER and ADMIN this view and no action covered it; the `authz-matrix` suite compares the model with the code |
| Invitations carry the PENDING envelopes in the creating request; acceptance makes them ACTIVE | DF-06 |
| PC-03 applies to inviting and approving in RESTRICTED rooms; PC-01 and PC-02 apply at acceptance | These gates are normative and Phase 6 introduces the actions they name; the full policy engine stays in Phase 10 |
| Room cleanup (worker) revokes invitations, deletes envelopes and marks key versions DESTROYED before a room becomes DELETED | key-lifecycle 1.1 and 1.7 |
| `lockRoom` now also returns the profile and the current key version | Needed to re-check invitation rules on locked state |
| `AZ-14` (re-sharing keys) and reinstatement are **not** implemented | The backlog assigns them to CM-T053 in Phase 11; Prompt 08 forbids pre-building rekey machinery (L-44) |
| `next` 16.3.6 to 16.3.8 (exact pin, lockfile refresh) | The dependency audit started failing during the pause: GHSA-cjq9-62q9-8jv4 (Server-Side Request Forgery in Image Optimization, patched in 16.3.8, released 2026-09-30, older than the 3-day release-age policy). The static export does not use image optimization; the patched release is the remediation. No other package changed |
| Legacy keyless rooms are not initialized | No document specifies a client-side initialization and the server must never create keys (L-43). Only development and test rooms exist |

## 4. Security review of the Phase 6 change

| Question | Answer |
|---|---|
| Can the server learn an RKM? | No. It receives the commitment (an HKDF output), RSA-OAEP ciphertexts addressed to one identity, and signatures. `room-keys.test.ts` and `tests/authz/room-keys.test.ts` search every table and the log for RKM_1 in hex, base64 and base64url |
| Can PLATFORM_ADMIN decrypt a room? | No. It holds no membership (PA-05, BOLA suite) and no envelope; no key route exists for it |
| Can the server replace an envelope or a key version undetected? | No. A replaced envelope fails the signed commitment (`KEY_COMMITMENT_MISMATCH`); an injected version needs a signature by an authorized member (`KEY_AUTHENTICATION_FAILED`). It can withhold data (T-32) |
| Can it swap the recipient identity? | The label names the recipient user and key, so an envelope for another identity does not open. Substituting a whole identity is T-25: fingerprint comparison, mandatory in RESTRICTED |
| Can an envelope or version of Room A be used in Room B? | No. The room ID is in the label and in every statement |
| Can a MEMBER or an ADMIN forge an OWNER-required grant? | No. ADMIN grants and ownership transfers verify only when signed by an identity with OWNER authority (NC-06-05) |
| Can a retired identity accept a grant for another key? | No. Grants name the invitee's key; a vault reset revokes the open invitations and acceptance requires the ACTIVE key (`IDENTITY_KEY_CHANGED`) |
| Can a different user accept the invitation? | No. Invitations are loaded by ID and invitee = session user (NC-06-06) |
| Can an invitation be replayed? | No. Acceptance is a conditional transition PENDING to ACCEPTED under lock; a second acceptance is 409 |
| Can an account disable miss a concurrently accepted membership? | No (NC-06-07; forced-overlap tests) |
| Can the client use an RKM before verifying it? | No. `openRoomKey` returns only after all steps; the raw bytes are overwritten before returning |
| Can the server fake the Safety Code? | The UI computes it locally from the verified key; a server-supplied value is not read anywhere (NC-06-09). Malicious JavaScript can still show a fake (L-02) |
| Is plaintext RKM stored anywhere persistent? | No: not in tables, logs, URLs, cookies, local or session storage, IndexedDB or the Cache API (E2E storage inspection, NC-06-10) |
| Did Prompt 08 implement Prompt 09 or later? | No: no file, note or secret encryption, object storage, policy engine, rekey, audit chain, Crypto Inspector or dashboard |

New findings: none in production code. Test-harness defects found and fixed: an address overflow in the `newAddress()` helper (past 0xffff the address became invalid and the API keyed requests as `unknown`, tripping the per-address limit once in a full run), and Safety Code leak checks that searched single common words. Two negative-control mutations were malformed at first and were corrected; the corrected controls fail on the intended tests.

## 5. Remaining after Phase 6

- L-46 (grants are statements); L-44 (reinstatement and the rekey: CM-T050, CM-T051, CM-T053); L-43 (legacy rooms); L-42 (remaining profile gates).
- Phase 7 (Prompt 09) builds encrypted files on `RWK_v`: `openRoomKey` already returns the non-extractable RWK, and `cm.dek.wrap` is the context for wrapped DEKs.
- Rekey (Phase 11) reuses the verification rule and must decide how a former ADMIN's signature is rejected (L-46).

## 6. Verification in Prompt 08

Gates on the final Phase 6 code (2026-10-11, local PostgreSQL), recorded in EV-06-07; the negative controls in EV-06-08 and the supply chain in EV-06-09.

| Gate | Result |
|---|---|
| `pnpm test` | 1734 tests in 71 files (Phase 5: 1516 in 66) |
| `pnpm test:e2e` (three engines, one worker) | 70 passed, 8 skipped by design |
| `pnpm security:negative-controls` | 59 of 59 caught (ten Phase 3, seventeen Phase 4, twenty-two Phase 5, ten Phase 6), both baselines pass |
| `pnpm test:coverage:crypto` | 98.5% statements, 92.3% branches |
| `pnpm test:coverage:authz` | 97.3% statements, 98.3% branches |
| `pnpm audit:deps`, `pnpm sbom:generate`, `pnpm build`, `pnpm smoke:api`, format, lint, typecheck, `db:check-schema`, `db:drift` | Pass |
| Secret scan | Staged scan clean; CI gitleaks over the full history passed |

## 7. Merge and CI

Pull request #22 was opened from `feature/CM-T033-cryptographic-membership` to `main`, and merged on 2026-10-11 with a normal merge commit `b3e9dd5` after every check passed: CI run 38126199518 (lint, types, tests, build, E2E in three engines), the dependency audit, the gitleaks scan and GitGuardian (EV-06-10).

