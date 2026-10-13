# Phase 11 Traceability

Status: implemented on 2026-10-13 (Prompt 13): CM-T050 to CM-T053, verified on branch `feature/CM-T050-key-rotation`, created from `main` at `8a5905d` (the Phase 10 handoff merge, pull request #31). Normative sources: [../architecture/adr/ADR-013-rekey-state-machine.md](../architecture/adr/ADR-013-rekey-state-machine.md), [../architecture/adr/ADR-015-identity-signing-keys.md](../architecture/adr/ADR-015-identity-signing-keys.md), [../crypto/key-lifecycle.md](../crypto/key-lifecycle.md), [../security/authorization-model.md](../security/authorization-model.md) section 9.12, [../security/runbook-compromised-identity-key.md](../security/runbook-compromised-identity-key.md). The merge record is in [current-state.md](current-state.md).

## 1. Work items

### CM-T050 Rekey state machine and rekey operation API

P1, crypto, backend, frontend; depends on CM-T036.

| Requirement | Implementation | Tests | Evidence | Result |
|---|---|---|---|---|
| Rekey operations: start, finalize, cancel; 10-minute lease; one live operation per room; membership-epoch snapshot with a server-computed recipient set; atomic activation; idempotent finalize by payload digest; stale and closed operations; manual rotation without the write lock | `apps/api/src/rooms/rekey.ts`, `apps/api/src/db/rekey-store.ts`, `apps/api/src/routes/rekey.ts`; migration `20261011000000_key_rotation` (guards, STALE trigger, consistency check at commit) | `rekey-lifecycle.test.ts`, `rekey-guards.test.ts`; NC-11-05, NC-11-06, NC-11-07 | EV-11-06, EV-11-07 | Met |
| The browser makes the version: fresh material, commitment, statement signed by the starter and chained to the previous commitment, one envelope per recipient, recipient snapshot reviewed first | `createRekeyKeys`, `reviewRekeyRecipients`, `openRoomKeys` (`packages/crypto/src/room-keys.ts`); `apps/web/src/rooms/rekey-panel.tsx`, `keys.ts` | `packages/crypto/src/rekey.test.ts`; NC-11-12 | EV-11-03 | Met |
| The admin flow with recipient review | Rekey panel: the review lists names and fingerprints, flags a key the room never signed, and the page says why the room is locked | `tests/e2e/rekey.spec.ts` A, B, C in Chromium, Firefox and WebKit | | Met |
| **AC:** Only the starter can finalize; concurrent starts return `REKEY_IN_PROGRESS`; the OWNER can cancel | `REKEY_NOT_STARTER` 403; the lease and a partial unique index; cancel by the starter or the OWNER (OL-13); an ADMIN cannot cancel the OWNER's operation | `rekey-lifecycle.test.ts` ("who may start, finalize and cancel", "two admins starting at once"); NC-11-01, NC-11-02 | | Met |
| **AC:** Finalize rejects a wrong recipient set (422), a changed epoch or version, and closed or expired operations (409); a repeated identical finalize returns the original result | Recomputed recipient digest, exact-set comparison, version and epoch checks on the locked rows; payload digest | `rekey-lifecycle.test.ts` ("finalize refuses a wrong recipient set...", "a repeated identical finalize...", "two concurrent finalizes"); NC-11-04, NC-11-07 | EV-11-07 | Met |
| **AC:** A rekey that never finalizes is recoverable after the lease expires, and no partial key state exists | Lease expiry abandons the operation at finalize, at the next start and in the worker; finalize is one transaction; a database failure leaves the old version, the lock and the operation | `rekey-lifecycle.test.ts` ("an expired lease...", "the worker abandons...", "a database failure inside finalize..."); NC-11-06 | EV-11-06 | Met |
| **AC:** After activation, writes naming the old version return `KEY_VERSION_STALE`, and old content stays readable | Existing Phase 7 to 9 version checks; the chain of versions opens for every member | `rekey-lifecycle.test.ts` (first and third scenario) | EV-11-01 | Met |
| **AC:** Every transition emits an audit event | `REKEY_STARTED`, `REKEY_COMPLETED`, `REKEY_ABANDONED`, `REKEY_SUPERSEDED`, `REKEY_CANCELLED`, `REKEY_STALE`, `REKEY_REJECTED`, `KEY_VERSION_RETIRED`; events go to the redacted log, not the ledger (INV-09 waits for Phase 12, L-33) | `rekey-lifecycle.test.ts` | EV-11-05 | Met, with L-33 |
| **AC:** A finalize without a valid key-version signature by the starter is refused | The statement is verified under the starter's ACTIVE identity at finalize; members verify it again in the browser | `rekey-lifecycle.test.ts` ("refuses a statement that does not verify...", "members refuse a forged rekeyed version..."); NC-11-03 | | Met |

### CM-T051 Member loss triggers REKEY_REQUIRED and the write lock

P1, crypto, backend, security; depends on CM-T050 and CM-T031.

| Requirement | Implementation | Tests | Evidence | Result |
|---|---|---|---|---|
| Removal, leaving, suspension: one transaction changes the membership, deletes the envelopes, advances the epoch and sets REKEY_REQUIRED | Removal and suspension since Phase 5 and 6; leaving (`POST /rooms/{roomId}/leave`, AZ-11) new; pending uploads are cancelled by the Phase 7 write-lock rule | `identity-reshare.test.ts` ("leaving a room"), `files-upload.test.ts` (pending uploads); `authz` suites | EV-11-02, EV-11-04 | Met |
| Account deletion | **Not built.** There is no account-deletion feature, so key-lifecycle R4 has no trigger; the reason code is reserved | | | Documented gap, L-67 |
| The removing admin is prompted to rekey immediately | The room page shows the locked state with a "Rotate the room key now" action to OWNER and ADMIN | `rekey.spec.ts` A | | Met |
| **AC:** The removed member gets 404 on every room endpoint and has no envelopes left | Unchanged generic 404 for non-members; the rekey routes are covered by the BOLA table | `bola.test.ts` (rekey and reshare targets), `rekey-lifecycle.test.ts`, `identity-reshare.test.ts` | EV-11-02 | Met |
| **AC:** Writes and invitations return 409 `REKEY_REQUIRED` until a rekey completes; reads continue | Unchanged PC-16 gates | `rekey-lifecycle.test.ts`, the Phase 6 to 10 suites | EV-11-04 | Met |
| **AC:** A pending rekey operation becomes STALE when membership changes | API and database trigger, whichever path changed the epoch | `rekey-lifecycle.test.ts` ("a membership change makes a pending operation STALE"), `rekey-guards.test.ts`; NC-11-05 | | Met |
| **AC:** A test holding the old RKM cannot unwrap DEKs created after the rekey | Browser test: RKM_1 cannot unwrap a DEK wrapped under RWK_2 | `packages/crypto/src/rekey.test.ts` | EV-11-03 | Met (L-04 stays) |

### CM-T052 Key-version retirement, destruction, wrap-count bound and cryptoperiod

P2, crypto, backend; depends on CM-T050.

| Requirement | Implementation | Tests | Evidence | Result |
|---|---|---|---|---|
| The worker destroys unreferenced RETIRED versions (envelopes deleted) | `runRekeyMaintenance` (`apps/api/src/db/rekey-cleanup.ts`, called by the worker retention job): a RETIRED version no live file or note names loses its envelopes and becomes DESTROYED | `rekey-lifecycle.test.ts` ("the worker destroys a retired version no live item names; it keeps one a note still names") | | Met |
| Wrap-count bound (CP-16) and cryptoperiods (PC-14) set REKEY_REQUIRED; reminder 14 days before | Wrap bound in the file store (Phase 7) with its resolution by a rekey; cryptoperiod in the worker from the stored catalogue version (an unknown version is skipped, never evaluated under another); the reminder is in the key state and the rekey panel | `rekey-lifecycle.test.ts` ("a CONFIDENTIAL room is reminded 14 days early...", "a room locked by the wrap bound (R7) or an expired cryptoperiod (R6) is unlocked only by a rekey"), `files-upload.test.ts` | | Met |
| **AC:** Tests with small thresholds trigger each path | The wrap bound is triggered by setting `wrap_count` to the limit and the cryptoperiod by ageing the version row, both in the test database (no production threshold is configurable) | as above | | Met |
| **AC:** Destroyed versions keep only commitment and metadata | Envelopes deleted; the version row, commitment and signed statement stay | `rekey-lifecycle.test.ts` | | Met |

### CM-T053 Compromised identity-key procedure

P2, crypto, security, documentation; depends on CM-T051.

| Requirement | Implementation | Tests | Evidence | Result |
|---|---|---|---|---|
| Vault reset deletes the old identity's envelopes, advances each room's epoch (stale snapshots) and, with the compromise flag, sets every room of the user to REKEY_REQUIRED | `VaultService.resetVault`, `RoomStore.replaceMemberIdentity`; `identityCompromised` in the request and a checkbox on the vault page | `identity-reshare.test.ts` ("the vault-reset procedure in rooms"); NC-11-10 | | Met |
| Re-share (AZ-14) with the invitation role ceilings, fingerprint rules, profile history rules and explicit reinstatement of a SUSPENDED member | `POST /rooms/{roomId}/members/{userId}/reshare`; a grant history table keeps an old identity's statements verifiable | `identity-reshare.test.ts` ("re-sharing keys to a new identity"); `rekey-guards.test.ts`; NC-11-09, NC-11-11 | | Met |
| **AC:** E2E: reset a vault, admins re-share, the user regains access as the history rule allows | Scenario C | `rekey.spec.ts` C in three engines | | Met |
| **AC:** The compromise path marks every affected room; runbook documented | As above; [runbook-compromised-identity-key.md](../security/runbook-compromised-identity-key.md) | `identity-reshare.test.ts` | | Met |

## 2. Cross-cutting finding SF-11-01 (RSA-OAEP and leading zero bytes)

**What:** the WebKit build Playwright runs on Linux (libgcrypt backend) returns the RSA-OAEP message as an integer, so a 32-byte value starting with `0x00` (1 in 256 room keys, SEKs and pair-check values) came back as 31 bytes, and an honest envelope was refused as tampered.

**Fix:** `unwrap32` (`packages/crypto/src/rsa-oaep.ts`) left-pads a shorter result to 32 bytes; a longer result, a wrong ciphertext length, a wrong label and a modified ciphertext still fail with the one generic error. Decision CD-33 in [../crypto/crypto-decisions.md](../crypto/crypto-decisions.md).

**Why it does not weaken the design:** whoever can encrypt a short value X with the public key can already encrypt the 32-byte value `00..X`, so the set of keys an attacker can make a victim accept is unchanged; every caller still checks what the value opens (the signed commitment, the AEAD tags, the pair-check); no new error distinguishes a short result, so the single-error rule against adaptive (Manger-style) queries is unchanged; RSA-OAEP still wraps only 32-byte values (INV-17).

**Regression evidence:** a known-answer test with OpenSSL (a value OpenSSL wraps at 31 bytes), a stub that strips leading zeros on top of the real decryption (1, 2 and 31 zero bytes restored; wrong label and bit flip still fail), the cross-browser known-answer in `room-keys.spec.ts`, and NC-11-13, which restores the old strict check and is caught.

## 3. Architecture-consistency review

| Question | Answer |
|---|---|
| Does the server ever hold or derive room key material? | No. It stores envelopes, a commitment and a signed statement, and checks the set, the signature and the order of versions (INV-01, INV-04). The starter's browser makes the key. A compromised server or a legitimate starter can still inject a key (T-36, L-23, L-63) |
| Can a content write or invitation succeed while REKEY_REQUIRED or REKEYING? | No (INV-07, PC-16), tested in every profile; the consistency trigger refuses a half-closed operation at commit |
| Can a removed member regain access through a re-share? | No. The recipient snapshot excludes removed and departed members, AZ-14 targets ACTIVE or SUSPENDED members, and a locked room refuses a re-share |
| Can a stale, replayed or foreign finalize take effect? | No: the operation is loaded by ID and room ID (OL-13), the epoch and the recipient digest are rechecked on the locked rows, a repeated identical finalize is idempotent and another payload is refused |
| Do two administrators or two requests race? | One live operation per room (partial unique index and the lease), forced lock orders and concurrent finalizes tested |
| Is the policy enforced at the right layer? | PC-03 on the start route and the locked row; PC-14 by the worker from the stored catalogue version; PC-05 and PC-07 in AZ-14; PC-16 unchanged |
| Are new tables and grants documented? | `room_member_grants` in data-model 4.9.2, the grant matrix and database-security section 14 |
| Do new events or errors leak secrets? | Events carry IDs, mode, versions, counts and reason codes; the operation row has no key material; `REKEY_*` errors are generic with stable codes (INV-10) |
| Are the UI claims accurate? | The profile panel said the cryptoperiod was "not enforced yet" after the worker enforced it; corrected. The reset form states the difference between a lost passphrase and a compromise |
| Were future features implemented? | No: no audit chain, no Security Dashboard, no external links, no account deletion, no UI redesign (Prompt 16.5) |

Findings of this phase: SF-11-01 (above); a stale browser assertion in `rooms.spec.ts` that matched the Phase 6 banner wording (updated to the new wording, same check); the PC-14 UI text; CD-33 cited by the code before it existed in the register (added); CRLF line endings introduced by scripted documentation edits, caught by the negative-control anchor check and normalized to LF.

## 4. Open items and honest gaps

- Account deletion has no trigger (L-67). Recorded, not built.
- The audit view of EV-11-05 is the redacted event record: the hash-chained ledger and the audit view arrive in Phases 12 and 14 (L-33).
- Intermittent E2E failures recorded in Phases 9 and 10 did not occur in the Phase 11 runs; one deterministic failure was found and fixed (the stale assertion above).
- Cross-browser coverage of leaving a room is in the integration suite only; the browser scenarios cover removal, cancellation and re-share.

## 5. Verification

Gates on the final Phase 11 code (2026-10-13, local PostgreSQL 17 and storage), EV-11-09:

| Gate | Result |
|---|---|
| `pnpm format:check`, `pnpm lint`, `pnpm typecheck` | Pass |
| `pnpm test` | 2302 tests in 88 files, all pass (Phase 10: 2201 in 84). New: `tests/rekey` (36 in 2 files), `tests/database/rekey-guards.test.ts`, `packages/crypto/src/rekey.test.ts`, SF-11-01 tests in `rsa-oaep.test.ts`. The database project has 140 tests in 9 files |
| `pnpm test:e2e` (three engines) | 128 passed, 0 failed, 16 skipped by design. The first full run had one deterministic failure in three engines (a stale banner assertion in `rooms.spec.ts`, section 3); after the fix the full run is clean. The three `rekey.spec.ts` scenarios pass in each engine. None of the intermittent failures recorded in Phases 9 and 10 occurred |
| `pnpm security:negative-controls` | NC-11-01 to NC-11-13: 13 of 13 caught. The 31 older controls whose target files Phase 11 changed: 31 of 31 caught. Both baselines pass; every anchor of all 115 controls matches exactly once. Running all 115 was not repeated: the other 71 controls target only files Phase 11 did not change |
| `pnpm test:coverage:crypto` | 98.36% statements, 93.85% branches (gate 90%) |
| `pnpm test:coverage:authz` | 96.92% statements, 97.24% branches |
| `pnpm build`, `pnpm smoke:api`, `pnpm sbom:generate`, `db:validate`, `db:check-schema`, `db:drift` | Pass; 17 models, 241 classified fields, no drift |
| `pnpm audit:deps` | No known vulnerabilities; no dependency added or changed |
| Secret scan (gitleaks) | 73 commits and the staged changes: no leaks found |


## 6. Negative controls

Each control writes one real defect into the working tree, runs the tests that must catch it, and restores the file (`scripts/security/negative-controls.mjs`, EV-11-08). Defects that the API repeats in the database (staleness, the grant history) are written into both layers.

| ID | Deliberate defect | Detected by | Result |
|---|---|---|---|
| NC-11-01 | Any OWNER or ADMIN may finalize another member's rekey operation (OL-13) | `rekey-lifecycle.test.ts` | Caught |
| NC-11-02 | Any ADMIN may cancel the OWNER's rekey operation (OL-13) | `rekey-lifecycle.test.ts` | Caught |
| NC-11-03 | The key-version statement signature is not checked at finalize (T-36) | `rekey-lifecycle.test.ts` | Caught |
| NC-11-04 | The recipient snapshot includes removed and departed members (T-21) | `rekey-lifecycle.test.ts` | Caught |
| NC-11-05 | A membership change no longer makes a pending rekey STALE (API and database trigger) | `rekey-lifecycle.test.ts` | Caught |
| NC-11-06 | An expired lease is still accepted at finalize (ADR-013 step 6) | `rekey-lifecycle.test.ts` | Caught |
| NC-11-07 | A different payload is answered as a retry of a completed rekey | `rekey-lifecycle.test.ts` | Caught |
| NC-11-08 | Starting a rekey in a RESTRICTED room needs no step-up (PC-03, route and locked row) | `rekey-lifecycle.test.ts` | Caught |
| NC-11-09 | An ADMIN may re-share keys to another ADMIN (AZ-14 without the role ceilings) | `identity-reshare.test.ts` | Caught |
| NC-11-10 | A vault reset leaves the old identity's envelopes in its rooms (CM-T053) | `identity-reshare.test.ts` | Caught |
| NC-11-11 | The grant history is not recorded (a re-shared ADMIN's earlier statements lose their authority) | `identity-reshare.test.ts` | Caught |
| NC-11-12 | The browser accepts a rekey snapshot that lists one user twice | `packages/crypto/src/rekey.test.ts` | Caught |
| NC-11-13 | SF-11-01 regression: a 32-byte value with dropped leading zeros is refused again | `packages/crypto/src/rsa-oaep.test.ts` | Caught |

## 7. Evidence

In [../report/evidence/phase-11/](../report/evidence/phase-11/), synthetic data only, no key material: EV-11-01 (key-version history and envelope sets before and after a removal), EV-11-02 (the removed member's responses: 404 on every room route, no envelopes), EV-11-03 (browser test report: forward protection and its limit, forged and forked versions), EV-11-04 (409 `REKEY_REQUIRED` for a write and an invitation while locked), EV-11-05 (the recorded events of a removal and rekey), EV-11-06 and EV-11-07 (recovery and idempotency report), EV-11-08 (negative controls), EV-11-09 (gate results). The CI record of the implementation pull request is in [current-state.md](current-state.md).
