# Phase 10 Traceability

Status: implemented on 2026-10-12 (Prompt 12): CM-T046 to CM-T049, verified on branch `feature/CM-T046-security-policies`, created from `main` at `b6a4da4` (the Phase 9 handoff merge, pull request #29). Merged into `main` through pull request #30, merge commit `3688722` (parents `b6a4da4` and `02c48e5`); see section 5 and [current-state.md](current-state.md) for the CI record. Normative sources: [security-policy-profiles.md](../security/security-policy-profiles.md) (values unchanged), [authorization-model.md](../security/authorization-model.md) section 9.11, data-model 4.6 and 4.16, DF-14.

## 1. Work items

### CM-T046 Policy catalogue as versioned code

P1, security, backend; depends on CM-T029.

| Requirement | Implementation | Tests | Evidence | Result |
|---|---|---|---|---|
| PC-01 to PC-16 as an immutable, versioned catalogue in `packages/shared` | `packages/shared/src/policy.ts`: catalogue version 1, one `ProfilePolicy` per profile with every PC control, deep-frozen; `POLICY_CATALOGUE_VERSION`, `SUPPORTED_POLICY_VERSIONS`, `resolveRoomPolicy`, `currentPolicy`. The per-feature constants of Phases 5 to 9 (`PROFILE_ACCESS_REQUIREMENTS`, `INVITATION_RULES`, `FILE_RULES`, `NOTE_RULES`, `SECRET_RULES`) were removed and every user now reads the catalogue | `policy-catalogue.test.ts`, `policy.test.ts` | EV-10-01 | Met |
| Rooms store profile and policy version | `rooms.security_profile`, `rooms.policy_version` (schema v1); new rooms and every profile change record the current version; the authorizer, the locked room row and the room detail response carry the version | `membership-lookup.test.ts`, `policy-matrix.test.ts` | | Met |
| UI labels come from the catalogue | The room page resolves the policy from the stored profile and version and lists its rules (`apps/web/src/rooms/profile-panel.tsx`); file, note, secret and invitation panels read their limits from it | `policies.spec.ts` | EV-10-04 | Met |
| **AC:** A test compares the catalogue with a fixture derived from the table in `security-policy-profiles.md` | Every PC row parsed from the document and compared cell by cell with version 1, plus the PC-03 operation list and the global step-up windows | `tests/security/policy-catalogue.test.ts` (25 tests) | EV-10-01 | Met |
| **AC:** No database table can change policy values at runtime | Values only in code; the test asserts that no Prisma model can hold policy values; an unknown stored version fails closed (503 `POLICY_UNSUPPORTED`) instead of falling back | `policy-catalogue.test.ts`, `policy-matrix.test.ts` (stored versions); NC-10-07 | | Met |

### CM-T047 Server-side policy enforcement gates

P1, security, backend; depends on CM-T046 and CM-T021.

| Requirement | Implementation | Tests | Evidence | Result |
|---|---|---|---|---|
| Gates in the evaluation order of the profiles document, applied to every room route through the route registry | `createRoomAuthorizer`: membership (404) → PC-01, PC-02 and the stored version → matrix → PC-03 for a route that declares `requires: { sensitive }`; `reapplyRoomPolicy` repeats the gates on the locked room row in every writing transaction (room service, invitations, files, notes, secrets) | `policy-matrix.test.ts` (PC-01 and PC-02 on all 32 room routes in each profile), `profile-change.test.ts` (forced lock order) | EV-10-02 | Met |
| Audit levels (PC-13) | The emitter reads the room's audit level: EXTENDED download URLs and note reads (existing), FULL adds `ENVELOPES_FETCHED` and `MEMBER_LIST_VIEWED`; every refusal is `ROOM_ACCESS_DENIED` with the action and a reason code | `policy-matrix.test.ts` (PC-13 per profile); NC-10-11 | | Met |
| Stable error codes | `MFA_REQUIRED` 403, `REAUTH_REQUIRED` 401, `STEP_UP_REQUIRED` 401, `FORBIDDEN` 403 (PC-12), `POLICY_UNSUPPORTED` 503 (new), `PROFILE_CHANGED` 409 (new); generic messages | all policy suites | | Met |
| **AC:** Each gate has allowed and denied tests | Section 5 of this file maps every control to its tests | `policy-matrix.test.ts`, `profile-change.test.ts` | EV-10-01 | Met |
| **AC:** Gates never read profile or role data from the request | Policy resolved from the database row; strict schemas refuse profile, version and role fields; headers and query fields change nothing | `policy-matrix.test.ts` ("never takes a profile or policy version from the request"), `profile-change.test.ts` (forged fields); NC-10-02 | | Met |

### CM-T048 Profile change rules and expiration clamping

P2, security, backend; depends on CM-T047.

| Requirement | Implementation | Tests | Evidence | Result |
|---|---|---|---|---|
| Upgrade and downgrade rules | `POST /rooms/{roomId}/profile` (AZ-03, OWNER only), `RoomService.changeProfile`, `decideProfileChange`: on the locked room row, stale expectation 409; upgrade needs the new profile's PC-01, PC-02 (and PC-03 for RESTRICTED); downgrade a step-up within 5 minutes | `profile-change.test.ts`; NC-10-02, NC-10-05 | | Met |
| Clamping of existing expiry dates on upgrade | `applyUpgrade` (`apps/api/src/db/policy-store.ts`): files, notes, ACTIVE secrets, open invitations shortened to at most the upgrade time plus the new maximum; migration `20261010000000_security_policies` lets an ACTIVE secret's and an open invitation's expiry move only earlier | `profile-change.test.ts`, `constraints.test.ts`; NC-10-06 | | Met |
| Revocation of non-compliant invitations | Open invitations that skipped approval (PC-04), lack a required fingerprint (PC-05) or share older versions (PC-07) are revoked with their PENDING envelopes; ACTIVE non-burn secrets are revoked when burn becomes mandatory (PC-10) | `profile-change.test.ts`; NC-10-09, NC-10-10 | | Met |
| High-severity audit event on downgrade | `PROFILE_DOWNGRADED` with `severity: 'HIGH'`; `PROFILE_UPGRADED` with the counts of shortened and revoked items | `profile-change.test.ts` | EV-10-03 | Met |
| **AC:** Clamping tests; downgrade requires a 5-minute step-up | As above; a 6-minute-old step-up is refused with reason `PROFILE_DOWNGRADE_STEP_UP` | `profile-change.test.ts` | EV-10-03 | Met |
| **AC:** After an upgrade to CONFIDENTIAL, members without MFA are denied until they enable it | The access gate on every request | `profile-change.test.ts`, `policies.spec.ts` | EV-10-02 | Met |

### CM-T049 Policy enforcement test matrix

P1, testing, security; depends on CM-T047.

| Requirement | Implementation | Tests | Evidence | Result |
|---|---|---|---|---|
| Generated tests for every control and profile with an allowed and a denied case, asserting status code, error code and audit event | `tests/policy/policy-matrix.test.ts`; every denial also asserts that the room's rows are unchanged | Vitest project `policy` | EV-10-01 | Met |
| **AC:** Every PC control is covered; the suite runs in CI and blocks merges on failure | Section 5; the `policy` project is part of `pnpm test`, which the CI test job runs | CI | EV-10-07 (CI run, recorded at merge) | Met |

## 2. Architecture-consistency review

The profile table, the authorization model, data-model 4.6 and 4.16, the step-up rules of authentication-security, and the existing Phase 6 to 9 enforcement agree. Before Phase 10:

| Control | State before Phase 10 | Phase 10 |
|---|---|---|
| PC-01, PC-02 | At room creation and invitation acceptance only (L-42) | Every room request and every write (locked row) |
| PC-03 | Invite and approve in RESTRICTED (in the transaction); delete and transfer always need a step-up (AZ-04, AZ-05) | Reveal, download URL, invite, approve, remove, change profile, delete; gate and locked row |
| PC-04 to PC-07 | Enforced at invitation (Phase 6) | Unchanged, now from the catalogue; preserved by the Phase 6 suites |
| PC-08, PC-09, PC-10 | Enforced at creation (Phases 7 to 9) | Unchanged at creation; upgrade clamping and revocation added |
| PC-11 | Not built (CM-T045) | Not built; catalogue value only |
| PC-12 | Files (Phase 7) | Unchanged, from the catalogue |
| PC-13 | EXTENDED events for download URLs and note reads | FULL events added; refusals at every level |
| PC-14 | Not built | Catalogue value only; CM-T052 (Phase 11) |
| PC-15, PC-16 | Enforced since Phases 5 to 9 | Unchanged, tested in every profile |
| Section 4 (profile changes) | Not built | Implemented |

Duplicated checks found and consolidated: the PC-03 check of the invitation service (`requireRestrictedStepUp`) and the PC-01 and PC-02 checks of creation and acceptance now use the shared decisions. No conflict with an accepted decision was found; the gaps the documents left open are the decisions below. No control was weakened.

## 3. Decisions

| ID | Decision | Reason |
|---|---|---|
| D-10-01 | The catalogue is code (`packages/shared/src/policy.ts`), version 1 = the Phase 0.5 table; a later change adds a version, never edits one | Data-model 4.16, CM-T046 |
| D-10-02 | A stored version the code does not know makes every request to the room fail with 503 `POLICY_UNSUPPORTED` and the reason recorded; there is no fallback to another version or profile | "Fail closed"; a database writer cannot weaken a room by inventing a version |
| D-10-03 | An upgrade to RESTRICTED also needs RESTRICTED's PC-03 step-up | The change is a sensitive operation of the room it produces; stricter than the minimum |
| D-10-04 | "Existing expiry dates" are those of live files and notes, ACTIVE secrets and open invitations; an item without expiry gets the upgrade time plus the new maximum | Section 4 names expiry dates without listing item types; PC-06 and PC-09 are lifetimes too |
| D-10-05 | On an upgrade to RESTRICTED, ACTIVE secrets without burn-after-reading are revoked (material removed), like invitations that break the new rules | A re-readable secret breaks PC-10; converting it would change what the sender chose |
| D-10-06 | A profile change is allowed while the room is REKEY_REQUIRED or REKEYING and does not change the key state | PC-16 blocks content writes and invitations; a profile change is neither and moves no key |
| D-10-07 | `GET /rooms` (SS-06) still lists a room to a member whose session does not meet its profile (name, profile, role) | The member learns why the room refuses them; room names are non-confidential metadata (T-28); L-60 |
| D-10-08 | PC-03 runs after the matrix and the target lookup; for a RESTRICTED VIEWER the download URL asks for the step-up, then PC-12 refuses | The order of the profile document, step 5; non-recipients and non-permitted roles are refused before any prompt |
| D-10-09 | Profile events go to the redacted security-event log like every event before Phase 12, with severity and counts only | INV-09: no unchained rows in `audit_events` |

No new dependency was added.

## 4. Security review

Answers to the review questions of Prompt 12 section 19, with the evidence:

1. *Clients choose a weaker policy through request fields?* No: strict schemas refuse profile, version and role fields; headers and query fields change nothing; the profile change uses `expectedProfile` only as a precondition (`policy-matrix.test.ts`, `profile-change.test.ts`, NC-10-02).
2. *Authorization bypassed through a secondary endpoint?* No: every route under `/rooms/:roomId` passes the authorizer and its gates (PC-01 and PC-02 tested on all 32 room routes); acceptance applies the same access decision; the inventory pins the PC-03 routes (NC-10-12).
3. *A user operating under the wrong room's profile?* No: the policy comes from the membership row of the addressed room, or the locked row of that room (`policy-matrix.test.ts`, the same session passes STANDARD and is refused in CONFIDENTIAL).
4. *A policy version silently downgraded?* No: only the current version is recorded, and only by a profile change; no request field carries a version.
5. *Unsupported version falls back insecurely?* No: 503 for reads, writes, profile changes and acceptance (NC-10-07).
6. *Sensitive operations bypass recent step-up?* No: gate and locked row (NC-10-03); the forced-order removal test shows the locked check.
7. *Stale step-up authorizes restricted actions?* No: 15-minute and 5-minute windows checked against the server clock; future timestamps never count (NC-10-04).
8. *VIEWER or outsider changes room policy?* No: 403 for ADMIN, MEMBER, VIEWER; 404 for outsiders (`profile-change.test.ts`, BOLA suite).
9. *PLATFORM_ADMIN gains room content?* No: 404 before any profile is read (PA-05).
10. *Expired content available again through profile changes?* No: a change never extends an expiry, triggers refuse a later expiry, and reads check expiry at read time (INV-14).
11. *A downgrade extends item expiry?* No: tested; the triggers refuse it too.
12. *Concurrent updates violate profile requirements?* No: the room row lock serializes changes with writes; forced-order tests for two changes, a note, a rename, a removal and a secret (NC-10-08).
13. *Writes during a forbidden key state?* No: PC-16 unchanged and tested in every profile; a profile change does not unlock the room.
14. *An unauthorized change leaves partial updates?* No: one transaction, refusals before any write; snapshots of every room table in the tests.
15. *The new gates weaken atomic Burn Secret redemption?* No: the gate and the locked re-check run before the destroying statement; a refused reveal leaves the row unchanged (`policy-matrix.test.ts`), the Phase 9 suites pass unchanged except that RESTRICTED actors now meet the profile.
16. *Logs reveal sensitive content through policy failures?* No: refusals record the action and a reason code; profile events record profiles, version, counts and severity.
17. *Legacy invitation checks still enforced?* Yes: PC-04 to PC-07 and PC-16 unchanged, Phase 6 suites pass, and the matrix repeats them per profile.
18. *Policies documented as server-side guarantees?* Yes, with their limits (L-59 to L-62).
19. *UI shows requirements not enforced?* No: the panel lists only enforced rules and marks the cryptoperiod as not yet enforced; external links are not mentioned.
20. *Future features implemented?* No: no rekey, no cryptoperiod worker, no external links, no audit chain, no Security Dashboard, no UI redesign.

Finding during development (fixed before any commit): the first upgrade through the API failed with a database error, because the Phase 6 invitation trigger and the Phase 9 secret guard made `expires_at` write-once. The migration now lets those expiries move only earlier; database tests cover both directions. This was not a security weakness (the upgrade failed closed and wrote nothing).

## 5. Control coverage and verification

| Control | Allowed case | Denied case | Where |
|---|---|---|---|
| PC-01 MFA session | MFA member in every profile; no-MFA member in STANDARD | 403 `MFA_REQUIRED` on all 32 room routes in CONFIDENTIAL and RESTRICTED; after an upgrade; in a write waiting behind an upgrade | matrix, profile-change |
| PC-02 sign-in age | 1 minute inside 12, 4, 1 hours | 401 `REAUTH_REQUIRED` 1 minute outside, on all 32 room routes in each profile; an upgrade the OWNER no longer qualifies for | matrix, profile-change |
| PC-03 step-up | Fresh step-up in RESTRICTED; none needed in STANDARD and CONFIDENTIAL | 401 `STEP_UP_REQUIRED` without and with a 16-minute-old step-up: reveal, download URL, invite, approve, remove, profile change, delete; a removal waiting behind an upgrade | matrix, profile-change |
| PC-04 approval | OWNER's invitation PENDING; ADMIN's PENDING in STANDARD | ADMIN's invitation PENDING_APPROVAL in CONFIDENTIAL and RESTRICTED; revoked by an upgrade | matrix, profile-change |
| PC-05 fingerprint | Optional in STANDARD and CONFIDENTIAL; the correct one in RESTRICTED | 422 `FINGERPRINT_REQUIRED`, 409 `FINGERPRINT_MISMATCH` in RESTRICTED; unconfirmed invitations revoked by an upgrade | matrix, profile-change |
| PC-06 validity | Server-set 7 days, 72 hours, 24 hours | A client-chosen expiry is refused (400); clamped by an upgrade | matrix, profile-change |
| PC-07 history | All retained versions outside RESTRICTED | Older versions refused in RESTRICTED (`invitations.test.ts`, synthetic version 2); revoked by an upgrade | invitations, profile-change |
| PC-08 file and note expiry | Within the maximum (none in STANDARD) | 422 `EXPIRY_NOT_ALLOWED` without expiry or 1 minute over; clamped by an upgrade; never extended by a downgrade | matrix, profile-change |
| PC-09 secret lifetime | 1 minute under the maximum | 1 minute over (422); clamped by an upgrade | matrix, profile-change |
| PC-10 burn | Non-burn allowed outside RESTRICTED | 422 `BURN_REQUIRED` in RESTRICTED; revoked by an upgrade; refused in a creation waiting behind an upgrade | matrix, profile-change |
| PC-11 external links | Not applicable: no route (CM-T045) | The path is 404 in every profile | matrix |
| PC-12 VIEWER file keys | VIEWER reads and downloads in STANDARD and CONFIDENTIAL | 403 `FORBIDDEN` (reason `PROFILE_PC_12`) in RESTRICTED, read and download URL | matrix, `files-access.test.ts` |
| PC-13 audit level | Events present at EXTENDED and FULL | Absent at lower levels (download URL, note read, member list, envelopes) | matrix |
| PC-14 cryptoperiod | Not applicable in Phase 10 (CM-T052) | Catalogue values asserted | matrix, catalogue |
| PC-15, PC-16 | Reveals stay possible while write-locked | Removal sets REKEY_REQUIRED; note, secret, invitation 409 `REKEY_REQUIRED` in every profile | matrix |
| Stored version | Version 1 | 503 `POLICY_UNSUPPORTED` for version 2: read, write, profile change, acceptance | matrix |

Gates on the final Phase 10 code (2026-10-12, local PostgreSQL 17 and storage), EV-10-05:

| Gate | Result |
|---|---|
| `pnpm install --frozen-lockfile`, `pnpm format:check`, `pnpm lint`, `pnpm typecheck` | Pass |
| `pnpm test` | 2201 tests in 84 files, all pass (Phase 9: 2044 in 81). New: `tests/policy` (matrix 110, profile changes 14), `policy-catalogue.test.ts` (25, replaces `profile-requirements.test.ts`), `policy.test.ts`. A first full run had one authz test fail with "timed out in 60000ms" after 596 s: the test process stalled (its timer could not fire). It passed in isolation and the whole suite passed on the second run, with a 10-second tick logger showing no stall; nothing was changed in between |
| `pnpm test:e2e` (three engines, one worker) | 118 passed, 16 skipped by design (the policy flow runs in Chromium only), 1 failed: the Firefox two-tab reveal test of Phase 9, a navigation to the static page that did not finish within the 5-minute test limit. It passed on rerun in 10.5 s and touches no Phase 10 code (STANDARD room) |
| `pnpm security:negative-controls` | 102 of 102 caught (twelve new: NC-10-01 to NC-10-12); both baselines pass; 54 source files restored byte for byte |
| `pnpm test:coverage:crypto` | 98.79% statements, 94.16% branches (gate 90%) |
| `pnpm test:coverage:authz` (now including `policy.ts`) | 96.92% statements, 97.24% branches; `policy.ts` 96.49% and 96% |
| `pnpm build`, `pnpm smoke:api`, `pnpm sbom:generate`, `db:validate`, `db:check-schema`, `db:drift` | Pass; 16 models, 232 classified fields, no drift |
| `pnpm audit:deps` | No known vulnerabilities; no dependency added or changed |
| Secret scan (gitleaks, pinned image) | Staged changes and full history (63 commits): no leaks found |

## 6. Negative controls

Each control writes one real defect into the working tree, runs the tests that must catch it, and restores the file (`scripts/security/negative-controls.mjs`, EV-10-06). Five older controls were updated so that their injected records carry a policy version and their anchors follow the moved code (NC-05-01, NC-05-05, NC-05-21, NC-07-08, NC-09-08); with `--show-failures` they fail the same tests as before, not a 503.

| ID | Deliberate defect | Detected by | Result |
|---|---|---|---|
| NC-10-01 | The room gate skips PC-01 and PC-02 | `policy-matrix.test.ts` | Caught |
| NC-10-02 | The profile change trusts the client's claim of the current profile | `profile-change.test.ts` (stale request, concurrent changes) | Caught |
| NC-10-03 | PC-03 removed at the gate and the locked re-check | `policy-matrix.test.ts` | Caught |
| NC-10-04 | An expired step-up is accepted | `policy-matrix.test.ts`, `profile-change.test.ts` | Caught |
| NC-10-05 | A downgrade needs no 5-minute step-up | `profile-change.test.ts` | Caught |
| NC-10-06 | No expiry clamping of files and notes on upgrade | `profile-change.test.ts` | Caught |
| NC-10-07 | An unsupported version falls back to version 1 | `policy-matrix.test.ts` | Caught |
| NC-10-08 | The locked re-check ignores the profile (TOCTOU) | `profile-change.test.ts` (forced lock order) | Caught |
| NC-10-09 | Rule-breaking invitations kept on upgrade | `profile-change.test.ts` | Caught |
| NC-10-10 | Re-readable secrets kept on upgrade to RESTRICTED | `profile-change.test.ts` | Caught |
| NC-10-11 | FULL level records no envelope fetches or member-list views | `policy-matrix.test.ts` | Caught |
| NC-10-12 | The download-URL route forgets its PC-03 declaration | `route-inventory.test.ts`, `policy-matrix.test.ts` | Caught |

## 7. Evidence

In [../report/evidence/phase-10/](../report/evidence/phase-10/), synthetic data only: EV-10-01 (policy matrix report, 149 tests), EV-10-02 (the three RESTRICTED refusals as API responses with their recorded reasons, and the browser refusal of a member without MFA), EV-10-03 (the recorded `PROFILE_DOWNGRADED` event with severity HIGH, and the downgrade in the browser), EV-10-04 (the profile panel after an upgrade), EV-10-05 (gates, section 5), EV-10-06 (negative controls). EV-10-07 is the CI run of pull request #30 (run 38236439654, three attempts): the dependency audit, GitGuardian and the secret scan passed and every Vitest project passed, but the E2E step failed on three attempts, each time on a different Phase 5 to 9 test (attempt 1: Firefox secrets two-tab, WebKit room-keys, WebKit rooms; 2: WebKit secrets lock-vault; 3: WebKit notes tamper), none in `policies.spec.ts`. `main`'s own run after the Phase 9 merge (38217990916) and the Phase 9 handoff run (38217907402) failed the same way, and the Phase 9 baseline also failed two E2E tests locally; each of these tests passes alone. The project owner merged pull request #30 manually after being told this. The Jira history of CM-T046 to CM-T049 stays pending until the backlog is imported; no Jira item was moved.
