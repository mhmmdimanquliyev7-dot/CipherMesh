# Phase 5 Traceability

Status: implemented on 2026-10-06 (Prompts 07A to 07C): CM-T029 to CM-T032 are implemented, verified and merged into `main` through pull request #13 (merge commit `bd4d2f6`, CI run 37462944884, EV-05-06). Covers CM-T029 to CM-T032 in [jira-backlog.md](jira-backlog.md) (checked against the current backlog before the work started). No item is DONE: DONE requires SECURITY REVIEW and TESTING in Jira and the full Definition of Done (CLAUDE.md section 14).

Branch: `feature/CM-T029-secure-rooms-rbac`, created from the updated `main` (`5c1ed32`: Phases 0 to 4 through pull requests #1, #7, #8 and #10, plus the handoff updates of #9 and #12). The phase was split over three sessions: Prompt 07A (CM-T029), Prompt 07B (CM-T030, CM-T031) and Prompt 07C (CM-T032, final gates, evidence, pull request).

Normative sources: [../security/authorization-model.md](../security/authorization-model.md) sections 1 to 8 (section 9 records the implementation), [../security/security-policy-profiles.md](../security/security-policy-profiles.md) section 6, [../architecture/data-model.md](../architecture/data-model.md) 4.6 and 4.7. No schema change and no migration in Phase 5 so far: the existing `rooms` and `room_members` tables, their partial unique indexes and CHECK constraints, and the `cm_api` and `cm_worker` grants were sufficient. Prompt 07B added the self-service action SS-06 to the authorization model (section 4). Prompt 07C added no schema change either; its one dependency change is the `source-map-js` lockfile refresh (section 10, EV-05-04).

## 1. Work items

Each row reads: requirement, then implementation, then test, then evidence.

| Item | Requirement (acceptance criterion) | Implementation | Tests | Evidence | Result |
|---|---|---|---|---|---|
| CM-T029 Central authorization module | The AZ, PA and SS matrix as data in `packages/shared` | `packages/shared/src/authorization.ts`: `ROOM_ACTIONS` (AZ-01 to AZ-30), `ACCOUNT_ACTIONS` (PA-01 to PA-05, SS-01 to SS-05), deeply frozen | `authorization.test.ts`; `authz-matrix.test.ts` parses the model and compares every cell; NC-05-06 | EV-05-01 (Prompt 07C) | Met |
| | A pure `authorize()` function | `decideRoomAction`: membership, room state and target facts in, allow or a reason code out; platform role not an input | `authorization.test.ts` (428 tests: every action and role through every kind of fact); NC-05-02, NC-05-07 | | Met |
| | Action declarations on every route | Registry: matrix action consistent with access, room path, step-up, resource loader, platform gate, paths that name a room, path and parameter grammar | `registry.test.ts`, `route-inventory.test.ts`; NC-05-08, NC-05-09 | | Met |
| | Room-scope middleware implementing OL-01 | `apps/api/src/authorization/rooms.ts`, run by the registry for every room route before the handler | `room-access.test.ts` (test-only room routes through the production registry); NC-05-01, NC-05-05 | | Met; the production room routes of CM-T030 and CM-T031 use it |
| | Room-scoped repository functions | `apps/api/src/db/room-access-store.ts`: the membership lookup, scoped by room, user, ACTIVE membership and ACTIVE room in the query; per-route resource loaders for target objects | `membership-lookup.test.ts`; NC-05-03, NC-05-04 | | Met: `apps/api/src/db/room-store.ts` (Prompt 07B) adds the room and member functions, every one constrained by room ID and the caller's membership |
| | The error semantics of the authorization model | Reason codes mapped to the generic 404 and 403 (model section 9.4); `ROOM_ACCESS_DENIED` security event with action and reason only | `rooms.test.ts`, `room-access.test.ts` | | Met for room authorization. The 409 codes belong to the policy gates (CM-T047) and the rekey state machine (CM-T050, CM-T051) |
| | Exhaustive unit tests over every action and role; coverage at least 90% | `pnpm test:coverage:authz` in CI | 97.3% statements, 98.3% branches, 100% functions | | Met |
| | Route inventory test fails for any undeclared or untested route | Undeclared or inconsistent declarations stop the application at startup; room routes exist only as a reviewed list | `route-inventory.test.ts` | | Partly: "untested" is enforced through the reviewed list now and by the BOLA suite over every room route in CM-T032 |
| | PLATFORM_ADMIN receives 404 on room-scoped endpoints of rooms they are not in | The platform role is not an input of the decision | `room-access.test.ts` (with an MFA-verified session and a step-up); NC-05-05 | | Met for the test routes and the production room routes (`rooms-lifecycle.test.ts`, `membership-admin.test.ts`) |
| CM-T030 Room creation, listing, renaming, deletion | Create a room with name, profile and OWNER membership | `POST /rooms` (SS-04): client-chosen UUIDv4 ID (DF-05), normalized name, profile; ACTIVE account under a user-row lock, ACTIVE vault, PC-01 and PC-02 for the profile; room and OWNER membership in one transaction, no key material | `rooms-lifecycle.test.ts`, `profile-requirements.test.ts`, `rooms.test.ts` (validation) | | Met. Key material joins creation in CM-T033 (L-43) |
| | List rooms filtered by membership in the query; users see only rooms they belong to | `GET /rooms` (SS-06, added to the model): ACTIVE memberships in ACTIVE rooms, in the query, keyset pages of at most 50 (OL-08) | `rooms-lifecycle.test.ts`; NC-05-17 | | Met |
| | Rename (AZ-02) | `POST /rooms/{roomId}/rename`, re-authorized under the room lock | `rooms-lifecycle.test.ts` (every role, cross-room, forged fields) | | Met |
| | Delete with step-up (AZ-04) into DELETING, with worker cleanup; deleted rooms refuse all reads immediately | `POST /rooms/{roomId}/delete` (step-up); DELETING refuses every request; `runRoomCleanup` in `pnpm worker:retention` makes a room DELETED only when no envelope, file, note or secret row is left | `rooms-lifecycle.test.ts`, `membership-concurrency.test.ts` | | Met |
| | Room-name warning in the UI | Rooms page and rename form; names refused with control or bidirectional-override characters | `rooms.spec.ts` (three engines) | | Met |
| | Audit events for creation, rename and deletion | `ROOM_CREATED`, `ROOM_RENAMED`, `ROOM_DELETED` without the name, to the security-event sink (L-33) | `rooms-lifecycle.test.ts` | | Met in the log; the ledger is Phase 12 (INV-09) |
| CM-T031 Membership administration | Role changes (AZ-10) with tests for every allowed and denied combination | `POST /rooms/{roomId}/members/{userId}/role`; target loaded by room and user ID; re-authorized under lock; epoch incremented | `membership-admin.test.ts` (all nine combinations for OWNER and ADMIN, MEMBER and VIEWER callers, OWNER never assignable) | | Met |
| | Ownership transfer to an ADMIN with step-up (AZ-05); the one-OWNER invariant cannot be broken through any endpoint | `POST /rooms/{roomId}/members/{userId}/transfer-ownership`; demote then promote under the room lock, both conditional; partial unique index as backstop; former OWNER becomes ADMIN | `membership-admin.test.ts`, `membership-concurrency.test.ts`; NC-05-13 to NC-05-15 | | Met |
| | Member removal (AZ-09, requested for Prompt 07B; DF-10) | `POST /rooms/{roomId}/members/{userId}/remove`: REMOVED, envelopes deleted, epoch incremented, REKEY_REQUIRED in one transaction (INV-07) | `membership-admin.test.ts`, `membership-concurrency.test.ts` | | Met. The rekey itself is Phase 11 (L-44) |
| PA-03 room consequence (authentication-security.md, "Phase 5") | Disabling an account suspends its memberships and sets those rooms to REKEY_REQUIRED | In the disable transaction: memberships SUSPENDED (ACCOUNT_DISABLED), envelopes deleted, rooms REKEY_REQUIRED with MEMBER_SUSPENDED; re-enabling restores no membership (AZ-14, Phase 6) | `account-disable.test.ts` (including a race with room creation); NC-05-16 | | Met |
| CM-T032 BOLA and IDOR suite | A reusable harness that creates two rooms with separate members and calls every room-scoped endpoint with identifiers from the other room | `tests/authz/bola.test.ts` (49 tests): two rooms, members in every role and state, people in two rooms with different roles, a PLATFORM_ADMIN, drives every case of `tests/helpers/bola-cases.ts` | `bola.test.ts`; NC-05-18 to NC-05-21 | EV-05-02, EV-05-03 | Met |
| | Every route in the registry is covered; all return 404 without side effects | Nine routes (seven room routes and the two self-service routes) with attack classes A to H; cross-room and outsider attacks give the generic 404, identical for a real and an invented room, and every denied mutation leaves rooms and memberships byte-for-byte unchanged. Where a role is refused by the matrix inside its own room (403), nothing about another room is revealed | `bola.test.ts` (classes A, B, C, G) | EV-05-02 | Met |
| | The suite fails when a new route has no coverage; runs in CI | `tests/security/bola-inventory.test.ts` compares the reviewed table with the production registry in both directions; both files run in `pnpm test` and so in CI | `bola-inventory.test.ts`; NC-05-22 | EV-05-02 | Met |

## 2. Security review of the CM-T029 change

| Check | Outcome |
|---|---|
| BOLA or IDOR through queries | The lookup filters by room ID and session user in the query, and the decision re-checks both; target objects must report the addressed room (`RESOURCE_OUTSIDE_ROOM`). Proven by `membership-lookup.test.ts`, NC-05-03 |
| Authorization from request fields | None: the actor comes from the session and the role from the membership row; strict schemas reject role fields; forged headers are ignored (`room-access.test.ts`) |
| Cross-room confusion | A membership of another room or user is `MEMBERSHIP_MISMATCH`; an OWNER of room B is an outsider in room A |
| PLATFORM_ADMIN bypass | Not possible through the decision, which has no platform-role input; as a member, a PLATFORM_ADMIN has exactly that member's role. NC-05-05 |
| OWNER and ADMIN confusion | OWNER-only actions (AZ-03, AZ-04, AZ-05, AZ-07) and the role ceilings asserted independently of the catalogue; NC-05-06, NC-05-07 |
| Stale membership | Loaded on every request, nothing cached; role changes and removals apply on the next request. Writes that change membership must re-check inside their transaction (model section 9.4, a rule for CM-T031) |
| UI-only access control | None. The web client may read the matrix only to hide controls |
| Route-registry bypass | Room actions need room routes, paths that name a room need room access, and no route can be mounted outside the registry (existing test); NC-05-08, NC-05-09 |
| Projections | Explicit `select`: identifiers, role and states only; no room name, no key material |
| Disclosure through different errors | One 404 body for outsiders, nonexistent rooms, malformed identifiers and objects outside the room; targets are never looked up for refused callers |
| Logging | Denials record the action ID and reason code with the actor and request ID; no room name, no request field |
| Phase 6 cryptography | None: no key material, envelopes, signatures or Room Safety Code |

**Finding R-05-01 (fixed in this change):** the new path parameters made Express decode route parameters while matching, before authentication. An undecodable percent-encoding (for example `%E0%A4%A`) raised a URIError that reached the error handler as an unhandled 500, with the raw segment in the logged error message. It disclosed nothing and granted nothing, but let anyone without a session produce unhandled-error log entries. The error handler now answers such errors with the generic 404 and logs no message. The regression test in `tests/security/malformed-requests.test.ts` failed before the fix (three cases and the existing "never logs an unhandled error" check) and passes after it; NC-05-10 reverts the fix. Linked threats: T-15, T-26.

## 3. Decisions and deviations

| Item | Decision | Reason |
|---|---|---|
| Profile conditions and the key-state lock (PC-16) | Not part of CM-T029 | They are gates of the policy engine (CM-T046, CM-T047). INV-07 still applies to the first invitation or content-write route (Phase 6) |
| AZ-27 | `inherited`: denied by the decision and not declarable | "Same as read access to the item" has no permission of its own |
| AZ-05 | OWNER rule restricted to a current ADMIN as target | The action title ("Transfer ownership to an ADMIN") |
| AZ-13 | Role cells only; OL-13 operation rules with the rekey state machine | They need the operation row (CM-T050) |
| Malformed path parameters | Generic 404, not 400 | A malformed identifier names no resource (OL-02) and a 400 would confirm the route's shape |
| Process | Targeted test runs only during Prompt 07A | The project owner split Phase 5 over three sessions; CLAUDE.md section 10 asks for the full gates before every commit, and they run in Prompt 07C before the pull request. Targeted runs: section 4 |

## 4. Verification in Prompt 07A

Targeted, on 2026-10-06, against the local PostgreSQL:

| Command | Result |
|---|---|
| `vitest run --project unit packages/shared apps/api/src` | 660 passed (10 files) |
| `vitest run --project security --project integration --project authz` | 166 passed (10 files) |
| `vitest run --project auth` for `step-up`, `admin`, `csrf`, `logging` (the registry gates are shared by every route) | 158 passed |
| `pnpm test:coverage:authz` | 97.3% statements, 98.3% branches |
| `node scripts/security/negative-controls.mjs --only=NC-05` | 10 of 10 caught; baseline passes; sources restored byte for byte |
| `pnpm typecheck`, ESLint and Prettier on the changed files, `pnpm --filter @ciphermesh/api build` | Pass |

Not run in Prompt 07A, by instruction (Prompt 07C): the complete `pnpm test`, the three-browser Playwright suite, the full negative-control run, SBOM, dependency audit and the full-history secret scan. Staged changes were scanned with gitleaks before each commit.

## 5. Open items for Prompt 07B (all resolved in Prompt 07B)

- Room listing: SS-06 added to the authorization model and the catalogue.
- PA-03 suspension: implemented in the disable transaction.
- In-transaction re-checks: every room change locks and re-authorizes (`reauthorizeRoomAction`).
- ADR-011: identifier routing confirmed with `/rooms/room?id=<UUIDv4>` in three engines.

## 6. Security review of the CM-T030 and CM-T031 change (Prompt 07B)

| Check | Outcome |
|---|---|
| Wrong role matrix | Routes use the shared catalogue; every role-change combination, removal ceiling and transfer case tested; NC-05-14 widens AZ-05 and is caught |
| Cross-room lookups | Target members loaded by room ID and user ID at the gate and again under lock; the locked row reports its own room, so the decision would reject a wrong one (store tests, NC-05-11, NC-05-12) |
| Client-controlled role or user ID | Strict schemas; OWNER not representable in a role change; the caller is the session user and roles come from rows |
| PLATFORM_ADMIN bypass | No room access without membership (list, delete, transfer tested); may create its own room like any user with a vault (model 9.5) |
| Multiple OWNER race | Room lock, re-authorization and conditional updates; demote before promote; partial unique index; two concurrent transfers leave one OWNER (forced race) |
| Stale membership | Gate decision re-run on locked state for every change; NC-05-13 removes it and the forced races fail |
| Disabled account keeps memberships | Suspended in the disable transaction, ordered against room creation; NC-05-16 |
| Deleted-room access | DELETING refuses every request immediately; races with rename and role change leave it DELETING |
| Step-up bypass | AZ-04 and AZ-05 routes declare the step-up, which the registry requires from the catalogue; tested for OWNER and for PLATFORM_ADMIN |
| UI-only authorization | Controls derived from the shared matrix are UX only; every action re-checked by the API |
| Route-registry bypass | All nine routes registered with matrix actions; reviewed inventory lists them; GET routes read only |
| Overbroad projections | Explicit selects; member lists without email or membership IDs |
| Audit leakage | Events carry room IDs, roles, reason codes and counts, never names, tokens or keys (tested) |
| Accidental room cryptography | None created or read; envelope rows only deleted on member loss (INV-07) and appear in tests as DUMMY fixtures |

No new security finding: the review produced one hardening (`lockMembership` and the actor facts now take the room from the locked row) before any commit.

## 7. Decisions recorded in Prompt 07B

| Item | Decision | Reason |
|---|---|---|
| SS-06 | New self-service action "List own rooms" | A list over the caller's memberships is not an action in one room (model 9.5) |
| Former OWNER after a transfer | Becomes ADMIN | Section 2.1 leaves it open; ADMIN keeps the person in the room with the next lower role |
| Removal of SUSPENDED members | Allowed with the same ceilings and the full member-loss transaction | Lets an OWNER or ADMIN clean up; conservative REKEY_REQUIRED |
| Room deletion cleanup | DELETED only when no envelope or content row is left | Fail-safe for later phases; destroys no key material |
| Profile requirements at creation | PC-01 and PC-02 from shared constants compared with the profile table | Creation needs them now; the policy engine (CM-T046, CM-T047) takes over later (L-42) |
| Policy version | 1 on every room | The profile table as approved in Phase 0.5 |
| Events | Room lifecycle events in the security-event catalogue | INV-09 forbids `audit_events` rows before the hash chain |
| Process | Full CLAUDE.md gates before each commit; E2E locally with one worker | The project owner asked for the full gates; this machine runs out of memory with parallel browsers (CI keeps the default) |

## 8. Verification in Prompt 07B

Full gates of CLAUDE.md section 10, run on 2026-10-06 against the local PostgreSQL, serially:

| Gate | Result |
|---|---|
| `pnpm install --frozen-lockfile`, `pnpm format:check`, `pnpm lint`, `pnpm typecheck` | Pass |
| `pnpm test` | Pass: 1462 tests in 64 files (Phase 4 ended at 772 in 53; Phases 5A and 5B add 690) |
| `pnpm build`, `pnpm smoke:api` | Pass (the graceful-shutdown check is not observable on Windows) |
| `pnpm test:e2e` (Chromium, Firefox, WebKit) | Pass with one worker: 58 passed, 2 skipped by design (the cross-engine vault test runs once). The rooms spec adds 6 |
| `pnpm security:negative-controls` (all) | 44 of 44 caught, both baselines pass, 27 sources restored byte for byte |
| `pnpm sbom:generate` | Generated (`sbom.cdx.json`, git-ignored) |
| `pnpm audit:deps` | **Fails**: one high advisory, `source-map-js` below 1.2.2 (GHSA-68fv-2mgg-jv7q), a build-time dependency of the web toolchain (`next`, `postcss`, Tailwind). No dependency changed in Phase 5: the same advisory applies to `main`. 1.2.2 was published 2026-09-30 and meets the release-age rule. Not fixed in Prompt 07B (a lockfile override changes the web build toolchain and needs its own review and E2E run); decision for the project owner, due before the Phase 5 pull request (Prompt 07C) |
| `pnpm scan:secrets --staged` | Run on staged changes before each commit (pinned gitleaks image): no findings. The full-history scan is a Prompt 07C gate |

Problems met while verifying, none hidden by weakening a test:
- **Connection limit.** One full run failed with `too many connections for role "cm_api"`: the new authz files each open an API pool and several clients, and the role is limited to 40 connections by design. The `authz` project now runs its files one at a time (`fileParallelism: false`); the peak during a full run is 24 of 40. The role limit was not changed.
- **Key-generation timeout.** `packages/crypto/src/identity.test.ts` timed out once at its 5-second default when two RSA-3072 key pairs were generated under load. The two tests that generate two pairs now have an explicit 30-second limit; no assertion changed, and `packages/crypto` is otherwise untouched.
- **Intermittent crypto test (found and fixed).** `packages/crypto/src/vault.test.ts` "refuses a second derivation while one is running" failed in about three of about twelve full runs (Prompts 07B and 07C locally, and once in CI on `main` after the merge, where the rerun of the same commit passed) and never when run alone. Root cause (found after it failed in CI on `main` after the merge): both concurrent calls verify the record with WebCrypto before their derivation starts and those steps finish in no guaranteed order, so either call can reach the derivation first; the test assumed it was always the first call, and when it was not, the first call was the one refused (an unhandled `KDF_BUSY` rejection) while the second succeeded. The product behaviour was correct: exactly one of two concurrent derivations was refused. The test now holds whichever derivation starts first until it is released, so the other call must be refused while it is held, with no timing assumption; it still fails if the busy guard is removed (checked by deleting the guard), passed 5 of 5 times and 6 of 6 under heavy CPU load, and no assertion about the guard was weakened. This is the only change to `packages/crypto` since Phase 4.
- **Timing-dependent tests seen in CI after the merge.** CI of the post-merge documentation pull request then failed twice in two other timing-dependent places, neither related to its change (a crypto test file and documents): the cross-engine vault E2E (`vault.spec.ts`, Chromium launching Firefox and WebKit) did not see "Vault unlocked" within its 90 seconds on a loaded runner in attempt 1, and in attempt 2 `tests/auth/mfa.test.ts` "accepts one step of clock drift either way" failed its replay check: each attempt logs in with Argon2id before computing its code from the real clock, so on a slow runner two "same step" attempts can straddle a 30-second TOTP step boundary, and the second is then a new step, which the server rightly accepts. The authentication code and the test were unchanged since Phase 3. The test now starts the sequence just after a step boundary (no assertion changed; NC-03-04, TOTP replay allowed, still fails it). The E2E timeout did not recur and is recorded, not changed.
- **E2E.** A first run with the default worker count ran out of memory (known on this machine); a second failed one registration with "Unexpected response from the server" in the first test of the run, which did not reproduce in the next full run (cause not established; the third run passed all 58). The E2E runs use one worker locally; CI keeps its default.
- **Negative controls.** Two full runs reported the five Phase 4 browser controls as "build failed" because I had loaded `NODE_ENV=development` from `.env`, which `next build` rejects. That was my invocation, not the code: with `NODE_ENV` unset the run passes.

## 9. Security review of the CM-T032 change and of Phase 5 as a whole (Prompt 07C)

Reviewed against T-04, T-05, T-06, T-21, T-28 and T-37, reading the final room routes, service, store, authorizer and registry:

| Check | Outcome |
|---|---|
| Room and user ID confusion | Path parameters are validated as UUIDv4 and named by schema; the caller is the session user; target lookups take the room ID and the user ID together |
| Broad queries filtered in memory | None: every read filters by room and the caller's ACTIVE membership in the query; list pages come from the query |
| Target fetched without the room | The gate loader and the locked re-check both select by room and user; the decision rejects a row whose room differs (three layers); the BOLA suite and NC-05-19 prove all three must fail together for a cross-room change |
| PLATFORM_ADMIN bypass | The platform role is not an input anywhere in the room path; proven at the outside (suite) and by NC-05-21 |
| OWNER and ADMIN confusion | Authority is per room: an ADMIN of one room is a VIEWER in another and an OWNER is a MEMBER, proven by the people in two rooms |
| Stale membership, TOCTOU | Every change re-runs the decision under the room lock on locked rows; forced races in the concurrency suite; NC-05-13 |
| Deleted-room and suspension access | DELETING and DELETED rooms refuse their own OWNER; SUSPENDED, REMOVED and LEFT members get the same 404 as strangers |
| Differentiated unauthorized errors | Outsiders, nonexistent rooms, former members, DELETING rooms and cross-room targets all answer with the same 404 body; NC-05-18 shows the suite detects a differing answer. A member refused by role gets 403, which discloses only their own room's rule |
| Over-projection and logging | Strict response schemas, no email or membership ID in member lists, no room name in any event or refusal |
| Registry declarations | Nine routes, each with a matrix action, checked at startup; the reviewed lists and the inventory fail on drift |
| Writes before authorization | None: every write is after the locked re-authorization, and creation after its own checks |

No new finding in Prompt 07C. The suite passed on its first full run against the code of Prompt 07B; its value is shown by the controls, which fail it when any layer is removed. Known and documented: L-45 (a reused room ID answers 409), and timing differences are not tested.

## 10. Dependency audit remediation (Prompt 07C)

Prompt 07B could not pass `pnpm audit:deps`: one high advisory on `source-map-js` below 1.2.2 (GHSA-68fv-2mgg-jv7q), reached only through the web build toolchain, present on `main` and unrelated to rooms. Every dependent declares `^1.2.1`, so a lockfile-only `pnpm update source-map-js --recursive` moved the single resolved version to 1.2.2 (published 2026-09-30, past the three-day release-age rule). `package.json` and `pnpm-workspace.yaml` are unchanged, no override or allowlist was added, and the audit threshold is unchanged. The lockfile diff is seven lines. Frozen install, audit, build, the full test suite, E2E in three engines and the SBOM were run on the result. Evidence: EV-05-04.

## 11. Decisions recorded in Prompt 07C

| Item | Decision | Reason |
|---|---|---|
| Place of the BOLA suite | `tests/authz/bola.test.ts` and `tests/security/bola-inventory.test.ts`, not a file in the `security` project | The attack suite needs the database global setup of the `authz` project; the inventory needs none and runs in `security` |
| Layered controls | The harness accepts several files per defect | The room checks repeat on purpose; a defect that must reach the outside has to defeat all layers |
| Dependency fix | Lockfile refresh, no override | The parents' ranges already accept the patched version |
| Local E2E | One worker | Parallel browsers run out of memory on this machine; the three engines all run |
| Evidence IDs | EV-05-01 to EV-05-03 as in the evidence plan, EV-05-04 and EV-05-05 added | Phase 4 added further IDs in the same way; EV-05-03, optional in the plan, is the local negative-control run |

## 12. Verification in Prompt 07C

Gates of CLAUDE.md section 10 on the final code (2026-10-06), details in EV-05-05:

| Gate | Result |
|---|---|
| `pnpm install --frozen-lockfile`, format, lint, typecheck | Pass |
| `pnpm test` | Pass: 1516 tests in 66 files (07B: 1462 in 64; CM-T032 adds 49 and 5) |
| `pnpm build`, `pnpm smoke:api` | Pass |
| `pnpm test:e2e` (Chromium, Firefox, WebKit, one worker) | 58 passed, 2 skipped by design |
| `pnpm security:negative-controls` | 49 of 49 caught (44 before; NC-05-18 to NC-05-22 added), both baselines pass, 28 sources restored byte for byte |
| `pnpm audit:deps` | Pass: no known vulnerabilities |
| `pnpm sbom:generate` | Generated; `source-map-js@1.2.2` only |
| `pnpm scan:secrets` (full history) | 44 commits scanned, no leaks |

The two intermittent tests of 07B did not fail in these runs.

## 13. Remaining after Phase 5

- L-42 (profile gates on every room request, CM-T046 and CM-T047), L-43 (rooms without a key version until CM-T033), L-44 (rekey, reinstatement), L-45 (reused room ID, no quota). See [../security/limitations.md](../security/limitations.md).
- Phase 6 must make invitation acceptance lock the invitee's user row like room creation, so an account disable cannot miss a membership it creates.
- Room cryptography is not part of Phase 5: no room key, envelope, commitment, signed statement, rekey or Room Safety Code exists. Prompt 08 starts the room-key work from the updated `main`.
