# Phase 5 Traceability

Status: in progress. Prompt 07A implemented CM-T029 on 2026-10-06 on the Phase 5 branch; CM-T030, CM-T031 and CM-T032 are not started. Covers CM-T029 to CM-T032 in [jira-backlog.md](jira-backlog.md) (checked against the current backlog before the work started). No item is DONE: DONE requires SECURITY REVIEW and TESTING in Jira and the full Definition of Done (CLAUDE.md section 14), including CI on the pull request, which Prompt 07C opens.

Branch: `feature/CM-T029-secure-rooms-rbac`, created from the updated `main` (`5c1ed32`: Phases 0 to 4 through pull requests #1, #7, #8 and #10, plus the handoff updates of #9 and #12). No pull request yet. The phase is split over three sessions: Prompt 07A (CM-T029), Prompt 07B (CM-T030, CM-T031) and Prompt 07C (CM-T032, final gates, evidence, pull request).

Normative sources: [../security/authorization-model.md](../security/authorization-model.md) sections 1 to 8 (section 9 records the implementation), [../security/security-policy-profiles.md](../security/security-policy-profiles.md) section 6, [../architecture/data-model.md](../architecture/data-model.md) 4.6 and 4.7. No schema change and no migration: the existing `rooms` and `room_members` tables, their partial unique indexes and the `cm_api` grants were sufficient.

## 1. Work items

Each row reads: requirement, then implementation, then test, then evidence.

| Item | Requirement (acceptance criterion) | Implementation | Tests | Evidence | Result |
|---|---|---|---|---|---|
| CM-T029 Central authorization module | The AZ, PA and SS matrix as data in `packages/shared` | `packages/shared/src/authorization.ts`: `ROOM_ACTIONS` (AZ-01 to AZ-30), `ACCOUNT_ACTIONS` (PA-01 to PA-05, SS-01 to SS-05), deeply frozen | `authorization.test.ts`; `authz-matrix.test.ts` parses the model and compares every cell; NC-05-06 | EV-05-01 (Prompt 07C) | Met |
| | A pure `authorize()` function | `decideRoomAction`: membership, room state and target facts in, allow or a reason code out; platform role not an input | `authorization.test.ts` (428 tests: every action and role through every kind of fact); NC-05-02, NC-05-07 | | Met |
| | Action declarations on every route | Registry: matrix action consistent with access, room path, step-up, resource loader, platform gate, paths that name a room, path and parameter grammar | `registry.test.ts`, `route-inventory.test.ts`; NC-05-08, NC-05-09 | | Met |
| | Room-scope middleware implementing OL-01 | `apps/api/src/authorization/rooms.ts`, run by the registry for every room route before the handler | `room-access.test.ts` (test-only room routes through the production registry); NC-05-01, NC-05-05 | | Met. No production room route exists yet (CM-T030) |
| | Room-scoped repository functions | `apps/api/src/db/room-access-store.ts`: the membership lookup, scoped by room, user, ACTIVE membership and ACTIVE room in the query; per-route resource loaders for target objects | `membership-lookup.test.ts`; NC-05-03, NC-05-04 | | Partly: room and member repository functions arrive with their routes (CM-T030, CM-T031) |
| | The error semantics of the authorization model | Reason codes mapped to the generic 404 and 403 (model section 9.4); `ROOM_ACCESS_DENIED` security event with action and reason only | `rooms.test.ts`, `room-access.test.ts` | | Met for room authorization. The 409 codes belong to the policy gates (CM-T047) and the rekey state machine (CM-T050, CM-T051) |
| | Exhaustive unit tests over every action and role; coverage at least 90% | `pnpm test:coverage:authz` in CI | 97.3% statements, 98.3% branches, 100% functions | | Met |
| | Route inventory test fails for any undeclared or untested route | Undeclared or inconsistent declarations stop the application at startup; room routes exist only as a reviewed list | `route-inventory.test.ts` | | Partly: "untested" is enforced through the reviewed list now and by the BOLA suite over every room route in CM-T032 |
| | PLATFORM_ADMIN receives 404 on room-scoped endpoints of rooms they are not in | The platform role is not an input of the decision | `room-access.test.ts` (with an MFA-verified session and a step-up); NC-05-05 | | Met for the test routes; production room routes follow in CM-T030 and CM-T031 |
| CM-T030 Room creation, listing, renaming, deletion | | Not started | | | Prompt 07B |
| CM-T031 Membership administration | | Not started | | | Prompt 07B |
| CM-T032 BOLA and IDOR suite | | Not started | | EV-05-02, EV-05-03 | Prompt 07C |

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

## 5. Open items for Prompt 07B

- Listing one's own rooms has no matrix action yet (authorization model section 9.5).
- Membership suspension when PA-03 disables an account (authentication-security.md promises it for Phase 5).
- Role changes and ownership transfer must re-check the stored state inside their transaction.
- ADR-011: the identifier routing pattern is confirmed with the first room page of the web client.
