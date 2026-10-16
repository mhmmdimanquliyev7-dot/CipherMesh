# Operational ISMS: Traceability (Phase 22A, CM-EPIC-17)

Status: implemented and merged into `main` through pull request #39 (merge commit `92ded2f`, 2026-10-16; CI run 38794222646 passed every job, EV-22-18), approved by the project owner as a dedicated workstream before the final report. Decision record: [ADR-016](../architecture/adr/ADR-016-operational-isms-records.md). Manual: [isms-operations.md](../security/isms-operations.md). The final university report (CM-T081) is **not started** and needs the owner's approval.

## 1. Baseline and gap analysis (2026-10-15, `main` at `b643a2b`)

| Area | Before this workstream | Kind | Now |
|---|---|---|---|
| Scope (4.3) | Phase 0 statement naming a cloud VM and managed services | Documentation, outdated | Revision 2 matching the local Docker demonstration; boundaries B-01 to B-08; fingerprinted; scope review records |
| Context (4.1, 4.2) | Not documented | Missing | Issues ISS-01 to ISS-06, interested parties IP-01 to IP-06 |
| Roles (5.3) | One sentence in the mapping | Documentation | ROLE-01 to ROLE-06, actual versus not available (no independent reviewer) |
| Policies (5.2) | 13 governing documents listed by the Trust Center | Documentation only | Policy register POL-01 to POL-13 with owners and review cycles; lifecycle computed from decision records and document fingerprints |
| Assets (5.9) | A-01 to A-13 with security properties | Documentation | A-01 to A-18 with category, owner, classification, integrity and availability, location; linked to risks |
| Risk assessment (6.1.2) | 44 risks with documented ratings | Documentation | 45 risks (T-45 added); dated re-assessments as records; the matrix computed |
| Risk treatment (6.1.3) | Treatment words in the register; no risk-to-control link | Documentation | Baseline Annex A controls per risk; treatment workflow with verified controls and a residual decision |
| Statement of Applicability | 48 rows with status and evidence | Documentation | Applicability, assurance computed from verification records and evidence freshness; 19 Annex A numbers listed as not assessed |
| Verification (9.1) | Evidence files without freshness | Evidence, static | Freshness classes; verification records with digest-checked output; assurance states |
| Internal audit (9.2) | Planned for Phase 20 | Missing | Audit records with declared independence; checks create findings |
| Corrective action (10.2) | Security Finding workflow in Jira (not imported) | Process described | Finding records with root cause, action, closure evidence, effectiveness check |
| Management review (9.3) | "Owner approval at each phase gate" | Process described | Review records with server-computed inputs, decisions, actions tracked as findings |
| Activity history (7.5.3) | Git history only | Partial | Append-only `isms_activity`, not tamper-evident (L-81) |

## 2. Backlog items

| Item | Delivered | Verified by |
|---|---|---|
| CM-T088 Records, workflows and API | Migration `20261015000000_operational_isms` (two tables, CHECKs, guard trigger, append-only trigger, grants); `packages/shared/src/isms.ts` and `isms-workflow.ts`; `packages/validation/src/isms.ts`; `apps/api/src/db/isms-store.ts`, `apps/api/src/isms/service.ts`, `apps/api/src/routes/isms.ts`; PA-06 to PA-08 in the matrix and the authorization model | `tests/isms/isms.test.ts`, `packages/shared/src/isms.test.ts`, privileges matrix, route inventory, authz-matrix suite, NC-22-01 to NC-22-05 |
| CM-T089 ISMS Control Center | `apps/web/src/isms/*`, `apps/web/src/app/trust/isms/page.tsx`, the Trust Center tab | `tests/e2e/isms.spec.ts` (three engines), `tests/e2e/trust-center.spec.ts` (CSP) |
| CM-T090 Foundation documents | `isms-operations.md`; threat model sections 2 and 5 (assets, controls column, T-45); scope revision 2; evidence capture dates of Phases 6, 8 to 10; the generated catalogue `packages/shared/src/isms-catalogue.ts` | `pnpm trust:check`, catalogue cross-checks in the generator |
| CM-T091 Verification | Tests above; negative controls NC-22-01 to NC-22-05 | EV-22-17 |
| CM-T092 Evidence and walkthrough | `tests/deployment/isms-evidence.spec.ts`; EV-22-04 to EV-22-16; [live-demo-guide.md](../report/live-demo-guide.md) section 5 | Evidence index, Phase 22A |

## 3. Decisions and honesty rules

- Real decisions (policy adoption, scope review, risk acceptance, management review) are the project owner's own; the evidence capture made only labelled exercises.
- Every audit is a self-assessment or a simulation (L-82); no independent audit, external audit or certification is claimed.
- The activity history is not tamper-evident; Phase 12 stays deferred (L-81).
- The ISMS has operated for days (L-83); review cycles have not elapsed.
- Local Docker and CI evidence is not cloud evidence (L-80); the Oracle deployment is deferred and not verified.

## 4. Findings and open items

- 19 Annex A numbers are covered by no Statement of Applicability row (observation recorded in the demonstration audit; assessing them is an open improvement).
- `packages/crypto/src/rekey.test.ts` exceeded Vitest's 5-second default under a loaded full run (RSA-3072 key generation for the rooms it builds) and failed the negative-control baseline; the file now sets a 60-second timeout, assertions unchanged. Unchanged Phase 11 code.
- `tests/helpers/auth.ts`: test client addresses could collide between parallel test files and add a foreign row to the abuse suite's per-address count (expected 20, got 21 once). Addresses are now a per-process group plus a counter shared across module reloads. The mechanism is inferred, not reproduced.
- One NC-11 run reported a failing baseline without a failing test; the same files passed directly and on a rerun. Cause not found.
- The Firefox navigation hang (current-state section 12) caused 6 to 11 timeouts in local full E2E runs; they pass alone. CI is the gate.
- The E2E test race in `rekey.spec.ts` B (current-state section 6h) is unchanged.
