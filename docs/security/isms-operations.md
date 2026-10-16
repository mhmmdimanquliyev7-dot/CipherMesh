# Operational ISMS (ISO/IEC 27001:2022-aligned)

Status: introduced 2026-10-15 for the Operational ISMS workstream (merged through pull request #39, merge commit `92ded2f`) (CM-EPIC-17, CM-T088 to CM-T092; [ADR-016](../architecture/adr/ADR-016-operational-isms-records.md)). Normative: the ISMS Control Center (`/trust/isms`) reads the registers of this document through the generated catalogue (`pnpm trust:generate`), and the API enforces the rules of sections 6 to 12. Related: [isms-control-mapping.md](isms-control-mapping.md) (scope, clauses, Statement of Applicability), [../threat-model/threat-model.md](../threat-model/threat-model.md) (assets, method, risk register), [limitations.md](limitations.md), [../report/evidence-plan.md](../report/evidence-plan.md).

## 1. What this is, and what it is not

CipherMesh implements an operational, ISO/IEC 27001:2022-aligned ISMS for an academic software project: a documented scope and context, an asset inventory, a risk assessment and treatment process, a Statement of Applicability, control verification against recorded evidence, internal audit or self-assessment, nonconformity and corrective action, management review and an activity history. The documents define the processes; the ISMS Control Center records each management activity as a persistent record made by an authenticated, authorized person.

It is **not** a certified ISMS. No external certification audit has taken place, no independent internal auditor exists (the project has one person, so audits are labelled self-assessments or simulations, section 9), and a passing automated test is evidence for one control, not for conformity with the standard. The standard's text is not reproduced; clause and control numbers are references only. The activity history is an ordinary authenticated record, not the tamper-evident ledger of ADR-009 (deferred with Phase 12). The cloud deployment of ADR-014 is designed but not deployed; local Docker and CI evidence is never cloud evidence (L-80).

The ISMS distinguishes eight things that are easily confused: a defined process (this document), a documented policy (section 4), an implemented control (Statement of Applicability status), verified operational evidence (a verification record, section 7), an outstanding finding (section 10), an accepted residual risk (section 6), a demonstration exercise (section 13) and a real organizational approval (a decision record made by the project owner, section 3).

## 2. Context of the organization (clauses 4.1 to 4.3)

### 2.1 Purpose and objectives

CipherMesh is a university cybersecurity project that demonstrates a client-side encrypted collaboration and secret-exchange platform across cryptography, cloud security and information security management. The information security objectives are the security goals G1 to G7 of [system-overview.md](../architecture/system-overview.md); the ISMS performance objectives and their measurement are in section 12.

### 2.2 Issues

| ID | Type | Issue | Effect on the ISMS |
|---|---|---|---|
| ISS-01 | Internal | One person holds every role (developer, operator, ISMS manager, auditor) | Segregation of duties is limited (5.3 Partial); audits are self-assessments; decisions are the project owner's, never presented as independent |
| ISS-02 | Internal | Fixed university deadline (2026-10-18) and $0 budget | Phases 12, 13, 15 and 16 deferred; Oracle deployment deferred; the ISMS operates for days, not months |
| ISS-03 | Internal | The security architecture is client-side encryption with a server that must not read content | Risks and controls concentrate on key handling, authorization and the honest scope of server-side guarantees |
| ISS-04 | External | Users depend on browsers and devices the project does not control | Compromised clients are an accepted residual risk (T-23, L-01) |
| ISS-05 | External | Third-party services (GitHub, Jira Cloud, npm registry, container registries, a future cloud provider) | Supplier controls 5.19 to 5.22 Partial; dependency and secret scanning in CI |
| ISS-06 | External | Evaluation by the course examiner against ISO/IEC 27001 concepts | Every claim must match evidence; no certification or independent audit is claimed |

### 2.3 Interested parties

| ID | Interested party | Relevant requirements and expectations | How the ISMS addresses them |
|---|---|---|---|
| IP-01 | Project owner (student) | A working, demonstrable and honestly documented system by the deadline | Phase gating, roadmap, this ISMS |
| IP-02 | Course examiner (professor) | Visible depth in cryptography, cloud security and ISMS; truthful claims | Trust Center, evidence register, limitations, ISMS Control Center |
| IP-03 | Users of CipherMesh (synthetic demonstration accounts only) | Confidentiality of room content, account protection, availability during the demonstration | Client-side encryption, authentication, authorization, backups |
| IP-04 | Room owners and members | Control over who reads room content; notice when keys change | RBAC, key rotation, Room Safety Code |
| IP-05 | Suppliers (GitHub, Jira Cloud, npm, container registries) | Their terms of service | Supplier controls, no runtime SaaS (CLAUDE.md section 4) |
| IP-06 | University (data protection expectations) | No real personal data in a student project | Synthetic accounts only; redaction checklist for evidence |

### 2.4 Scope boundaries

The scope statement is section 1 of [isms-control-mapping.md](isms-control-mapping.md) (revision 2). Its text is fingerprinted (SHA-256) in the generated catalogue, so a scope review record names exactly the revision that was reviewed.

| ID | Boundary | Element | Reason |
|---|---|---|---|
| B-01 | In scope | Browser client, API, worker, PostgreSQL, SeaweedFS, Nginx in the local Docker demonstration | The running system that is demonstrated |
| B-02 | In scope | Source code, CI pipeline, dependencies and container images (GitHub) | Integrity of what is built and delivered |
| B-03 | In scope | Encrypted backups, restore procedures and the operator workstation | Recovery and operation |
| B-04 | In scope | Security evidence, ISMS records and project management (Jira) | The management system itself |
| B-05 | Designed, not in operation | Oracle Cloud Always Free VM (ADR-014) | Not provisioned; enters the scope when deployed |
| B-06 | Out of scope | Real users and real personal data | The project uses synthetic accounts only |
| B-07 | Out of scope | Physical security of data centres and of the laptop's premises | Provider responsibility (7.1 to 7.14) or outside a student project |
| B-08 | Out of scope | Human-resources controls (6.1 to 6.8) | No employees; one student |

## 3. Roles and responsibilities (clause 5.3, control 5.2)

Every role is held by the project owner. The Control Center attributes each record to the authenticated account that made it; a second account held by the same person is the same person and is labelled so in audits (section 9).

| ID | Role | Held by | Responsibilities | Permission in CipherMesh |
|---|---|---|---|---|
| ROLE-01 | ISMS manager and risk owner | Project owner (actual) | Scope, risk assessment and treatment, Statement of Applicability, policy adoption, risk acceptance | PLATFORM_ADMIN with MFA: PA-06, PA-07, PA-08 |
| ROLE-02 | Developer and security reviewer | Project owner (actual) | Secure development, security review of pull requests, tests | Repository write; reviews recorded in pull requests |
| ROLE-03 | Operator | Project owner (actual) | Deployment, backups, restore drills, status collection | Operator scripts on the host; no application role |
| ROLE-04 | Internal auditor | Project owner (actual, not independent) | Self-assessments and audit records | PLATFORM_ADMIN with MFA: PA-07 |
| ROLE-05 | Top management (management review) | Project owner (actual; one-person project review) | Management reviews, resources, objectives | PLATFORM_ADMIN with MFA: PA-08 |
| ROLE-06 | Independent reviewer | Nobody (not available) | Would perform an independent internal audit | None; no record may claim independence (section 9) |

## 4. Policy register (clause 5.2, control 5.1)

Each policy is an existing project document; the register gives it an identifier, an owner and a review cycle. Its lifecycle state is computed from policy review records and the document's current SHA-256 fingerprint (section 11): Documented (no adoption recorded), Effective, Review due, Changed since approval (the document changed after the last decision), Under revision, Retired.

| ID | Policy | Document | Owner | Review cycle (days) | Controls | Risks |
|---|---|---|---|---|---|---|
| POL-01 | Information security policy: engineering rules and security invariants | CLAUDE.md | ROLE-01 | 90 | 5.1, 5.8, 8.25 | T-24, T-27 |
| POL-02 | Security principles | docs/security/security-principles.md | ROLE-01 | 180 | 5.1, 8.27 | T-06, T-14 |
| POL-03 | Access control: authorization model | docs/security/authorization-model.md | ROLE-01 | 90 | 5.15, 5.18, 8.2, 8.3 | T-04, T-05, T-06 |
| POL-04 | Classification and handling: security policy profiles | docs/security/security-policy-profiles.md | ROLE-01 | 90 | 5.12, 5.13 | T-41 |
| POL-05 | Cryptography: crypto decisions and parameter register | docs/crypto/crypto-decisions.md | ROLE-01 | 90 | 8.24 | T-01, T-07, T-29 |
| POL-06 | Key management: key lifecycle | docs/crypto/key-lifecycle.md | ROLE-01 | 90 | 8.24, 5.18 | T-21, T-37 |
| POL-07 | Authentication and sessions | docs/security/authentication-security.md | ROLE-01 | 90 | 5.17, 8.5 | T-08, T-09, T-10 |
| POL-08 | Secure development and testing | docs/security/security-testing-plan.md | ROLE-02 | 90 | 8.25, 8.28, 8.29 | T-12, T-14 |
| POL-09 | Change management: Jira workflow and pull requests | docs/management/jira-workflow.md | ROLE-01 | 180 | 8.32, 5.8 | T-24 |
| POL-10 | Backup and recovery | docs/deployment/backup-and-restore.md | ROLE-03 | 90 | 8.13, 5.37 | T-43 |
| POL-11 | Incident management: compromised identity key runbook | docs/security/runbook-compromised-identity-key.md | ROLE-01 | 180 | 5.24 to 5.27 | T-22, T-40 |
| POL-12 | Cloud security and shared responsibility | docs/cloud/shared-responsibility.md | ROLE-01 | 180 | 5.23 | T-17, T-42 |
| POL-13 | Known limitations and accepted risks | docs/security/limitations.md | ROLE-01 | 90 | 5.1 | T-23 |

## 5. Assets (control 5.9)

The asset inventory is section 2 of the threat model (A-01 to A-18, with owner, classification and integrity and availability requirements). The Control Center links each asset to the risks whose threat model section names it.

## 6. Risk assessment and treatment (clauses 6.1.2, 6.1.3, 8.2, 8.3)

**Method.** The method of the threat model, unchanged: qualitative likelihood and impact (Low, Medium, High) and the 3x3 matrix of its section 1 give Low, Medium, High or Critical. Inherent risk is the rating without CipherMesh-specific controls; residual risk is the rating with the treatment working as designed. The documented ratings of the risk register (threat model section 5) are the baseline assessment; a risk assessment record in the Control Center is a dated re-assessment by a named person and becomes the current assessment of that risk.

**Risk acceptance criteria.** Residual Low or Medium may be accepted by the risk owner. Residual High may be accepted only by the project owner in a decision record with a fresh identity confirmation (step-up) and a limitation entry in [limitations.md](limitations.md). Residual Critical is never accepted: the risk must be treated further. No residual risk is accepted automatically.

**Treatment workflow.** A risk assessment record moves through:

| State | Entered by | Condition checked by the API |
|---|---|---|
| ASSESSED | Recording an assessment (PA-07) | Likelihood, impact, rationale and owner present; affected assets from the inventory |
| TREATMENT_PLANNED | Planning a treatment (PA-07) | Option (Mitigate, Avoid, Transfer, Accept), responsible party, activity; Mitigate names at least one applicable control of the Statement of Applicability |
| TREATMENT_VERIFIED | Verifying the treatment (PA-07) | Every linked control has a current verification (section 7); a residual assessment with rationale; residual not above inherent |
| RESIDUAL_ACCEPTED | Accepting the residual risk (PA-08, step-up) | Acceptance criteria above; the approver and the decision note are recorded |

A rejected acceptance returns the record to TREATMENT_PLANNED. RESIDUAL_ACCEPTED is final; a later re-assessment is a new record. Only one open assessment may exist per risk.

## 7. Evidence freshness and control assurance (clauses 7.5, 9.1)

Evidence items are the committed evidence files of the evidence register (EV-xx-yy, captured date from the evidence index). Operational evidence is a verification record's attached output (at most 32 KiB of text, stored with its SHA-256 digest, refused if it contains secret material) or a link to a GitHub Actions run of this repository.

**Freshness rule.** An evidence item is current for the validity of its class, counted from its capture date. An item without a capture date in the index is not current.

| Class | Validity (days) | Applies to |
|---|---|---|
| VULNERABILITY | 7 | Dependency audits, secret scans and other results that change when new vulnerabilities are published |
| TECHNICAL | 30 | Test runs, CI runs, local verifications, screenshots and command output (the default class) |
| DESIGN | 180 | Architecture, design and document reviews |

| Evidence | Class |
|---|---|
| EV-00-01 | DESIGN |
| EV-00-02 | DESIGN |
| EV-00-03 | DESIGN |
| EV-00-04 | DESIGN |
| EV-00-07 | DESIGN |
| EV-00-08 | DESIGN |
| EV-00-09 | DESIGN |
| EV-01-05 | VULNERABILITY |
| EV-01-07 | VULNERABILITY |

**Verification record.** A control verification names the Statement of Applicability row, the method (automated test, CI run, local verification, document review, manual inspection), the procedure, the environment (local Docker, CI, development, documentation), the result (PASS, FAIL, INCONCLUSIVE), the limitations and the support: current evidence items, an attached output or a CI run link. The API refuses a PASS without current support and a PASS that cites an evidence item that is not current. A verification is valid until the earliest of: its own class validity counted from the verification, and the expiry of every evidence item it cites. Verification records are never edited.

**Control assurance** is computed for each Statement of Applicability row, never stored:

| State | Meaning |
|---|---|
| VERIFIED | The latest verification is a PASS and still valid |
| VERIFICATION_DUE | The latest verification was a PASS but has expired |
| FAILED | The latest verification is a FAIL or INCONCLUSIVE |
| EVIDENCE_CURRENT | No verification record yet, but a cited evidence item is captured and current |
| EVIDENCE_STALE | No verification record; cited evidence is captured but none is current |
| NO_EVIDENCE | No verification record and no captured evidence |
| NOT_APPLICABLE | Excluded in the Statement of Applicability (justified there) |
| PROVIDER | Transferred to a provider under shared responsibility |

## 8. Statement of Applicability (clause 6.1.3 d)

The Statement of Applicability is section 3 of [isms-control-mapping.md](isms-control-mapping.md): 48 rows, some covering a range of Annex A controls. Applicability: Implemented by design and Partial rows are applicable (Partial names its limits), Provider rows are transferred, Not applicable rows are excluded with the justification given in the row. The Control Center adds to each row the linked risks (threat model section 5), the responsible role (ROLE-01 unless stated), the computed assurance state, the last verification and its next due date. Annex A control numbers that no row covers are listed as not assessed; nothing is marked applicable or implemented by default.

## 9. Internal audit and self-assessment (clause 9.2)

An audit record has a plan (scope, criteria as clause or control references, objective, scheduled date, assigned auditor, independence) and moves PLANNED, IN_PROGRESS, COMPLETED. While in progress the auditor records checks against criteria with a result: conformity, major or minor nonconformity, observation, improvement opportunity, or insufficient evidence. Every result other than conformity creates a finding (section 10) in the same transaction. Completing requires a conclusion and at least one check.

**Independence** is declared, never inferred. SELF_ASSESSMENT: the project owner assesses their own work. SIMULATED_INTERNAL_AUDIT: an educational exercise of the audit procedure. INTERNAL_AUDIT: only if the assigned auditor is a different account from the planner and records the checks; in this project such an account is still held by the project owner, so the project uses SELF_ASSESSMENT and SIMULATED_INTERNAL_AUDIT and no record claims independence. An external certification audit has not occurred.

## 10. Nonconformity and corrective action (clause 10.2)

A finding comes from an audit check, a self-assessment, an evidence-freshness check, an incident exercise, a management review or another source. It moves:

| State | Entered by | Condition checked by the API |
|---|---|---|
| OPEN | Raising a finding (PA-07) | Source, classification, criterion, observation, responsible party |
| ANALYZED | Recording the analysis (PA-07) | Root cause present; an immediate correction is optional |
| ACTION_PLANNED | Planning the corrective action (PA-07) | Action, owner and due date |
| ACTION_IMPLEMENTED | Recording the implementation (PA-07) | Implementation note |
| AWAITING_EFFECTIVENESS | Submitting closure evidence (PA-07) | At least one PASS verification of a related control recorded after the action was planned, or current evidence items |
| CLOSED | Effectiveness check and closure (PA-08, step-up) | Result EFFECTIVE, a note, and every related control currently VERIFIED; whether the checker is the implementer is recorded |

An effectiveness check with result NOT_EFFECTIVE returns the finding to ACTION_PLANNED. A finding whose action is past its due date and not yet awaiting effectiveness is overdue. No status can be set directly: each change is a named transition with its own input.

## 11. Management review, scope and policy reviews (clauses 9.3, 4.3, 5.2)

A management review is prepared as a draft whose inputs the API computes from the records when it is created: the metrics of section 12, open and overdue findings, controls by assurance state, risks awaiting treatment or acceptance, and open actions from earlier reviews. The project owner records the participants actually present, notes on the inputs, decisions and follow-up actions with owner and due date; recording it (PA-08, step-up) makes it final and turns each follow-up action into an improvement finding. In this project the format is a one-person project review, and the Control Center says so.

A scope review records the reviewed scope revision (its fingerprint), the decision (confirmed or changes required), the reason and the next review date. A policy review records the policy, the reviewed document fingerprint, the decision (adopted, reviewed without change, changes required, retired), the effective date and the next review date. Both are decisions (PA-08, step-up). No review is recorded on anyone's behalf, and none is back-dated: the API sets every time.

## 12. Objectives and metrics (clause 9.1)

Each metric is computed by the Control Center from the records and the catalogue at the time of viewing; nothing is entered by hand. Exercise records that were withdrawn are excluded.

| ID | Objective | Calculation | Data source | Frequency | Owner | Target | Limitation |
|---|---|---|---|---|---|---|---|
| M-01 | Applicable controls are verified with current evidence | Statement of Applicability rows in state VERIFIED, out of applicable rows | Verification records, evidence register | Each view; reviewed at management review | ROLE-01 | Increase at every management review | Rows, not individual controls; a verification covers what its procedure tests |
| M-02 | Every risk has a documented treatment decision | Risks whose current assessment is TREATMENT_VERIFIED or RESIDUAL_ACCEPTED, out of all risks | Risk assessment records, risk register | Each view | ROLE-01 | All risks with residual High or Critical first | The register's baseline treatments count as documented, not as operational records |
| M-03 | Corrective actions are completed on time | Findings past their action due date and not yet awaiting effectiveness or closed | Finding records | Each view | ROLE-01 | 0 | Due dates are set by the project owner |
| M-04 | Findings are resolved | Findings not CLOSED, by classification | Finding records | Each view | ROLE-01 | No open major nonconformity | Self-assessment findings only |
| M-05 | Evidence stays current | Captured evidence items whose freshness rule has expired, out of captured items | Evidence register and index | Each view | ROLE-01 | Stale items have a finding or a planned refresh | Capture dates come from the evidence index |
| M-06 | Policies are adopted and reviewed | Policies in state Effective, out of the policy register | Policy review records | Each view | ROLE-01 | All policies Effective before the final report | Adoption is the project owner's own decision |
| M-07 | Management reviews take place | Days since the last recorded management review | Management review records | Each view | ROLE-05 | At most 30 days during the project | One-person project reviews |

## 13. Exercises, incidents, changes and exceptions

**Exercises.** Any record may be marked as an exercise when it is created; the Control Center labels it EXERCISE everywhere. An exercise record can be withdrawn (status WITHDRAWN) by PA-07 at any time; withdrawn records are hidden from the default views and excluded from metrics but stay in the activity history. Real records cannot be withdrawn. `pnpm` has no command that deletes ISMS records.

**Incidents.** An incident record (real or exercise) moves OPEN, CONTAINED (containment), RESOLVED (recovery), CLOSED (lessons learned, PA-08). No real security incident has occurred; the demonstration uses labelled exercises.

**Changes.** Change control is the pull-request workflow (POL-09): every change to `main` arrives through a pull request with passing CI, recorded in Git and in the traceability documents. The Control Center lists the merged pull requests of the cloud and ISMS workstreams with their CI evidence; it does not invent approvals that GitHub does not record.

**Exceptions.** No mechanism disables a security control. Accepted risks (treatment Accept in the register, or a RESIDUAL_ACCEPTED record) are the exceptions; each names its limitation entry, and the register's Accept decisions are reviewed before the final report.

## 14. Activity history (clause 7.5.3)

Every creation and transition of an ISMS record writes one row to `isms_activity` in the same transaction: actor, action, record, previous and new status, rationale and the record's data after the change. The application never updates or deletes these rows (database trigger and grants, [database-security.md](database-security.md)); this is an authenticated operational history, **not** tamper-evident: a database administrator could change it, which only the deferred hash chain of ADR-009 would detect (L-81).

## 15. Authorization (control 5.15)

| Action | What | Who |
|---|---|---|
| PA-06 | View ISMS records, the Control Center and operational evidence | PLATFORM_ADMIN with an MFA-verified session |
| PA-07 | Record: assessments, treatments, verifications, audits, checks, findings and their non-decision transitions, incidents, draft management reviews, withdrawal of exercises | PLATFORM_ADMIN with an MFA-verified session |
| PA-08 | Decide: accept or reject residual risk, close a finding after the effectiveness check, record a management review, scope and policy decisions, close an incident | PLATFORM_ADMIN with an MFA-verified session and a step-up every time |

Every other account receives the generic 404 for every ISMS route (authorization model section 4). The public Trust Center keeps showing the documents only.
