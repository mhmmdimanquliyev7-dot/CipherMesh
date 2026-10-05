# Jira Backlog Specification

Status: Phase 0.5 specification, ready for import; CM-T023, CM-T025 to CM-T028, CM-T033, CM-T034, CM-T036, CM-T050 and CM-T053 were updated in Phase 4 to match ADR-015, as CM-T086 requires (markdown and CSV changed together). Nothing has been created in Jira. The same data is exported as [jira-backlog.csv](jira-backlog.csv), and the import steps are in [jira-import-guide.md](jira-import-guide.md). Related: [jira-workflow.md](jira-workflow.md), [project-roadmap.md](project-roadmap.md).

## How to use this backlog

- **IDs are placeholders.** `CM-T001` to `CM-T087` identify work items here and in every other document. Jira assigns real keys (for example `CM-42`) on import. The placeholder ID is kept at the start of each Jira summary, so documents and tests stay traceable.
- **Epics** keep the IDs `CM-EPIC-01` to `CM-EPIC-16` in their summary.
- **Plan line.** Each item states its phase and release, its security impact (High, Medium or Low, which sets how deep the SECURITY REVIEW goes), the evidence it must produce (IDs from the evidence plan) and its initial status.
- **Security findings** are not listed here. They are created during testing and assessment with the Security Finding template.
- Every item goes through the full workflow, including SECURITY REVIEW.
- After import, Jira is the source of truth for status and scheduling. This document stays the design reference for scope and acceptance criteria.

## Priorities

| Priority | Meaning | Items |
|---|---|---|
| P0 Blocker | **Rare.** Work whose absence blocks the project entirely, breaks a fundamental security invariant that later work relies on, or prevents safe continuation into a dependent phase | 11 |
| P1 High | Core product or security functionality required for the final project | 66 |
| P2 Medium | Important functionality that does not block other work | 8 |
| P3 Low | Enhancement, polish or optional work | 2 |
| **Total** | | **87** |

Priority expresses impact, not order. Phases and dependency links set the order, so a P0 item may depend on P1 items scheduled before it. In Phase 0 the backlog had 49 P0, 26 P1, 5 P2 and 1 P3 items; Phase 0.5 reserved P0 for the items below.

| P0 item | Why it is P0 |
|---|---|
| CM-T005 Phase 0 security architecture review and ADR baseline | Phase 0 gate: approval before any implementation |
| CM-T006 Initialize pnpm TypeScript monorepo with strict compiler, lint and format | Every implementation item builds on the monorepo, lint bans and dependency controls |
| CM-T007 Scaffold Express API with secure middleware baseline | Deny-by-default routing and fail-closed errors that every endpoint relies on |
| CM-T010 Structured logging with mandatory redaction and request correlation | Log redaction must exist before any endpoint handles secrets (INV-10) |
| CM-T013 Prisma schema v1 and initial migrations | The schema encodes INV-01, INV-04 and INV-16 for all persistence |
| CM-T016 Login with opaque server-side sessions | Every authenticated feature depends on the session model (INV-12) |
| CM-T020 CSRF defences: same-origin verification, request header and login CSRF | Every state-changing endpoint relies on the CSRF checks (INV-19) |
| CM-T023 packages/crypto foundation: WebCrypto wrappers, canonical contexts, known-answer tests | All client-side cryptography depends on it (INV-02, INV-17) |
| CM-T029 Central authorization module implementing the authorization matrix | Every room feature depends on central authorization (INV-05, INV-06) |
| CM-T082 Phase 0.5 architecture hardening and consistency review (gate) | Phase 0.5 gate: approval before Phase 1 |
| CM-T086 Decide key-version authentication (OCD-12) before Phase 4 | Gate before Phase 4: decides the identity key format |

## Epic summary

| Epic | Name | Phases | Items | Main subject focus |
|---|---|---|---|---|
| CM-EPIC-01 | Architecture & Threat Modelling | 0, 0.5 | T001 to T005, T082 to T084 | All three subjects |
| CM-EPIC-02 | Application Foundation | 1, 2 | T006 to T014 | Secure development, change control |
| CM-EPIC-03 | Authentication & Session Security | 3 | T015 to T022 | Password hashing, MFA, sessions |
| CM-EPIC-04 | Cryptographic Identity & Vault | 4 | T023 to T028, T086 | Cryptography |
| CM-EPIC-05 | Secure Rooms & RBAC | 5 | T029 to T032 | Access control (ISMS) |
| CM-EPIC-06 | Cryptographic Room Membership | 6 | T033 to T036, T085 | Cryptography |
| CM-EPIC-07 | Encrypted File System | 7 | T037 to T041 | Cryptography, cloud storage |
| CM-EPIC-08 | Secure Notes & Secret Exchange | 8, 9 | T042 to T045 | Cryptography |
| CM-EPIC-09 | Security Policy Engine | 10 | T046 to T049 | Information classification (ISMS) |
| CM-EPIC-10 | Key Lifecycle & Rotation | 11 | T050 to T053 | Cryptography, key management |
| CM-EPIC-11 | Tamper-Evident Auditing | 12 | T054 to T058 | Cryptography, logging (ISMS) |
| CM-EPIC-12 | Crypto Inspector & Security Dashboard | 13, 14 | T059 to T062 | Transparency, monitoring |
| CM-EPIC-13 | Cloud Deployment | 17, 18 | T063 to T068 | Cloud security |
| CM-EPIC-14 | Infrastructure Hardening | 19 | T069 to T072, T087 | Cloud security |
| CM-EPIC-15 | Security Testing & Remediation | 15, 16, 20, 21 | T073 to T078 | Assurance, corrective action |
| CM-EPIC-16 | Documentation & Final Report | 22 | T079 to T081 | Evidence, reporting |

---

## CM-EPIC-01 Architecture & Threat Modelling

#### CM-T001 Repository skeleton, CLAUDE.md and documentation structure
- **Epic:** CM-EPIC-01 | **Priority:** P1 | **Labels:** architecture, documentation | **Depends on:** none
- **Plan:** Phase 0 | M0 Architecture Baseline | Security impact: Medium | Evidence: EV-00-07 | Initial status: Done
- **Description:** Create the monorepo directory skeleton, repository hygiene files (`.gitignore`, `.gitattributes`, `.editorconfig`), the README, placeholder READMEs, and CLAUDE.md with the rules every future session follows. *Completed in Phase 0.*
- **Acceptance criteria:**
  - Directory structure matches CLAUDE.md section 5.
  - CLAUDE.md covers mission, architecture, stack, structure, invariants, cryptographic rules, conventions, testing, documentation, Git, Jira, forbidden practices, phases and Definition of Done.
  - `.gitignore` excludes environment files, keys, dumps and build output.
- **Security considerations:** CLAUDE.md encodes the invariants so later sessions cannot silently weaken the design; `.gitignore` reduces the chance of committing secrets.

#### CM-T002 Architecture documentation: overview, data flow, trust boundaries, data model, cloud models
- **Epic:** CM-EPIC-01 | **Priority:** P1 | **Labels:** architecture, cloud, documentation | **Depends on:** CM-T001
- **Plan:** Phase 0 | M0 Architecture Baseline | Security impact: Medium | Evidence: EV-00-01, EV-00-02 | Initial status: Done
- **Description:** Write the system overview, the data flows DF-01 to DF-12, the trust boundaries TB-01 to TB-11, the data-model proposal, and the cloud service-model, shared-responsibility and deployment documents. *Completed in Phase 0.*
- **Acceptance criteria:**
  - Each document has Mermaid diagrams where useful and states what crosses each boundary in plaintext and in ciphertext.
  - The data model classifies every field and lists fields that must never exist.
  - Cloud documents are provider-neutral and include a shared-responsibility matrix.
- **Security considerations:** Makes metadata exposure and trust assumptions explicit before any code exists.

#### CM-T003 Initial threat model and risk register
- **Epic:** CM-EPIC-01 | **Priority:** P1 | **Labels:** risk, security, architecture | **Depends on:** CM-T002
- **Plan:** Phase 0 | M0 Architecture Baseline | Security impact: Medium | Evidence: EV-00-04 | Initial status: Done
- **Description:** Asset-centric threat model with STRIDE where useful, qualitative risk ratings, treatments and a risk register. *Completed in Phase 0.*
- **Acceptance criteria:**
  - Every required threat is covered with asset, threat, scenario, controls, residual risk and testing strategy.
  - Risk register lists likelihood, impact, inherent and residual risk and treatment.
  - Accepted risks are listed for acknowledgement by the project owner.
- **Security considerations:** Basis for the security testing plan and the ISMS risk assessment (ISO/IEC 27001 clause 6.1.2).

#### CM-T004 Cryptographic architecture, key hierarchy, key lifecycle and parameter register
- **Epic:** CM-EPIC-01 | **Priority:** P1 | **Labels:** crypto, architecture | **Depends on:** CM-T002
- **Plan:** Phase 0 | M0 Architecture Baseline | Security impact: High | Evidence: EV-00-03 | Initial status: Done
- **Description:** Specify all cryptographic mechanisms, the acyclic key hierarchy, lifecycle and rotation rules, and the single parameter register. *Completed in Phase 0.*
- **Acceptance criteria:**
  - Only established primitives; every composition documented with its context binding.
  - Parameter register, library register and open crypto decisions exist.
  - Limitations of rotation, burn-after-reading and web delivery are stated.
- **Security considerations:** Prevents ad-hoc cryptographic choices during implementation.

#### CM-T005 Phase 0 security architecture review and ADR baseline
- **Epic:** CM-EPIC-01 | **Priority:** P0 | **Labels:** security, architecture, documentation | **Depends on:** CM-T002, CM-T003, CM-T004
- **Plan:** Phase 0 | M0 Architecture Baseline | Security impact: High | Evidence: EV-00-06 | Initial status: Done
- **Description:** Review the Phase 0 design for cryptographic mistakes, nonce problems, unsafe key storage, circular key dependencies, authorization gaps, misleading claims, cloud responsibility confusion and unnecessary complexity; fix what is found; record ADR-001 to ADR-011; obtain approval.
- **Acceptance criteria:**
  - Review findings and resolutions recorded in `docs/security/architecture-review.md`.
  - ADR index complete; proposed ADRs identify how they will be confirmed.
  - Project owner approval of Phase 0 recorded in Jira.
- **Security considerations:** Catches design flaws when they are cheapest to fix.

#### CM-T082 Phase 0.5 architecture hardening and consistency review (gate)
- **Epic:** CM-EPIC-01 | **Priority:** P0 | **Labels:** architecture, security, documentation | **Depends on:** CM-T005
- **Plan:** Phase 0.5 | M0 Architecture Baseline | Security impact: High | Evidence: EV-00-08 | Initial status: Testing
- **Description:** Apply the external review's corrections consistently across all documents: envelope encryption for secrets, the corrected commitment claims and the Room Safety Code (ADR-012), the rekey state machine (ADR-013), the audit trust model with Level 1 and Level 2 key custody (ADR-009), the object-storage classification (ADR-006), the session and CSRF design, and normalized priorities. Run a consistency review and an attack-focused architecture review. *Completed in Phase 0.5, awaiting approval.*
- **Acceptance criteria:**
  - No document contradicts the corrected design: automated link, identifier and diagram checks plus targeted searches.
  - The architecture gate record lists every attacked area, the result and the unresolved risks.
  - Project owner approval recorded in Jira.
- **Security considerations:** Design flaws are cheapest to fix now. Unresolved risks are recorded, not hidden.

#### CM-T083 Jira project setup and backlog import
- **Epic:** CM-EPIC-01 | **Priority:** P1 | **Labels:** documentation, risk | **Depends on:** CM-T082
- **Plan:** Phase 0.5 | M0 Architecture Baseline | Security impact: Medium | Evidence: EV-00-05, EV-00-10 | Initial status: Backlog
- **Description:** Create the team-managed Kanban project CipherMesh (key CM) as described in `docs/management/jira-import-guide.md`: statuses and transitions, labels, custom fields and releases M0 to M8. Then import `docs/management/jira-backlog.csv` and verify the result.
- **Acceptance criteria:**
  - The workflow allows SECURITY REVIEW to IN PROGRESS and TESTING to IN PROGRESS, and no transition skips SECURITY REVIEW.
  - 16 epics and 87 work items are imported with parents, priorities, labels, releases and phases; counts match the guide.
  - MFA is enforced and project access is limited to the team.
  - Board screenshot and import summary captured (EV-00-05, EV-00-10).
- **Security considerations:** Jira holds no secrets or production data (T-34).

#### CM-T084 Git repository initialization and baseline commit
- **Epic:** CM-EPIC-01 | **Priority:** P1 | **Labels:** infrastructure, documentation | **Depends on:** CM-T082
- **Plan:** Phase 0.5 | M0 Architecture Baseline | Security impact: Medium | Evidence: EV-00-09 | Initial status: Done
- **Description:** Initialize the local git repository on `main`, verify `.gitignore`, create the baseline commit with the Phase 0 and Phase 0.5 documentation, and record the hash in the evidence plan. No remote yet. *Completed in Phase 0.5.*
- **Acceptance criteria:**
  - `.gitignore` excludes environment files, keys, dumps, logs, build output and raw evidence; nothing sensitive is staged.
  - The baseline commit hash is recorded in `docs/report/evidence-plan.md` (EV-00-09).
- **Security considerations:** An auditable starting point for change management (ISO/IEC 27001 control 8.32).

---

## CM-EPIC-02 Application Foundation

#### CM-T006 Initialize pnpm TypeScript monorepo with strict compiler, lint and format
- **Epic:** CM-EPIC-02 | **Priority:** P0 | **Labels:** infrastructure, architecture | **Depends on:** CM-T082
- **Plan:** Phase 1 | M1 Foundation | Security impact: Medium | Evidence: EV-01-01 | Initial status: Backlog
- **Description:** pnpm workspaces for `apps/*` and `packages/*`; shared strict `tsconfig`; ESLint with security rules and forbidden-API rules; Prettier; Node.js LTS version pinned; workspace boundary rules.
- **Acceptance criteria:**
  - Install with a frozen lockfile, lint and typecheck succeed on the empty scaffolds.
  - Lint fails on `eval`, `new Function`, `Math.random` in security code, `$queryRawUnsafe`, `dangerouslySetInnerHTML` and forbidden cross-package imports.
  - Dependency lifecycle scripts are blocked unless explicitly allowlisted.
- **Security considerations:** Establishes supply-chain hygiene and static enforcement of forbidden practices (T-14, T-27).

#### CM-T007 Scaffold Express API with secure middleware baseline
- **Epic:** CM-EPIC-02 | **Priority:** P0 | **Labels:** backend, security | **Depends on:** CM-T006
- **Plan:** Phase 1 | M1 Foundation | Security impact: High | Evidence: none | Initial status: Backlog
- **Description:** Express API with request IDs, JSON-only body parsing with size limits, schema-validation hook, a deny-by-default route registry requiring an action declaration per route, a central error handler, `Cache-Control: no-store`, a health endpoint, startup configuration validation, and the worker entrypoint stub.
- **Acceptance criteria:**
  - Undeclared routes prevent startup; unknown routes return 404.
  - Non-JSON bodies return 415 and oversized bodies 413.
  - Errors return a stable code and request ID, never a stack trace.
  - Missing or malformed configuration stops the process with a clear message.
- **Security considerations:** Deny by default and fail closed from the first line of code (principles 4 and 10).

#### CM-T008 Scaffold Next.js static-export web app with Tailwind and strict CSP
- **Epic:** CM-EPIC-02 | **Priority:** P1 | **Labels:** frontend, security | **Depends on:** CM-T006
- **Plan:** Phase 1 | M1 Foundation | Security impact: Medium | Evidence: EV-01-04 | Initial status: Backlog
- **Description:** Next.js static export with Tailwind; routing pattern for identifiers that works with deep links and reloads; build step that generates CSP hashes; no inline event handlers. Validates ADR-011.
- **Acceptance criteria:**
  - The build produces a static export that runs behind a local Nginx.
  - A CSP without `'unsafe-inline'` or `'unsafe-eval'` for scripts loads the app without violations in Chromium, Firefox and WebKit.
  - ADR-011 updated to Accepted or revised with the findings.
- **Security considerations:** Strict CSP is the main structural defence against XSS (T-12) and limits injected code (T-24).

#### CM-T009 Shared validation and shared-types packages
- **Epic:** CM-EPIC-02 | **Priority:** P1 | **Labels:** backend, frontend | **Depends on:** CM-T006
- **Plan:** Phase 1 | M1 Foundation | Security impact: Medium | Evidence: none | Initial status: Backlog
- **Description:** `packages/validation` with strict schemas (UUID, ISO timestamps, base64url binary with exact lengths) and `packages/shared` with error codes, suite identifiers and skeletons for the policy catalogue and authorization matrix.
- **Acceptance criteria:**
  - Schemas reject unknown keys, `__proto__` and malformed values; unit tests cover each format.
  - The API validates requests and the client validates responses with the same schemas.
- **Security considerations:** Single validation source at every trust boundary (principle 11, T-14).

#### CM-T010 Structured logging with mandatory redaction and request correlation
- **Epic:** CM-EPIC-02 | **Priority:** P0 | **Labels:** backend, security | **Depends on:** CM-T007
- **Plan:** Phase 1 | M1 Foundation | Security impact: High | Evidence: none | Initial status: Backlog
- **Description:** JSON logger with a central redaction list (passwords, passphrases, tokens, cookies, authorization headers, keys, envelopes, presigned URLs), request logging without bodies, correlation IDs.
- **Acceptance criteria:**
  - Redaction unit tests for every listed field.
  - A canary test sends known secret values through endpoints and finds none in the logs.
- **Security considerations:** Enforces INV-10 (T-15, T-16).

#### CM-T011 Local development environment with Docker Compose
- **Epic:** CM-EPIC-02 | **Priority:** P1 | **Labels:** infrastructure | **Depends on:** CM-T006
- **Plan:** Phase 1 | M1 Foundation | Security impact: Medium | Evidence: none | Initial status: Backlog
- **Description:** Compose file with PostgreSQL and an S3-compatible emulator chosen after a licence and maintenance check; synthetic seed data; `.env.example` with placeholders; setup instructions in the README.
- **Acceptance criteria:**
  - One command starts a working database and storage; ports bound to 127.0.0.1.
  - No real credentials in the repository; emulator choice documented.
- **Security considerations:** Separation of development and production (ISO/IEC 27001 control 8.31).

#### CM-T012 CI pipeline: lint, typecheck, tests, dependency audit, secret scanning
- **Epic:** CM-EPIC-02 | **Priority:** P1 | **Labels:** infrastructure, testing, security | **Depends on:** CM-T006
- **Plan:** Phase 1 | M1 Foundation | Security impact: Medium | Evidence: EV-01-01, EV-01-02, EV-01-03, EV-01-05 | Initial status: Backlog
- **Description:** GitHub Actions on every pull request: frozen install, lint, typecheck, unit and integration tests (PostgreSQL service), dependency audit, secret scan over the full history, SBOM generation. Branch protection on `main`.
- **Acceptance criteria:**
  - Pull requests cannot merge with failing checks.
  - Actions pinned to commit SHAs; default token permissions read-only.
  - Evidence screenshot of branch protection and a failing check blocking a merge.
- **Security considerations:** Supply-chain and secret-leak controls (T-16, T-27); change control (control 8.32).

#### CM-T013 Prisma schema v1 and initial migrations
- **Epic:** CM-EPIC-02 | **Priority:** P0 | **Labels:** database | **Depends on:** CM-T011
- **Plan:** Phase 2 | M1 Foundation | Security impact: High | Evidence: EV-02-01 | Initial status: Backlog
- **Description:** Implement the entities of `docs/architecture/data-model.md` with constraints (partial unique indexes for one ACTIVE key pair per user, one ACTIVE OWNER per room and one PENDING rekey operation per room), foreign keys, and indexes for room-scoped lookups.
- **Acceptance criteria:**
  - Field names and types follow the data model; a script checks that no "must never exist" field is present.
  - Migrations apply cleanly to an empty database; constraint tests pass.
- **Security considerations:** Encodes INV-01, INV-04 and INV-16 in the schema; composite indexes support object-level authorization (OL-02).

#### CM-T014 Database least-privilege roles and append-only audit protection
- **Epic:** CM-EPIC-02 | **Priority:** P1 | **Labels:** database, security | **Depends on:** CM-T013
- **Plan:** Phase 2 | M1 Foundation | Security impact: High | Evidence: EV-02-02, EV-02-03 | Initial status: Backlog
- **Description:** Roles for migration, API, worker and read-only verification; audit tables with INSERT and SELECT only for runtime roles; a trigger that rejects UPDATE, DELETE and TRUNCATE on audit tables.
- **Acceptance criteria:**
  - Integration tests prove the API role cannot change schema or modify audit rows.
  - The trigger blocks modification even if grants are misconfigured.
- **Security considerations:** Least privilege and the first layer of audit protection (T-20).

---

## CM-EPIC-03 Authentication & Session Security

#### CM-T015 Registration with Argon2id password hashing and password policy
- **Epic:** CM-EPIC-03 | **Priority:** P1 | **Labels:** backend, security, crypto | **Depends on:** CM-T013, CM-T009
- **Plan:** Phase 3 | M2 Identity and Access | Security impact: High | Evidence: EV-03-01, EV-03-02 | Initial status: Backlog
- **Description:** Registration endpoint with NFKC normalization, length 12 to 128, local blocklist, and Argon2id hashing (CP-05) using the library selected in this item (LIB-04, OCD-03) after a benchmark on a VM-sized machine. Audit event `USER_REGISTERED`.
- **Acceptance criteria:**
  - Stored value is an Argon2id PHC string with the registered parameters.
  - Blocklisted and too-short passwords are rejected with a helpful message.
  - Benchmark and final parameters recorded in `docs/crypto/crypto-decisions.md`.
  - Registration is rate-limited; passwords never appear in logs.
- **Security considerations:** INV-11; T-03. Registration reveals taken emails; accepted and rate-limited (T-15).

#### CM-T016 Login with opaque server-side sessions
- **Epic:** CM-EPIC-03 | **Priority:** P0 | **Labels:** backend, security | **Depends on:** CM-T015
- **Plan:** Phase 3 | M2 Identity and Access | Security impact: High | Evidence: EV-03-03, EV-03-06 | Initial status: Backlog
- **Description:** Login per DF-01 and ADR-008: dummy Argon2id verification for unknown accounts, one generic error, `__Host-cm_session` cookie, token digest storage, token rotation, rehash on parameter change, login attempts recorded with an identifier HMAC for unknown accounts (CP-12). A token presented with the login request is never promoted: login always issues a new one.
- **Acceptance criteria:**
  - Cookie has HttpOnly, Secure, SameSite=Strict, Path=/ and no Domain.
  - Only the SHA-256 digest of the token is stored.
  - Failed attempts store no password and no raw identifier for unknown accounts.
- **Security considerations:** T-08, T-09, INV-12.

#### CM-T017 Session lifecycle: rotation, invalidation, expiry, concurrent sessions and logout
- **Epic:** CM-EPIC-03 | **Priority:** P1 | **Labels:** backend, frontend, security | **Depends on:** CM-T016
- **Plan:** Phase 3 | M2 Identity and Access | Security impact: High | Evidence: EV-03-08 | Initial status: Backlog
- **Description:** Implement `docs/security/session-and-csrf.md` sections 3 to 7: idle timeout 30 minutes and absolute lifetime 12 hours (CP-08); rotation and invalidation for every event in the rotation table; server-side logout with cookie deletion and a client vault lock; at most 10 active sessions with least-recently-used eviction; a session list with per-session revoke and "sign out other sessions"; worker cleanup of expired sessions.
- **Acceptance criteria:**
  - Each event in the rotation table has the documented effect on the current and the other sessions (tests).
  - Revoked, idle-expired and absolutely expired tokens are rejected; logout clears the cookie.
  - Password change, MFA change and vault reset revoke the user's other sessions.
  - An 11th login evicts the least recently used session and records an audit event.
- **Security considerations:** Limits the value of stolen sessions and prevents session fixation (T-08).

#### CM-T018 Brute-force and credential-stuffing protections
- **Epic:** CM-EPIC-03 | **Priority:** P1 | **Labels:** backend, security | **Depends on:** CM-T016
- **Plan:** Phase 3 | M2 Identity and Access | Security impact: High | Evidence: EV-03-04 | Initial status: Backlog
- **Description:** Nginx rate-limit zones plus API limits per IP, account and identifier HMAC; progressive backoff without permanent lockout; a concurrency limit for Argon2id computations; 90-day retention of login attempts.
- **Acceptance criteria:**
  - Scripted bursts receive 429 and the backoff schedule is observable.
  - A small load test shows the Argon2id concurrency limit protects memory.
  - Failed-login data is available for the Security Dashboard.
- **Security considerations:** T-09, T-10, T-26. Avoids lockout-based denial of service.

#### CM-T019 TOTP MFA enrollment, verification and recovery codes
- **Epic:** CM-EPIC-03 | **Priority:** P1 | **Labels:** backend, frontend, security, crypto | **Depends on:** CM-T016
- **Plan:** Phase 3 | M2 Identity and Access | Security impact: High | Evidence: EV-03-05 | Initial status: Backlog
- **Description:** DF-02: TOTP per CP-09 with a vetted library (LIB-06); secrets encrypted per CP-11; ten recovery codes per CP-10; MFA step at login; disabling MFA requires step-up.
- **Acceptance criteria:**
  - RFC 6238 test vectors pass; replayed codes and codes outside one step are rejected.
  - At most 5 attempts per pre-auth state; recovery codes single use and stored as digests.
  - The TOTP secret appears only once (enrollment) and never in logs.
  - Session token rotates after MFA verification.
- **Security considerations:** T-10, T-30. Server-readable secret by design; documented in the key hierarchy.

#### CM-T020 CSRF defences: same-origin verification, request header and login CSRF
- **Epic:** CM-EPIC-03 | **Priority:** P0 | **Labels:** backend, security | **Depends on:** CM-T016
- **Plan:** Phase 3 | M2 Identity and Access | Security impact: High | Evidence: EV-03-07 | Initial status: Backlog
- **Description:** Implement `docs/security/session-and-csrf.md` section 8: `Sec-Fetch-Site` or exact `Origin` verification on every state-changing request, including registration, login, MFA and logout; JSON-only bodies; the required `X-CipherMesh-Request` header; no CORS; no state changes on GET. The client uses fetch() only and never submits forms.
- **Acceptance criteria:**
  - Cross-site form posts, foreign-origin fetches, `Origin: null`, missing headers and wrong content types are rejected before any handler runs (403 `ORIGIN_REJECTED` or 415).
  - Login CSRF is prevented: cross-origin registration and login fail.
  - A route test confirms that no GET handler changes state.
  - Playwright confirms that fetch() sends the real Origin under `Referrer-Policy: no-referrer` in Chromium, Firefox and WebKit.
- **Security considerations:** T-13. SameSite=Strict stays as one layer but is not relied on (INV-19).

#### CM-T021 Step-up re-authentication and session freshness
- **Epic:** CM-EPIC-03 | **Priority:** P1 | **Labels:** backend, security | **Depends on:** CM-T019
- **Plan:** Phase 3 | M2 Identity and Access | Security impact: High | Evidence: none | Initial status: Backlog
- **Description:** Step-up endpoint (password and TOTP) that sets `stepUpAt` and rotates the token; reusable gates that return `REAUTH_REQUIRED` and `STEP_UP_REQUIRED`; step-up validity 15 minutes, and 5 minutes for profile downgrades.
- **Acceptance criteria:**
  - Gates return the correct codes at window boundaries (tests).
  - Token rotates on step-up.
- **Security considerations:** Foundation for PC-02 and PC-03; limits damage of stolen sessions (T-08).

#### CM-T022 Platform administrator bootstrap and account disabling
- **Epic:** CM-EPIC-03 | **Priority:** P1 | **Labels:** backend, security | **Depends on:** CM-T017
- **Plan:** Phase 3 | M2 Identity and Access | Security impact: High | Evidence: none | Initial status: Backlog
- **Description:** Server-side CLI to grant PLATFORM_ADMIN; API to disable and re-enable accounts (PA-03) with step-up, revoking all sessions; documented administrator-assisted password and MFA reset procedure (PA-04); audit events.
- **Acceptance criteria:**
  - PLATFORM_ADMIN cannot be granted through the API.
  - Admins cannot disable themselves or the last admin.
  - Disabling an account sets its memberships to SUSPENDED and its rooms to REKEY_REQUIRED once rooms exist (integration test added in Phase 11).
- **Security considerations:** Least privilege for administrators; T-30.

---

## CM-EPIC-04 Cryptographic Identity & Vault

#### CM-T023 packages/crypto foundation: WebCrypto wrappers, canonical contexts, known-answer tests
- **Epic:** CM-EPIC-04 | **Priority:** P0 | **Labels:** crypto | **Depends on:** CM-T006
- **Plan:** Phase 4 | M2 Identity and Access | Security impact: High | Evidence: none | Initial status: Backlog
- **Description:** Wrappers for AES-256-GCM (encrypt, decrypt, wrap, unwrap) with internally generated IVs, RSA-OAEP with labels, ECDSA P-256 signatures over canonical statements (CP-26, ADR-015), HKDF, SHA-256, base64url; RFC 8785 canonicalization (OCD-04); builders for every context in the cryptographic architecture; typed errors; a test-only IV seam excluded from production builds.
- **Acceptance criteria:**
  - Known-answer tests for AES-GCM, HKDF (RFC 5869), SHA-256, RSA-OAEP fixed vectors, ECDSA P-256 vectors and RFC 8785 vectors.
  - Tamper tests for every decrypt function; no production function accepts an IV.
  - Different contexts produce different bytes; decryption under a wrong context fails.
  - Runs in browsers and the Node.js test environment; coverage at least 90%.
- **Security considerations:** INV-02, principle 9; the base for every later crypto feature.

#### CM-T024 Browser Argon2id library selection, Web Worker integration and benchmark
- **Epic:** CM-EPIC-04 | **Priority:** P1 | **Labels:** crypto, frontend | **Depends on:** CM-T023
- **Plan:** Phase 4 | M2 Identity and Access | Security impact: High | Evidence: EV-04-03 | Initial status: Backlog
- **Description:** Evaluate LIB-03 candidates, integrate the chosen one in a Web Worker, benchmark on a mid-range laptop and phone, set the final CP-04 parameters.
- **Acceptance criteria:**
  - Comparison of candidates recorded; RFC 9106 vectors pass in CI.
  - Final parameters recorded in the register; ADR-010 updated to Accepted.
  - CSP relaxed only by `'wasm-unsafe-eval'`; failure to load WASM fails closed.
- **Security considerations:** T-22, INV-15.

#### CM-T025 Vault setup: key-pair generation, private-key wrapping and upload
- **Epic:** CM-EPIC-04 | **Priority:** P1 | **Labels:** crypto, frontend, backend | **Depends on:** CM-T024, CM-T016, CM-T086
- **Plan:** Phase 4 | M2 Identity and Access | Security impact: High | Evidence: EV-04-01, EV-04-02 | Initial status: Backlog
- **Description:** DF-03 end to end, with Vault Passphrase policy (CP-06) and strength feedback. Per ADR-015 the identity is an RSA-OAEP-3072 encryption key pair and an ECDSA P-256 signing key pair under one key ID, with a binding signature and a fingerprint over both public keys; each private key is wrapped under its own HKDF-derived key (CP-27). API validation of key types and sizes, the binding signature, the fingerprint, parameters between the floor and the ceiling, unique key ID and one ACTIVE identity; audit `VAULT_CREATED`.
- **Acceptance criteria:**
  - A Playwright test inspects network traffic and finds neither the passphrase nor any PKCS#8 private key.
  - Parameters below the floor are rejected by the client and the API.
  - The API refuses an identity whose binding signature or fingerprint does not verify.
- **Security considerations:** INV-01; T-22.

#### CM-T026 Vault unlock, auto-lock and in-memory key handling
- **Epic:** CM-EPIC-04 | **Priority:** P1 | **Labels:** crypto, frontend | **Depends on:** CM-T025
- **Plan:** Phase 4 | M2 Identity and Access | Security impact: High | Evidence: EV-04-04 | Initial status: Backlog
- **Description:** DF-04 including the consistency checks of both key pairs (RSA-OAEP round trip and ECDSA signature, ADR-015); non-extractable private keys; auto-lock after 15 minutes (CP-22), on logout, on tab close and when the session becomes invalid; generic error for a wrong passphrase.
- **Acceptance criteria:**
  - No key material or plaintext in localStorage, sessionStorage, IndexedDB or cookies (Playwright inspection).
  - Neither private key can be exported (test).
  - Auto-lock clears keys and decrypted views.
- **Security considerations:** T-23, L-15.

#### CM-T027 Public-key directory API and fingerprint display
- **Epic:** CM-EPIC-04 | **Priority:** P1 | **Labels:** backend, frontend, crypto | **Depends on:** CM-T025
- **Plan:** Phase 4 | M2 Identity and Access | Security impact: High | Evidence: EV-04-05 | Initial status: Backlog
- **Description:** Exact-match, rate-limited user lookup returning ID, display name, account creation date, key ID, both public keys, the binding signature and the fingerprint, with the email labelled unverified (SS-05, T-35); the browser verifies the binding signature and computes the fingerprint over both keys itself (CP-17 as revised by ADR-015); fingerprint display in 16 groups of 4; audit events and notices for key changes.
- **Acceptance criteria:**
  - Lookup returns no other fields and is rate-limited.
  - Users can view their own fingerprint for out-of-band comparison.
- **Security considerations:** T-25, T-15.

#### CM-T028 Vault passphrase change
- **Epic:** CM-EPIC-04 | **Priority:** P2 | **Labels:** crypto, frontend | **Depends on:** CM-T026
- **Plan:** Phase 4 | M2 Identity and Access | Security impact: Medium | Evidence: none | Initial status: Backlog
- **Description:** Re-wrap both private keys under a new salt and new wrapping keys. The change is signed by the identity's signing key and applied by compare-and-swap on the previous salt (ADR-015 section 3). When stored parameters are below the current target, offer the same re-wrap after unlock; it needs a step-up, so it is offered rather than automatic (ADR-010). Audit `VAULT_REWRAPPED`.
- **Acceptance criteria:**
  - Same key pair after the change; the old record is replaced.
  - Old passphrase no longer unlocks the stored record.
  - An unsigned, wrongly signed, replayed or stale re-wrap is refused.
- **Security considerations:** Does not protect against an attacker who already has the old blob and old passphrase; that requires an identity reset (documented in the key lifecycle).

#### CM-T086 Decide key-version authentication (OCD-12) before Phase 4
- **Epic:** CM-EPIC-04 | **Priority:** P0 | **Labels:** crypto, architecture, security | **Depends on:** CM-T082
- **Plan:** Phase 4 | M2 Identity and Access | Security impact: High | Evidence: none | Initial status: Backlog
- **Description:** Decide how clients authenticate room-key versions and envelopes, so that a server-side attacker cannot distribute a key of its own (T-36). Evaluate per-user ECDSA P-256 signing keys held in the vault (recommended) against an authenticator chained to the previous room key. Record the decision in an ADR and update the identity, envelope and key-version formats before vault work starts.
- **Acceptance criteria:**
  - An ADR with the options, the chosen design, its limits and its effect on the vault, fingerprints, envelopes and rekey finalize.
  - Parameter register, data model, data flows and threat model (T-36, L-23) updated.
  - CM-T025 and later items updated to match.
- **Security considerations:** Closes, or explicitly accepts, the largest open cryptographic gap in the baseline.

---

## CM-EPIC-05 Secure Rooms & RBAC

#### CM-T029 Central authorization module implementing the authorization matrix
- **Epic:** CM-EPIC-05 | **Priority:** P0 | **Labels:** backend, security | **Depends on:** CM-T016, CM-T009
- **Plan:** Phase 5 | M2 Identity and Access | Security impact: High | Evidence: EV-05-01 | Initial status: Backlog
- **Description:** The AZ, PA and SS matrix as data in `packages/shared`; a pure `authorize()` function; action declarations on every route; room-scope middleware implementing OL-01; room-scoped repository functions; the error semantics of the authorization model.
- **Acceptance criteria:**
  - Exhaustive unit tests over every action and role; coverage at least 90%.
  - Route inventory test fails for any undeclared or untested route.
  - PLATFORM_ADMIN receives 404 on room-scoped endpoints of rooms they are not in.
- **Security considerations:** INV-05, INV-06; T-05, T-06.

#### CM-T030 Room creation, listing, renaming and deletion
- **Epic:** CM-EPIC-05 | **Priority:** P1 | **Labels:** backend, frontend | **Depends on:** CM-T029
- **Plan:** Phase 5 | M2 Identity and Access | Security impact: Medium | Evidence: none | Initial status: Backlog
- **Description:** Create a room with name and profile and OWNER membership; list rooms filtered by membership in the query; rename (AZ-02); delete with step-up (AZ-04) into DELETING, with worker cleanup. Room-name warning in the UI. Key material is added to creation in CM-T033.
- **Acceptance criteria:**
  - Users see only rooms they belong to; deleted rooms refuse all reads immediately.
  - Audit events for creation, rename and deletion.
- **Security considerations:** T-05; room names are metadata (T-28).

#### CM-T031 Membership administration: role changes and ownership transfer
- **Epic:** CM-EPIC-05 | **Priority:** P1 | **Labels:** backend, frontend, security | **Depends on:** CM-T030
- **Plan:** Phase 5 | M2 Identity and Access | Security impact: High | Evidence: none | Initial status: Backlog
- **Description:** Role changes (AZ-10) and ownership transfer to an ADMIN with step-up (AZ-05), with the one-OWNER invariant enforced in the database and the API. Leaving a room (AZ-11) is implemented with the rekey machinery in CM-T051.
- **Acceptance criteria:**
  - Tests for every allowed and denied role-change combination.
  - The one-OWNER invariant cannot be broken through any endpoint.
- **Security considerations:** T-04 (privilege escalation).

#### CM-T032 BOLA and IDOR object-level authorization test suite
- **Epic:** CM-EPIC-05 | **Priority:** P1 | **Labels:** testing, security | **Depends on:** CM-T030
- **Plan:** Phase 5 | M2 Identity and Access | Security impact: High | Evidence: EV-05-02, EV-05-03 | Initial status: Backlog
- **Description:** A reusable harness that creates two rooms with separate members and calls every room-scoped endpoint with identifiers from the other room. Extended with every new endpoint.
- **Acceptance criteria:**
  - Every route in the registry is covered; all return 404 without side effects.
  - The suite fails when a new route has no coverage; runs in CI.
- **Security considerations:** Primary control test for T-06 (rated Critical inherent).

---

## CM-EPIC-06 Cryptographic Room Membership

#### CM-T033 Initial room-key version with commitment and owner envelope
- **Epic:** CM-EPIC-06 | **Priority:** P1 | **Labels:** crypto, backend, frontend | **Depends on:** CM-T030, CM-T026
- **Plan:** Phase 6 | M3 Encrypted Collaboration | Security impact: High | Evidence: EV-06-01 | Initial status: Backlog
- **Description:** DF-05: room creation requires version 1 with commitment and the owner envelope; the API checks envelope length, that the recipient key is the caller's ACTIVE key, and commitment length; everything is stored in one transaction. The commitment is written once at activation and never changes. Per ADR-015 the creator also signs `cm.room.genesis` and the version-1 key-version statement (commitment and recipient list), and the API verifies both signatures under the creator's ACTIVE signing key before storing them.
- **Acceptance criteria:**
  - A room cannot be created without valid key data.
  - Request schemas contain no field that could carry raw key material.
  - E2E: create a room, lock and unlock the vault, reopen the room.
  - Unsigned or wrongly signed genesis and key-version statements are refused.
- **Security considerations:** INV-04.

#### CM-T034 Invitations with pre-wrapped key envelopes
- **Epic:** CM-EPIC-06 | **Priority:** P1 | **Labels:** crypto, backend, frontend, security | **Depends on:** CM-T033, CM-T027
- **Plan:** Phase 6 | M3 Encrypted Collaboration | Security impact: High | Evidence: EV-06-02 | Initial status: Backlog
- **Description:** DF-06 on the inviter side: role ceiling (ADMINs invite only MEMBER or VIEWER), history rule (PC-07), fingerprint confirmation (PC-05), server-set validity (PC-06), PENDING envelopes, revocation (AZ-08), invalidation when the invitee's key changes. Every invitation carries a membership grant signed by the inviter, or by the OWNER for ADMIN grants (`cm.room.membership-grant`, ADR-015). Invitations are rejected while the room is REKEY_REQUIRED or REKEYING.
- **Acceptance criteria:**
  - Envelope sets are validated: the current version is required, older versions only where allowed.
  - RESTRICTED invitations require a confirmed fingerprint equal to the invitee's current key.
  - Profile-specific tests for every rule; audit events.
- **Security considerations:** T-25 (key substitution), T-05.

#### CM-T035 Invitation acceptance, OWNER approval and envelope delivery
- **Epic:** CM-EPIC-06 | **Priority:** P1 | **Labels:** backend, frontend, security | **Depends on:** CM-T034
- **Plan:** Phase 6 | M3 Encrypted Collaboration | Security impact: High | Evidence: EV-06-02 | Initial status: Backlog
- **Description:** OWNER approval of ADMIN-created invitations in CONFIDENTIAL and RESTRICTED rooms (PC-04, approver differs from inviter); accept and decline; expiry job; envelope activation; own-envelope fetch (AZ-12, OL-05).
- **Acceptance criteria:**
  - PENDING envelopes are never served.
  - Expired or revoked invitations cannot be accepted.
  - Approval rules tested per profile.
- **Security considerations:** Two-person rule (segregation of duties, control 5.3).

#### CM-T036 Client-side room-key unwrap, commitment check and cross-browser checks
- **Epic:** CM-EPIC-06 | **Priority:** P1 | **Labels:** crypto, frontend, testing | **Depends on:** CM-T033
- **Plan:** Phase 6 | M3 Encrypted Collaboration | Security impact: High | Evidence: EV-06-03, EV-06-04 | Initial status: Backlog
- **Description:** Envelope decryption, commitment check, reuse check against the previous version, RWK derivation and an in-memory cache cleared on lock; the verification rule of ADR-015 section 4 (the creator's identity, the key-version signature, the creator's authority from the chain of signed grants back to the genesis statement, the decrypted key against the signed commitment, the client's own identity in the signed recipient list), with `KEY_AUTHENTICATION_FAILED` and a security alert on failure; reporting of mismatches (AZ-29); Playwright cross-browser tests of OAEP labels and decryption into HKDF keys (OCD-01).
- **Acceptance criteria:**
  - A tampered envelope, or one whose key does not match the stored commitment, is rejected and reported.
  - A test documents the limit: a harness that serves a different commitment with a matching envelope passes this check; the Room Safety Code (CM-T085) covers that case.
  - The cross-browser suite passes in Chromium, Firefox and WebKit.
  - ADR-007 updated to Accepted or revised with the results.
  - The `key-injection` suite: unsigned, forged, wrongly attributed and unauthorized versions, a commitment mismatch and a missing recipient are refused; a negative control removes the verification.
- **Security considerations:** The commitment detects inconsistent envelopes while the server is honest (T-29). Split views need the Room Safety Code. Tampering: T-07. Key versions created by the server are refused (T-36, ADR-015).

#### CM-T085 Room Safety Code
- **Epic:** CM-EPIC-06 | **Priority:** P1 | **Labels:** crypto, frontend, security | **Depends on:** CM-T036
- **Plan:** Phase 6 | M3 Encrypted Collaboration | Security impact: High | Evidence: EV-06-05, EV-06-06 | Initial status: Backlog
- **Description:** Implement ADR-012 and CP-24: HKDF derivation from the decrypted room key material; the six-word display with the key version and a numeric alternative; the word list (LIB-08); the Safety Code panel with guidance and advisory prompts per profile; optional comparison records and mismatch reports that carry only the key version (AZ-30); the mismatch flow.
- **Acceptance criteria:**
  - Known-answer vectors for the derivation and the word mapping pass in all three browser engines.
  - The code changes with key material, key version and room, and never appears in requests, logs or storage (network and storage inspection).
  - A two-browser test harness with different keys shows different codes, while the commitment check alone does not catch it.
  - UI wording states the limits (L-22) and never presents the code as automatic protection.
- **Security considerations:** Detects split views only when members compare (T-29, L-22). Does not detect T-36.

---

## CM-EPIC-07 Encrypted File System

#### CM-T037 S3-compatible object storage adapter and presigned URL service
- **Epic:** CM-EPIC-07 | **Priority:** P1 | **Labels:** backend, cloud | **Depends on:** CM-T011, CM-T029
- **Plan:** Phase 7 | M3 Encrypted Collaboration | Security impact: High | Evidence: EV-07-06 | Initial status: Backlog
- **Description:** Storage interface with an S3 implementation; presigned PUT (at most 5 minutes, fixed size) and GET (at most 60 seconds, attachment headers) per CP-20; HEAD verification; delete; random object keys; scoped credentials.
- **Acceptance criteria:**
  - Works against the local emulator; expired URLs fail (test).
  - Presigned URLs never appear in logs (redaction test).
- **Security considerations:** T-02, T-18, OL-07.

#### CM-T038 Client-side file encryption and upload
- **Epic:** CM-EPIC-07 | **Priority:** P1 | **Labels:** crypto, frontend, backend | **Depends on:** CM-T036, CM-T037
- **Plan:** Phase 7 | M3 Encrypted Collaboration | Security impact: High | Evidence: EV-07-01, EV-07-02, EV-07-03, EV-07-05 | Initial status: Backlog
- **Description:** DF-07: FEK, encrypted manifest, wrap under RWK_v, ciphertext hash, size limit (CP-19), PENDING_UPLOAD to AVAILABLE with completion check, wrap-count increment, current-version and room key-state checks, profile expiry rules.
- **Acceptance criteria:**
  - Canary scan finds no filename or content canary in the database or bucket.
  - Stale key versions (`KEY_VERSION_STALE`) and write-locked rooms (`REKEY_REQUIRED`) return 409, including at upload completion.
  - Size mismatch at completion rejects the upload and deletes the object.
- **Security considerations:** INV-01, INV-16; T-01, T-02.

#### CM-T039 File download and authenticated decryption with tamper handling
- **Epic:** CM-EPIC-07 | **Priority:** P1 | **Labels:** crypto, frontend, backend | **Depends on:** CM-T038
- **Plan:** Phase 7 | M3 Encrypted Collaboration | Security impact: High | Evidence: EV-07-04 | Initial status: Backlog
- **Description:** DF-08: POST for download URLs, VIEWER restriction in RESTRICTED (PC-12), ciphertext hash check, unwrap, authenticated decryption of manifest and content, plaintext hash check, integrity-error UI, audit at EXTENDED and FULL levels.
- **Acceptance criteria:**
  - Bit flips in the object, manifest or wrapped FEK produce an integrity error and no plaintext.
  - Downloaded bytes equal the original (E2E).
  - VIEWERs are denied in RESTRICTED rooms.
- **Security considerations:** T-07; L-14 (download restrictions are API-level only).

#### CM-T040 File deletion, expiration and storage cleanup worker
- **Epic:** CM-EPIC-07 | **Priority:** P1 | **Labels:** backend, cloud | **Depends on:** CM-T038
- **Plan:** Phase 7 | M3 Encrypted Collaboration | Security impact: Medium | Evidence: none | Initial status: Backlog
- **Description:** Deletion rights (AZ-18), expiry enforced at read time, worker deletion of objects with retries, cleanup of abandoned uploads, tombstones, storage lifecycle rules as a safety net.
- **Acceptance criteria:**
  - Expired files are refused immediately, before the worker runs.
  - Deleted files have no object, wrapped FEK or manifest left in the live system.
- **Security considerations:** INV-14; L-12 (backups).

#### CM-T041 Upload limits, quotas and safe download handling
- **Epic:** CM-EPIC-07 | **Priority:** P1 | **Labels:** backend, frontend, security | **Depends on:** CM-T038
- **Plan:** Phase 7 | M3 Encrypted Collaboration | Security impact: High | Evidence: none | Initial status: Backlog
- **Description:** Per-room and per-user quotas; forced attachment downloads; preview allowlist (images through blob URLs only); HTML and SVG never rendered inline; warning for executable types.
- **Acceptance criteria:**
  - Quota and size tests.
  - Playwright confirms HTML and SVG uploads never render inline.
  - Filenames with path traversal characters do not influence storage keys.
- **Security considerations:** T-11, T-26.

---

## CM-EPIC-08 Secure Notes & Secret Exchange

#### CM-T042 Encrypted notes
- **Epic:** CM-EPIC-08 | **Priority:** P1 | **Labels:** crypto, frontend, backend | **Depends on:** CM-T036
- **Plan:** Phase 8 | M3 Encrypted Collaboration | Security impact: High | Evidence: EV-08-01, EV-08-02 | Initial status: Backlog
- **Description:** DF-12: fresh NEK per revision, revision number in AAD, optimistic concurrency, edit and delete rights (AZ-19 to AZ-22), expiry rules, note-read audit at EXTENDED and FULL, text-only rendering.
- **Acceptance criteria:**
  - Canary scan finds no note title or body in the database.
  - A stale revision returns 409; ciphertext moved to another revision fails authentication.
  - XSS payloads in notes render as text (Playwright).
- **Security considerations:** T-07, T-12, T-32.

#### CM-T043 Recipient-bound secrets with envelope encryption and expiration
- **Epic:** CM-EPIC-08 | **Priority:** P1 | **Labels:** crypto, backend, frontend | **Depends on:** CM-T036, CM-T027
- **Plan:** Phase 9 | M3 Encrypted Collaboration | Security impact: High | Evidence: EV-09-04 | Initial status: Backlog
- **Description:** DF-09 creation: a fresh SEK per secret; the payload encrypted with AES-256-GCM under the SEK (AAD ctx `secret.payload`); only the 32-byte SEK wrapped to the recipient's ACTIVE key with RSA-OAEP (label ctx `secret.sek-wrap`); the recipient must be an ACTIVE member with that key; the room must be ACTIVE; lifetime bounds (PC-09); metadata-only listing; revocation (AZ-25).
- **Acceptance criteria:**
  - The stored row holds only the AES-256-GCM ciphertext, IV, wrapped SEK, suite and context identifiers (INV-17).
  - The RSA wrapper rejects anything but a 32-byte key, and no code path RSA-encrypts the payload (review and test).
  - Other members cannot obtain the ciphertext through the API, and a test shows they cannot unwrap the SEK with their own keys.
  - Lifetime bounds are enforced per profile; expired secrets are refused; creation is refused while the room is write-locked.
- **Security considerations:** CD-06, CD-17; T-05, T-07.

#### CM-T044 Atomic burn-after-reading reveal
- **Epic:** CM-EPIC-08 | **Priority:** P1 | **Labels:** backend, security, testing | **Depends on:** CM-T043
- **Plan:** Phase 9 | M3 Encrypted Collaboration | Security impact: High | Evidence: EV-09-01, EV-09-02, EV-09-03 | Initial status: Backlog
- **Description:** DF-09 reveal: POST only, locking transaction, payload ciphertext and wrapped SEK set to NULL in the same transaction, at-most-once delivery, UI warning that the recipient can still copy the text, burn mandatory in RESTRICTED (PC-10).
- **Acceptance criteria:**
  - Many parallel reveal requests produce exactly one success.
  - GET requests never consume a secret; a second reveal fails.
  - After reveal, the database row holds no payload ciphertext or wrapped SEK.
- **Security considerations:** INV-13; limitations L-03 and L-12 shown in the UI and report.

#### CM-T045 External one-time secret links (stretch)
- **Epic:** CM-EPIC-08 | **Priority:** P3 | **Labels:** crypto, frontend, backend, security | **Depends on:** CM-T044, CM-T047
- **Plan:** Phase 9 | M3 Encrypted Collaboration | Security impact: High | Evidence: none | Initial status: Backlog
- **Description:** Key carried only in the URL fragment, POST-to-reveal, STANDARD rooms only (PC-11), maximum 24 hours, `Referrer-Policy: no-referrer`, clear "already opened" message.
- **Acceptance criteria:**
  - A network-inspection test shows the fragment never reaches the server.
  - CONFIDENTIAL and RESTRICTED rooms receive 403.
- **Security considerations:** T-33.

---

## CM-EPIC-09 Security Policy Engine

#### CM-T046 Policy catalogue as versioned code
- **Epic:** CM-EPIC-09 | **Priority:** P1 | **Labels:** security, backend | **Depends on:** CM-T029
- **Plan:** Phase 10 | M4 Governance and Key Lifecycle | Security impact: High | Evidence: none | Initial status: Backlog
- **Description:** Implement PC-01 to PC-16 as an immutable, versioned catalogue in `packages/shared`; rooms store profile and policy version; UI labels come from the catalogue.
- **Acceptance criteria:**
  - A test compares the catalogue with a fixture derived from the table in `security-policy-profiles.md`.
  - No database table can change policy values at runtime.
- **Security considerations:** A database-level attacker cannot weaken all rooms by editing a table.

#### CM-T047 Server-side policy enforcement gates
- **Epic:** CM-EPIC-09 | **Priority:** P1 | **Labels:** security, backend | **Depends on:** CM-T046, CM-T021
- **Plan:** Phase 10 | M4 Governance and Key Lifecycle | Security impact: High | Evidence: EV-10-02 | Initial status: Backlog
- **Description:** Gates in the evaluation order of the profiles document, applied to every room route through the route registry; audit levels (PC-13); stable error codes.
- **Acceptance criteria:**
  - Each gate has allowed and denied tests.
  - Gates never read profile or role data from the request.
- **Security considerations:** INV-08.

#### CM-T048 Profile change rules and expiration clamping
- **Epic:** CM-EPIC-09 | **Priority:** P2 | **Labels:** security, backend | **Depends on:** CM-T047
- **Plan:** Phase 10 | M4 Governance and Key Lifecycle | Security impact: Medium | Evidence: EV-10-03 | Initial status: Backlog
- **Description:** Upgrade and downgrade rules, clamping of existing expiry dates on upgrade, revocation of non-compliant invitations, high-severity audit event on downgrade.
- **Acceptance criteria:**
  - Clamping tests; downgrade requires a 5-minute step-up.
  - After an upgrade to CONFIDENTIAL, members without MFA are denied until they enable it.
- **Security considerations:** Prevents silent weakening of a room (principle 15).

#### CM-T049 Policy enforcement test matrix
- **Epic:** CM-EPIC-09 | **Priority:** P1 | **Labels:** testing, security | **Depends on:** CM-T047
- **Plan:** Phase 10 | M4 Governance and Key Lifecycle | Security impact: High | Evidence: EV-10-01 | Initial status: Backlog
- **Description:** Generated tests for every control and profile with an allowed and a denied case, asserting status code, error code and audit event.
- **Acceptance criteria:**
  - Every PC control is covered; the suite runs in CI and blocks merges on failure.
- **Security considerations:** Proves that profiles are real controls, not badges.

---

## CM-EPIC-10 Key Lifecycle & Rotation

#### CM-T050 Rekey state machine and rekey operation API
- **Epic:** CM-EPIC-10 | **Priority:** P1 | **Labels:** crypto, backend, frontend | **Depends on:** CM-T036
- **Plan:** Phase 11 | M4 Governance and Key Lifecycle | Security impact: High | Evidence: EV-11-01, EV-11-03, EV-11-06, EV-11-07 | Initial status: Backlog
- **Description:** Implement ADR-013 and key-lifecycle sections 1.2 to 1.5: room key states; rekey operations (start, finalize, cancel) with a 10-minute lease and one live operation per room; the membership-epoch snapshot and server-computed recipient set; atomic activation; idempotent finalize by payload digest; stale and closed operation handling; worker cleanup of abandoned operations; manual rotation without the write lock; the admin flow with recipient review. The finalize payload carries the starter's signed key-version statement (ADR-015), which the API verifies and stores with the version.
- **Acceptance criteria:**
  - Only the starter can finalize; concurrent starts return `REKEY_IN_PROGRESS`; the OWNER can cancel.
  - Finalize rejects a wrong recipient set (422), a changed epoch or version, and closed or expired operations (409). A repeated identical finalize returns the original result.
  - A rekey that never finalizes is recoverable after the lease expires, and no partial key state exists.
  - After activation, writes naming the old version return `KEY_VERSION_STALE`, and old content stays readable.
  - Every transition emits an audit event.
  - A finalize without a valid key-version signature by the starter is refused.
- **Security considerations:** T-21, T-37. Departed members never receive the new version.

#### CM-T051 Member loss triggers REKEY_REQUIRED and the write lock
- **Epic:** CM-EPIC-10 | **Priority:** P1 | **Labels:** crypto, backend, security | **Depends on:** CM-T050, CM-T031
- **Plan:** Phase 11 | M4 Governance and Key Lifecycle | Security impact: High | Evidence: EV-11-02, EV-11-04, EV-11-05 | Initial status: Backlog
- **Description:** Removal (AZ-09), leaving (AZ-11), membership suspension (account disabled) and account deletion. In one transaction the membership changes, all of the member's envelopes are deleted, the membership epoch increments, pending uploads are cancelled and the room enters REKEY_REQUIRED. Content writes and invitations are blocked while the room is REKEY_REQUIRED or REKEYING (PC-16). The removing admin is prompted to rekey immediately.
- **Acceptance criteria:**
  - The removed member gets 404 on every room endpoint and has no envelopes left.
  - Writes and invitations return 409 `REKEY_REQUIRED` until a rekey completes; reads continue.
  - A pending rekey operation becomes STALE when membership changes.
  - A test holding the old RKM cannot unwrap DEKs created after the rekey.
- **Security considerations:** INV-07; T-21; L-04 and L-24 demonstrated.

#### CM-T052 Key-version retirement, destruction, wrap-count bound and cryptoperiod
- **Epic:** CM-EPIC-10 | **Priority:** P2 | **Labels:** crypto, backend | **Depends on:** CM-T050
- **Plan:** Phase 11 | M4 Governance and Key Lifecycle | Security impact: High | Evidence: none | Initial status: Backlog
- **Description:** Worker destroys unreferenced RETIRED versions (envelopes deleted); wrap-count bound (CP-16) and cryptoperiods (PC-14) set REKEY_REQUIRED, with a reminder 14 days before cryptoperiod expiry.
- **Acceptance criteria:**
  - Tests with small thresholds in test configuration trigger each path.
  - Destroyed versions keep only commitment and metadata.
- **Security considerations:** Enforces key-usage bounds (CP-16).

#### CM-T053 Compromised identity-key procedure
- **Epic:** CM-EPIC-10 | **Priority:** P2 | **Labels:** crypto, security, documentation | **Depends on:** CM-T051
- **Plan:** Phase 11 | M4 Governance and Key Lifecycle | Security impact: High | Evidence: none | Initial status: Backlog
- **Description:** Vault reset (old identity with both key pairs SUPERSEDED, envelopes deleted; the Phase 4 reset already replaces the identity and revokes the other sessions), optional compromise flag that sets all of the user's rooms to REKEY_REQUIRED, re-share flow (AZ-14) with fingerprint rules, and an incident runbook.
- **Acceptance criteria:**
  - E2E: reset a vault, admins re-share, the user regains access as the history rule allows.
  - The compromise path marks every affected room; runbook documented.
- **Security considerations:** Key lifecycle sections 3 and 6.

---

## CM-EPIC-11 Tamper-Evident Auditing

#### CM-T054 Audit event schema, canonical serialization and hash chaining
- **Epic:** CM-EPIC-11 | **Priority:** P1 | **Labels:** security, backend, crypto | **Depends on:** CM-T014, CM-T023
- **Plan:** Phase 12 | M4 Governance and Key Lifecycle | Security impact: High | Evidence: EV-12-01 | Initial status: Backlog
- **Description:** ADR-009 sections 1 to 3: fixed field set, RFC 8785 canonicalization, chain-head lock, append in the same transaction as the action, `hashVersion`.
- **Acceptance criteria:**
  - Concurrent appends produce gap-free sequence numbers and a valid chain.
  - Property tests confirm lossless database round trips of canonical records.
  - Recomputed hashes equal stored hashes.
- **Security considerations:** T-20.

#### CM-T055 Audit emission for security-relevant actions per audit level
- **Epic:** CM-EPIC-11 | **Priority:** P1 | **Labels:** backend, security | **Depends on:** CM-T054, CM-T047
- **Plan:** Phase 12 | M4 Governance and Key Lifecycle | Security impact: High | Evidence: none | Initial status: Backlog
- **Description:** Event catalogue with allowlisted detail keys per action; BASELINE, EXTENDED and FULL levels (PC-13); platform-level events; denied requests.
- **Acceptance criteria:**
  - Each catalogued action emits its event (tests).
  - Details never contain secrets, content or IP addresses (tests).
- **Security considerations:** Accountability (control 8.15) without leaking data (INV-10).

#### CM-T056 Chain verification service and room audit view
- **Epic:** CM-EPIC-11 | **Priority:** P1 | **Labels:** backend, frontend, security | **Depends on:** CM-T055
- **Plan:** Phase 12 | M4 Governance and Key Lifecycle | Security impact: High | Evidence: EV-12-02 | Initial status: Backlog
- **Description:** Hourly incremental and daily full verification in the worker, stored verification runs, PLATFORM_ADMIN verification endpoint, room audit view for OWNER and ADMIN (AZ-28).
- **Acceptance criteria:**
  - Verification detects tampering in tests and records the first bad sequence number.
  - The room view shows only events of that room.
- **Security considerations:** T-20.

#### CM-T057 Signed checkpoints, anchoring and Level 1 key custody
- **Epic:** CM-EPIC-11 | **Priority:** P1 | **Labels:** crypto, cloud, security | **Depends on:** CM-T056
- **Plan:** Phase 12 | M4 Governance and Key Lifecycle | Security impact: High | Evidence: EV-12-04, EV-12-05 | Initial status: Backlog
- **Description:** Ed25519 checkpoint signing (CP-14) with the key mounted only into the worker; storage in the database and in the anchor bucket (compliance-mode retention lock where available, write-only credential); public keys and the revocation list in the repository; checkpoints after security-critical events; the weekly external witness procedure; refusal to sign a chain that no longer matches the last anchor. Decide on RFC 3161 timestamps (OCD-08).
- **Acceptance criteria:**
  - Checkpoints verify with the repository public key; checkpoints signed with a revoked key after its revocation time are rejected.
  - The worker refuses to sign when the chain diverges from the last anchored checkpoint and records an INVALID run.
  - The anchor credential cannot delete or overwrite objects (tested where the provider or emulator supports it).
  - The witness procedure is documented and executed once; the OCD-08 decision is recorded.
- **Security considerations:** Closes the regenerated-chain gap up to the last anchor (L-13). Does not protect against an attacker holding the signing key (L-25, T-38).

#### CM-T058 Offline audit verifier and tampering demonstration
- **Epic:** CM-EPIC-11 | **Priority:** P1 | **Labels:** security, testing, crypto | **Depends on:** CM-T057
- **Plan:** Phase 12 | M4 Governance and Key Lifecycle | Security impact: High | Evidence: EV-12-03, EV-12-06 | Initial status: Backlog
- **Description:** Command-line verifier and a demonstration script run against a copy of the database: edit an event, delete an event, recompute the chain without the signing key. Also simulate the trust-model scenarios A to D of ADR-009 section 8.
- **Acceptance criteria:**
  - The verifier reports the first mismatch for each tampering type.
  - A recomputed chain is detected through the anchored checkpoint mismatch.
  - Evidence captured for the report.
  - Scenario simulations recorded as evidence (EV-12-06).
- **Security considerations:** Demonstrates "tamper-evident, not tamper-proof" honestly.

---

## CM-EPIC-12 Crypto Inspector & Security Dashboard

#### CM-T059 Crypto Inspector metadata API
- **Epic:** CM-EPIC-12 | **Priority:** P1 | **Labels:** backend, security | **Depends on:** CM-T039, CM-T043
- **Plan:** Phase 13 | M5 Visibility | Security impact: High | Evidence: EV-13-01 | Initial status: Backlog
- **Description:** Endpoints returning the allowlisted inspection fields of `docs/architecture/crypto-inspector.md` for files, notes, secrets, rooms and the caller's identity, with the same authorization as reading the item (AZ-27).
- **Acceptance criteria:**
  - A response-schema test fails on any field outside the allowlist.
  - No key material, wrapped or unwrapped, appears in responses.
  - Non-members receive 404.
- **Security considerations:** INV-10; T-15.

#### CM-T060 Crypto Inspector UI
- **Epic:** CM-EPIC-12 | **Priority:** P1 | **Labels:** frontend, crypto | **Depends on:** CM-T059
- **Plan:** Phase 13 | M5 Visibility | Security impact: High | Evidence: EV-13-01, EV-13-02 | Initial status: Backlog
- **Description:** Panel combining server metadata with client-side results (tag verification, commitment check, locally computed plaintext hash); the room view with key state and the Room Safety Code; a "what this does not protect" section linking to the limitations.
- **Acceptance criteria:**
  - A DOM scan with known test keys finds no key material rendered.
  - A network test shows the locally computed plaintext hash is never sent to the server.
  - Wording reviewed against the honest-claims rule.
  - The Safety Code shown in the Inspector matches the room's Safety Code panel and never appears in network traffic.
- **Security considerations:** Transparency without exposure; supports the cryptography demonstration.

#### CM-T061 Security Dashboard metrics API
- **Epic:** CM-EPIC-12 | **Priority:** P1 | **Labels:** backend, security | **Depends on:** CM-T056, CM-T018
- **Plan:** Phase 14 | M5 Visibility | Security impact: Medium | Evidence: EV-14-02 | Initial status: Backlog
- **Description:** Metrics defined in `docs/architecture/security-dashboard.md`, computed from real data by documented queries, available to PLATFORM_ADMIN only, aggregates only, each with an "as of" timestamp.
- **Acceptance criteria:**
  - Each metric has a test with seeded data that checks the exact value.
  - Empty data produces empty states, never invented values.
  - Responses contain no room names or content.
- **Security considerations:** No fake scores; privacy of room metadata (T-28).

#### CM-T062 Security Dashboard UI
- **Epic:** CM-EPIC-12 | **Priority:** P1 | **Labels:** frontend | **Depends on:** CM-T061
- **Plan:** Phase 14 | M5 Visibility | Security impact: Medium | Evidence: EV-14-01 | Initial status: Backlog
- **Description:** Dashboard showing each metric with its definition and timestamp, the audit-integrity status, and highlighted counts of write-locked rooms awaiting a rekey, recent profile downgrades and Room Safety Code mismatch reports.
- **Acceptance criteria:**
  - Displayed values match the API.
  - No composite "security score" anywhere.
- **Security considerations:** Monitoring evidence for ISO/IEC 27001 clause 9.1.

---

## CM-EPIC-13 Cloud Deployment

#### CM-T063 Cloud provider selection ADR
- **Epic:** CM-EPIC-13 | **Priority:** P1 | **Labels:** cloud, architecture | **Depends on:** CM-T082
- **Plan:** Phase 17 | M7 Cloud Deployment | Security impact: Medium | Evidence: EV-17-01 | Initial status: Backlog
- **Description:** Compare providers against the criteria in `docs/cloud/service-models.md` (managed PostgreSQL features, S3 compatibility, object lock, private networking, region, MFA, cost) and record the choice as ADR-014.
- **Acceptance criteria:**
  - ADR-012 with a comparison table and decision.
  - Shared-responsibility matrix updated with provider specifics.
- **Security considerations:** Supplier selection (controls 5.19 and 5.23).

#### CM-T064 VM provisioning and baseline configuration
- **Epic:** CM-EPIC-13 | **Priority:** P1 | **Labels:** cloud, infrastructure | **Depends on:** CM-T063
- **Plan:** Phase 17 | M7 Cloud Deployment | Security impact: Medium | Evidence: EV-17-01, EV-17-02 | Initial status: Backlog
- **Description:** Ubuntu Server LTS VM, provider firewall, SSH keys, named operator account, updates, Docker from the official repository; reproducible runbook in `infrastructure/deployment`.
- **Acceptance criteria:**
  - Runbook reproduces the VM; no secrets in the repository.
  - Evidence: console configuration, firewall rules, external port scan.
- **Security considerations:** T-19; principle 12.

#### CM-T065 Production container images and Compose stack
- **Epic:** CM-EPIC-13 | **Priority:** P1 | **Labels:** infrastructure | **Depends on:** CM-T064
- **Plan:** Phase 17 | M7 Cloud Deployment | Security impact: Medium | Evidence: EV-17-03 | Initial status: Backlog
- **Description:** Multi-stage Dockerfiles, non-root users, read-only root filesystems, images pinned by digest, Compose networks `edge` and `app`, secrets as files, health checks, image scanning in CI.
- **Acceptance criteria:**
  - `docker inspect` evidence shows non-root users and no published API port.
  - Image scan has no unresolved Critical findings; image history shows no secrets.
- **Security considerations:** T-16, T-19.

#### CM-T066 Nginx reverse proxy, TLS and security headers
- **Epic:** CM-EPIC-13 | **Priority:** P1 | **Labels:** infrastructure, security | **Depends on:** CM-T065
- **Plan:** Phase 17 | M7 Cloud Deployment | Security impact: High | Evidence: EV-17-04, EV-17-05 | Initial status: Backlog
- **Description:** ACME certificates with automatic renewal, TLS per CP-21, the header set from the deployment document, rate-limit zones, static asset serving, staged HSTS.
- **Acceptance criteria:**
  - External TLS scan result recorded (target grade A or better).
  - Header check passes; HTTP redirects to HTTPS; E2E runs without CSP violations.
- **Security considerations:** T-12, T-31.

#### CM-T067 Managed PostgreSQL integration
- **Epic:** CM-EPIC-13 | **Priority:** P1 | **Labels:** cloud, database, security | **Depends on:** CM-T064
- **Plan:** Phase 18 | M7 Cloud Deployment | Security impact: High | Evidence: EV-18-01, EV-18-02 | Initial status: Backlog
- **Description:** Provision the database, restrict access to the VM, verify TLS with the provider CA, create the roles from CM-T014, configure backups and point-in-time recovery.
- **Acceptance criteria:**
  - Connections from other addresses, without TLS or with a wrong CA fail (tests).
  - Credentials stored only as secret files on the VM.
- **Security considerations:** T-01, T-31.

#### CM-T068 Provider-managed object storage integration
- **Epic:** CM-EPIC-13 | **Priority:** P1 | **Labels:** cloud, security | **Depends on:** CM-T064, CM-T037
- **Plan:** Phase 18 | M7 Cloud Deployment | Security impact: High | Evidence: EV-18-03, EV-18-04, EV-18-05 | Initial status: Backlog
- **Description:** Content bucket (private, versioned, CORS, lifecycle) and anchor bucket (retention lock, write-only credential); scoped credentials.
- **Acceptance criteria:**
  - Anonymous access and foreign-origin CORS requests are denied.
  - Deleting an anchored checkpoint with the worker credential is denied.
  - Canary scan against the deployed bucket with synthetic data passes.
- **Security considerations:** T-02, T-18, T-20.

---

## CM-EPIC-14 Infrastructure Hardening

#### CM-T069 SSH, OS and firewall hardening with Lynis baseline
- **Epic:** CM-EPIC-14 | **Priority:** P1 | **Labels:** infrastructure, security, cloud | **Depends on:** CM-T064
- **Plan:** Phase 19 | M7 Cloud Deployment | Security impact: High | Evidence: EV-19-01, EV-19-02, EV-19-03, EV-19-05 | Initial status: Backlog
- **Description:** Apply the VM hardening checklist, including the Docker port-publishing caveat, unattended upgrades and time synchronization; run Lynis before and after.
- **Acceptance criteria:**
  - Checklist complete; Lynis reports before and after stored as evidence.
  - Password-based SSH login is refused (test); SSH configuration audit is clean.
- **Security considerations:** T-19.

#### CM-T070 Docker and container runtime hardening
- **Epic:** CM-EPIC-14 | **Priority:** P2 | **Labels:** infrastructure, security | **Depends on:** CM-T065
- **Plan:** Phase 19 | M7 Cloud Deployment | Security impact: Medium | Evidence: EV-19-04 | Initial status: Backlog
- **Description:** Docker daemon configuration (log rotation, `no-new-privileges` by default), resource limits, Docker Bench for Security run and triage.
- **Acceptance criteria:**
  - Docker Bench report stored; findings triaged in Jira.
  - All containers match the security settings table.
- **Security considerations:** T-19.

#### CM-T071 Secrets management and credential rotation
- **Epic:** CM-EPIC-14 | **Priority:** P1 | **Labels:** security, cloud | **Depends on:** CM-T065
- **Plan:** Phase 19 | M7 Cloud Deployment | Security impact: High | Evidence: EV-19-06, EV-19-08 | Initial status: Backlog
- **Description:** Credential inventory, secret files with restrictive permissions, one executed rotation (for example the database password) as evidence, MFA verified on cloud, GitHub and Jira accounts.
- **Acceptance criteria:**
  - Inventory documented; rotation performed and recorded in Jira.
  - `docker inspect` shows no secrets in environment variables.
- **Security considerations:** T-16, T-17.

#### CM-T072 Backups, restore test, logging and monitoring
- **Epic:** CM-EPIC-14 | **Priority:** P2 | **Labels:** cloud, infrastructure | **Depends on:** CM-T067
- **Plan:** Phase 19 | M7 Cloud Deployment | Security impact: Medium | Evidence: EV-19-07 | Initial status: Backlog
- **Description:** Backup retention settings, restore to a temporary instance, log rotation, health checks, certificate-expiry and disk alerts, audit verification status visible.
- **Acceptance criteria:**
  - Restore test report stored as evidence.
  - Retention periods documented (they affect L-12).
- **Security considerations:** Availability (L-06), control 8.13.

#### CM-T087 Optional Level 2 audit signing with a provider-managed key (OCD-13)
- **Epic:** CM-EPIC-14 | **Priority:** P3 | **Labels:** cloud, crypto, security | **Depends on:** CM-T057, CM-T063
- **Plan:** Phase 19 | M7 Cloud Deployment | Security impact: High | Evidence: EV-19-09 | Initial status: Backlog
- **Description:** If the selected provider offers asymmetric signing with non-exportable keys, move checkpoint signing to it: a key policy granting the worker "sign" only, an MFA-protected administration role, provider signing logs, a checkpoint format that records the algorithm, and a documented migration from the Level 1 key.
- **Acceptance criteria:**
  - No signing key file remains on the VM; checkpoints verify with the provider key's public key.
  - The worker cannot administer or export the key (tested).
  - Evidence EV-19-09 captured; ADR-009 status updated.
- **Security considerations:** Separates key custody from the VM (T-38). Does not help against a full cloud-account compromise.

---

## CM-EPIC-15 Security Testing & Remediation

#### CM-T073 API hardening pass
- **Epic:** CM-EPIC-15 | **Priority:** P1 | **Labels:** backend, security | **Depends on:** CM-T047
- **Plan:** Phase 15 | M6 Hardening and Test Automation | Security impact: High | Evidence: EV-15-01, EV-15-02 | Initial status: Backlog
- **Description:** Review every endpoint for validation, error handling, headers and rate limits against the relevant OWASP ASVS sections; evaluate Trusted Types; run a ZAP baseline scan; fix findings.
- **Acceptance criteria:**
  - ZAP baseline with no unresolved High findings.
  - Review checklist stored; findings tracked in Jira.
- **Security considerations:** T-12, T-14, T-15.

#### CM-T074 Automated security regression suite in CI
- **Epic:** CM-EPIC-15 | **Priority:** P1 | **Labels:** testing, security | **Depends on:** CM-T012, CM-T049
- **Plan:** Phase 16 | M6 Hardening and Test Automation | Security impact: High | Evidence: EV-16-01, EV-16-02 | Initial status: Backlog
- **Description:** Consolidate the suites listed in the security testing plan, tag tests with threat and control IDs, and generate the traceability table.
- **Acceptance criteria:**
  - All suites run on every pull request; coverage thresholds enforced.
  - Traceability table generated automatically.
- **Security considerations:** Principle 13 (security controls must be testable).

#### CM-T075 Playwright E2E suite across Chromium, Firefox and WebKit
- **Epic:** CM-EPIC-15 | **Priority:** P2 | **Labels:** testing, frontend | **Depends on:** CM-T039, CM-T044
- **Plan:** Phase 16 | M6 Hardening and Test Automation | Security impact: Medium | Evidence: none | Initial status: Backlog
- **Description:** Full flows: registration, MFA, vault, rooms, invitations, files, notes, secrets, rotation and audit view, with the canary-scan hook.
- **Acceptance criteria:**
  - Full suite nightly on three engines; smoke subset on every pull request.
- **Security considerations:** Cross-browser crypto correctness (OCD-01).

#### CM-T076 Dependency, container and configuration scanning
- **Epic:** CM-EPIC-15 | **Priority:** P2 | **Labels:** security, infrastructure, testing | **Depends on:** CM-T012
- **Plan:** Phase 16 | M6 Hardening and Test Automation | Security impact: Medium | Evidence: EV-16-03 | Initial status: Backlog
- **Description:** Weekly scheduled dependency, container and secret scans plus SBOM per release, with a triage process.
- **Acceptance criteria:**
  - Scheduled workflow active; findings triaged in Jira; SBOM attached to releases.
- **Security considerations:** T-27.

#### CM-T077 Security assessment against OWASP ASVS with DAST and manual testing
- **Epic:** CM-EPIC-15 | **Priority:** P1 | **Labels:** security, testing | **Depends on:** CM-T066, CM-T069, CM-T074
- **Plan:** Phase 20 | M8 Assessment and Report | Security impact: High | Evidence: EV-20-01, EV-20-02, EV-20-03 | Initial status: Backlog
- **Description:** Phase 20 assessment: ASVS 5.0 Level 2 checklist, selected WSTG tests, authenticated ZAP scan, infrastructure scans, and a review of the implementation against `docs/crypto`.
- **Acceptance criteria:**
  - Assessment report stored; every finding recorded with the Security Finding template.
  - Residual risks in the threat model updated.
- **Security considerations:** Independent review (control 5.35), internal audit (clause 9.2).

#### CM-T078 Security finding remediation and regression tests
- **Epic:** CM-EPIC-15 | **Priority:** P1 | **Labels:** security-finding, security, testing | **Depends on:** CM-T077
- **Plan:** Phase 21 | M8 Assessment and Report | Security impact: High | Evidence: EV-21-01, EV-21-02, EV-21-03, EV-21-04 | Initial status: Backlog
- **Description:** Fix each finding with a regression test that fails before the fix, retest, close; formal acceptance for anything not fixed.
- **Acceptance criteria:**
  - All Critical and High findings fixed; Medium fixed or accepted with approval.
  - At least one finding documented through its full lifecycle as evidence.
- **Security considerations:** Corrective action (clause 10.2).

---

## CM-EPIC-16 Documentation & Final Report

#### CM-T079 Evidence capture and evidence index
- **Epic:** CM-EPIC-16 | **Priority:** P1 | **Labels:** documentation | **Depends on:** CM-T001
- **Plan:** Phase 22 | M8 Assessment and Report | Security impact: Low | Evidence: EV-22-03 | Initial status: Backlog
- **Description:** Maintain `docs/report/evidence/` and the evidence index throughout the project, applying the redaction rules.
- **Acceptance criteria:**
  - The index is complete for every finished phase; every item passed the redaction checklist.
- **Security considerations:** T-16, T-34 (no secrets in evidence).

#### CM-T080 ISMS documentation set
- **Epic:** CM-EPIC-16 | **Priority:** P1 | **Labels:** documentation, risk, security | **Depends on:** CM-T003
- **Plan:** Phase 22 | M8 Assessment and Report | Security impact: Medium | Evidence: none | Initial status: Backlog
- **Description:** Update the risk register, complete applicability and evidence in the ISO/IEC 27001 control mapping, write the incident response procedure, record an access review and a supplier (cloud and SaaS) assessment.
- **Acceptance criteria:**
  - Documents updated; project owner signs off the risk acceptances.
- **Security considerations:** Demonstrates the management-system side of the project.

#### CM-T081 Final report and demonstration
- **Epic:** CM-EPIC-16 | **Priority:** P1 | **Labels:** documentation | **Depends on:** CM-T078, CM-T079, CM-T080
- **Plan:** Phase 22 | M8 Assessment and Report | Security impact: Low | Evidence: EV-22-01, EV-22-02 | Initial status: Backlog
- **Description:** Final report structured by the three subjects, a demonstration script, and optional slides; includes limitations and the test traceability table.
- **Acceptance criteria:**
  - Every security claim in the report is checked against `docs/security/limitations.md`.
  - The demonstration has been rehearsed end to end on the deployed system.
- **Security considerations:** Honest-claims rule.

---

## Items per release

| Release | Phases | Items |
|---|---|---|
| M0 Architecture Baseline | 0, 0.5 | T001 to T005, T082 to T084 |
| M1 Foundation | 1, 2 | T006 to T014 |
| M2 Identity and Access | 3, 4, 5 | T015 to T032, T086 |
| M3 Encrypted Collaboration | 6, 7, 8, 9 | T033 to T045, T085 |
| M4 Governance and Key Lifecycle | 10, 11, 12 | T046 to T058 |
| M5 Visibility | 13, 14 | T059 to T062 |
| M6 Hardening and Test Automation | 15, 16 | T073 to T076 |
| M7 Cloud Deployment | 17, 18, 19 | T063 to T072, T087 |
| M8 Assessment and Report | 20, 21, 22 | T077 to T081 |
