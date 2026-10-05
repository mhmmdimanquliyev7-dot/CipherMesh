# CLAUDE.md: CipherMesh engineering rules

This file governs every Claude Code session in this repository. Read it completely before changing anything.
If a request conflicts with this file, stop and raise the conflict. Never resolve it by silently weakening security.

## 1. Mission

CipherMesh is a university cybersecurity project: a **client-side encrypted secure collaboration and secret-exchange platform**.
It is one project that must show real depth in three subjects. Security depth matters more than feature count or infrastructure complexity.

| Subject | Where it must be visible |
|---|---|
| Cryptography Fundamentals | Client-side authenticated encryption, envelope encryption, asymmetric key wrapping, password-based KDFs, HKDF key separation, key rotation, hash-chained audit ledger |
| Cloud Security | Hardened IaaS VM, PaaS managed PostgreSQL, Jira Cloud as SaaS, provider-managed object storage, documented shared responsibility |
| Information Security Management Systems | Risk-based threat model and register, security profiles as an information-classification scheme, change control through the Jira workflow, evidence collection, ISO/IEC 27001 control mapping |

## 2. Current phase and phase gating

- **Phase 0 (Architecture and project bootstrap): complete and approved.**
- **Phase 0.5 (Architecture hardening and project-management bootstrap): complete and approved.** Review record: `docs/security/architecture-gate-phase-0-5.md`.
- **Phase 1 (Repository and Application Foundation): implemented; the project owner continued to Phase 2.** Merged into `main` through pull request #1 with CI passing; its branch-protection evidence is still pending. Traceability: `docs/management/phase-01-traceability.md`.
- **Phase 2 (Database and Prisma): implemented and merged into `main` through pull request #7; the project owner continued to Phase 3.** Traceability: `docs/management/phase-02-traceability.md`. Database controls: `docs/security/database-security.md`.
- **Phase 3 (Authentication): implemented and merged into `main` through pull request #8; the project owner continued to Phase 4.** Traceability: `docs/management/phase-03-traceability.md`. Controls: `docs/security/authentication-security.md`.
- **Phase 4 (Cryptographic Identity and Vault): implemented, approved by the project owner and merged into `main` through pull request #10 (merge commit `9e13259`).** ADR-015 (OCD-12) was accepted before implementation. Traceability: `docs/management/phase-04-traceability.md`. Specification: `docs/crypto/vault.md`.
- Next phase: **Phase 5 (Secure Rooms and RBAC)**, starting with Prompt 07A. Do not start it without explicit approval. Its branch starts from the updated `main`.
- Work is phase-gated. Finish one phase, report, and wait for approval before starting the next.
- Phase details: `docs/management/project-roadmap.md`. Backlog: `docs/management/jira-backlog.md`.

## 3. Architecture summary

- **Browser client** (Next.js static export, TypeScript, Tailwind): UI plus all content cryptography through `packages/crypto` (WebCrypto and an Argon2id WASM module).
- **Nginx** on the VM: TLS termination, security headers, rate limits, static assets, `/api` reverse proxy.
- **API** (Express, TypeScript): authentication, sessions, MFA, authorization, security-policy enforcement, audit ledger, presigned storage URLs. It stores metadata, ciphertext and wrapped keys. It never holds content keys.
- **Worker** (same codebase and image as the API, different entrypoint): expiry cleanup, abandoned rekey operations, audit verification, signed audit checkpoints.
- **Managed PostgreSQL (PaaS)**: users, sessions, rooms, memberships, key envelopes, encrypted notes and secrets, audit events.
- **Provider-managed object storage (S3-compatible)**: encrypted file blobs in a private bucket, plus a retention-locked bucket for audit checkpoints. It is not the PaaS example (ADR-006).
- **Jira Cloud and GitHub (SaaS)**: project management and source control. They are not part of the runtime.

Key hierarchy (details: `docs/crypto/key-hierarchy.md`):

```
Vault Passphrase -> Argon2id -> HKDF (one key per private key) -> wrapping keys -> user RSA-OAEP and ECDSA P-256 private keys
user ECDSA signing key -> binding signature over both public keys; signed vault re-wraps; signed room statements (Phase 6, ADR-015)
user RSA-OAEP public key -> envelope -> room key material (per version) -> HKDF -> room wrapping key -> per-item DEK -> content
room key material -> HKDF -> commitment (public) and Room Safety Code (shown to members, never sent)
recipient RSA-OAEP public key -> wrapped SEK (32 bytes) -> AES-256-GCM -> secret payload
```

## 4. Approved stack

| Area | Choice |
|---|---|
| Language | TypeScript 6.0 (strict) everywhere practical. TypeScript 7 waits for typescript-eslint support |
| Frontend | Next.js 16 static export (ADR-011, accepted for export and CSP), React 19, Tailwind CSS 4 |
| Backend | Node.js (current Active LTS), Express, TypeScript |
| Database | PostgreSQL 17 (managed in production), Prisma ORM 7 with the pg driver adapter |
| Object storage | S3-compatible API (managed in production, local emulator in development) |
| Client crypto | WebCrypto (SubtleCrypto); Argon2id through `argon2id` 1.0.1 in a Web Worker (LIB-03, selected in Phase 4, ADR-010) |
| Server crypto | Node.js `crypto` and WebCrypto; Argon2id through Node.js `crypto.argon2` (LIB-04, selected in Phase 3); TOTP through `otpauth` (LIB-06) |
| Validation | Schema validation at every trust boundary (planned: zod) |
| Testing | Vitest (unit), HTTP-level API integration tests, Playwright (E2E), security regression suite |
| Infrastructure | Ubuntu Server LTS, Docker, Docker Compose, Nginx |
| Tooling | pnpm 12 workspaces (build scripts blocked, 3-day release-age delay), ESLint with security guards, Prettier, GitHub Actions CI, gitleaks, CycloneDX SBOM |
| Management | GitHub (code), Jira Cloud (work tracking) |

Adding a runtime dependency, a service or an infrastructure component requires a justification in the PR.
Security-relevant libraries and any new infrastructure require an ADR or a `docs/crypto/crypto-decisions.md` entry.
Not allowed without an ADR: Kubernetes, microservices, blockchain, Kafka, message queues, extra databases, additional SaaS in the runtime path.

## 5. Repository structure

```
ciphermesh/
  apps/web/                  Next.js client (all client-side crypto executes here)
  apps/api/                  Express API and worker entrypoint
  packages/crypto/           WebCrypto wrappers, Argon2id integration, canonical context builders
  packages/shared/           Policy catalogue, authorization matrix, shared types and constants
  packages/validation/       Request and response schemas used at trust boundaries
  prisma/                    Prisma schema and migrations (from Phase 2)
  infrastructure/docker/     Dockerfiles and Compose files
  infrastructure/nginx/      Nginx configuration
  infrastructure/deployment/ Provisioning, hardening and deployment runbooks
  tests/integration/         API and database integration tests
  tests/security/            Security regression suite
  tests/e2e/                 Playwright tests
  docs/                      Architecture, crypto, cloud, threat model, security, management, report
```

Boundary rules: `apps/web` must not import `apps/api`. `packages/crypto` must not import Node-only modules or server code. Server secrets never enter any package bundled for the browser.

## 6. Security invariants (must always hold)

- **INV-01** The server never receives the Vault Passphrase, vault-derived keys, plaintext private keys, plaintext room key material, plaintext DEKs, or plaintext file, note or secret content.
- **INV-02** Every AES-GCM encryption uses a fresh 96-bit IV from a CSPRNG, generated inside the crypto module, plus the canonical AAD for its context. An IV is never reused with the same key.
- **INV-03** Each DEK protects exactly one item (a file with its manifest, one note revision, or one secret). DEKs are never shared between items.
- **INV-04** Room key material exists server-side only as RSA-OAEP envelopes per room, key version and recipient key. Never in plaintext in PostgreSQL, object storage, logs or browser storage.
- **INV-05** Every privileged action is authorized server-side by the central authorization module, using membership loaded from the database. Frontend checks are UX only.
- **INV-06** Room-scoped queries are always constrained by room ID and the membership of the caller (object-level authorization). Non-members receive 404.
- **INV-07** Losing a member (removal, leaving, suspension or deletion) or a reported identity-key compromise sets the room to REKEY_REQUIRED in the same transaction that deletes the member's envelopes. While a room is REKEY_REQUIRED or REKEYING, the API rejects all new content writes and invitations. A new key version becomes current only through a validated rekey finalize (ADR-013). Writes that name a non-current key version are rejected.
- **INV-08** Security-policy controls are enforced by the API, never only by the UI.
- **INV-09** Audit events are append-only and hash-chained. Application code never updates or deletes audit rows.
- **INV-10** Keys, passwords, Vault Passphrases, session tokens, recovery codes, TOTP secrets, presigned URLs and decrypted content never appear in logs, error messages, analytics, audit details or API responses.
- **INV-11** Account passwords are hashed with Argon2id on the server. They are never encrypted, stored in plaintext or logged.
- **INV-12** Sessions are opaque random tokens in `__Host-` HttpOnly, Secure, SameSite=Strict cookies, stored server-side only as SHA-256 digests. No JWTs in browser storage.
- **INV-13** Burn-after-reading reveal is a single atomic, single-use server transaction triggered by POST.
- **INV-14** Expired content is refused at read time, independently of cleanup jobs.
- **INV-15** No silent downgrade. If a required primitive (WebCrypto, Argon2id WASM) is unavailable, fail closed with a clear error.
- **INV-16** Plaintext hashes, filenames or MIME types of user content are never stored server-side in the clear.
- **INV-17** RSA-OAEP is used only on 32-byte random values: room key material, SEKs and the vault pair-check value. Every file, note and secret is encrypted with AES-256-GCM under its own data key (envelope encryption). Content is never RSA-encrypted.
- **INV-18** The Room Safety Code is computed only in the browser from decrypted room key material. It is never sent to the server, stored or logged, and is never presented as automatic protection.
- **INV-19** Every state-changing request, including registration and login, must pass same-origin verification (`Sec-Fetch-Site`, otherwise an exact `Origin` match), carry a JSON body and the `X-CipherMesh-Request` header. The API never grants CORS access with credentials.

## 7. Cryptographic rules

- **NEVER implement custom cryptography.** Use WebCrypto, Node.js `crypto`, and libraries approved in `docs/crypto/crypto-decisions.md`. Compose them only as specified in `docs/crypto/`.
- Algorithms and parameters come only from the parameter register (CP-xx) in `docs/crypto/crypto-decisions.md`. Changing one requires an ADR update and tests.
- ADR-007 (RSA-OAEP-3072 key distribution) is Proposed: implement it as designed and record the confirming cross-browser envelope test in the ADR (Phase 6) before marking it Accepted. ADR-010 (browser Argon2id) was accepted in Phase 4 with its benchmark. ADR-015 (identity signing keys, OCD-12) is Accepted; its room-statement part is confirmed by the Phase 6 and Phase 11 tests. ADR-011 is Accepted for the static export and CSP; its identifier routing pattern is confirmed in Phase 5.
- Encoding is not encryption. Base64 and hex are representations, not protection.
- Use non-extractable `CryptoKey` objects wherever the API allows, and restrict key usages to the minimum needed.
- Every encrypted record stores its algorithm suite identifier (`CM1` in the baseline) for crypto agility.
- AAD, OAEP labels and HKDF info values are built only by the canonical context builders (RFC 8785 JSON canonicalization). Never concatenate ad-hoc strings.
- Fail closed on any authentication-tag or key-commitment failure. Never display, cache or partially release unverified plaintext.
- Use a CSPRNG only (`crypto.getRandomValues`, `crypto.randomBytes`). `Math.random` is forbidden for anything security-related.
- Server-side comparisons of secret values use constant-time comparison.
- SHA-256 is a hash function. Never describe it as encryption and never use it to hash passwords.
- RSA-OAEP wraps only 32-byte keys, through the single wrapper in `packages/crypto`. Never call RSA-OAEP `encrypt` on content.
- The commitment detects inconsistent envelopes only while the server is honest. The Room Safety Code detects split views only when members compare it. Neither detects a key that every member received from a compromised server (T-36, OCD-12). Never describe them as more than that.
- Terminology: say "client-side encrypted", "authenticated encryption", "tamper-evident". Never say "unhackable", "military grade", "zero knowledge", "perfect security" or "tamper-proof".

## 8. Forbidden practices

- **NEVER** implement custom cryptography: no custom ciphers, modes, KDFs, MACs, padding, random generators, or ECIES-like compositions that are not specified in `docs/crypto/`.
- **NEVER** log keys, passwords, Vault Passphrases, plaintext secrets, session tokens, recovery codes, TOTP secrets, presigned URLs or decrypted confidential content.
- **NEVER** disable, bypass or weaken authorization to make a test pass. Tests create real users and memberships through fixtures.
- **NEVER** skip, delete or weaken a security test to get a green build.
- **NEVER** commit `.env` files, credentials, private keys, database dumps or unredacted evidence.
- **NEVER** silently alter the cryptographic architecture, algorithms or parameters. Propose an ADR change first and wait for approval.
- **NEVER** add major infrastructure (new services, queues, orchestration, runtime SaaS) without an ADR.
- **NEVER** claim a security guarantee stronger than the implemented system provides, in code comments, UI text, docs or the report.
- **NEVER** send the Vault Passphrase or any vault-derived key to the server, and never persist unlocked keys in browser storage.
- **NEVER** store plaintext room key material, DEKs or private keys in PostgreSQL, object storage or browser storage.
- **NEVER** reuse an AES-GCM IV with the same key, and never accept caller-supplied IVs in encryption APIs.
- **NEVER** RSA-encrypt content, or anything other than 32-byte key material.
- **NEVER** send, store or log a Room Safety Code.
- **NEVER** accept content writes or invitations while a room is REKEY_REQUIRED or REKEYING, and never let the server generate room key material or envelopes.
- **NEVER** store database migration or database-owner credentials on the VM, and never mount the audit signing key into any container except the worker.
- **NEVER** return Prisma models directly from handlers. Always use explicit response projections.
- **NEVER** use `$queryRawUnsafe`, string-built SQL, `eval`, `new Function`, `child_process` with user input, or `dangerouslySetInnerHTML`.
- **NEVER** put session tokens, secrets or keys in URLs. The only exception is the documented URL-fragment key of external one-time links, which the browser never sends to the server.
- **NEVER** change state on GET requests.
- **NEVER** add third-party runtime scripts (analytics, tag managers, script CDNs) to the web client.
- **NEVER** disable TLS certificate verification, including for the managed database.
- **NEVER** expose the API container, the database or the Docker socket directly to the internet.
- **NEVER** move a Jira issue to DONE without passing SECURITY REVIEW and TESTING.

## 9. Coding conventions

- TypeScript `strict: true` and `noUncheckedIndexedAccess`. No `any` in security-sensitive code: use `unknown` plus validation.
- Validate all external input (body, params, query, headers used for decisions, environment configuration) against schemas from `packages/validation`. Reject unknown fields.
- API handler order: authenticate, load actor context, validate input, authorize (central module), execute, project response, audit.
- Fail closed. Return generic messages with stable error codes and a request ID. Never leak stack traces, SQL or internal paths.
- Structured JSON logging with a central redaction list. Never log bodies of auth, vault, key, note or secret endpoints.
- Database access through Prisma. Raw SQL only through parameterized tagged templates, reviewed. Every room-scoped query filters by room ID and membership.
- Time is UTC everywhere. APIs and audit records use ISO 8601 with milliseconds.
- Externally visible identifiers are UUIDv4.
- Render decrypted content as text. No HTML rendering of user content. No inline scripts or styles that would require weakening CSP.
- Keep security logic in small dedicated modules (authorization, policy, audit, crypto), not scattered across handlers.
- Comments explain non-obvious security rationale and reference invariants (`INV-06`) and threats (`T-06`).

## 10. Testing requirements

- Security-sensitive changes require tests. A security fix is done only when a regression test fails before the fix and passes after it.
- Unit tests (Vitest) for packages and API modules. Known-answer tests for every crypto wrapper. Tamper tests (bit flip, AAD mismatch, wrong key version) for every decrypt path.
- Integration tests against real PostgreSQL for authentication, authorization, policy enforcement, audit chaining and burn-after-reading atomicity.
- The security regression suite in `tests/security` runs in CI on every PR: authorization matrix, BOLA/IDOR, policy matrix, log redaction, response projection, CSRF, session handling, rekey state machine, Room Safety Code, secret envelopes, audit tamper detection, and canary scans for plaintext in the database and object storage.
- Playwright E2E runs in Chromium, Firefox and WebKit for vault, rooms, files, notes, secrets and rotation.
- Never disable authorization, mock away the authorization module or relax a policy in tests. Use fixtures that create real users, memberships and keys.
- Coverage target: at least 90% statements and branches for `packages/crypto`, the authorization module and the policy engine.
- Before every commit run `pnpm format:check`, `pnpm lint`, `pnpm typecheck`, `pnpm test` and `pnpm build`; run `pnpm test:e2e` when the web client changes. `pnpm test` includes the database suite and needs the development database (`pnpm services:up && pnpm db:bootstrap && pnpm db:migrate`). All commands are listed in `docs/architecture/engineering-baseline.md` section 7.
- Schema changes arrive only as reviewed migrations under `prisma/migrations` (generated SQL plus hand-written constraints, triggers and grants). Never use `prisma db push`, `migrate dev` or `migrate reset`; the wrapper `scripts/db/prisma.mjs` refuses them. Every new column needs a `/// class:` comment, and any grant change updates the matrix in `tests/database/privileges.test.ts` and `docs/security/database-security.md`.
- Database access in the API goes only through `apps/api/src/db` (ESLint enforced).
- Authenticated routes declare `access: { kind: 'authenticated', requires? }` in the route registry; the registry resolves the session centrally and applies the step-up and platform-administrator gates. Never read identity from headers, bodies or query strings, and never re-implement session checks in a handler.
- Authentication security events go through `apps/api/src/auth/security-events.ts` (fixed catalogue, no secrets in details). Do not insert into `audit_events` before the Phase 12 hash chain exists (INV-09).
- `pnpm test` includes the `auth` and `database` suites. Run `pnpm security:negative-controls` before a phase sign-off that touches authentication.
- Scripted edits (Python or sed) must assert that their anchor text exists; a silent non-match once left a documented test unwritten (database-security.md section 11).
- New API routes go through the route registry (`apps/api/src/routes/registry.ts`). Never mount Express handlers directly.

## 11. Documentation requirements

- Keep docs in sync with code in the same PR. Architecture, crypto, threat-model, policy and authorization docs are normative.
- Security-sensitive architectural decisions require an ADR in `docs/architecture/adr/` (template in its README).
- Update `docs/threat-model/threat-model.md` when a change adds an asset, trust boundary, entry point or data flow.
- Update `docs/crypto/crypto-decisions.md` for any algorithm, parameter or library change.
- Record limitations honestly in `docs/security/limitations.md`.
- Capture the evidence listed in `docs/report/evidence-plan.md` when completing the related work.

## 12. Git workflow

- The repository was initialized locally in Phase 0.5 with a baseline commit on `main`. Its GitHub remote is `mhmmdimanquliyev7-dot/CipherMesh`, where a ruleset protects `main`. Phases 1 to 4 arrived through pull requests #1, #7, #8 and #10 with merge commits. New branches start from the updated `main`.
- `main` is protected. Changes arrive only through pull requests with passing CI. No direct commits and no force pushes.
- Branch names: `feature/CM-<n>-short-description`, `fix/CM-<n>-...`, `security/CM-<n>-...`, `docs/CM-<n>-...`, `infra/CM-<n>-...`.
- Commit messages use Conventional Commits with the Jira key, for example `feat(api): add session revocation endpoint (CM-17)`.
- Pull requests link the Jira issue, describe the security impact, list the tests, and complete the security checklist in `docs/management/jira-workflow.md`.
- Do not publish exploit details of unfixed findings in commits or PR text before the fix is merged.
- Claude Code sessions commit or push only when the project owner asks.

## 13. Jira workflow

- Workflow: BACKLOG -> READY -> IN PROGRESS -> SECURITY REVIEW -> TESTING -> DONE. SECURITY REVIEW and TESTING can return an item to IN PROGRESS.
- Priorities: P0 blocker (rare: phase gates and foundation controls that later work relies on), P1 core product or security functionality, P2 important but not blocking, P3 enhancement or optional. Definitions in `docs/management/jira-workflow.md`.
- Labels: architecture, cloud, crypto, security, frontend, backend, database, testing, documentation, infrastructure, risk, security-finding.
- Every branch, commit and PR references a Jira key. Security findings use the `security-finding` label and the finding template.
- Details: `docs/management/jira-workflow.md`. Backlog: `docs/management/jira-backlog.md`.

## 14. Definition of Done

An item is done only when all of the following hold:

1. Acceptance criteria are met and demonstrated.
2. Code is reviewed through a pull request, and CI (lint, typecheck, unit, integration, security regression) passes.
3. The security review checklist is completed and recorded in Jira (SECURITY REVIEW passed).
4. Tests cover the new behaviour, including negative and authorization tests for security-relevant changes.
5. No invariant in section 6 is violated. No new secrets in code, logs or history.
6. Documentation and ADRs are updated, and limitations are documented honestly.
7. Evidence listed in the evidence plan for this item is captured and redacted.
8. The Jira issue links to the PR and is moved to DONE.

## 15. Key documents

- Architecture: `docs/architecture/` (system-overview, data-flow, trust-boundaries, data-model, crypto-inspector, security-dashboard, security-ui, engineering-baseline, `adr/`)
- Cryptography: `docs/crypto/` (cryptographic-architecture, vault, key-hierarchy, key-lifecycle, crypto-decisions)
- Threat model: `docs/threat-model/threat-model.md`
- Security: `docs/security/` (security-principles, authorization-model, security-policy-profiles, security-testing-plan, session-and-csrf, authentication-security, database-security, limitations, isms-control-mapping, architecture-review, architecture-gate-phase-0-5)
- Cloud: `docs/cloud/` (service-models, shared-responsibility, deployment-architecture)
- Management: `docs/management/` (jira-workflow, jira-backlog, jira-backlog.csv, jira-import-guide, project-roadmap, github-repository-settings, phase-01-traceability, phase-02-traceability, phase-03-traceability, phase-04-traceability, current-state for session handoff)
- Report: `docs/report/evidence-plan.md`
