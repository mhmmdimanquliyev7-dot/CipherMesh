# Security Testing Plan

Status: Phase 0.5 baseline. Related: [../threat-model/threat-model.md](../threat-model/threat-model.md), [authorization-model.md](authorization-model.md), [security-policy-profiles.md](security-policy-profiles.md), [../report/evidence-plan.md](../report/evidence-plan.md).

## 1. Objectives

1. Every security control in the policy profiles, authorization matrix and invariants has an automated test.
2. Every threat in the threat model has at least one test or a documented verification activity.
3. Security tests run on every pull request and cannot be skipped or weakened to get a green build.
4. Findings from assessment become Jira issues, get fixed, and get a regression test that fails before the fix.

## 2. Test levels and tools

| Level | Scope | Tools (open source) | When |
|---|---|---|---|
| Unit | Crypto wrappers, canonical contexts, authorization decision function, policy engine, audit hashing | Vitest | Every PR |
| Integration | API with a real PostgreSQL in Docker: auth, sessions, authorization, policy, audit chain, burn atomicity | Vitest with an HTTP test client | Every PR |
| Security regression | `tests/security`: the suites in section 3 | Vitest, Playwright | Every PR |
| End-to-end | Browser flows in Chromium, Firefox and WebKit | Playwright | Every PR (smoke), nightly (full) |
| Static analysis | TypeScript strict, ESLint with security rules, forbidden-API lint rules | tsc, ESLint | Every PR |
| Supply chain | Vulnerable dependencies, secrets, SBOM, container images | OSV-Scanner or `pnpm audit`, gitleaks, CycloneDX, Trivy | Every PR and weekly |
| Dynamic (DAST) | Running application | OWASP ZAP baseline and authenticated scans | Phase 15 and Phase 20 |
| Infrastructure | VM, TLS, SSH, containers, storage configuration | nmap, testssl.sh, ssh-audit, Lynis, Docker Bench for Security, provider CLI checks | Phase 19 and Phase 20 |
| Manual assessment | OWASP ASVS 5.0 (Level 2 as target) and the OWASP Web Security Testing Guide | Browser devtools, ZAP, scripts | Phase 20 |

All scanning and testing targets only CipherMesh infrastructure, following the cloud provider's acceptable-use and penetration-testing rules.

## 3. Security regression suites (`tests/security`)

| Suite | What it proves | Threats |
|---|---|---|
| `authz-matrix` | Every action, role and profile combination returns the expected result, generated from the shared matrix | T-04, T-05 |
| `bola` | Identifiers from another room or user always give 404 with no side effects, for every endpoint | T-06 |
| `route-inventory` | Every route declares an action and has tests; public routes match the allowlist | T-05, T-06 |
| `policy-matrix` | PC-01 to PC-16: one allowed and one denied case per control and profile | T-04, T-21 |
| `session` | Cookie attributes, fixation, every rotation and invalidation event, idle and absolute expiry, logout, session limit ([session-and-csrf.md](session-and-csrf.md)) | T-08 |
| `csrf` | `Sec-Fetch-Site` and `Origin` checks, the custom request header, content types, login CSRF, side-effect-free GETs, `Origin` behaviour under `no-referrer` in three engines | T-13 |
| `auth-abuse` | Rate limits, backoff, TOTP attempt limits, replay, recovery-code reuse | T-09, T-10, T-30 |
| `crypto-invariants` | Known-answer tests, tamper tests, context separation, IV uniqueness, commitment checks, the RSA wrapper rejecting anything but 32-byte keys | T-07, T-29 |
| `projection` | Responses contain only allowlisted fields; forbidden field names never appear | T-15 |
| `log-redaction` | Canary secrets sent through every endpoint never appear in logs | T-15, T-16 |
| `canary-scan` | After E2E runs, canary strings are absent from database dumps and bucket objects | T-01, T-02, T-28 |
| `burn` | Concurrent reveals: exactly one succeeds; GET never consumes; expired secrets refused | T-33 |
| `rekey` | Member loss sets REKEY_REQUIRED and deletes envelopes in one transaction; writes and invitations blocked while locked; recipient snapshot excludes departed members; idempotent, mismatched and stale finalize handling; lease-expiry recovery; concurrent starts; old-version writes rejected; old keys cannot unwrap new DEKs | T-21, T-37 |
| `safety-code` | Known-answer vectors for the derivation and word mapping; the code changes with key, version and room; it never appears in requests, logs or storage; a two-browser harness with different keys shows different codes | T-29 |
| `secret-envelope` | Secret payloads are AES-256-GCM ciphertext; only a 32-byte SEK is RSA-wrapped; a tampered payload or wrapped SEK fails; burn sets both to NULL | T-07, T-33 |
| `key-injection` | Before OCD-12: a documented demonstration of the gap in a test environment. After OCD-12: clients reject key versions and envelopes not created by an authorized member | T-36 |
| `audit-tamper` | Edited, deleted or reordered events and recomputed chains are detected; the worker refuses to sign a diverged chain; conflicting and revoked-key checkpoints are reported; anchor deletion is denied; scenarios A to D of the audit trust model are simulated | T-20, T-38 |
| `xss` | Payload corpus in every user-controlled field never executes | T-12 |
| `upload` | HTML and SVG never render inline; size and quota limits; storage keys independent of filenames | T-11 |
| `browser-storage` | No key material or plaintext in localStorage, sessionStorage, IndexedDB or cookies after use | T-23 |
| `identity` | Lookup responses label identifiers as unverified; fingerprint confirmation enforced in RESTRICTED invitations; key changes are audited | T-25, T-35 |

## 4. Canary scan design

1. E2E fixtures create content that contains a unique random canary string in filenames, file content, note titles and bodies, and secrets.
2. After the run, a test dumps the test database and lists and downloads every object in the test bucket.
3. The test fails if any canary appears in any column, object or log file.

This is the automated proof of invariants INV-01 and INV-16, and a strong piece of report evidence.

## 5. Cryptography tests

- **Known-answer tests** for AES-256-GCM (NIST CAVP-style vectors), RSA-OAEP decryption of fixed vectors, HKDF (RFC 5869 vectors), SHA-256, Argon2id (RFC 9106 vectors) and RFC 8785 canonicalization vectors.
- **Tamper tests** for every decrypt path: bit flips in IV, ciphertext and tag; wrong AAD field; envelope moved to another room, version, user or key; wrapped DEK moved between items.
- **Context separation:** two contexts that differ in any field produce different bytes; decryption under the wrong context fails.
- **IV management:** production encryption functions accept no IV; many encryptions produce distinct IVs; the test-only IV seam is absent from production builds.
- **Commitment:** an envelope with the wrong RKM is rejected and reported. A test documents the limit: a harness that serves a different commitment together with a matching envelope passes this check, and only the Safety Code comparison reveals it.
- **RSA input restriction:** the RSA wrapper accepts only 32-byte keys, and a lint rule forbids direct RSA-OAEP `encrypt` calls outside `packages/crypto` (INV-17).
- **Room Safety Code:** known-answer vectors for HKDF output and word mapping, including the numeric form; context separation from RWK_v and RKC_v.
- **Cross-browser:** Playwright runs the crypto suite in Chromium, Firefox and WebKit, including OAEP labels and unwrapping into HKDF keys (OCD-01).
- **Parameter floors:** vault creation and unlock refuse Argon2id parameters below the floor; the API rejects them too.

## 6. CI gates

A pull request cannot merge unless all of these pass:

1. Lint (including forbidden-API rules) and typecheck.
2. Unit, integration and security regression suites.
3. E2E smoke tests.
4. Secret scan with no findings.
5. Dependency scan with no unresolved Critical or High findings (exceptions need a documented risk acceptance in Jira).
6. Coverage thresholds for `packages/crypto`, the authorization module and the policy engine (CLAUDE.md section 10).

## 7. Security assessment (Phase 20)

- **Scope:** production-like deployment, API, web client, VM, managed database and storage configuration.
- **Method:** OWASP ASVS 5.0 Level 2 checklist, selected OWASP WSTG tests, ZAP authenticated scan, infrastructure scans, and a crypto design review against `docs/crypto`.
- **Rules of engagement:** own infrastructure only; test accounts only; no real personal data; provider rules respected.
- **Output:** findings in Jira using the Security Finding template, an assessment summary for the report, and updated residual risks in the threat model.

## 8. Finding management

| Severity | Examples | Target |
|---|---|---|
| Critical | Plaintext or keys reach the server; authorization bypass across rooms; remote code execution | Stop feature work; fix immediately |
| High | Stored XSS; session fixation; policy control not enforced | Fix within the current phase |
| Medium | Missing security header; weak rate limit; verbose error | Fix before Phase 22 |
| Low | Hardening improvements, informational issues | Fix or accept with documented rationale |

Each finding records: affected component, threat ID, CWE and OWASP category where applicable, reproduction steps (restricted visibility until fixed), impact, severity, fix PR, regression test and retest result. Severity can additionally be scored with CVSS v4.0 when useful for the report.

## 9. Traceability

Each automated test is tagged with the threat IDs and control IDs it covers (for example `@T-06 @OL-02`). A script produces a table of threats and controls with their tests. The table is attached to the final report as evidence that every control is tested.
