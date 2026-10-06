# Security Testing Plan

Status: Phase 0.5 baseline; section 3.2 implemented in Phase 3; section 3.3 (vault and cryptography) and the coverage gate implemented in Phase 4; section 3.4 (room authorization, room lifecycle and membership administration, CM-T029 to CM-T032, including the BOLA and IDOR suite) implemented in Phase 5. Related: [../threat-model/threat-model.md](../threat-model/threat-model.md), [authorization-model.md](authorization-model.md), [security-policy-profiles.md](security-policy-profiles.md), [../report/evidence-plan.md](../report/evidence-plan.md).

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
| Database | `tests/database`: migrations from zero, drift, constraints, append-only audit, role privileges, deletion behaviour, database client, seed, retention (section 3.1, implemented in Phase 2) | Vitest against a throwaway PostgreSQL database per run | Every PR |
| Authentication | `tests/auth`: the `session`, `csrf` and `auth-abuse` suites of section 3 and the MFA, recovery, step-up, administrator and logging suites (section 3.2, implemented in Phase 3) | Vitest against the real API and a throwaway PostgreSQL database; Playwright for browser checks | Every PR |
| Vault and cryptography | `packages/crypto` unit and known-answer tests, `tests/vault` (setup, re-wrap, reset, directory, BOLA, leakage) and `tests/e2e/vault.spec.ts` (section 3.3, implemented in Phase 4) | Vitest against the real API, real Argon2id and a throwaway PostgreSQL database; Playwright in three engines | Every PR |
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
| `authz-matrix` | Every action, role and profile combination returns the expected result, generated from the shared matrix. **Phase 5:** every action and role, with the matrix compared cell by cell with the authorization model (section 3.4); profile combinations follow with the policy matrix (CM-T049) | T-04, T-05 |
| `bola` | Identifiers from another room or user always give 404 with no side effects, for every endpoint. **Phase 5 (CM-T032):** `tests/authz/bola.test.ts` attacks every production room route with identifiers from another room, tied to the registry by `tests/security/bola-inventory.test.ts` (section 3.4) | T-06 |
| `route-inventory` | Every route declares an action and has tests; public routes match the allowlist. **Phase 5:** every route's matrix action is consistent with its access, and room routes exist only as a reviewed list (empty until CM-T030) | T-05, T-06 |
| `http-baseline` | Security headers on every response, no framework disclosure, server-generated request IDs, no CORS grants, the same-origin gate, and no secrets from headers, query strings or bodies in the log (implemented in Phase 1) | T-12, T-13, T-15 |
| `malformed-requests` | Malformed and dot-segment paths, oversized URLs and compressed bodies get generic errors without crashes or decompression (implemented in Phase 1); undecodable path parameters get the generic 404 (Phase 5, R-05-01) | T-14, T-15, T-26 |
| `startup-config` | The real server process refuses invalid configuration and never echoes values (implemented in Phase 1) | Principle 10 |
| `lint-guards` | The ESLint guards for CLAUDE.md section 8 fire on forbidden code (implemented in Phase 1); Phase 2 adds `Prisma.raw` and database imports outside `apps/api/src/db` | T-14, T-27 |
| `schema-forbidden-fields` | The forbidden-field checker passes the real schema and fails on every "must never exist" field, unclassified fields and text-typed ciphertext (33 negative controls, implemented in Phase 2) | T-01, T-28 |
| `policy-matrix` | PC-01 to PC-16: one allowed and one denied case per control and profile | T-04, T-21 |
| `session` | Cookie attributes, fixation, every rotation and invalidation event, idle and absolute expiry, logout, session limit ([session-and-csrf.md](session-and-csrf.md)) | T-08 |
| `csrf` | `Sec-Fetch-Site` and `Origin` checks, the custom request header, content types, login CSRF, side-effect-free GETs, `Origin` behaviour under `no-referrer` in three engines | T-13 |
| `auth-abuse` | Rate limits, backoff, TOTP attempt limits, replay, recovery-code reuse | T-09, T-10, T-30 |
| `crypto-invariants` | Known-answer tests, tamper tests, context separation, IV uniqueness, commitment checks, the RSA wrapper rejecting anything but 32-byte keys. **Phase 4:** implemented as the `packages/crypto` unit suites listed in section 3.3 (commitment checks follow in Phase 6) | T-07, T-29 |
| `projection` | Responses contain only allowlisted fields; forbidden field names never appear | T-15 |
| `log-redaction` | Canary secrets sent through every endpoint never appear in logs | T-15, T-16 |
| `canary-scan` | After E2E runs, canary strings are absent from database dumps and bucket objects | T-01, T-02, T-28 |
| `burn` | Concurrent reveals: exactly one succeeds; GET never consumes; expired secrets refused | T-33 |
| `rekey` | Member loss sets REKEY_REQUIRED and deletes envelopes in one transaction; writes and invitations blocked while locked; recipient snapshot excludes departed members; idempotent, mismatched and stale finalize handling; lease-expiry recovery; concurrent starts; old-version writes rejected; old keys cannot unwrap new DEKs | T-21, T-37 |
| `safety-code` | Known-answer vectors for the derivation and word mapping; the code changes with key, version and room; it never appears in requests, logs or storage; a two-browser harness with different keys shows different codes | T-29 |
| `secret-envelope` | Secret payloads are AES-256-GCM ciphertext; only a 32-byte SEK is RSA-wrapped; a tampered payload or wrapped SEK fails; burn sets both to NULL | T-07, T-33 |
| `key-injection` | Clients reject key versions and envelopes not created by an authorized member: unsigned, forged, wrongly attributed and unauthorized versions, commitment mismatch, missing recipient (ADR-015, Phase 6). Phase 4 tests the identity part: binding signatures, fingerprints and signed re-wraps | T-36 |
| `audit-tamper` | Edited, deleted or reordered events and recomputed chains are detected; the worker refuses to sign a diverged chain; conflicting and revoked-key checkpoints are reported; anchor deletion is denied; scenarios A to D of the audit trust model are simulated | T-20, T-38 |
| `xss` | Payload corpus in every user-controlled field never executes | T-12 |
| `upload` | HTML and SVG never render inline; size and quota limits; storage keys independent of filenames | T-11 |
| `browser-storage` | No key material or plaintext in localStorage, sessionStorage, IndexedDB or cookies after use. **Phase 4:** `tests/e2e/vault.spec.ts` also checks the Cache API and the network traffic of every vault flow | T-23 |
| `identity` | Lookup responses label identifiers as unverified; fingerprint confirmation enforced in RESTRICTED invitations; key changes are audited. **Phase 4:** the directory part is in `tests/vault/reset-and-directory.test.ts`; invitations follow in Phase 6 | T-25, T-35 |

### 3.2 Authentication suites (`tests/auth`, Phase 3)

The real API runs on a loopback port against a throwaway database as `cm_api`, with production Argon2id parameters. Only the clock is controllable (a test seam that the application refuses in production), so expiry windows, backoff and TOTP steps can be tested exactly. Each scenario uses its own client address through one trusted forwarding hop. Details: [authentication-security.md](authentication-security.md) section 15.

| Suite | What it proves | Threats |
|---|---|---|
| `registration` | Argon2id PHC storage, mass-assignment refusal, normalization, one winner among concurrent duplicates, password policy, rate limit | T-03, T-04 |
| `login` | Cookie attributes, digest-only storage, identical failures and timing, fixation, disabled accounts, rehash, privacy of login attempts | T-08, T-09, T-15 |
| `session` | Identity only from the session, expiry, logout, revocation, eviction, password change, disabled accounts | T-08 |
| `abuse` | Backoff without lockout, unknown identifiers, per-address limits without writes, Argon2id burst | T-09, T-10, T-26 |
| `csrf` | Nine attack shapes on eleven routes, login CSRF, side effects, preflight | T-13 |
| `mfa`, `recovery` | Enrollment confirmation, encrypted secret, bypass attempts, attempt limits, expiry, drift window, replay, single use under concurrency | T-10, T-30 |
| `step-up`, `admin`, `logging` | Server-side gates, forged claims, re-verification limits, CLI-only administrator role, disabling, secret-free logs and events | T-08, T-16, T-30 |
| `tests/e2e/auth.spec.ts` | Cookie attributes in the browser, no secrets in browser storage, real `Origin` under `no-referrer`, MFA flows in three engines | T-08, T-13, T-23 |

`pnpm security:negative-controls` writes deliberate defects into the code one at a time and requires the suites to fail for each, then pass on the unmodified code. Phase 3 added ten controls (CSRF gate removed, reusable recovery codes, MFA step removed, TOTP replay, password not redacted, route outside the registry, cookie without HttpOnly, step-up gate disabled, disabled accounts kept, no dummy verification); Phase 4 adds seventeen (section 3.3). It restores every file, compares each touched file with its original by SHA-256, and is run before phase sign-off.

### 3.3 Vault and cryptography suites (Phase 4)

| Suite | What it proves | Threats |
|---|---|---|
| `packages/crypto/src/primitives.test.ts` | SHA-256 (FIPS 180-2), HKDF (RFC 5869 cases 1 to 3), AES-256-GCM (GCM specification cases 13 to 16) known answers; tamper of IV, ciphertext, tag and AAD; no IV parameter; 10,000 distinct IVs; wrapped private keys bound to their AAD | T-07 |
| `rsa-oaep.test.ts`, `signing.test.ts` | Wycheproof RSA-OAEP-3072 SHA-256 (37 cases) and ECDSA P-256 P1363 (114 cases), RFC 6979 A.2.5, OpenSSL interoperability; 32-byte values only; canonical key encodings only | T-07, T-25 |
| `argon2id.test.ts`, `argon2id-no-simd.test.ts`, `kdf-worker.test.ts` | RFC 9106 vector with both WebAssembly builds, OpenSSL differential at floor and target, embedded bytes equal the pinned package, floor and ceiling, one derivation at a time, the worker message protocol | T-22, T-26, T-27 |
| `canonical.test.ts`, `contexts.test.ts`, `encoding.test.ts` | RFC 8785 sorting example and byte dump, the Phase 3 `cm.srv.totp` bytes, exact field sets, domain separation, strict base64url, hex and UTF-8 | T-07 |
| `identity.test.ts`, `vault.test.ts`, `passphrase.test.ts` | Binding signature and fingerprint over both keys; unlock failures are generic; tamper, swap, substitution and pair-check mismatch; format version and parameter refusals; signed re-wrap and upgrade; passphrase policy | T-07, T-22, T-25, T-40 |
| `fail-closed.test.ts`, `boundary.test.ts` | Missing WebCrypto, CSPRNG, WebAssembly or Worker, a CSP that blocks compilation, worker errors and timeouts all fail closed with fixed codes; the export surface and the test-only seam are fixed | INV-15, T-27 |
| `tests/vault/setup.test.ts`, `rewrap.test.ts`, `reset-and-directory.test.ts`, `leakage.test.ts` | Step-up gates, strict schemas, the stored row, identity verification on the server, signed and compare-and-swap re-wraps, reset in one transaction, directory projection and rate limit, BOLA, no secrets or ciphertext in logs and events | T-01, T-06, T-15, T-22, T-35, T-40 |
| `tests/e2e/web-shell.spec.ts` (SF-04-01) | With every client script blocked, the prerendered sign-in and registration forms cannot be submitted: the button is disabled, and a forced submission is refused by the CSP (`form-action 'none'`) without any request or URL carrying the typed values | T-15, T-16 |
| `tests/e2e/vault.spec.ts` | In Chromium, Firefox and WebKit: no passphrase (raw, URL, base64, base64url or hex) and no PKCS#8 in any request; empty browser storage; independent fingerprint check; a vault created in Chromium opens in the other two engines; a modified record is refused; auto-lock with a controlled clock; sign-out and session-end locks; a failed background refresh keeps an unlocked vault under the auto-lock without a false identity-change message (R-04-01); no CSP violations; a negative control for the leak checks | T-23, T-24, T-25 |

Negative controls NC-04-01 to NC-04-14: AAD removed from the private-key wrap, fixed AES-GCM nonce, directory leaking wrapped-key data, vault ownership bypass, fingerprint over one key only, version downgrade accepted, re-wrap signature not checked, KDF floor and ceiling not enforced, unlocked keys extractable, canonical JSON without sorting, RSA wrapper accepting any size, passphrase in localStorage, passphrase sent at setup, auto-lock disabled; NC-04-15 and NC-04-16 revert the two layers of the SF-04-01 fix (CSP `form-action 'self'`, buttons enabled before hydration); NC-04-17 lets a failed background refresh replace the unlocked vault (R-04-01). NC-04-12 to NC-04-14, NC-04-16 and NC-04-17 are browser controls: the script rebuilds the web client with the defect and runs the Playwright test that must catch it, then rebuilds the clean client.

Coverage: `pnpm test:coverage:crypto` enforces at least 90% statements, branches, functions and lines for `packages/crypto` in CI. Phase 4 result: 99.5% statements and 91.8% branches. The uncovered branches are `?? 0` defaults that `noUncheckedIndexedAccess` requires for typed-array reads and checks on WebCrypto's own output; none can run with a correct platform.

Performance: `pnpm bench:vault` measures the real crypto code in the three engines under the production CSP (crypto-decisions section 8).

### 3.4 Room authorization, lifecycle, membership and BOLA suites (Phase 5, CM-T029 to CM-T032)

The central decision is pure, so it is tested exhaustively as a unit; the authorizer, the membership lookup and the registry are tested against the real API and PostgreSQL as `cm_api` (`pnpm test:authz`), with real users, sessions and memberships and nothing in the authorization path mocked. Rooms are created through the API; further members are inserted as fixtures until invitations exist (Phase 6). Key versions and envelopes appear only as DUMMY byte fixtures, to prove that a member loss deletes envelopes. The `authz` project runs its files one at a time: each file starts an API pool and several clients as `cm_api`, whose connection limit of 40 is shared with the other projects (peak in a full run: 24). Design: [authorization-model.md](authorization-model.md) section 9.

| Suite | What it proves | Threats |
|---|---|---|
| `packages/shared/src/authorization.test.ts` | Every action and role through every kind of fact (allow, deny, own, recipient, target roles, inherited); no membership, a membership of another room or user, SUSPENDED, REMOVED and LEFT memberships, DELETING and DELETED rooms, unknown roles and unknown actions all deny; the platform role grants nothing; OWNER-only actions, the VIEWER and MEMBER columns and the role ceilings asserted independently; the catalogue is frozen | T-04, T-05, T-06 |
| `tests/security/authz-matrix.test.ts` | Parses sections 3 and 4 of the authorization model and compares every cell, title and step-up note with the catalogue; role-model invariants | T-04 |
| `tests/authz/membership-lookup.test.ts` | The query enforces room, user, ACTIVE membership and ACTIVE room: a membership in room A never comes back for room B; historical rows are ignored; malformed identifiers return nothing without a database error; changes are visible at once | T-05, T-06 |
| `tests/authz/room-access.test.ts` | Test-only room routes through the production registry and authorizer: outsiders, nonexistent rooms, malformed identifiers and objects outside the room get one identical 404; PLATFORM_ADMIN without a membership is an outsider, and as a member has exactly that role; every role gets its cells; the matrix is checked before the step-up prompt; forged headers, query and body fields never carry a role; role changes and removals apply on the next request; AZ-10 ceilings with the stored target role; targets are never looked up for refused callers; denials record only the action and the reason | T-04, T-05, T-06, T-15 |
| `apps/api/src/routes/registry.test.ts`, `apps/api/src/authorization/rooms.test.ts` | Startup refusals for missing, unknown or inconsistent declarations (room path, room action, step-up, resource loader, platform gate, paths that name a room, path grammar, parameter schemas); every reason code maps to the response of section 7; the shared role and state lists equal the database enums | T-05, T-06 |
| `tests/authz/rooms-lifecycle.test.ts` | Creation (OWNER membership, no key rows, strict body, vault, PC-01 and PC-02, reused ID), listing (own ACTIVE memberships only, pagination, cursors, PLATFORM_ADMIN), reading, renaming (matrix, cross-room, forged fields), deletion (OWNER-only, step-up, immediate 404, fail-safe worker cleanup) | T-04, T-05, T-06, T-28 |
| `tests/authz/membership-admin.test.ts` | Every role-change combination for OWNER and ADMIN, no OWNER through role changes, targets only inside the room, removal ceilings and the member-loss transaction (REMOVED, envelopes deleted, epoch, REKEY_REQUIRED, events), ownership transfer (only to a current ADMIN, OWNER-only, step-up, one OWNER) | T-04, T-06, T-21 |
| `tests/authz/membership-concurrency.test.ts` | Races forced by holding the room lock until both requests wait: two transfers, an ADMIN demotion against an OWNER promotion, two removals, removal against role change, transfer against role change, deletion against role change and rename | T-04, T-37 |
| `tests/authz/account-disable.test.ts` | PA-03: memberships SUSPENDED, rooms REKEY_REQUIRED with MEMBER_SUSPENDED, envelopes deleted, unrelated rooms untouched, idempotent, no access afterwards, re-enabling restores no membership, no ACTIVE membership survives a disable racing a room creation | T-21 |
| `packages/validation/src/rooms.test.ts`, `tests/security/profile-requirements.test.ts` | Room schemas (normalization, refused characters, strict objects, cursors) and the PC-01 and PC-02 values compared with the profile table | T-12, T-28 |
| `tests/authz/bola.test.ts` (49 tests) | The CM-T032 attack matrix over every production room route and the self-service routes. **A, B, G:** callers outside room B (OWNER, ADMIN, MEMBER, VIEWER of room A, SUSPENDED, REMOVED and LEFT members, a user with no room, PLATFORM_ADMIN) get the generic 404 for a real room B and for an invented room, with identical status, code, message and body shape, no room data, and no changed row. **C:** addressed room A with a target member of room B: OWNER and ADMIN get the same 404 as for an invented target, MEMBER, VIEWER and (for a transfer) ADMIN are refused by role, nothing changes. **D:** an ADMIN of A is a VIEWER in B and an OWNER of C is a MEMBER in B, with no authority beyond that role, correct data and member lists, and per-room roles in the list. **E:** former members have no authority in their own former room. **F:** DELETING and DELETED rooms refuse their own OWNER; a REKEY_REQUIRED room stays invisible to outsiders and PLATFORM_ADMIN. **H:** forged identity, role and room fields (body and query) and identity headers never change the outcome; the room list belongs to the session user. **L-45:** a known room ID answers 409 and changes nothing | T-04, T-05, T-06, T-15 |
| `tests/security/bola-inventory.test.ts` (5 tests) | The reviewed table of `tests/helpers/bola-cases.ts` equals the production registry in both directions, so a room route cannot ship without a BOLA case and a case cannot outlive its route; every room route carries the object-level classes and every mutation the unchanged-state class | T-06 |
| `tests/e2e/rooms.spec.ts` | In Chromium, Firefox and WebKit: create, reload and direct visit of the room page (ADR-011), rename, delete with a step-up prompt, the name warning, no CSP violation; promote, transfer and remove with the controls the role allows |  T-04, T-28 |

Negative controls NC-05-01 to NC-05-22 (`pnpm security:negative-controls --only=NC-05`): the registry skips the membership check, the decision allows a missing membership, the lookup is not scoped to the room, the lookup accepts inactive memberships, PLATFORM_ADMIN is treated as a room ADMIN, AZ-04 is widened to ADMIN, the role ceiling is checked with `some` instead of `every`, a room action or a room path is accepted without room access, the R-05-01 fix is reverted; for CM-T030 and CM-T031, the target-member lookup and the locked membership lose their room scope, membership changes skip the re-authorization on locked state, an ADMIN may transfer ownership, a transfer leaves no OWNER, disabling no longer suspends memberships, and the room list is not limited to the caller; and for CM-T032, four defects that remove every layer a request meets (gate, locked re-check, store query), run against the BOLA files alone: a cross-room target is refused differently from an invented one (an existence oracle), a cross-room target member is accepted and changed, a membership in room A authorizes room B, and PLATFORM_ADMIN is treated as a member; plus a room route shipped without a reviewed BOLA case. All twenty-two are caught. The harness takes several files per defect (`also`) because the checks repeat on purpose, `--only=` takes comma-separated prefixes, and `--show-failures` prints the failing test names, which confirmed that each CM-T032 control was caught by the intended attack class.

Coverage: `pnpm test:coverage:authz` enforces at least 90% statements, branches, functions and lines for the decision module in CI. Phase 5 result: 97.3% statements, 98.3% branches; the uncovered lines are the unreachable fallback for an unknown rule kind.

### 3.1 Database suite (`tests/database`, Phase 2)

A global setup creates one database per test run as the local or CI container administrator, hands it to the migration role and applies all migrations with `prisma migrate deploy`. Tests connect as the real roles (`cm_api`, `cm_worker`, `cm_verifier`, `cm_migrator`); nothing is mocked and no grant is widened for testing. Tests that need a pristine or deliberately misconfigured database create their own. Details: [database-security.md](database-security.md) section 9.

| Suite | What it proves | Threats |
|---|---|---|
| `migrations` | Clean apply from an empty database, idempotent re-run, no drift, every live column declared and classified, drift negative control | T-01, T-39 |
| `constraints` | Partial unique indexes, composite foreign keys, CHECK constraints and write-once triggers, asserted by SQLSTATE | T-01, T-25, T-36, T-37 |
| `audit` | Grant and trigger layers of the append-only table, including misconfigured grants; the owner's ability to disable the trigger is shown as a limit | T-20 |
| `privileges` | Role attributes, ownership, the exact grant matrix, no PUBLIC privileges, no DDL or escalation by the API role | T-19, T-39 |
| `deletion` | No cascades, member removal transaction, retention deletes only by the worker | T-21 |
| `client` | Lazy connection, readiness with real and unreachable databases, no query logging, no URLs or row values in errors and logs | T-15, T-16 |
| `seed` | Synthetic data only, idempotent, refuses production, remote hosts and other roles | T-16 |

## 4. Canary scan design

1. E2E fixtures create content that contains a unique random canary string in filenames, file content, note titles and bodies, and secrets.
2. After the run, a test dumps the test database and lists and downloads every object in the test bucket.
3. The test fails if any canary appears in any column, object or log file.

This is the automated proof of invariants INV-01 and INV-16, and a strong piece of report evidence.

## 5. Cryptography tests

- **Known-answer tests** for AES-256-GCM (NIST CAVP-style vectors), RSA-OAEP decryption of fixed vectors, HKDF (RFC 5869 vectors), SHA-256, Argon2id (RFC 9106 vectors) and RFC 8785 canonicalization vectors. **Implemented in Phase 4** (section 3.3), plus Wycheproof RSA-OAEP and ECDSA vectors for the identity keys (CP-26).
- **Tamper tests** for every decrypt path: bit flips in IV, ciphertext and tag; wrong AAD field; envelope moved to another room, version, user or key; wrapped DEK moved between items.
- **Context separation:** two contexts that differ in any field produce different bytes; decryption under the wrong context fails.
- **IV management:** production encryption functions accept no IV; many encryptions produce distinct IVs; the test-only IV seam is absent from production builds.
- **Commitment:** an envelope with the wrong RKM is rejected and reported. A test documents the limit: a harness that serves a different commitment together with a matching envelope passes this check, and only the Safety Code comparison reveals it.
- **RSA input restriction:** the RSA wrapper accepts only 32-byte keys, and a lint rule forbids direct RSA-OAEP `encrypt` calls outside `packages/crypto` (INV-17).
- **Room Safety Code:** known-answer vectors for HKDF output and word mapping, including the numeric form; context separation from RWK_v and RKC_v.
- **Cross-browser:** Playwright runs the crypto suite in Chromium, Firefox and WebKit, including OAEP labels and unwrapping into HKDF keys (OCD-01). **Phase 4:** the vault flows run in all three engines, and a vault created in Chromium is opened in Firefox and WebKit; envelope interoperability follows in Phase 6.
- **Parameter floors:** vault creation and unlock refuse Argon2id parameters below the floor, and since Phase 4 above the ceiling; the API rejects them too.

## 6. CI gates

A pull request cannot merge unless all of these pass:

1. Lint (including forbidden-API rules) and typecheck.
2. Unit, integration, security regression and database suites, after the database checks: Prisma schema validation, the forbidden-field check, migrations from zero as the migration role, and the drift check.
3. E2E smoke tests.
4. Secret scan with no findings.
5. Dependency scan with no unresolved Critical or High findings (exceptions need a documented risk acceptance in Jira).
6. Coverage thresholds for `packages/crypto` (enforced since Phase 4 by `pnpm test:coverage:crypto`), the authorization module and the policy engine (CLAUDE.md section 10).

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
