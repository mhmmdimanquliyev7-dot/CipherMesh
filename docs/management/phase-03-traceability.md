# Phase 3 Traceability

Status: Phase 3 implemented on 2026-10-04, awaiting project owner approval. Covers CM-T015 to CM-T022 in [jira-backlog.md](jira-backlog.md) (verified against the current backlog before the work started). No item is DONE: DONE requires SECURITY REVIEW and TESTING in Jira and the full Definition of Done (CLAUDE.md section 14), including CI on a pull request, which cannot run before a GitHub remote exists.

Branch: `feature/CM-T015-authentication`, **another stacked branch**, created from the committed Phase 2 branch `feature/CM-T013-database-prisma` (commit `92418c3`), which itself is stacked on the Phase 1 branch. No history was rewritten. The Phase 1 CI evidence (EV-01-01 CI run, EV-01-02, EV-01-03) and the Phase 2 pull request remain pending.

Design and controls: [../security/authentication-security.md](../security/authentication-security.md).

## 1. Work items

Each row reads: requirement, then implementation, then test, then evidence.

| Item | Requirement (acceptance criterion) | Implementation | Tests | Evidence | Result |
|---|---|---|---|---|---|
| CM-T015 Registration | Stored value is an Argon2id PHC string with the registered parameters | `auth/password.ts` (LIB-04: Node.js `crypto.argon2`), CHECK constraint from Phase 2 | `password.test.ts`, `tests/auth/registration.test.ts` | EV-03-01 | Met |
| | Blocklisted and too-short passwords are rejected with a helpful message | CP-06 policy, 30,402-entry blocklist, issue codes, web text | Same | | Met |
| | Benchmark and final parameters recorded | CP-05 final, section 7 of crypto-decisions.md, `pnpm bench:argon2` | RFC 9106 vector in the benchmark and unit tests | EV-03-02 | Met on a 2-vCPU container; the production VM re-run is a Phase 17 task |
| | Registration is rate-limited; passwords never appear in logs | Per-address limiter; redaction; no bodies logged | `registration.test.ts`, `logging.test.ts` | | Met |
| CM-T016 Login with opaque sessions | Cookie has HttpOnly, Secure, SameSite=Strict, Path=/ and no Domain | `auth/cookies.ts` (no weakening option) | `primitives.test.ts`, `login.test.ts`, `tests/e2e/auth.spec.ts` (three engines) | EV-03-03, EV-03-12 | Met |
| | Only the SHA-256 digest of the token is stored | `auth/tokens.ts`, `sessions.token_digest` | `login.test.ts` | | Met |
| | Failed attempts store no password and no raw identifier for unknown accounts | CP-12 identifier HMAC, `login_attempts` | `login.test.ts` | EV-03-06 | Met |
| | Dummy verification, generic error, fixation, rehash | `auth/service.ts` | `login.test.ts`, negative control NC-03-10 | EV-03-11 | Met |
| CM-T017 Session lifecycle | Each rotation and invalidation event has the documented effect | `auth/sessions.ts`, `auth/service.ts` | `session.test.ts`, `mfa.test.ts`, `recovery.test.ts`, `step-up.test.ts`, `admin.test.ts` | | Met for every event that exists now. Vault reset arrives in Phase 4 |
| | Revoked, idle-expired and absolutely expired tokens are rejected; logout clears the cookie | Session resolution in the registry | `session.test.ts` | | Met |
| | Password change, MFA change and vault reset revoke the other sessions | `changePassword`, `confirmTotpEnrollment`, `disableTotp` | `session.test.ts`, `mfa.test.ts` | EV-03-08 | Met for password and MFA; vault reset in Phase 4 |
| | An 11th login evicts the least recently used session and records an event | `createSession` under a row lock | `session.test.ts` | | Met (security event in the log, see L-33) |
| | Session list with per-session revoke and "sign out other sessions"; worker cleanup | Routes and web account page; `pnpm worker:retention` as `cm_worker` | `session.test.ts`, `tests/database/retention.test.ts` | | Met; scheduling with the worker (Phase 12) |
| CM-T018 Brute force and credential stuffing | Scripted bursts receive 429 and the backoff schedule is observable | Per-address limits, per-account and per-identifier backoff | `abuse.test.ts` | EV-03-04 | Met for the API. Nginx zones: Phase 17 |
| | The Argon2id concurrency limit protects memory | `ConcurrencyLimiter` (min(4, CPUs), queue 32, 503) | `password.test.ts`, `abuse.test.ts` burst | EV-03-02 | Met |
| | Failed-login data is available for the Security Dashboard | `login_attempts` with outcomes; 90-day retention | `login.test.ts`, `retention.test.ts` | EV-03-06 | Met (dashboard in Phase 14) |
| CM-T019 TOTP MFA and recovery codes | RFC 6238 test vectors pass; replayed codes and codes outside one step are rejected | `auth/totp.ts` (LIB-06 `otpauth`), step replay protection | `totp.test.ts`, `mfa.test.ts`, NC-03-04 | EV-03-09 | Met |
| | At most 5 attempts per pre-auth state; recovery codes single use and stored as digests | `auth_challenges` table, atomic counters | `mfa.test.ts`, `recovery.test.ts`, NC-03-02 | EV-03-09 | Met |
| | The TOTP secret appears only once and never in logs | Enrollment response only; CP-11 encryption at rest | `mfa.test.ts`, `logging.test.ts`, e2e storage check | EV-03-05 | Met |
| | Session token rotates after MFA verification | New session at the MFA step; rotation on enable and disable | `mfa.test.ts` | | Met |
| CM-T020 CSRF | Cross-site posts, foreign fetches, `Origin: null`, missing headers and wrong content types are rejected before any handler | Same-origin gate (Phase 1) on all new routes | `csrf.test.ts` (104 cases), NC-03-01 | EV-03-07 | Met |
| | Cross-origin registration and login fail | Same gate | `csrf.test.ts` | EV-03-07 | Met |
| | No GET handler changes state | Route inventory; GET routes listed | `route-inventory.test.ts`, `csrf.test.ts` | | Met; GET `/auth/session` updates only the session's activity time (bookkeeping, documented) |
| | Playwright confirms fetch() sends the real Origin under no-referrer in three engines | Client uses fetch() only | `tests/e2e/auth.spec.ts` | EV-03-12 | Met |
| CM-T021 Step-up | Gates return the correct codes at window boundaries | `requireStepUp`, `requireRecentAuthentication`, registry gates | `primitives.test.ts`, `step-up.test.ts`, NC-03-08 | EV-03-09 | Met |
| | Token rotates on step-up | `stepUp` | `step-up.test.ts` | | Met |
| CM-T022 Administrator bootstrap and disabling | PLATFORM_ADMIN cannot be granted through the API | CLI only (`pnpm admin:platform-role`); strict schemas | `admin.test.ts`, `route-inventory.test.ts` | | Met |
| | Admins cannot disable themselves or the last admin | `disableAccount`, `changePlatformRole` | `admin.test.ts` | EV-03-10 | Met |
| | Disabling suspends memberships and sets rooms REKEY_REQUIRED once rooms exist | Not applicable yet (no rooms) | Integration test planned in Phase 11 | | Deferred as the backlog states |
| | Administrator-assisted reset (PA-04) documented | Procedure in authentication-security.md section 13 | | | Documented; tooling deferred |

## 2. Decisions taken in this phase

| Decision | Record |
|---|---|
| CP-05 final parameters m = 65536 KiB, t = 3, p = 4, with an Argon2id concurrency limit | crypto-decisions.md CP-05 and section 7 |
| LIB-04 Node.js `crypto.argon2`; LIB-06 `otpauth` 9.5.2 | Library register |
| No password pepper (OCD-05) | CD-20 |
| Server canonical context for `cm.srv.totp` built for a restricted subset until OCD-04 | CD-22 |
| Pre-authentication state in its own table `auth_challenges` | data-model 4.3.1, migration `20261004000000_auth_challenges` |
| Authentication security events in the structured log until the Phase 12 hash chain, not in `audit_events` | authentication-security.md section 12, L-33 |
| QR code rendered client-side with `uqr` | engineering-baseline.md |

## 3. Security checkpoint (roadmap Phase 3)

| Check | Result |
|---|---|
| Argon2id library and parameters benchmarked and recorded (CP-05, OCD-03) | Done (container sized like a 2-vCPU VM); production VM re-run in Phase 17 |
| TOTP library chosen (LIB-06) | `otpauth` 9.5.2 |
| Pepper decision taken (OCD-05) | No pepper (CD-20) |
| Cookie attributes verified | API tests on Set-Cookie; Playwright in three engines |
| No raw identifiers or passwords stored for failed logins | `login.test.ts`, EV-03-06 |
| Threat model check of T-03, T-08, T-09, T-10, T-13, T-30 | threat-model.md section 9 |

## 4. Pending outside the repository

- GitHub remote, pull requests for Phases 1 to 3 and CI runs.
- Jira: issue history of the MFA item through SECURITY REVIEW (roadmap evidence), status changes for CM-T013 to CM-T022.
- EV-03-05 asks for a screenshot of MFA enrollment; Phase 3 captured the Playwright run of the enrollment flow instead, because a live QR code is a secret.
