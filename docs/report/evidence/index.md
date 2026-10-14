# Evidence Index

Rules: [../evidence-plan.md](../evidence-plan.md) section 2. Every file is redacted. Text exports are preferred over screenshots. Raw, unredacted captures go to the git-ignored `_raw/` folder and are never committed.

## Phase 0 and Phase 0.5

| ID | File or location | Date | Jira | Caption |
|---|---|---|---|---|
| EV-00-01 to EV-00-04 | Diagrams and tables in `docs/` | 2026-09-28 | CM-T002 to CM-T004 | Architecture, trust boundaries, key hierarchy, risk register (export when writing the report) |
| EV-00-08 | [../../security/architecture-gate-phase-0-5.md](../../security/architecture-gate-phase-0-5.md) | 2026-09-28 | CM-T082 | Phase 0.5 attack-focused architecture review |
| EV-00-09 | Baseline commit `cb3b2229788ab2bea023630905077582e02cdd69`, recorded in the evidence plan section 6 | 2026-09-28 | CM-T084 | Initial architecture checkpoint |
| EV-00-05, EV-00-06, EV-00-10 | Pending | | CM-T083 | Jira board, issue lifecycle and import result: captured after the manual Jira setup |

## Phase 1

| ID | File | Date | Jira | Caption |
|---|---|---|---|---|
| EV-01-01 (local part) | [phase-01/EV-01-01_install-format-lint-typecheck.txt](phase-01/EV-01-01_install-format-lint-typecheck.txt) | 2026-10-02 | CM-T006, CM-T012 | Fresh install from the lockfile; format, lint and typecheck all pass |
| EV-01-01 (CI run) | Pending | | CM-T012 | GitHub Actions run summary: needs the GitHub remote |
| EV-01-02, EV-01-03 | Pending | | CM-T012 | Branch protection and a blocked merge: manual tasks in [../../management/github-repository-settings.md](../../management/github-repository-settings.md) |
| EV-01-04 | [phase-01/EV-01-04_csp-and-e2e.txt](phase-01/EV-01-04_csp-and-e2e.txt) | 2026-10-02 | CM-T008 | Generated CSP without unsafe directives; zero violations in Chromium, Firefox and WebKit; negative control |
| EV-01-05 | [phase-01/EV-01-05_secret-scan.txt](phase-01/EV-01-05_secret-scan.txt) | 2026-10-02 | CM-T012 | gitleaks over the git history and the staged Phase 1 changes |
| EV-01-06 | [phase-01/EV-01-06a_build.txt](phase-01/EV-01-06a_build.txt), [phase-01/EV-01-06b_api-smoke.txt](phase-01/EV-01-06b_api-smoke.txt) | 2026-10-02 | CM-T007 | Build output; built API answers health, readiness and 404 with minimal, generic bodies |
| EV-01-07 | [phase-01/EV-01-07_dependency-audit-and-sbom.txt](phase-01/EV-01-07_dependency-audit-and-sbom.txt) | 2026-10-02 | CM-T012 | No known vulnerabilities; CycloneDX SBOM generated |
| EV-01-08 | [phase-01/EV-01-08_dev-services.txt](phase-01/EV-01-08_dev-services.txt) | 2026-10-02 | CM-T011 | PostgreSQL and the S3 emulator listen on 127.0.0.1 only; wrong credentials rejected |
| EV-01-09 | [phase-01/EV-01-09_test-results.txt](phase-01/EV-01-09_test-results.txt) | 2026-10-02 | CM-T007, CM-T009, CM-T010 | All 129 unit, integration and security tests pass, including redaction, CSRF gate and route inventory |

## Phase 2

Captured on the stacked branch `feature/CM-T013-database-prisma` against the local PostgreSQL container and throwaway test databases. The CI-run versions of these items need the GitHub remote.

| ID | File | Date | Jira | Caption |
|---|---|---|---|---|
| EV-02-01 | [phase-02/EV-02-01_forbidden-field-check.txt](phase-02/EV-02-01_forbidden-field-check.txt) | 2026-10-04 | CM-T013 | Forbidden-field check passes on 203 classified fields; 33 negative controls fail as expected |
| EV-02-02 | [phase-02/EV-02-02_audit-append-only.txt](phase-02/EV-02-02_audit-append-only.txt) | 2026-10-04 | CM-T014 | UPDATE, DELETE and TRUNCATE on `audit_events` refused for the API role (grants) and for the owner and a misgranted role (trigger) |
| EV-02-03 | [phase-02/EV-02-03_role-grants.txt](phase-02/EV-02-03_role-grants.txt) | 2026-10-04 | CM-T014 | Role attributes, ownership, table grants per role; DDL and role creation refused for `cm_api` |
| EV-02-04 | [phase-02/EV-02-04_migrations-and-drift.txt](phase-02/EV-02-04_migrations-and-drift.txt) | 2026-10-04 | CM-T013 | Migrations from an empty database, idempotent re-run, drift check passing and failing on an out-of-band change |
| EV-02-05 | [phase-02/EV-02-05_database-tests-and-seed.txt](phase-02/EV-02-05_database-tests-and-seed.txt) | 2026-10-04 | CM-T011, CM-T013, CM-T014 | All 103 database tests pass; synthetic seed output |
| EV-02-06 | [phase-02/EV-02-06_database-url-rules.txt](phase-02/EV-02-06_database-url-rules.txt) | 2026-10-04 | CM-T013 | Database URL rules (role, TLS), redaction, and the built API with fail-closed and working readiness |

## Phase 3

Captured on the stacked branch `feature/CM-T015-authentication` against the real API, throwaway test databases and the local HTTPS E2E server. Synthetic accounts only; every password, token, cookie value, TOTP secret, code and hash byte is redacted. The CI-run versions and the Jira issue history need the GitHub remote and Jira.

| ID | File | Date | Jira | Caption |
|---|---|---|---|---|
| EV-03-01 | [phase-03/EV-03-01_argon2id-phc-in-database.txt](phase-03/EV-03-01_argon2id-phc-in-database.txt) | 2026-10-04 | CM-T015 | Argon2id PHC string (parameters visible, salt and hash redacted) |
| EV-03-02 | [phase-03/EV-03-02_argon2-benchmark.txt](phase-03/EV-03-02_argon2-benchmark.txt) | 2026-10-04 | CM-T015, CM-T018 | Argon2id benchmark on a 2-CPU container and the laptop; RFC 9106 vector |
| EV-03-03 | [phase-03/EV-03-03_session-cookie-attributes.txt](phase-03/EV-03-03_session-cookie-attributes.txt) | 2026-10-04 | CM-T016 | `__Host-cm_session` with HttpOnly, Secure, SameSite=Strict, Path=/ |
| EV-03-04 | [phase-03/EV-03-04_rate-limit-and-backoff.txt](phase-03/EV-03-04_rate-limit-and-backoff.txt) | 2026-10-04 | CM-T018 | 429 after five failures (even for the right password) and after 20 attempts from one address |
| EV-03-05 | [phase-03/EV-03-05_mfa-enrollment.txt](phase-03/EV-03-05_mfa-enrollment.txt) | 2026-10-04 | CM-T019 | Enrollment needs step-up and a valid code; encrypted secret; pre-auth cookie opens nothing |
| EV-03-06 | [phase-03/EV-03-06_login-attempts-privacy.txt](phase-03/EV-03-06_login-attempts-privacy.txt) | 2026-10-04 | CM-T016, CM-T018 | Login attempts with user ID or 32-byte HMAC only |
| EV-03-07 | [phase-03/EV-03-07_csrf-rejections.txt](phase-03/EV-03-07_csrf-rejections.txt) | 2026-10-04 | CM-T020 | Cross-site login attempts rejected with ORIGIN_REJECTED or 415, no cookie |
| EV-03-08 | [phase-03/EV-03-08_password-change-revokes-sessions.txt](phase-03/EV-03-08_password-change-revokes-sessions.txt) | 2026-10-04 | CM-T017 | Session list before and after a password change |
| EV-03-09 | [phase-03/EV-03-09_auth-security-suites.txt](phase-03/EV-03-09_auth-security-suites.txt) | 2026-10-04 | CM-T015 to CM-T022 | All 186 authentication security tests pass |
| EV-03-10 | [phase-03/EV-03-10_account-disable.txt](phase-03/EV-03-10_account-disable.txt) | 2026-10-04 | CM-T022 | Administrator bootstrap and account disabling tests |
| EV-03-11 | [phase-03/EV-03-11_negative-controls.txt](phase-03/EV-03-11_negative-controls.txt) | 2026-10-04 | CM-T016 to CM-T021 | Ten deliberate defects, each caught |
| EV-03-12 | [phase-03/EV-03-12_browser-checks.txt](phase-03/EV-03-12_browser-checks.txt) | 2026-10-04 | CM-T016, CM-T019, CM-T020 | 18 Playwright tests in Chromium, Firefox and WebKit |

## Phase 4

Captured on `feature/CM-T023-cryptographic-vault` (from `main` at `f86a2ce`) against the real API, the built export behind the local HTTPS E2E server, throwaway test databases and the local development database. Synthetic accounts only; every Vault Passphrase and account password is random and redacted; ciphertexts and public keys are shortened (they are public or opaque by design).

| ID | File | Date | Jira | Caption |
|---|---|---|---|---|
| EV-04-01 | [phase-04/EV-04-01_vault-setup-request.txt](phase-04/EV-04-01_vault-setup-request.txt) | 2026-10-05 | CM-T025 | The setup request holds public keys, KDF metadata and ciphertext; no passphrase or PKCS#8 in any request |
| EV-04-02 | [phase-04/EV-04-02_stored-vault-row.txt](phase-04/EV-04-02_stored-vault-row.txt) | 2026-10-05 | CM-T025 | The stored `user_key_pairs` row: sizes, parameters, no plaintext private key |
| EV-04-03 | [phase-04/EV-04-03_vault-benchmark.txt](phase-04/EV-04-03_vault-benchmark.txt) | 2026-10-05 | CM-T024 | Browser benchmark in three engines and the library comparison |
| EV-04-04 | [phase-04/EV-04-04_browser-storage-after-unlock.txt](phase-04/EV-04-04_browser-storage-after-unlock.txt) | 2026-10-05 | CM-T026 | Browser storage after setup, lock and unlock: nothing readable by scripts |
| EV-04-05 | [phase-04/EV-04-05_fingerprint.txt](phase-04/EV-04-05_fingerprint.txt), [phase-04/EV-04-05_fingerprint.png](phase-04/EV-04-05_fingerprint.png) | 2026-10-05 | CM-T027 | Displayed fingerprint equals an independent recomputation; screenshot on a throwaway account |
| EV-04-06 | [phase-04/EV-04-06_identity-authenticity-tests.txt](phase-04/EV-04-06_identity-authenticity-tests.txt) | 2026-10-05 | CM-T086 | ADR-015 acceptance; binding, fingerprint, signature and signed re-wrap tests |
| EV-04-07 | [phase-04/EV-04-07_crypto-tests-and-coverage.txt](phase-04/EV-04-07_crypto-tests-and-coverage.txt) | 2026-10-05 | CM-T023, CM-T024 | Known-answer, invariant and fail-closed tests of `packages/crypto` with coverage |
| EV-04-08 | [phase-04/EV-04-08_vault-api-security-suites.txt](phase-04/EV-04-08_vault-api-security-suites.txt) | 2026-10-05 | CM-T025 to CM-T028 | Vault API suites, CSRF and route inventory |
| EV-04-09 | [phase-04/EV-04-09_negative-controls.txt](phase-04/EV-04-09_negative-controls.txt) | 2026-10-05 | CM-T023 to CM-T028 | 27 deliberate defects, each caught; sources restored byte for byte |
| EV-04-10 | [phase-04/EV-04-10_browser-tests.txt](phase-04/EV-04-10_browser-tests.txt) | 2026-10-05 | CM-T025 to CM-T028 | Playwright in Chromium, Firefox and WebKit, including cross-engine unlock |
| EV-04-11 | [phase-04/EV-04-11_totp-context-migration.txt](phase-04/EV-04-11_totp-context-migration.txt) | 2026-10-05 | CM-T023 | Phase 3 TOTP ciphertext opens with the shared context builder (CD-22) |
| EV-04-12 | [phase-04/EV-04-12_supply-chain.txt](phase-04/EV-04-12_supply-chain.txt) | 2026-10-05 | CM-T024 | Dependency audit, SBOM and secret scan with the new dependencies |
| EV-04-13 | [phase-04/EV-04-13_ci-run.txt](phase-04/EV-04-13_ci-run.txt) | 2026-10-05 | CM-T023 to CM-T028 | CI run of pull request #10: every job passed (772 Vitest tests, coverage gate, E2E in three engines, audit, gitleaks) |
| EV-04-14 | [phase-04/EV-04-14_sf-04-01-regression.txt](phase-04/EV-04-14_sf-04-01-regression.txt) | 2026-10-05 | SF-04-01 | Security finding: regression test fails before the fix and passes after it |

## Phase 5

Captured on `feature/CM-T029-secure-rooms-rbac` (from `main` at `5c1ed32`) against the real API and the local development PostgreSQL as the least-privilege API role, with synthetic accounts only. No password, token or key appears in any file.

| ID | File | Date | Work item | What it shows |
|---|---|---|---|---|
| EV-05-01 | [phase-05/EV-05-01_authorization-matrix-report.txt](phase-05/EV-05-01_authorization-matrix-report.txt) | 2026-10-06 | CM-T029 to CM-T031 | Authorization matrix test report: the decision through every action and role, the matrix compared cell by cell with the authorization model, the registry, the room routes against PostgreSQL, 97.3% coverage |
| EV-05-02 | [phase-05/EV-05-02_bola-suite-report.txt](phase-05/EV-05-02_bola-suite-report.txt) | 2026-10-06 | CM-T032 | BOLA and IDOR suite report: every production room route attacked with identifiers from another room; non-disclosure, cross-room targets, role and state variants, unchanged-state checks |
| EV-05-03 | [phase-05/EV-05-03_negative-controls.txt](phase-05/EV-05-03_negative-controls.txt) | 2026-10-06 | CM-T029 to CM-T032 | All 49 negative controls caught, including the Phase 5 defects that remove the room checks; the optional "failing suite without a room check" as a local run |
| EV-05-04 | [phase-05/EV-05-04_supply-chain.txt](phase-05/EV-05-04_supply-chain.txt) | 2026-10-06 | CM-T029 to CM-T032 | The `source-map-js` advisory and its lockfile-only remediation to 1.2.2; audit clean |
| EV-05-05 | [phase-05/EV-05-05_phase-5-gates.txt](phase-05/EV-05-05_phase-5-gates.txt) | 2026-10-06 | CM-T029 to CM-T032 | Every gate of CLAUDE.md section 10: 1516 Vitest tests, E2E in three engines, build, smoke, audit, SBOM, full-history secret scan |
| EV-05-06 | [phase-05/EV-05-06_ci-run.txt](phase-05/EV-05-06_ci-run.txt) | 2026-10-06 | CM-T029 to CM-T032 | CI run of pull request #13: every job passed (1516 Vitest tests, both coverage gates, E2E in three engines, dependency audit, full-history secret scan); merge commit `bd4d2f6` |

## Phase 6

Captured in Prompt 08; the files are in [phase-06/](phase-06/): EV-06-01 (stored key material: lengths and hashes), EV-06-02 (RESTRICTED invitation screenshots), EV-06-03 (commitment and key-injection refusals), EV-06-04 (three-engine results), EV-06-05 and EV-06-06 (Safety Code screenshots), EV-06-07 (gates), EV-06-08 (negative controls), EV-06-09 (supply chain), EV-06-10 (CI run of pull request #22).

## Phase 7

Captured on `feature/CM-T037-encrypted-files` (from `main` at `c175d22`) against the real API, PostgreSQL and the local S3-compatible storage, with synthetic data only. Merged through pull request #24 (merge commit `ce331c0`).

| ID | File | Date | Work item | What it shows |
|---|---|---|---|---|
| EV-07-01 | [phase-07/EV-07-01-original-head.txt](phase-07/EV-07-01-original-head.txt), [phase-07/EV-07-01-object-head.txt](phase-07/EV-07-01-object-head.txt) | 2026-10-11 | CM-T038 | First 64 bytes of a synthetic original file and of its stored object (hex): the object is ciphertext |
| EV-07-02 | [phase-07/EV-07-02_bucket-objects.txt](phase-07/EV-07-02_bucket-objects.txt) | 2026-10-11 | CM-T037, CM-T038 | Bucket listing by the administrator: random object names only; runtime credential cannot list; anonymous read refused (stands in for the provider console until Phase 19) |
| EV-07-03 | [phase-07/EV-07-03_file-row.txt](phase-07/EV-07-03_file-row.txt) | 2026-10-11 | CM-T038 | The file row: wrapped FEK, encrypted manifest, sizes and hashes only; no name, type or key column |
| EV-07-04 | [phase-07/EV-07-04_tamper-tests.txt](phase-07/EV-07-04_tamper-tests.txt), [phase-07/EV-07-04-tampered.png](phase-07/EV-07-04-tampered.png), [phase-07/EV-07-04-download-ok.png](phase-07/EV-07-04-download-ok.png) | 2026-10-11 | CM-T039 | Tamper tests; the integrity error with nothing saved; a second member's download |
| EV-07-05 | [phase-07/EV-07-05_canary-scan.txt](phase-07/EV-07-05_canary-scan.txt) | 2026-10-11 | CM-T038 | Canary scan: no file name or content in any table, the object or the log |
| EV-07-06 | [phase-07/EV-07-06_presigned-expiry.txt](phase-07/EV-07-06_presigned-expiry.txt) | 2026-10-11 | CM-T037 | Presigned URLs expire; one object, one method, one size |
| EV-07-07 | [phase-07/EV-07-07_file-benchmark.txt](phase-07/EV-07-07_file-benchmark.txt) | 2026-10-11 | CM-T038 | CP-19 benchmark in three engines; memory was not measured (L-47) |
| EV-07-08 | [phase-07/EV-07-08_phase-7-gates.txt](phase-07/EV-07-08_phase-7-gates.txt) | 2026-10-11 | CM-T037 to CM-T041 | Gates: 1876 Vitest tests in 75 files, 83 E2E passed (10 skipped by design), coverage, build, audit |
| EV-07-09 | [phase-07/EV-07-09_negative-controls.txt](phase-07/EV-07-09_negative-controls.txt) | 2026-10-11 | CM-T037 to CM-T041 | 69 of 69 negative controls caught, ten of them new |
| EV-07-10 | [phase-07/EV-07-10_supply-chain.txt](phase-07/EV-07-10_supply-chain.txt) | 2026-10-11 | CM-T037 | `aws4fetch` 1.0.20 (LIB-09), audit, SBOM, secret scan |
| EV-07-11 | [phase-07/EV-07-11_ci-run.txt](phase-07/EV-07-11_ci-run.txt) | 2026-10-11 | CM-T037 to CM-T041 | CI run 38143399418 of pull request #24: every job passed on attempt 2 after one unrelated WebKit timeout on attempt 1 |

## Phase 11

Captured on branch `feature/CM-T050-key-rotation` against the local PostgreSQL container and throwaway test databases, synthetic data only, no key material. The JSON files were produced by a temporary capture test that drove the real API and database through a removal and a rekey; it is not kept in the repository.

| ID | File | Date | Jira | Caption |
|---|---|---|---|---|
| EV-11-01 | [phase-11/EV-11-01_key-version-history.json](phase-11/EV-11-01_key-version-history.json) | 2026-10-13 | CM-T050 | Key versions and envelope sets before and after a removal: v1 RETIRED, v2 ACTIVE with reason MEMBER_REMOVED, envelopes for exactly the three remaining members |
| EV-11-02 | [phase-11/EV-11-02_removed-member-404.json](phase-11/EV-11-02_removed-member-404.json) | 2026-10-13 | CM-T051 | The removed member gets the generic 404 on six room routes including the rekey start; no envelope is left |
| EV-11-03 | [phase-11/EV-11-03_forward-protection.txt](phase-11/EV-11-03_forward-protection.txt) | 2026-10-13 | CM-T050, CM-T051 | Browser cryptography report: RKM_1 cannot unwrap a DEK created after the rekey (L-04); forged, forked and substituted versions refused; SF-11-01 tests |
| EV-11-04 | [phase-11/EV-11-04_write-lock.json](phase-11/EV-11-04_write-lock.json) | 2026-10-13 | CM-T051 | 409 `REKEY_REQUIRED` for a note write and an invitation while the room is locked; the key state a member sees |
| EV-11-05 | [phase-11/EV-11-05_rekey-events.json](phase-11/EV-11-05_rekey-events.json) | 2026-10-13 | CM-T050, CM-T051 | Recorded events of a removal and rekey: MEMBER_REMOVED, REKEY_REQUIRED, REKEY_STARTED, REKEY_COMPLETED, KEY_VERSION_RETIRED, and the refusals of the removed member (redacted log; the ledger is Phase 12) |
| EV-11-06, EV-11-07 | [phase-11/EV-11-06-07_recovery-and-idempotency.txt](phase-11/EV-11-06-07_recovery-and-idempotency.txt) | 2026-10-13 | CM-T050 | Integration report: lease expiry and worker recovery, idempotent and concurrent finalize, stale and foreign operations |
| EV-11-08 | [phase-11/EV-11-08_negative-controls.txt](phase-11/EV-11-08_negative-controls.txt) | 2026-10-13 | CM-T050 to CM-T053 | 13 of 13 new negative controls caught; baseline passes; sources restored byte for byte |
| EV-11-09 | [phase-11/EV-11-09_gates.txt](phase-11/EV-11-09_gates.txt) | 2026-10-13 | CM-T050 to CM-T053 | Gate results of the final Phase 11 code |
| EV-11-10 | [phase-11/EV-11-10_ci-run.txt](phase-11/EV-11-10_ci-run.txt) | 2026-10-13 | CM-T050 to CM-T053 | CI run 38392960689 of pull request #32: every job passed on the first attempt |

## Phase 14 + Prompt 16.5

Captured on branch `feature/CM-T061-trust-center-redesign` by `tests/e2e/evidence-capture.spec.ts` (`CM_CAPTURE_EVIDENCE=1`, Chromium, 1440 x 900) from the built application on the local HTTPS test server and the local PostgreSQL, synthetic accounts and content only. The dashboard counts include the synthetic rows earlier test runs left in the development database. No screenshot shows a password, passphrase, TOTP secret, recovery code, key or Room Safety Code; fingerprints are public values. Cloud views show the not-connected state.

| ID | File | Date | Jira | Caption |
|---|---|---|---|---|
| EV-14-01 | [phase-14/EV-14-01_security-dashboard.png](phase-14/EV-14-01_security-dashboard.png) | 2026-10-14 | CM-T061, CM-T062 | Platform security dashboard after the capture scenario; four ledger metrics marked not implemented |
| EV-14-02 | [phase-14/EV-14-02_metric-definition.png](phase-14/EV-14-02_metric-definition.png) | 2026-10-14 | CM-T061, CM-T062 | SD-07 with its definition: no composite score |
| EV-14-03 | [phase-14/EV-14-03_landing.png](phase-14/EV-14-03_landing.png) | 2026-10-14 | CM-T061 | Public start page stating what is built and its limits |
| EV-14-04 | [phase-14/EV-14-04_overview.png](phase-14/EV-14-04_overview.png) | 2026-10-14 | CM-T061 | Workspace overview from the user's own rooms, invitations and session |
| EV-14-05 | [phase-14/EV-14-05_room.png](phase-14/EV-14-05_room.png) | 2026-10-14 | CM-T061 | Room header, badges and section navigation (clipped above the Room Safety Code) |
| EV-14-06 | [phase-14/EV-14-06_files-receipt.png](phase-14/EV-14-06_files-receipt.png) | 2026-10-14 | CM-T061 | File with an expanded encryption receipt |
| EV-14-07 | [phase-14/EV-14-07_notes-receipt.png](phase-14/EV-14-07_notes-receipt.png) | 2026-10-14 | CM-T061 | Note with an expanded encryption receipt |
| EV-14-08 | [phase-14/EV-14-08_secrets.png](phase-14/EV-14-08_secrets.png) | 2026-10-14 | CM-T061 | Secrets section after sending a recipient-bound secret |
| EV-14-09 | [phase-14/EV-14-09_vault.png](phase-14/EV-14-09_vault.png) | 2026-10-14 | CM-T061 | Vault status and the key-protection flow |
| EV-14-10 | [phase-14/EV-14-10a_rekey-review.png](phase-14/EV-14-10a_rekey-review.png), [phase-14/EV-14-10b_rekey-done.png](phase-14/EV-14-10b_rekey-done.png) | 2026-10-14 | CM-T061 | Key rotation after a removal: recipient review, then version 2 current |
| EV-14-11 | [phase-14/EV-14-11_trust-summary.png](phase-14/EV-14-11_trust-summary.png) | 2026-10-14 | CM-T061 | Trust Center summary: claims with mechanism, verification, evidence and limitation; not implemented items |
| EV-14-12 | [phase-14/EV-14-12_data-protection.png](phase-14/EV-14-12_data-protection.png) | 2026-10-14 | CM-T061 | Data Protection & Key Management |
| EV-14-13 | [phase-14/EV-14-13_infrastructure.png](phase-14/EV-14-13_infrastructure.png) | 2026-10-14 | CM-T061 | Deployment & Infrastructure: cloud not connected, live checks, control register |
| EV-14-14 | [phase-14/EV-14-14_governance-risk.png](phase-14/EV-14-14_governance-risk.png) | 2026-10-14 | CM-T061 | Governance & Risk with T-06 opened |
| EV-14-15 | [phase-14/EV-14-15_control-evidence.png](phase-14/EV-14-15_control-evidence.png) | 2026-10-14 | CM-T061 | Annex A control 8.3 with its evidence coverage |
| EV-14-16 | [phase-14/EV-14-16_evidence-register.png](phase-14/EV-14-16_evidence-register.png) | 2026-10-14 | CM-T061 | Evidence register with missing and deferred items |
| EV-14-17 | [phase-14/EV-14-17_walkthrough.png](phase-14/EV-14-17_walkthrough.png) | 2026-10-14 | CM-T061 | Guided walkthrough |
| EV-14-18 | [phase-14/EV-14-18_mobile-overview.png](phase-14/EV-14-18_mobile-overview.png) | 2026-10-14 | CM-T061 | Overview at 390 px width |
| EV-14-19 | [phase-14/EV-14-19_gates.txt](phase-14/EV-14-19_gates.txt) | 2026-10-14 | CM-T061, CM-T062 | Gate results: 2326 Vitest tests, 169 E2E passed in three engines, 10 negative controls caught, coverage, build, audit, secret scan |
| EV-14-20 | Pending | | CM-T061, CM-T062 | CI run of the pull request: recorded in the handoff |
