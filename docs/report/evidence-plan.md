# Evidence Plan

Status: Phase 0.5 baseline. Maintained through Jira item CM-T079. Related: [../management/project-roadmap.md](../management/project-roadmap.md), [../security/security-testing-plan.md](../security/security-testing-plan.md).

## 1. Purpose

CipherMesh will be demonstrated to instructors of three subjects. This plan defines, per phase, which evidence to capture, how, and what it proves, so that the final report is assembled from material collected as the work happened.

Subject tags: **CRY** Cryptography Fundamentals, **CLD** Cloud Security, **ISMS** Information Security Management Systems, **APP** application security that supports all three.

## 2. Capture rules

1. Capture evidence when the related Jira item reaches TESTING or DONE, not at the end of the project.
2. Use test accounts and synthetic data only. Never use real personal data.
3. Store files in `docs/report/evidence/phase-NN/` named `EV-NN-MM_short-name.ext`, and list them in `docs/report/evidence/index.md` (created in Phase 1) with date, Jira key and a one-line caption.
4. Prefer text exports (command output, JSON, test reports) over screenshots where possible; they are searchable and easy to redact.
5. Large recordings stay outside the repository; the index records where they are.

### Redaction checklist (apply before every commit of evidence)

- [ ] No private keys, room key material, DEKs, Vault Passphrases or passwords.
- [ ] No session cookie values, TOTP secrets or QR codes of accounts that remain in use, recovery codes.
- [ ] No presigned URLs with their query strings, database or storage credentials, `.env` contents or API tokens.
- [ ] No real personal data; cloud account identifiers and public IP addresses blurred unless needed.
- [ ] Ciphertext, wrapped keys, public keys, fingerprints, commitments and hashes may be shown: they are designed to be public or opaque.

## 3. Evidence by phase

### Phase 0: Architecture
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-00-01 | System architecture diagram | Export the Mermaid diagram from `system-overview.md` | Component design, service models | CRY, CLD, ISMS |
| EV-00-02 | Trust-boundary diagram | Export from `trust-boundaries.md` | Boundary analysis | CLD, ISMS |
| EV-00-03 | Key hierarchy and file-encryption diagrams | Export from `key-hierarchy.md` and `cryptographic-architecture.md` | Envelope encryption design | CRY |
| EV-00-04 | Risk register | Table from `threat-model.md` section 5 | Risk assessment and treatment | ISMS |
| EV-00-05 | Jira board with epics and Phase 0 items | Screenshot after Jira setup | Planned, structured work | ISMS |
| EV-00-06 | Issue lifecycle of CM-T005 | Jira issue history | SECURITY REVIEW gate in use | ISMS |
| EV-00-07 | First commit or pull request of Phase 0 | GitHub view | Version-controlled documentation | ISMS |
| EV-00-08 | Phase 0.5 architecture gate record | [architecture-gate-phase-0-5.md](../security/architecture-gate-phase-0-5.md) | Attack-focused design review with recorded residual risks | CRY, ISMS |
| EV-00-09 | Initial baseline commit (hash, author, file list) | `git log --stat` output; hash recorded in section 6 | Controlled starting point for all later changes | ISMS |
| EV-00-10 | Jira CSV import result and board after import | Import summary and board screenshot | Backlog managed in the SaaS tool | ISMS, CLD |

### Phase 1: Foundation
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-01-01 | CI run with all checks | GitHub Actions summary | Automated quality and security gates | ISMS |
| EV-01-02 | Branch protection settings | GitHub settings screenshot | Change control | ISMS |
| EV-01-03 | Merge blocked by a failing check | Pull request screenshot | Gates are enforced | ISMS |
| EV-01-04 | CSP header and a console without violations | Browser devtools | XSS defence in depth | APP |
| EV-01-05 | Secret scan result | CI log excerpt, or local gitleaks output before the remote exists | Secret-leak prevention | ISMS |
| EV-01-06 | Built API smoke test and safe error responses | `pnpm smoke:api` and integration test output | Minimal health endpoints, generic errors without internal details | APP |
| EV-01-07 | Dependency audit and SBOM | `pnpm audit:deps` output and SBOM summary | Supply-chain management (T-27) | ISMS, CLD |
| EV-01-08 | Development services bound to loopback with authentication enforced | `docker compose ps` and access-check output | Development services not exposed; no default credentials | CLD |
| EV-01-09 | Log redaction and security test results | `pnpm test` output for the redaction, CSRF-gate and route-inventory tests | Secrets never logged (INV-10); deny-by-default routing | APP, ISMS |

### Phase 2: Database
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-02-01 | Forbidden-field check passing | Script output | Schema follows the data-model rules | CRY |
| EV-02-02 | Rejected UPDATE on the audit table | Test output | Append-only protection | ISMS |
| EV-02-03 | Grants per database role | Query output | Least privilege | CLD, ISMS |
| EV-02-04 | Migrations from an empty database and the drift check, including its negative control | `pnpm db:migrate`, `pnpm db:drift` and `tests/database/migrations.test.ts` output | Controlled, reviewed schema changes (control 8.32) | ISMS |
| EV-02-05 | Database security test results and the synthetic seed | `pnpm test:database` output, `pnpm db:seed` output | Constraints, deletion behaviour, client hygiene, synthetic test data (control 8.33) | APP, ISMS |
| EV-02-06 | Database URL rules and redaction | `env.test.ts`, `startup-config` and `client.test.ts` output | TLS required in production; connection strings never logged | CLD, APP |

### Phase 3: Authentication
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-03-01 | Argon2id PHC hash in the users table | Query output with email redacted | Password hashing, not encryption | CRY |
| EV-03-02 | Server Argon2id benchmark | Table in the issue | Parameter choice justified | CRY |
| EV-03-03 | Session cookie attributes | Browser devtools, value blurred | Session security | APP |
| EV-03-04 | 429 responses after a login burst | Test output | Brute-force defence | APP |
| EV-03-05 | MFA enrollment | Screenshot on a throwaway account | Multi-factor authentication | APP |
| EV-03-06 | Login attempt records without raw identifiers | Query output | Privacy-aware security logging | ISMS |
| EV-03-07 | Cross-site requests rejected with `ORIGIN_REJECTED`, including login | Test output | CSRF defence beyond SameSite | APP |
| EV-03-08 | Other sessions revoked after a password change | Session list before and after | Session invalidation policy | APP |
| EV-03-09 | Step-up gate, recovery-code single use and MFA bypass attempts | Test output | Server-side enforcement of authentication state | APP |
| EV-03-10 | Account disabled by a platform administrator: sessions end, login refused | Test output | Identity lifecycle (control 5.16) | ISMS, APP |
| EV-03-11 | Negative controls: ten deliberate defects caught by the security suites | `pnpm security:negative-controls` output | The tests can fail | ISMS |
| EV-03-12 | Browser checks: cookie attributes, empty browser storage, real Origin in three engines | Playwright output | Session and CSRF design in real browsers | APP |

### Phase 4: Vault
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-04-01 | Vault setup request body | Network capture of the real setup flow in a browser (Playwright), ciphertext shortened | The passphrase and private keys never leave the browser | CRY |
| EV-04-02 | Encrypted private key row | Query output | Private keys stored only encrypted | CRY |
| EV-04-03 | Browser Argon2id benchmark | `pnpm bench:vault` output and the library comparison | KDF parameter choice | CRY |
| EV-04-04 | Empty browser storage after unlock | Playwright inspection of cookies, localStorage, sessionStorage, IndexedDB and the Cache API | Keys held only in memory | CRY |
| EV-04-05 | Key fingerprint display | Screenshot on a throwaway account, plus an independent recomputation | Public-key verification support | CRY |
| EV-04-06 | OCD-12 decision and identity authenticity tests | ADR-015 acceptance record; identity, signature and re-wrap test output | Design decided before implementation; signatures and fingerprints verified | CRY, ISMS |
| EV-04-07 | Cryptographic known-answer, invariant and fail-closed tests with coverage | `pnpm test:coverage:crypto` output | Primitives match published vectors; the package fails closed; coverage target met | CRY |
| EV-04-08 | Vault API security suites | `pnpm test:vault`, CSRF and route-inventory output | Step-up, strict schemas, signed re-wraps, reset, directory, BOLA, no secrets in logs | APP, CRY |
| EV-04-09 | Negative controls | `pnpm security:negative-controls` output | The vault and crypto tests can fail | ISMS |
| EV-04-14 | Security finding SF-04-01: regression test before and after the fix | Playwright output on the unfixed and the fixed build | Finding management: a test that fails before the fix and passes after it | ISMS, APP |
| EV-04-10 | Cross-browser vault tests | `pnpm test:e2e` output | Tamper refusal, wrong-passphrase refusal, passphrase change, auto-lock and cross-engine unlock in real browsers | CRY, APP |
| EV-04-11 | Server context migration (CD-22) | Unit test output | Phase 3 TOTP ciphertexts still open after the switch to the shared builder | CRY |
| EV-04-12 | Dependency audit, secret scan and SBOM with the new dependency | `pnpm audit:deps`, `pnpm scan:secrets`, `pnpm sbom:generate` output | Supply-chain checks for LIB-03 | ISMS |
| EV-04-13 | CI run of the Phase 4 pull request | GitHub Actions summary | All gates pass in CI, including the coverage gate | ISMS |

### Phase 5: Rooms and RBAC
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-05-01 | Authorization matrix test report | Test report | Server-side authorization | ISMS, APP |
| EV-05-02 | BOLA suite report | Test report | Object-level authorization | APP |
| EV-05-03 | Optional: failing suite on a branch without a room check | CI screenshot | Tests catch real mistakes | ISMS |

### Phase 6: Cryptographic Membership
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-06-01 | KeyEnvelope rows and a key-version commitment | Query output | Room keys stored only as envelopes | CRY |
| EV-06-02 | RESTRICTED invitation with fingerprint confirmation | Screenshots | Mitigation of key substitution | CRY, ISMS |
| EV-06-03 | Commitment mismatch detected | Test output or UI alert | Defence against key equivocation | CRY |
| EV-06-04 | Cross-browser crypto test results | Playwright report | Interoperability of WebCrypto usage | CRY |
| EV-06-05 | Room Safety Code shown in two members' browsers for the same key version | Screenshots side by side | Out-of-band key consistency check | CRY |
| EV-06-06 | Test harness giving two browsers different keys: the commitment check passes, the Safety Codes differ | Test output and screenshots | What the commitment can and cannot detect | CRY |

Captured in Phase 7 (Prompt 09), with synthetic data only, in [evidence/phase-07/](evidence/phase-07/): EV-07-01 (original file next to the stored object, hex heads), EV-07-02 (bucket objects with random names, listed by the administrator, standing in for the provider console until Phase 19), EV-07-03 (the file row), EV-07-04 (tampered object, screenshot and test output), EV-07-05 (canary scan output), EV-07-06 (presigned URL expiry), plus EV-07-07 (CP-19 benchmark), EV-07-08 (verification gates), EV-07-09 (negative controls), EV-07-10 (supply chain) and EV-07-11 (CI run).

Captured in Phase 6 (Prompt 08), with synthetic data only, in [evidence/phase-06/](evidence/phase-06/): EV-06-01 (stored rows: lengths and hashes), EV-06-02 (RESTRICTED invitation screenshots), EV-06-03 (refusal tests), EV-06-04 (three-engine results), EV-06-05 and EV-06-06 (Safety Code screenshots), plus EV-06-07 (verification gates), EV-06-08 (negative controls), EV-06-09 (supply chain) and EV-06-10 (CI run). EV-06-05 shows the same code in two browsers; EV-06-06 shows a split view that every automatic check accepts and two different codes.

### Phase 7: Encrypted Files
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-07-01 | Original file next to the stored object (hex dump) | Terminal output | Encryption demonstration | CRY |
| EV-07-02 | Object in the storage console with a random name | Console screenshot | Ciphertext visible in storage, no filenames | CLD, CRY |
| EV-07-03 | File row with encrypted manifest | Query output | Metadata minimization | CRY |
| EV-07-04 | Tampered object produces an integrity error | Screenshot and test output | Authenticated encryption | CRY |
| EV-07-05 | Canary scan report | Test output | No plaintext in persistent server storage | CRY, ISMS |
| EV-07-06 | Expired presigned URL rejected | Command output | Short-lived storage capabilities | CLD |

### Phase 8: Notes
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-08-01 | Note ciphertext next to the rendered note | Query output and screenshot | Client-side encrypted notes | CRY |
| EV-08-02 | XSS payload rendered as text | Screenshot | Safe rendering | APP |
| EV-08-03 | Note canary scan report | Test output | No note plaintext in persistent server storage or logs | CRY, ISMS |
| EV-08-04 | Revision, conflict and tamper tests | Test output | Revision binding and optimistic concurrency | CRY, APP |
| EV-08-05 | Phase 8 verification gates | Command output | Release readiness of the phase | ISMS |
| EV-08-06 | Phase 8 negative controls | Command output | The note tests detect real defects | ISMS |
| EV-08-07 | CI run of the Phase 8 pull request | CI summary | Change control through CI | ISMS |

Captured in Phase 8 (Prompt 10), with synthetic data only, in [evidence/phase-08/](evidence/phase-08/): EV-08-01 (the stored note row, ciphertext head, next to the rendered note), EV-08-02 (an XSS corpus shown as text in Chromium), EV-08-03 (canary scan output), EV-08-04 (revision, conflict and tamper test output), EV-08-05 (gate results), EV-08-06 (negative controls) and EV-08-07 (the CI run of pull request #26). Jira history items stay pending until the backlog is imported.

### Phase 9: Secrets
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-09-01 | Secret revealed once on an explicit click (the row after the reveal is asserted by `secrets-lifecycle.test.ts`) | Screenshot and test | Burn-after-reading removes the live copy | CRY |
| EV-09-02 | Concurrent reveal test | Test output | Single-use atomicity | APP |
| EV-09-03 | UI warning that copying cannot be prevented | Screenshot | Honest limitation (L-03) | ISMS |
| EV-09-04 | Secret row with AES-256-GCM payload and a 384-byte wrapped SEK | Query output | Envelope encryption for secrets; RSA wraps only the key | CRY |
| EV-09-05 | Secret canary scan report | Test output | No secret plaintext in persistent server storage, logs or events | CRY, ISMS |
| EV-09-06 | Phase 9 verification gates | Command output | Release readiness of the phase | ISMS |
| EV-09-07 | Phase 9 negative controls | Command output | The secret tests detect real defects | ISMS |
| EV-09-08 | CI run of the Phase 9 pull request | CI summary | Change control through CI | ISMS |
| EV-09-09 | Tampered reveal refused; XSS in a secret shown as text | Screenshot | Authenticated decryption and safe rendering | CRY, APP |

Captured in Phase 9 (Prompt 11), with synthetic data only, in [evidence/phase-09/](evidence/phase-09/): EV-09-01 (the revealed page; the row after the reveal is asserted by `secrets-lifecycle.test.ts`), EV-09-02 (concurrency test output), EV-09-03 (the reveal warning), EV-09-04 (the stored row), EV-09-05 (canary scan output), EV-09-06 (gate results), EV-09-07 (negative controls) and EV-09-09 (tamper and XSS screenshot). EV-09-08 (the CI run of pull request #28) is in the same folder. Jira history items stay pending until the backlog is imported.

### Phase 10: Policies
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-10-01 | Policy matrix report | Test report | Profiles are enforced controls | ISMS |
| EV-10-02 | Denials in a RESTRICTED room (MFA, step-up, VIEWER download) | API responses | Classification-based handling rules | ISMS |
| EV-10-03 | Profile downgrade audit event | Audit view | Accountability for weakening controls | ISMS |
| EV-10-04 | Profile panel after an upgrade (rules shown from the catalogue) | Screenshot | Labelling of classified rooms (5.13) | ISMS |
| EV-10-05 | Phase 10 gate results | Test output | Verification before merge | ISMS |
| EV-10-06 | Phase 10 negative controls | Test output | The policy tests detect real defects | ISMS |
| EV-10-07 | CI run of the Phase 10 pull request | CI log | Change control | ISMS |

Captured in Phase 10 (Prompt 12), with synthetic data only, in [evidence/phase-10/](evidence/phase-10/): EV-10-01 (policy matrix report), EV-10-02 (RESTRICTED refusals as API responses, plus a browser screenshot), EV-10-03 (the recorded `PROFILE_DOWNGRADED` event and a screenshot; the audit view arrives with Phases 12 and 14), EV-10-04, EV-10-05 (gate results in phase-10-traceability.md section 5) and EV-10-06. EV-10-07 is the CI log of pull request #30 (run 38236439654, three attempts: E2E flakiness, see current-state.md; every other job passed). Jira history items stay pending until the backlog is imported.

### Phase 11: Key Rotation
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-11-01 | Key-version history after a removal | Query output or Inspector | Key rotation event | CRY |
| EV-11-02 | Removed member receives 404 | API responses | Immediate loss of access | APP |
| EV-11-03 | Old key material cannot unwrap new DEKs | Test output | Forward protection by rotation, and its limit (L-04) | CRY |
| EV-11-04 | Writes rejected with `REKEY_REQUIRED` while the room is write-locked | API response | No new content under a departed member's key | CRY, ISMS |
| EV-11-05 | Rekey audit trail: MEMBER_REMOVED, REKEY_REQUIRED, REKEY_STARTED, REKEY_COMPLETED | Audit view | Accountable, client-driven rekey | CRY, ISMS |
| EV-11-06 | Crash recovery: an operation abandoned after lease expiry, then a new operation succeeds | Test output | The room never becomes permanently unusable | CRY |
| EV-11-07 | Repeated finalize returns the same result; a stale finalize is rejected | Test output | Idempotent, replay-safe rekey | CRY |

Captured in Phase 11 (Prompt 13), with synthetic data only and no key material, in [evidence/phase-11/](evidence/phase-11/): EV-11-01 (key-version history and envelope sets before and after a removal), EV-11-02 (the removed member's 404 responses), EV-11-03 (browser test report: forward protection and its limit), EV-11-04 (409 `REKEY_REQUIRED` for a write and an invitation while locked), EV-11-05 (the recorded events of a removal and rekey; the audit view arrives with Phases 12 and 14), EV-11-06 and EV-11-07 (recovery and idempotency report), plus EV-11-08 (negative controls NC-11-01 to NC-11-13) and EV-11-09 (gate results). EV-11-10 is the CI record of pull request #32 (run 38392960689: dependency audit, GitGuardian, the secret scan and the lint, types, tests, build and E2E job all passed on the first attempt; see [current-state.md](../management/current-state.md)). The incident procedure is [runbook-compromised-identity-key.md](../security/runbook-compromised-identity-key.md). Jira history items stay pending until the backlog is imported.

### Phase 12: Audit
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-12-01 | Audit rows with seq, prevHash and eventHash | Query output | Hash chaining | CRY, ISMS |
| EV-12-02 | Verification result VALID | Dashboard or API output | Audit verification | ISMS |
| EV-12-03 | Verifier detecting a modified event in a copy | Terminal output | Tamper evidence | CRY, ISMS |
| EV-12-04 | Checkpoint object in the retention-locked bucket and a denied delete | Console and command output | External anchoring | CLD, CRY |
| EV-12-05 | Offline signature verification | Terminal output | Digital signatures in practice | CRY |
| EV-12-06 | Trust-model scenarios A to D simulated on a copy (edited anchored event, edited tail, forged checkpoint, revoked key) | Verifier output | What signed checkpoints can and cannot prove | CRY, ISMS |

### Phase 13 and 14: Inspector and Dashboard (Phase 13 deferred; Phase 14 combined with Prompt 16.5)
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-13-01 | Crypto Inspector for a file in a RESTRICTED room | Screenshot | Explainable protection without key exposure | CRY |
| EV-13-02 | Crypto Inspector room view with key versions | Screenshot | Key lifecycle transparency | CRY |
| EV-14-01 | Security Dashboard after a scripted scenario | Screenshot | Monitoring with real data | ISMS |
| EV-14-02 | Metric definitions | Screenshot | No invented scores | ISMS |
| EV-14-03 | Public start page stating what is built | Screenshot (`tests/e2e/evidence-capture.spec.ts`) | Honest product claims | APP |
| EV-14-04 | Workspace overview from real data | Screenshot | Product dashboard without invented metrics | APP |
| EV-14-05 | Room page with profile, role, key state and section navigation | Screenshot | Secure workspace UI | APP, ISMS |
| EV-14-06 | File list with an expanded encryption receipt | Screenshot | Explainable file encryption without key exposure | CRY |
| EV-14-07 | Note with an expanded encryption receipt | Screenshot | Explainable note encryption and integrity check | CRY |
| EV-14-08 | Secrets section after sending a secret | Screenshot | Recipient-bound, one-time secret exchange | CRY |
| EV-14-09 | Vault status and key-protection flow | Screenshot | Vault Passphrase, Argon2id and non-extractable keys explained | CRY |
| EV-14-10 | Key rotation review and completion in the browser | Screenshots | Rekey after a removal | CRY, ISMS |
| EV-14-11 | Trust Center summary: claims, proof and what is not implemented | Screenshot | Claim, mechanism, verification, evidence, limitation | ISMS, CRY |
| EV-14-12 | Data Protection & Key Management | Screenshot | Encryption flow, mechanisms, key hierarchy | CRY |
| EV-14-13 | Deployment & Infrastructure with live checks and the control register | Screenshot | Designed, configured and verified kept apart; cloud not connected | CLD |
| EV-14-14 | Governance & Risk with a risk opened | Screenshot | Risk register with treatment and residual risk | ISMS |
| EV-14-15 | An Annex A control with its evidence coverage | Screenshot | Control to evidence traceability | ISMS |
| EV-14-16 | Evidence register with missing and deferred items | Screenshot | Missing evidence is visible | ISMS |
| EV-14-17 | Guided walkthrough | Screenshot | Live demonstration of the three subjects | ISMS, CRY, CLD |
| EV-14-18 | Overview on a phone-sized screen | Screenshot | Responsive layout | APP |
| EV-14-19 | Gate results of the combined phase | Command output | Verified build, tests, negative controls and scans | ISMS |
| EV-14-20 | CI run of the Phase 14 + Prompt 16.5 pull request | CI summary | Continuous verification | ISMS |

### Phase 15 and 16: Hardening and Test Automation
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-15-01 | ZAP baseline summary | Report excerpt | Dynamic testing | APP |
| EV-15-02 | Security header check | Command output | Hardened HTTP layer | APP, CLD |
| EV-16-01 | Security suite run in CI | CI summary | Continuous security testing | ISMS |
| EV-16-02 | Traceability table | Generated file | Every threat and control tested | ISMS |
| EV-16-03 | SBOM and scan results | CI artifacts | Supply-chain management | ISMS, CLD |

### Phases 17 to 19: Cloud
Adapted to ADR-014 (Oracle Cloud Always Free, one VM, self-hosted PostgreSQL and SeaweedFS) on 2026-10-14. The IDs are unchanged; items that named a managed database or a provider bucket are captured for their self-hosted equivalents. Items EV-17-06 and EV-19-10 are rehearsal evidence (CI on linux/arm64, throwaway CA), and EV-17-09 and EV-19-13 are local Docker demonstration evidence (the project owner's Windows laptop, 2026-10-14 priority); none of them is presented as cloud evidence.

| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-17-01 | VM configuration in the cloud console: shape VM.Standard.A1.Flex with 2 OCPUs and 12 GB, the "Always Free-eligible" label, home region, boot volume | Screenshot (identifiers redacted) | IaaS resource within the Always Free allowance | CLD |
| EV-17-02 | Provider firewall rules (security list or NSG) | Screenshot (operator address redacted) | Network exposure minimized | CLD |
| EV-17-03 | Docker deployment: containers, users, read-only filesystems, capabilities, networks | `docker ps` and `docker inspect` excerpts | Container hardening | CLD |
| EV-17-04 | TLS and header check of the public origins | `scripts/cloud/edge-check.mjs` output and the browser's certificate view | Transport security | CLD |
| EV-17-05 | Deployed asset hashes match the release | Script output | Code-delivery integrity check | CLD, APP |
| EV-17-06 | The cloud stack built natively and run on linux/arm64 in CI: image architectures, container hardening, edge checks, smoke test in three engines | CI artifact `cloud-stack-arm64-evidence` | ARM64 compatibility before provisioning (rehearsal) | CLD |
| EV-17-07 | Cost classification: the account's Always Free resources and the billing or usage page showing no charges | Console screenshots | Zero-cost policy followed (not a guarantee of future charges) | CLD, ISMS |
| EV-17-08 | Deployment smoke test against the public origin (vault, room, encrypted note and file, no plaintext in requests) | `playwright.deployment.config.ts` output | Client-side encryption on the cloud deployment | CRY, CLD |
| EV-17-09 | Local Docker demonstration verified on the Windows laptop (`pnpm demo:verify`): images, container hardening and networks, secrets as files, edge checks, database access rules, browser tests (smoke and collaboration: invitation, burn secret, removal, key rotation) in three engines, backup, restore drill, full restore with browser decryption | Evidence files of `stack-check.sh` | The production stack and its controls work on a local Docker host (local evidence, not cloud) | CLD, CRY, ISMS |
| EV-18-01 | Database settings on the VM: TLS 1.3 only for runtime roles, HBA rules, roles without a superuser password, connection limits | `pg_hba.conf`, `pg_authid` and `pg_stat_ssl` excerpts | Self-hosted database configuration (ADR-014) | CLD |
| EV-18-02 | Failed connection without TLS, superuser network login refused | Command output | Enforced database access controls | CLD |
| EV-18-03 | Storage settings: one identity limited to one bucket, IAM API off, only signed object paths proxied, CORS for the application origin | Identity file (keys redacted) and Nginx excerpt | Private object storage | CLD |
| EV-18-04 | Unsigned, listing, forged-signature and cookie-carrying requests to storage refused | Edge checker output | Storage misconfiguration prevented | CLD |
| EV-18-05 | Canary scan against deployed services | Test output | Ciphertext only in the cloud | CRY, CLD |
| EV-19-01 | SSH configuration | `sshd -T` excerpt | SSH hardening | CLD |
| EV-19-02 | Host firewall status | `cm-firewall status` output | Host network hardening | CLD |
| EV-19-03 | Lynis before and after | Report excerpts | Measurable OS hardening | CLD |
| EV-19-04 | Docker Bench summary | Report excerpt | Container runtime review | CLD |
| EV-19-05 | External port and path check of the public IP | Edge checker output (and nmap where available) from outside the VM | Minimal exposed services | CLD |
| EV-19-06 | Credential rotation record | Jira item | Credential lifecycle | ISMS, CLD |
| EV-19-07 | Backup restore drill on the VM | `cm-restore-drill` report | Recoverability | CLD, ISMS |
| EV-19-08 | MFA enabled on cloud, GitHub and Jira | Settings screenshots | Account protection for management planes | ISMS |
| EV-19-09 | Optional Level 2: provider key policy allowing the worker to sign only, and the provider's signing log | Console screenshots | Key custody outside the VM | CLD, CRY |
| EV-19-10 | Backup, isolated restore drill and full restore with browser decryption of the restored note and file (CI, linux/arm64) | CI artifact `cloud-stack-arm64-evidence` | Backup and restore procedure works end to end (rehearsal) | CLD, ISMS, CRY |
| EV-19-11 | Measured platform status of the deployment on the security dashboard | Dashboard screenshot as a platform administrator | Monitoring with freshness, no invented health | CLD, ISMS |
| EV-19-12 | Certificate renewal dry run and timer | `cm-tls renew-test` output | Automated certificate renewal | CLD |
| EV-19-13 | Screenshots of the local Docker demonstration: vault, room with encryption receipts, Trust Center live card, security dashboard with the measured local status, governance | `tests/deployment/demo-evidence.spec.ts` | What the examiner sees in the demonstration (local, labelled as such) | CRY, CLD, ISMS |

### Phases 20 to 22: Assessment, Remediation, Report
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-20-01 | Assessment summary | Report | Independent review | ISMS |
| EV-20-02 | A discovered vulnerability as a Security Finding | Jira issue (restricted details redacted) | Findings are tracked | ISMS |
| EV-20-03 | Authenticated DAST summary | Report excerpt | Dynamic testing | APP |
| EV-21-01 | Remediation issue lifecycle | Jira history | Corrective action | ISMS |
| EV-21-02 | Regression test failing before the fix | CI run | Test proves the problem | ISMS |
| EV-21-03 | Regression test passing after the fix, retest recorded | CI run and Jira | Fixed vulnerability | ISMS |
| EV-21-04 | Updated risk register | Document diff | Residual risk management | ISMS |
| EV-22-01 | Final board and release report | Jira screenshots | Project control | ISMS |
| EV-22-02 | Demonstration recording (optional) | Video outside the repository | End-to-end system | All |
| EV-22-03 | Complete evidence index | `index.md` | Evidence management | ISMS |

## 4. Required demonstrations and where they come from

| Demonstration | Evidence |
|---|---|
| Jira board screenshot | EV-00-05, EV-22-01 |
| Jira issue lifecycle | EV-00-06, EV-21-01 |
| Architecture diagram | EV-00-01 |
| Threat model | EV-00-04 |
| Cloud console configuration | EV-17-01, EV-18-01, EV-18-03 |
| VM firewall configuration | EV-17-02, EV-19-02 |
| SSH configuration | EV-19-01 |
| Docker deployment | EV-17-03 |
| Managed database | EV-18-01, EV-18-02 |
| Private object storage | EV-18-03, EV-18-04 |
| Encryption demonstration | EV-07-01, EV-04-01 |
| Ciphertext visible in storage and database | EV-07-02, EV-07-03, EV-08-01, EV-06-01 |
| Crypto Inspector | EV-13-01, EV-13-02 |
| Key rotation event | EV-11-01, EV-11-05 |
| Rekey recovery and replay safety | EV-11-06, EV-11-07 |
| Room Safety Code | EV-06-05, EV-06-06 |
| Initial architecture commit | EV-00-09 |
| Audit verification | EV-12-02, EV-12-03 |
| Security test | EV-05-02, EV-10-01, EV-16-01 |
| Discovered vulnerability | EV-20-02 |
| Jira remediation issue | EV-21-01 |
| Regression test | EV-21-02 |
| Fixed vulnerability | EV-21-03 |

## 5. Demonstration storyline

1. Architecture, trust boundaries and risk register (EV-00-01, EV-00-02, EV-00-04).
2. Register two test users, enable MFA, create vaults; show the vault request and the encrypted private key (EV-03-05, EV-04-01, EV-04-02).
3. Create a RESTRICTED room and invite the second user with fingerprint confirmation (EV-06-02).
4. Compare the Room Safety Code in both browsers, and explain what it can and cannot show (EV-06-05, EV-06-06).
5. Upload a file; show the ciphertext in storage and the Crypto Inspector (EV-07-01, EV-07-02, EV-13-01).
6. Download as the second user; then tamper with a copy and show the integrity error (EV-07-04).
7. Send a burn-after-reading secret; show the AES-256-GCM payload and wrapped SEK, reveal it, show the empty row, and state that copying cannot be prevented (EV-09-04, EV-09-01, EV-09-03).
8. Remove a third member; show the write lock, the rekey, the new key version and the removed member's 404 (EV-11-04, EV-11-05, EV-11-01, EV-11-02).
9. Verify the audit chain; tamper with a copy; run the offline verifier and walk through the trust model (EV-12-02, EV-12-03, EV-12-06).
10. Show the Security Dashboard (EV-14-01).
11. Walk through the cloud evidence: console, firewall, SSH, Docker, TLS, database and bucket settings (EV-17 to EV-19).
12. Show the lifecycle of a real security finding with its regression test (EV-20-02, EV-21-01 to EV-21-03).
13. Close with the limitations: code delivery (L-02), copying (L-03), rekeys (L-04), metadata (L-05) and unauthenticated key versions until OCD-12 is implemented (L-23).

## 6. Initial architecture evidence checkpoint (EV-00-09)

| Item | Value |
|---|---|
| Repository | Local git repository, branch `main`, no remote yet |
| Baseline commit | `cb3b2229788ab2bea023630905077582e02cdd69` (2026-09-28) |
| Commit message | `docs: establish CipherMesh security architecture and project baseline` |
| Contents | Phase 0 and Phase 0.5 architecture, security, cryptography, cloud, management and report documentation, and the repository skeleton. No application code |
| How to verify | `git show --stat <hash>` lists every file in the baseline |

A commit cannot contain its own hash, so the hash is recorded in a follow-up commit that changes only this table.
