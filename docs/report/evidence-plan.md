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
| EV-01-05 | Secret scan result | CI log excerpt | Secret-leak prevention | ISMS |

### Phase 2: Database
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-02-01 | Forbidden-field check passing | Script output | Schema follows the data-model rules | CRY |
| EV-02-02 | Rejected UPDATE on the audit table | Test output | Append-only protection | ISMS |
| EV-02-03 | Grants per database role | Query output | Least privilege | CLD, ISMS |

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

### Phase 4: Vault
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-04-01 | Vault setup request body | Devtools network panel | The passphrase and private key never leave the browser | CRY |
| EV-04-02 | Encrypted private key row | Query output | Private keys stored only encrypted | CRY |
| EV-04-03 | Browser Argon2id benchmark | Table in the issue | KDF parameter choice | CRY |
| EV-04-04 | Empty browser storage after unlock | Devtools Application panel | Keys held only in memory | CRY |
| EV-04-05 | Key fingerprint display | Screenshot | Public-key verification support | CRY |

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

### Phase 9: Secrets
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-09-01 | Secret row before and after reveal | Query output | Burn-after-reading removes the live copy | CRY |
| EV-09-02 | Concurrent reveal test | Test output | Single-use atomicity | APP |
| EV-09-03 | UI warning that copying cannot be prevented | Screenshot | Honest limitation (L-03) | ISMS |
| EV-09-04 | Secret row with AES-256-GCM payload and a 384-byte wrapped SEK | Query output | Envelope encryption for secrets; RSA wraps only the key | CRY |

### Phase 10: Policies
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-10-01 | Policy matrix report | Test report | Profiles are enforced controls | ISMS |
| EV-10-02 | Denials in a RESTRICTED room (MFA, step-up, VIEWER download) | API responses | Classification-based handling rules | ISMS |
| EV-10-03 | Profile downgrade audit event | Audit view | Accountability for weakening controls | ISMS |

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

### Phase 12: Audit
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-12-01 | Audit rows with seq, prevHash and eventHash | Query output | Hash chaining | CRY, ISMS |
| EV-12-02 | Verification result VALID | Dashboard or API output | Audit verification | ISMS |
| EV-12-03 | Verifier detecting a modified event in a copy | Terminal output | Tamper evidence | CRY, ISMS |
| EV-12-04 | Checkpoint object in the retention-locked bucket and a denied delete | Console and command output | External anchoring | CLD, CRY |
| EV-12-05 | Offline signature verification | Terminal output | Digital signatures in practice | CRY |
| EV-12-06 | Trust-model scenarios A to D simulated on a copy (edited anchored event, edited tail, forged checkpoint, revoked key) | Verifier output | What signed checkpoints can and cannot prove | CRY, ISMS |

### Phase 13 and 14: Inspector and Dashboard
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-13-01 | Crypto Inspector for a file in a RESTRICTED room | Screenshot | Explainable protection without key exposure | CRY |
| EV-13-02 | Crypto Inspector room view with key versions | Screenshot | Key lifecycle transparency | CRY |
| EV-14-01 | Security Dashboard after a scripted scenario | Screenshot | Monitoring with real data | ISMS |
| EV-14-02 | Metric definitions | Screenshot | No invented scores | ISMS |

### Phase 15 and 16: Hardening and Test Automation
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-15-01 | ZAP baseline summary | Report excerpt | Dynamic testing | APP |
| EV-15-02 | Security header check | Command output | Hardened HTTP layer | APP, CLD |
| EV-16-01 | Security suite run in CI | CI summary | Continuous security testing | ISMS |
| EV-16-02 | Traceability table | Generated file | Every threat and control tested | ISMS |
| EV-16-03 | SBOM and scan results | CI artifacts | Supply-chain management | ISMS, CLD |

### Phases 17 to 19: Cloud
| ID | Evidence | How to capture | Demonstrates | Tags |
|---|---|---|---|---|
| EV-17-01 | VM configuration in the cloud console | Screenshot | IaaS resource | CLD |
| EV-17-02 | Provider firewall rules | Screenshot | Network exposure minimized | CLD |
| EV-17-03 | Docker deployment: containers, users, read-only filesystems | `docker ps` and `docker inspect` excerpts | Container hardening | CLD |
| EV-17-04 | TLS scan result | Report | Transport security | CLD |
| EV-17-05 | Deployed asset hashes match the release | Script output | Code-delivery integrity check | CLD, APP |
| EV-18-01 | Managed database settings (network, TLS, backups) | Console screenshot | PaaS configuration responsibility | CLD |
| EV-18-02 | Failed connection without TLS or from another host | Command output | Enforced database access controls | CLD |
| EV-18-03 | Private bucket settings (public access blocked, CORS, versioning) | Console screenshot | Private object storage | CLD |
| EV-18-04 | Anonymous object access denied | Command output | Storage misconfiguration prevented | CLD |
| EV-18-05 | Canary scan against deployed services | Test output | Ciphertext only in the cloud | CRY, CLD |
| EV-19-01 | SSH configuration | `sshd -T` excerpt | SSH hardening | CLD |
| EV-19-02 | Host firewall status | Command output | Host network hardening | CLD |
| EV-19-03 | Lynis before and after | Report excerpts | Measurable OS hardening | CLD |
| EV-19-04 | Docker Bench summary | Report excerpt | Container runtime review | CLD |
| EV-19-05 | External port scan | nmap output | Minimal exposed services | CLD |
| EV-19-06 | Credential rotation record | Jira item | Credential lifecycle | ISMS, CLD |
| EV-19-07 | Backup restore test | Report | Recoverability | CLD, ISMS |
| EV-19-08 | MFA enabled on cloud, GitHub and Jira | Settings screenshots | Account protection for management planes | ISMS |
| EV-19-09 | Optional Level 2: provider key policy allowing the worker to sign only, and the provider's signing log | Console screenshots | Key custody outside the VM | CLD, CRY |

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
| Baseline commit | `PENDING-BASELINE-HASH` |
| Commit message | `docs: establish CipherMesh security architecture and project baseline` |
| Contents | Phase 0 and Phase 0.5 architecture, security, cryptography, cloud, management and report documentation, and the repository skeleton. No application code |
| How to verify | `git show --stat <hash>` lists every file in the baseline |

A commit cannot contain its own hash, so the hash is recorded in a follow-up commit that changes only this table.
