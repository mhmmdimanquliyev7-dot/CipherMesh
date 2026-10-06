# ISMS Control Mapping (ISO/IEC 27001:2022)

Status: Phase 0 baseline, with implementation notes for Phases 2 to 4. This is a **learning-oriented, project-level mapping** in the style of a Statement of Applicability. It is not a certified ISMS and makes no claim of conformity. Evidence IDs refer to [../report/evidence-plan.md](../report/evidence-plan.md).

## 1. Scope statement

The scope covers the design, development, deployment and demonstration operation of the CipherMesh platform: the web client, API and worker, the cloud VM, the managed database and object storage, and the management tooling (GitHub, Jira Cloud) used to build it. Physical security of data centres is the cloud provider's responsibility. People-related controls apply only in the limited sense of a student project team.

## 2. Management-system clauses

| Clause | Requirement (summary) | CipherMesh implementation |
|---|---|---|
| 4.3 | Scope of the ISMS | Section 1 of this document |
| 5.2 | Information security policy | CLAUDE.md and [security-principles.md](security-principles.md) |
| 6.1.2 | Risk assessment | [threat-model.md](../threat-model/threat-model.md): assets, threats, likelihood, impact |
| 6.1.3 | Risk treatment, applicability of controls | Risk register treatments; section 3 of this document |
| 6.2 | Security objectives | Security goals G1 to G7 in [system-overview.md](../architecture/system-overview.md) |
| 6.3 | Planning of changes | Roadmap, phase gating and ADRs |
| 7.5 | Documented information | `docs/`, ADRs, Jira history, Git history |
| 8.1 | Operational planning and control | Jira workflow with SECURITY REVIEW and TESTING gates |
| 8.2, 8.3 | Performing risk assessment and treatment | Threat model review at the end of every phase |
| 9.1 | Monitoring and measurement | Security Dashboard, CI security suites, audit verification runs |
| 9.2 | Internal audit | Phase 20 security assessment |
| 9.3 | Management review | Project owner approval at each phase gate |
| 10.1, 10.2 | Continual improvement, corrective action | Security Finding workflow with regression tests; residual risk re-rating |

## 3. Annex A controls

Status values: **Implemented by design** (designed in Phase 0, built in the listed phase), **Partial** (limited by project context), **Provider** (responsibility transferred under shared responsibility), **Not applicable**.

| Control | Title | Status | CipherMesh implementation | Evidence |
|---|---|---|---|---|
| 5.1 | Policies for information security | Implemented by design | CLAUDE.md rules, security principles, invariants | EV-00-07 |
| 5.2 | Roles and responsibilities | Partial | Project roles in [shared-responsibility.md](../cloud/shared-responsibility.md); one person may hold several roles | Report |
| 5.3 | Segregation of duties | Partial | Two-person approval of ADMIN invitations (PC-04); reviewer separate from author where the team allows; PLATFORM_ADMIN excluded from rooms | EV-06-02, EV-00-06 |
| 5.8 | Information security in project management | Implemented by design | SECURITY REVIEW status, security considerations on every backlog item | EV-00-05, EV-00-06 |
| 5.9 | Inventory of information and assets | Implemented by design | Asset list in the threat model (A-13, public identities, added in Phase 4), key inventory in [key-hierarchy.md](../crypto/key-hierarchy.md) (identity signing key added in Phase 4), credential inventory (CM-T071) | EV-00-04, EV-19-06 |
| 5.12 | Classification of information | Implemented by design | STANDARD, CONFIDENTIAL, RESTRICTED profiles | EV-10-01 |
| 5.13 | Labelling of information | Implemented by design | Profile shown on every room and in API responses | EV-10-02 |
| 5.14 | Information transfer | Implemented by design | Client-side encrypted files, notes and secrets; TLS | EV-07-01, EV-17-04 |
| 5.15 | Access control | Implemented by design | [authorization-model.md](authorization-model.md); central room authorization module, shared matrix and route-registry enforcement built in Phase 5 (CM-T029, section 9 of the model); room lifecycle and membership routes built in Phase 5 (CM-T030, CM-T031) | EV-05-01 |
| 5.16 | Identity management | Implemented by design | Account lifecycle (registration, disabling and re-enabling with immediate session revocation), PLATFORM_ADMIN only through the server-side CLI with MFA required (built in Phase 3) | EV-03-05, EV-03-10 |
| 5.17 | Authentication information | Implemented by design | Argon2id with benchmarked parameters, CP-06 password policy with a breach blocklist, single-use recovery codes stored as digests, TOTP secrets encrypted at rest (built in Phase 3, [authentication-security.md](authentication-security.md)). Separate Vault Passphrase with its own policy, checked only in the browser and never transmitted or stored; no recovery or escrow path (built in Phase 4, [../crypto/vault.md](../crypto/vault.md)) | EV-03-01, EV-03-02, EV-04-01, EV-04-02 |
| 5.18 | Access rights | Implemented by design | Invitations, approvals, removal with an immediate write lock and a client-driven rekey (ADR-013); access review in CM-T080. Built in Phase 5: role changes within the role ceilings, removal with the write lock, ownership transfer with a step-up, and suspension of all memberships when an account is disabled (PA-03); invitations and the rekey follow | EV-11-02 |
| 5.19 to 5.22 | Supplier relationships | Partial | Provider selection ADR; Jira and GitHub treated as suppliers; shared-responsibility matrix. ICT supply chain (5.21): security libraries are selected against written criteria and reviewed (Phase 4: LIB-03 with a comparison, a code review finding and checksummed WebAssembly; LIB-05 kept in the repository) | EV-17-01, EV-04-03, EV-04-12 |
| 5.23 | Information security for use of cloud services | Implemented by design | [service-models.md](../cloud/service-models.md), [shared-responsibility.md](../cloud/shared-responsibility.md) | EV-18-01, EV-18-03 |
| 5.24 to 5.27 | Incident management | Partial | Compromise response table in the key lifecycle; incident procedure in CM-T080 | Report |
| 5.28 | Collection of evidence | Implemented by design | Evidence plan; tamper-evident audit ledger | EV-12-03 |
| 5.33 | Protection of records | Implemented by design | Append-only, hash-chained, anchored audit records | EV-12-01, EV-12-04 |
| 5.34 | Privacy and protection of PII | Partial | Metadata minimization, retention limits, no IP addresses in audit; metadata still visible (L-05) | EV-03-06 |
| 5.35 | Independent review | Partial | Phase 20 assessment; independence limited in a student team | EV-20-01 |
| 5.37 | Documented operating procedures | Implemented by design | Runbooks in `infrastructure/deployment` | EV-19-07 |
| 6.1 to 6.8 | People controls | Not applicable | Student project context; awareness covered informally by project documentation | Not applicable |
| 7.1 to 7.14 | Physical controls | Provider | Data-centre security belongs to the cloud provider | Provider documentation |
| 8.1 | User endpoint devices | Partial | Vault auto-lock, non-extractable keys held only in memory, no key persistence, tested in three browser engines (built in Phase 4); device security is the user's (L-01, L-38) | EV-04-04, EV-04-10 |
| 8.2 | Privileged access rights | Implemented by design | PLATFORM_ADMIN limits, SSH keys, database roles (four least-privilege roles and a tested grant matrix built in Phase 2, [database-security.md](database-security.md)) | EV-02-03, EV-19-01 |
| 8.3 | Information access restriction | Implemented by design | RBAC, object-level rules, encryption as second layer | EV-05-02 |
| 8.4 | Access to source code | Implemented by design | GitHub permissions, protected `main` | EV-01-02 |
| 8.5 | Secure authentication | Implemented by design | TOTP MFA, opaque server-side sessions with rotation and revocation, login backoff without lockout, CSRF defences including login CSRF, step-up (built in Phase 3). Phase 4: vault setup and passphrase change need a recent step-up, a vault reset a strict one, and a reset ends all other sessions | EV-03-03 to EV-03-09, EV-04-08 |
| 8.7 | Protection against malware | Partial | Forced attachment downloads, no inline rendering, CSP; no scanning of encrypted files (L-11) | EV-08-02 |
| 8.8 | Management of technical vulnerabilities | Implemented by design | Dependency, container and secret scanning; patching | EV-16-03 |
| 8.9 | Configuration management | Implemented by design | Compose, Nginx and hardening configuration in Git; checklists | EV-19-03 |
| 8.10 | Information deletion | Implemented by design | Expiry, burn-after-reading, crypto-shredding of live data; backup caveat (L-12) | EV-09-01 |
| 8.12 | Data leakage prevention | Implemented by design | Client-side encryption, log redaction, encrypted filenames. Phase 4: browser tests inspect every vault request for the passphrase in five encodings and for private-key structures, and a log test searches for every secret and ciphertext used | EV-07-05, EV-04-01, EV-04-08 |
| 8.13 | Information backup | Provider and team | Managed backups plus team-tested restore | EV-19-07 |
| 8.15 | Logging | Implemented by design | Audit ledger (append-only table protection built in Phase 2, hash chain in Phase 12) and redacted application logs | EV-02-02, EV-12-01 |
| 8.16 | Monitoring activities | Implemented by design | Security Dashboard, verification runs, health checks | EV-14-01 |
| 8.17 | Clock synchronization | Implemented by design | NTP on the VM (needed for TOTP and audit) | EV-19-03 |
| 8.20 | Network security | Implemented by design | Provider and host firewalls, TLS | EV-17-02, EV-19-05 |
| 8.21 | Security of network services | Implemented by design | Database network restriction, bucket policies | EV-18-02, EV-18-04 |
| 8.22 | Segregation of networks | Implemented by design | Separate Docker networks; database reachable only from the VM | EV-17-03 |
| 8.24 | Use of cryptography | Implemented by design | `docs/crypto/` and the parameter register. Phase 4: `packages/crypto` with narrow interfaces and known-answer tests from published sources, browser Argon2id selected by benchmark (ADR-010), identity signing keys decided before implementation (ADR-015), a specified vault format ([../crypto/vault.md](../crypto/vault.md)) | EV-00-03, EV-07-01, EV-04-03, EV-04-06, EV-04-07 |
| 8.25 | Secure development life cycle | Implemented by design | Workflow, Definition of Done, phase gates | EV-01-01 |
| 8.26 | Application security requirements | Implemented by design | Invariants, policy profiles, ASVS target | EV-10-01 |
| 8.27 | Secure system architecture and engineering principles | Implemented by design | Security principles, ADRs, trust boundaries | EV-00-02 |
| 8.28 | Secure coding | Implemented by design | Coding conventions, forbidden-API lint rules. Phase 4: no cryptographic function accepts an IV, an algorithm or a raw AAD; the export surface and the test-only seam are fixed by a test; browser code may not import crypto internals (lint) | EV-01-01, EV-04-07 |
| 8.29 | Security testing in development and acceptance | Implemented by design | [security-testing-plan.md](security-testing-plan.md). Phase 4: 17 more negative controls (27 in total, five of them in a real browser), a 90% coverage gate for `packages/crypto` in CI, and cross-engine browser tests; security finding SF-04-01 fixed with a regression test that failed before the fix | EV-16-01, EV-04-07, EV-04-09, EV-04-10 |
| 8.31 | Separation of environments | Implemented by design | Local development versus production; no production credentials in development | Report |
| 8.32 | Change management | Implemented by design | Jira workflow plus pull requests; database changes only as reviewed migrations, with destructive Prisma commands refused and a drift check in CI (Phase 2). Phase 4: the cryptographic design change (OCD-12) was decided in an ADR and accepted by the project owner before any code was written; the identity migration fails rather than altering existing rows | EV-02-04, EV-21-01, EV-04-06, EV-04-13 |
| 8.33 | Test information | Implemented by design | Synthetic data only: the seed uses reserved `.test` addresses, disabled accounts, no credentials and no key material (Phase 2) | EV-02-05 |

Controls not listed were judged not relevant to this project scope. The list is revisited in CM-T080.
