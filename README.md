# CipherMesh

**Client-Side Encrypted Secure Collaboration & Secret Exchange Platform**

CipherMesh lets authorized members of a *Secure Room* exchange sensitive files, notes and one-time secrets. Content is encrypted in the member's browser before it is uploaded. The server stores ciphertext, wrapped keys and the metadata it needs to enforce access control, security policy and auditing.

> **Status: Phase 0.5 (architecture hardening and project-management bootstrap) complete, awaiting approval.** No application code exists yet. This repository contains the architecture, security model, cryptographic design, cloud design, threat model, Jira backlog and import package, roadmap and evidence plan that the implementation will follow.

## Why this project exists

CipherMesh is a university project that demonstrates three subjects in one coherent system:

| Subject | What CipherMesh demonstrates |
|---|---|
| Cryptography Fundamentals | AES-256-GCM authenticated encryption, one envelope-encryption pattern with per-item keys for files, notes and secrets, RSA-OAEP wrapping of 32-byte keys for room membership, Argon2id for passwords and the Vault, HKDF key separation, key commitments and the Room Safety Code, versioned client-driven rekeys, a SHA-256 hash-chained audit ledger with signed checkpoints and an explicit trust model |
| Cloud Security | IaaS: a hardened VM (Ubuntu, Docker, Nginx, TLS, firewall, SSH). PaaS: managed PostgreSQL. SaaS: Jira Cloud. Plus provider-managed object storage configured securely and an explicit shared-responsibility model |
| Information Security Management Systems | Risk-based threat model and risk register, security profiles that implement information classification, change management through a Jira workflow with a security-review gate, evidence collection, ISO/IEC 27001:2022 Annex A control mapping |

## Planned capabilities (designed, not yet implemented)

1. Client-side encrypted Secure Rooms
2. Cryptographic room membership (per-member key envelopes)
3. Envelope encryption (a fresh key per file, note revision and secret)
4. Burn-after-reading secrets
5. Expiring encrypted content
6. Security policy profiles: STANDARD, CONFIDENTIAL, RESTRICTED (enforced by the backend)
7. Cryptographic room-key rotation (client-driven rekey; the room is write-locked until it completes)
8. Tamper-evident audit ledger
9. Crypto Inspector (explains the protection of an item without exposing keys)
10. Security Dashboard (real metrics only, no invented scores)
11. Room Safety Code (an optional, manual check that members hold the same room key)

## Security model in one paragraph

Each user has an RSA-OAEP key pair whose private key is encrypted in the browser under a key derived from a separate **Vault Passphrase** with Argon2id. The Vault Passphrase never leaves the browser. Each room has versioned random key material that is shared with members by wrapping it to their public keys. Every file, note revision and secret is encrypted with AES-256-GCM under its own key. File and note keys are wrapped by the room key, and a secret's key is wrapped to its recipient's public key. RSA only ever wraps 32-byte keys. When a member leaves or is removed, the room becomes read-only until an owner or admin creates a new key version for the remaining members. Members can compare a Room Safety Code out of band to check that they hold the same key. The server authenticates users (Argon2id password hashes, server-side sessions, TOTP MFA), enforces role-based and policy-based authorization and CSRF defences, and keeps a hash-chained audit log. It never receives the keys needed to decrypt room content.

## Limitations (read these)

Client-side encryption in a web application has real limits. The most important ones:

- A compromised browser or device can read whatever its user has decrypted.
- If the server that delivers the web application is compromised, it can deliver malicious JavaScript that captures plaintext or passphrases. Client-side encryption cannot prevent this on its own.
- Burn-after-reading cannot stop an authorized recipient from copying the plaintext.
- Key rotation protects future content. It cannot make a removed member forget what they already obtained.
- Metadata (room names, membership, sizes, timestamps) remains visible to the server.
- The server distributes public keys and key envelopes. Members detect a manipulated key only by comparing fingerprints and Room Safety Codes, and authenticating key versions against a compromised server is still an open design decision (OCD-12).
- Availability depends on the cloud provider and our infrastructure.

The full list, with the reasoning behind each item, is in [docs/security/limitations.md](docs/security/limitations.md).

## Documentation map

| Area | Documents |
|---|---|
| Rules for contributors and Claude Code | [CLAUDE.md](CLAUDE.md) |
| Architecture | [System overview](docs/architecture/system-overview.md), [Data flow](docs/architecture/data-flow.md), [Trust boundaries](docs/architecture/trust-boundaries.md), [Data model](docs/architecture/data-model.md), [Crypto Inspector](docs/architecture/crypto-inspector.md), [Security Dashboard](docs/architecture/security-dashboard.md), [Security UI](docs/architecture/security-ui.md), [ADRs](docs/architecture/adr/README.md) |
| Cryptography | [Cryptographic architecture](docs/crypto/cryptographic-architecture.md), [Key hierarchy](docs/crypto/key-hierarchy.md), [Key lifecycle](docs/crypto/key-lifecycle.md), [Crypto decisions and parameters](docs/crypto/crypto-decisions.md) |
| Threat model | [Threat model and risk register](docs/threat-model/threat-model.md) |
| Security | [Principles](docs/security/security-principles.md), [Authorization model](docs/security/authorization-model.md), [Policy profiles](docs/security/security-policy-profiles.md), [Testing plan](docs/security/security-testing-plan.md), [Sessions and CSRF](docs/security/session-and-csrf.md), [Limitations](docs/security/limitations.md), [ISMS control mapping](docs/security/isms-control-mapping.md), [Phase 0 review](docs/security/architecture-review.md), [Phase 0.5 gate](docs/security/architecture-gate-phase-0-5.md) |
| Cloud | [Service models](docs/cloud/service-models.md), [Shared responsibility](docs/cloud/shared-responsibility.md), [Deployment architecture](docs/cloud/deployment-architecture.md) |
| Project management | [Jira workflow](docs/management/jira-workflow.md), [Jira backlog](docs/management/jira-backlog.md), [Jira import guide](docs/management/jira-import-guide.md), [Jira CSV](docs/management/jira-backlog.csv), [Roadmap](docs/management/project-roadmap.md) |
| Report | [Evidence plan](docs/report/evidence-plan.md) |

## Repository layout

```
apps/web              Next.js client (static export); all client-side cryptography runs here
apps/api              Express API and worker entrypoint
packages/crypto       WebCrypto wrappers, Argon2id integration, canonical context builders
packages/shared       Policy catalogue, authorization matrix, shared types
packages/validation   Request and response schemas for trust boundaries
prisma                Prisma schema and migrations (from Phase 2)
infrastructure        Docker, Nginx and deployment material
tests                 Integration, security regression and E2E tests
docs                  All design, security, cloud, management and report documentation
```

## Technology stack (planned)

TypeScript, Next.js, React, Tailwind CSS, Node.js, Express, PostgreSQL, Prisma, S3-compatible object storage, WebCrypto, Argon2id, Docker, Docker Compose, Nginx, Ubuntu Server, Vitest, Playwright, GitHub Actions, Jira Cloud.

## Getting started

There is nothing to run yet. Phase 1 will add the monorepo tooling, the local Docker Compose environment and setup instructions here.

## Project management

- Source control and pull requests: GitHub.
- Backlog, workflow, security findings and milestones: Jira Cloud (workflow BACKLOG, READY, IN PROGRESS, SECURITY REVIEW, TESTING, DONE). The backlog is ready for CSV import; see the Jira import guide.

## Terminology

CipherMesh is described as **client-side encrypted** and its audit log as **tamper-evident**. It is not "unhackable", "military grade", "zero knowledge" or "tamper-proof", and the documentation explains why.
