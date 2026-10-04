# Architecture Decision Records

An ADR records one significant decision: its context, the decision, the alternatives, the consequences and the security implications. Security-sensitive decisions always need an ADR (CLAUDE.md, section 11).

## Index

| ADR | Title | Status |
|---|---|---|
| [ADR-001](ADR-001-monorepo-architecture.md) | Monorepo architecture | Accepted |
| [ADR-002](ADR-002-client-side-encryption.md) | Client-side encryption of room content | Accepted |
| [ADR-003](ADR-003-aes-256-gcm.md) | AES-256-GCM for symmetric encryption | Accepted |
| [ADR-004](ADR-004-key-management.md) | Key-management approach | Accepted (revised in Phase 0.5) |
| [ADR-005](ADR-005-jira-cloud-management-saas.md) | Jira Cloud as management SaaS | Accepted |
| [ADR-006](ADR-006-cloud-service-models.md) | IaaS, PaaS and SaaS architecture | Accepted (classification corrected in Phase 0.5; provider selection deferred) |
| [ADR-007](ADR-007-asymmetric-key-wrapping.md) | RSA-OAEP-3072 for room-key distribution | Proposed |
| [ADR-008](ADR-008-server-side-sessions.md) | Opaque server-side sessions | Accepted (lifecycle and CSRF completed in Phase 0.5) |
| [ADR-009](ADR-009-tamper-evident-audit-ledger.md) | Tamper-evident audit ledger | Accepted (trust model added in Phase 0.5) |
| [ADR-010](ADR-010-browser-argon2id.md) | Argon2id in the browser for the Vault | Proposed |
| [ADR-011](ADR-011-static-frontend-delivery.md) | Static Next.js export served by Nginx | Accepted for export and CSP (Phase 1); identifier routing confirmed in Phase 5 |
| [ADR-012](ADR-012-room-safety-code.md) | Room Safety Code | Accepted |
| [ADR-013](ADR-013-rekey-state-machine.md) | Client-driven rekey state machine | Accepted |

"Accepted" means the decision is part of the architecture baseline, subject to the project owner's approval of Phase 0.5. ADR-014 is reserved for the cloud provider selection in Phase 17. "Proposed" means the direction is recommended but must be confirmed by a test or benchmark in a later phase.

## Status values

Proposed, Accepted, Superseded by ADR-xxx, Deprecated, Rejected.

## Template

```markdown
# ADR-NNN: Title

- Status: Proposed | Accepted | Superseded by ADR-xxx | Deprecated | Rejected
- Date: YYYY-MM-DD
- Related: links to documents, threats (T-xx), Jira items

## Context
What problem forces a decision? What constraints apply?

## Decision
What we will do, stated precisely.

## Alternatives Considered
Each alternative with its main advantages and why it was not chosen.

## Consequences
Positive and negative effects on the project, including work created.

## Security Implications
Which threats this addresses or creates, which limitations follow, which tests prove it.

## Status
Current status and what would trigger a review.
```
