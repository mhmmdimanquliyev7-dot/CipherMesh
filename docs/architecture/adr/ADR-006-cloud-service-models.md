# ADR-006: IaaS, PaaS and SaaS architecture

- Status: Accepted (classification corrected in Phase 0.5; cloud provider selection deferred to Phase 17)
- Date: 2026-09-28
- Related: [service-models.md](../../cloud/service-models.md), [shared-responsibility.md](../../cloud/shared-responsibility.md), [deployment-architecture.md](../../cloud/deployment-architecture.md), [ADR-005](ADR-005-jira-cloud-management-saas.md)

## Context

The project must visibly demonstrate all three cloud service models, with meaningful security responsibilities in each. It must avoid infrastructure that adds complexity without security depth. The demonstration must also rest on a classification that instructors will not dispute. Phase 0 labelled object storage as PaaS, but taxonomies differ: object storage is often grouped with infrastructure services or treated as a category of its own. The mapping therefore must not depend on that label.

## Decision

| Model | Component | Why it is uncontested |
|---|---|---|
| **IaaS** | One cloud VM running Ubuntu Server LTS, Docker, Docker Compose, Nginx, the API and the worker. It also serves the static web client | We receive virtual hardware and operate everything above the hypervisor |
| **PaaS** | Managed PostgreSQL | The provider operates the database platform (engine, patching, backups, availability). We use it through the database interface and configure access, roles and settings |
| **SaaS** | Jira Cloud as the project-management service ([ADR-005](ADR-005-jira-cloud-management-saas.md)) | A finished application consumed through the browser. It is the SaaS demonstration for the management requirement |

Components that are not part of the three-model demonstration:

- **Provider-managed cloud object storage** (S3-compatible). It holds encrypted file blobs and, in a separate retention-locked bucket, the audit checkpoints. It is described as its own category with its own shared-responsibility profile. Some providers file it under infrastructure, and some courses call it PaaS or "storage as a service". CipherMesh's demonstration does not rely on any of those labels.
- **GitHub** is the source-control and development-collaboration service (repository, pull requests, CI, container registry). It is also a SaaS product, but Jira is the designated SaaS for the management requirement.
- **Optional managed frontend hosting** and a **provider key service** for audit signing ([ADR-009](ADR-009-tamper-evident-audit-ledger.md), Level 2) are deferred hardening options, not part of the baseline.

The design stays **provider-neutral** until Phase 17. The PostgreSQL wire protocol and the S3 API sit behind interfaces, and the provider is chosen in ADR-014 using the criteria in [service-models.md](../../cloud/service-models.md).

## Alternatives Considered

- **Everything on the VM (database and storage in containers):** more IaaS work but no PaaS demonstration, and backups and durability become our problem.
- **Everything on PaaS (application platform or serverless):** less operations work, but removes the OS and network hardening that IaaS demonstrates.
- **Calling object storage the PaaS example:** contestable, so rejected as the basis of the demonstration.
- **Kubernetes or several VMs:** complexity without added security depth, and explicitly out of scope.

## Consequences

- The VM must reach the managed database securely: TLS with certificate verification, and private networking or an address allowlist.
- Two buckets and several scoped credentials must be managed.
- Provider-specific features, such as retention-lock modes and private networking, must be checked during provider selection.

## Security Implications

- Shared responsibility differs per component and is documented per component, with object storage as its own column.
- A VM compromise exposes the credentials for the managed services, but stored content remains ciphertext (T-19).
- Provider encryption at rest is an additional layer, never the primary protection for content.

## Status

Accepted. The provider-selection decision in Phase 17 (ADR-014) will reference this ADR.
