# Shared Responsibility

Status: Phase 0.5 baseline, provider-neutral. Related: [service-models.md](service-models.md), [deployment-architecture.md](deployment-architecture.md), [../security/isms-control-mapping.md](../security/isms-control-mapping.md) (ISO/IEC 27001:2022 control 5.23, information security for use of cloud services).

## 1. Principle

The provider is responsible for the security **of** the service it offers. The CipherMesh team is responsible for security **in** and **around** that service: configuration, identities, data and the application. The further a service is from raw infrastructure (IaaS, then PaaS, then SaaS), the more the provider does. The customer always keeps responsibility for data, identities and access.

## 2. Responsibility matrix

Legend: **P** provider, **C** CipherMesh team, **S** shared (the provider supplies the capability; the team must configure and verify it).

| Layer | IaaS: VM | PaaS: managed PostgreSQL | Provider-managed object storage | SaaS: Jira Cloud | GitHub (development collaboration) |
|---|---|---|---|---|---|
| Physical data centre, hardware | P | P | P | P | P |
| Provider network and hypervisor | P | P | P | P | P |
| Operating system patching | **C** | P | P | P | P |
| Service software patching | C (Nginx, Docker, Node.js, app) | P (engine); C schedules major version upgrades | P | P | P |
| Network exposure (firewall rules, allowlists, private networking) | **C** | **S** | **S** | P | P |
| TLS configuration | **C** (Nginx) | S (service enforces; C verifies the certificate) | P (endpoint); C uses HTTPS only | P | P |
| Identity and access management | C (SSH users, keys) | C (database roles, grants) | C (credentials, bucket policies) | S (Atlassian identity; C manages users and permissions) | S (GitHub identity; C manages access, branch protection) |
| MFA on accounts | C (cloud console) | C (cloud console) | C (cloud console) | C (enable and enforce) | C (enable and enforce) |
| Encryption at rest (provider) | S (disk encryption option) | S (usually on by default; C verifies) | S (server-side encryption option; C enables) | P | P |
| Client-side encryption of room content | C | C | C | Not applicable | Not applicable |
| Durability and backups | C (VM needs little state; configuration in Git) | S (P runs backups; C sets retention and tests restores) | S (P provides durability; C enables versioning) | P | P (C may export) |
| Retention locks (anchor bucket) | Not applicable | Not applicable | S (P provides the lock feature; C chooses compliance mode and retention period and verifies deletion is refused) | Not applicable | Not applicable |
| Logging and monitoring | C | S (P offers logs; C reviews) | S (P offers access logs; C enables) | S | S |
| Secrets management | C | C (credentials) | C (credentials) | C (no secrets in tickets) | C (repository and CI secrets) |
| Application security (authentication, authorization, validation) | C | C (schema, queries) | C (presigned URL issuance) | Not applicable | C (code) |
| Incident response | C | S | S | S | S |
| Data classification and handling | C | C | C | C | C |

**Optional Level 2 audit signing key.** If a provider key service is adopted (OCD-13), it adds one more shared-responsibility boundary. The provider protects the non-exportable key material and logs every signing operation. The team defines the key policy, grants the worker only the "sign" permission, protects the administration role with MFA, and reviews the logs.

## 3. Common misunderstandings this project avoids

1. **"The provider encrypts data at rest, so the data is protected."** Provider encryption protects disks and backups from physical theft. Anyone with valid database or storage credentials still reads plaintext through the service. CipherMesh relies on client-side encryption for room content and treats provider encryption as an additional layer.
2. **"Managed means secure by default."** A managed database can still be reachable from the internet with a weak password, and a bucket can still be made public. Network rules, credentials and bucket policies are the team's job.
3. **"The provider handles backups, so restore works."** Restores are only proven by testing them. A restore test is part of the evidence plan.
4. **"SaaS tools are the vendor's problem."** Access control, MFA and what is written into Jira or GitHub remain the team's responsibility.
5. **"The VM is behind the cloud firewall, so the host firewall does not matter."** Both layers are configured. Docker publishes ports by editing firewall rules directly, which can bypass the host firewall, so only 80 and 443 are ever published ([deployment-architecture.md](deployment-architecture.md)).
6. **"Presigned URLs are safe because they are hard to guess."** They are bearer capabilities. CipherMesh issues them only after authorization, with short lifetimes, and never logs them.
7. **"Object lock makes checkpoints permanent."** Governance-mode locks can be lifted by privileged users, and every lock ends when its retention period ends. The lock mode and period are the team's configuration decisions ([ADR-009](../architecture/adr/ADR-009-tamper-evident-audit-ledger.md) section 8).
8. **"Object storage is our PaaS example."** Classifications differ between providers and courses. The three-model demonstration uses the VM (IaaS), managed PostgreSQL (PaaS) and Jira Cloud (SaaS), and treats object storage as provider-managed storage.

## 4. Effect of client-side encryption on shared responsibility

Client-side encryption moves the confidentiality of room content out of the provider's hands and out of the server's hands. The provider and the server see only ciphertext. The price is that CipherMesh must manage keys in the browser and accept that the server delivers the code that holds those keys (L-02). It must also design recovery without server-side escrow and keep rekeys client-driven (ADR-013).

## 5. Team responsibilities

The project may be run by one person or a small team. Where one person holds several roles, segregation of duties is limited, and the report notes this.

| Role | Responsibilities |
|---|---|
| Project owner | Approves phases, ADRs and risk acceptances; owns the risk register |
| Developer | Implements work items, writes tests, updates documentation |
| Security reviewer | Performs the SECURITY REVIEW step in Jira; ideally a different person from the author |
| Operator | Provisions and hardens cloud resources, manages credentials, runs backups and restore tests, makes the weekly audit witness copy |
