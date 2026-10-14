# Shared Responsibility

Status: Phase 0.5 baseline, updated for the Oracle Cloud Always Free deployment of [ADR-014](../architecture/adr/ADR-014-cloud-provider-oci-always-free.md) on 2026-10-14. Related: [service-models.md](service-models.md), [deployment-architecture.md](deployment-architecture.md), [../security/isms-control-mapping.md](../security/isms-control-mapping.md) (ISO/IEC 27001:2022 control 5.23, information security for use of cloud services).

## 1. Principle

The provider is responsible for the security **of** the service it offers. The CipherMesh team is responsible for security **in** and **around** that service: configuration, identities, data and the application. The further a service is from raw infrastructure (IaaS, then PaaS, then SaaS), the more the provider does. The customer always keeps responsibility for data, identities and access.

## 2. Responsibility matrix

Legend: **P** provider, **C** CipherMesh team, **S** shared (the provider supplies the capability; the team must configure and verify it).

Deployment of [ADR-014](../architecture/adr/ADR-014-cloud-provider-oci-always-free.md): PostgreSQL and the object storage run in containers on the team's VM, so their columns carry the team's responsibilities above the hypervisor. The managed-service responsibilities of the earlier design (provider patching of the database engine, provider backups, bucket policies) are the team's in this deployment.

| Layer | IaaS: OCI VM | PostgreSQL (container on the VM) | Object storage: SeaweedFS (container on the VM) | SaaS: Jira Cloud | GitHub (development collaboration) |
|---|---|---|---|---|---|
| Physical data centre, hardware | P | P | P | P | P |
| Provider network and hypervisor | P | P | P | P | P |
| Operating system patching | **C** (unattended upgrades) | C (VM) | C (VM) | P | P |
| Service software patching | C (Nginx, Docker, Node.js, app) | **C** (pinned image, rebuilt by the team) | **C** (pinned image) | P | P |
| Network exposure (firewall rules, allowlists, private networking) | **C** (security list, host firewall) | **C** (internal network, HBA rules) | **C** (internal network, signed-path proxy) | P | P |
| TLS configuration | **C** (Nginx, Let's Encrypt) | C (private CA, TLS 1.3, verify-full) | C (TLS at Nginx; plain HTTP on the internal network) | P | P |
| Identity and access management | C (SSH users, keys) | C (database roles, grants, no superuser password) | C (one identity, one bucket) | S (Atlassian identity; C manages users and permissions) | S (GitHub identity; C manages access, branch protection) |
| MFA on accounts | C (OCI console) | C (OCI console) | C (OCI console) | C (enable and enforce) | C (enable and enforce) |
| Encryption at rest (provider) | S (OCI encrypts block volumes by default; C verifies) | S (on the encrypted boot volume) | S (on the encrypted boot volume) | P | P |
| Client-side encryption of room content | C | C | C | Not applicable | Not applicable |
| Durability and backups | C (VM rebuilt from Git) | **C** (encrypted dumps, restore drill) | **C** (volume in the encrypted backup) | P | P (C may export) |
| Retention locks (anchor bucket) | Not applicable | Not applicable | Not applicable (Phase 12 deferred, ADR-014) | Not applicable | Not applicable |
| Logging and monitoring | C (status collector, Docker logs) | C | C | S | S |
| Secrets management | C | C (credentials) | C (credentials) | C (no secrets in tickets) | C (repository and CI secrets) |
| Application security (authentication, authorization, validation) | C | C (schema, queries) | C (presigned URL issuance) | Not applicable | C (code) |
| Incident response | C | C | C | S | S |
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
8. **"Object storage is our PaaS example."** Classifications differ between providers and courses. The design uses the VM (IaaS), managed PostgreSQL (PaaS) and Jira Cloud (SaaS). In the ADR-014 deployment the database and the storage run on the VM, so the live demonstration shows IaaS and SaaS, and the PaaS model is explained rather than shown.
9. **"Self-hosting on the VM is as safe as a managed service."** It moves the provider's duties (patching the engine, backups, network isolation of the service) to the team, and root on the VM controls the data services (L-71). The team carries them explicitly here.

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
