# Cloud Service Models

Status: Phase 0.5 baseline, provider-neutral. The cloud provider is selected in Phase 17 through ADR-014 (Jira CM-T063). Related: [shared-responsibility.md](shared-responsibility.md), [deployment-architecture.md](deployment-architecture.md), [ADR-006](../architecture/adr/ADR-006-cloud-service-models.md).

## 1. Summary

CipherMesh demonstrates the three service models with components whose classification is not in dispute.

| Model | Service | Role in CipherMesh | What we must secure |
|---|---|---|---|
| **IaaS** | Cloud virtual machine: Ubuntu Server LTS, Docker, Docker Compose, Nginx, the API and the worker | Runs the application and serves the static web client | OS configuration, patching, SSH, firewall, Docker, Nginx, TLS, deployment, application security, OS hardening |
| **PaaS** | Managed PostgreSQL | System of record: users, sessions, rooms, memberships, envelopes, encrypted notes and secrets, audit ledger | Database roles and grants, network access, TLS verification, backup settings and restore tests, credentials |
| **SaaS** | Jira Cloud | Project management: backlog, workflow with the SECURITY REVIEW gate, security findings, releases | Accounts, MFA, project permissions, what information is stored |

Components outside the three-model demonstration:

| Component | Category used in this project | Role | What we must secure |
|---|---|---|---|
| Object storage (S3-compatible) | **Provider-managed cloud object storage** | Encrypted file blobs; a separate retention-locked bucket for audit checkpoints | Bucket policies, public-access blocking, CORS, versioning, lifecycle, retention-lock mode, scoped credentials, presigned URLs |
| GitHub | **Source-control and development-collaboration service** | Repository, pull requests, CI (GitHub Actions), container registry | Branch protection, MFA, repository and CI secrets, action pinning |
| DNS provider and ACME certificate authority | External services | Domain resolution and TLS certificates | Account MFA, DNS records, certificate automation |
| Provider key service (optional, Level 2) | Provider-managed signing keys | Non-exportable audit checkpoint signing key ([ADR-009](../architecture/adr/ADR-009-tamper-evident-audit-ledger.md)) | Key policy, least-privilege sign permission, logs |

Jira Cloud and GitHub are **not part of the CipherMesh runtime**. They manage the development of CipherMesh. Jira is the SaaS example chosen for the management requirement.

## 2. IaaS: the virtual machine

The VM is where the team carries the most responsibility, so the Cloud Security subject is most visible here.

- **Operating system:** Ubuntu Server LTS from the provider's official image, with minimal packages, automatic security updates and time synchronization. TOTP and audit timestamps depend on the clock.
- **Access:** SSH with keys only, no root login, SSH reachable only from allowlisted addresses, named user accounts.
- **Network:** the provider firewall (security group) is the primary control, with the host firewall as a second layer. Only ports 80 and 443 are public.
- **Runtime:** Docker Engine and Docker Compose, with non-root, read-only containers and dropped capabilities.
- **Edge:** Nginx for TLS termination, security headers, rate limits and static assets.
- **Application:** API and worker containers, reachable only on the internal Docker network.

## 3. PaaS: managed PostgreSQL

- TLS is enforced by the service and verified by the client against the provider's CA.
- Access is limited to the VM through private networking or an IP allowlist. There is no public access from arbitrary addresses.
- Separate roles exist for the migration owner, API runtime, worker runtime and read-only verifier. Runtime roles cannot alter the schema, and they cannot update or delete audit rows.
- Migration and owner credentials are used from the operator workstation during deployments and are never stored on the VM.
- Automated backups and point-in-time recovery are enabled. Retention is documented, because it affects L-12, and at least one restore test is recorded as evidence.
- Provider encryption at rest is enabled. It protects disks and snapshots, **not** logical access with valid credentials. Client-side encryption covers that.

## 4. Provider-managed cloud object storage

Providers and courses classify object storage differently. Some list it among infrastructure services, and others call it a platform or "storage as a service" offering. CipherMesh describes it as provider-managed storage with its own shared-responsibility profile ([shared-responsibility.md](shared-responsibility.md)). The three-model demonstration does not rely on any of those labels.

- **Content bucket:** private, with public access blocked. Versioning is on, lifecycle rules remove old versions and incomplete uploads, and CORS is limited to the application origin with PUT and GET only.
- **Anchor bucket:** a separate bucket for signed audit checkpoints. It uses a retention lock in compliance mode where the provider offers it, because governance-mode locks can be bypassed by privileged users. Its credential can write but cannot delete or overwrite.
- Browsers access objects through presigned URLs. The API and worker use scoped credentials.
- The code uses the S3 API behind a storage interface. Many providers and local emulators implement that API. A provider without S3 compatibility would need an adapter, which counts in provider selection.

## 5. Optional managed frontend hosting (deferred)

Hosting the static client on a managed frontend service would move code delivery (TB-03) off the VM. A VM compromise alone could then no longer change the served JavaScript, although a compromise of the hosting service could. The web origin would also differ from the API origin. That would require CORS with credentials, and with it a synchronizer CSRF token ([../security/session-and-csrf.md](../security/session-and-csrf.md) section 8.2). The baseline serves the client from the VM on the same origin as the API. The option is revisited in Phase 18 if time allows.

## 6. SaaS and development services

| Service | Used for | Data placed there | Security configuration |
|---|---|---|---|
| Jira Cloud (SaaS) | Epics, tasks, bugs, security findings, workflow with SECURITY REVIEW gate, releases | Work items, redacted evidence | MFA, team-only project, restricted detail for open findings, no secrets or production data |
| GitHub (development collaboration) | Code, pull requests, CI, images | Source code, CI configuration, build artifacts | MFA, protected `main`, required checks, secret scanning, actions pinned to commit SHAs, least-privilege tokens |

## 7. Provider selection criteria (for ADR-014 in Phase 17)

1. Ubuntu LTS VM images, a cloud firewall or security groups, and SSH key injection.
2. Managed PostgreSQL (version 16 or newer) with enforced TLS, private networking or IP allowlisting, automated backups and point-in-time recovery.
3. S3-compatible object storage with public-access blocking, versioning, lifecycle rules, CORS and presigned URLs, and a retention lock (preferably compliance mode) for the anchor bucket.
4. All services in one region that satisfies the university's data-protection expectations.
5. MFA for the console, scoped API credentials, and activity logs for the account.
6. Optional: a key service with asymmetric signing for audit Level 2 (OCD-13).
7. Cost within the available student credits.

Feature availability, especially retention-lock modes, private networking and signing algorithms, differs between providers. It must be verified at selection time, not assumed.
