# ADR-014: Cloud provider and deployment model (Oracle Cloud Always Free, one VM)

- Status: Accepted (2026-10-14, project owner decision for the university delivery; supersedes the PaaS row and the provider-managed object storage of [ADR-006](ADR-006-cloud-service-models.md) for this deployment)
- Date: 2026-10-14
- Related: [ADR-006](ADR-006-cloud-service-models.md), [ADR-011](ADR-011-static-frontend-delivery.md), [deployment-architecture.md](../../cloud/deployment-architecture.md), [oracle-always-free.md](../../deployment/oracle-always-free.md), [cloud-security-hardening.md](../../deployment/cloud-security-hardening.md), T-16 to T-19, T-24, T-26, T-31, T-42 to T-44, L-71 to L-80, Jira CM-T063 to CM-T072

## Context

ADR-006 chose the three service models for the demonstration: one IaaS VM, managed PostgreSQL as the PaaS example and Jira Cloud as SaaS, plus provider-managed S3-compatible object storage. It deferred the provider to this ADR, with the criteria of [service-models.md](../../cloud/service-models.md) section 7, including "cost within the available student credits".

The constraints changed before the provider was chosen:

- The budget is **$0**. No paid service, no credit-funded resource and no upgrade to a paid account may be used (project owner, 2026-10-14). A free-trial credit balance is not evidence that a resource is free.
- The delivery deadline is 2026-10-18.
- Oracle Cloud Infrastructure (OCI) offers an Always Free allowance that includes Ampere A1 compute (VM.Standard.A1.Flex, 1,500 OCPU hours and 9,000 GB hours per month, which equals 2 OCPUs and 12 GB of memory in total, as Oracle's Always Free page stated on 2026-10-14) and 200 GB of block and boot volume storage, in the tenancy's home region. Oracle may reclaim Always Free instances that stay idle for 7 days. OCI Database with PostgreSQL is not part of it. The Always Free Object Storage tier (20 GB, 50,000 API requests per month) exists, but its support for browser CORS on the S3 compatibility API could not be confirmed, and the project owner chose to keep SeaweedFS. The allowance has to be re-checked against Oracle's page and the account itself before provisioning ([oracle-always-free.md](../../deployment/oracle-always-free.md) section 2).
- Free managed PostgreSQL offers from other providers exist, but they add a second provider to the runtime path, often without network restriction, with small quotas and terms that can change.

Three questions had to be decided by the project owner, because each changes an accepted decision or a CLAUDE.md rule. They were asked on 2026-10-14, and the owner chose the recommended option each time.

## Decision

1. **Provider:** Oracle Cloud Infrastructure, Always Free resources only, in the tenancy's home region. One VM.Standard.A1.Flex instance (aarch64) with **2 OCPUs and 12 GB** of memory, inside the Always Free allowance, running Canonical Ubuntu 24.04 LTS (aarch64), a 50 GB boot volume, one VCN with one public subnet, an internet gateway, a security list or NSG with ingress TCP 22 (operator address only), 80 and 443, and an ephemeral public IPv4 address. No load balancer, no reserved public IP, no paid storage, no managed database, no paid monitoring.
2. **PostgreSQL runs in a container on the VM** (the image pinned since Phase 1), not as a managed service. The PaaS row of ADR-006 is superseded for this deployment: the PaaS model is explained in the documents and the report, not demonstrated live. The reasons are the $0 budget (OCI's PostgreSQL service is not Always Free) and the network exposure a free external database would add.
3. **Object storage is SeaweedFS in a container on the VM**, the S3-compatible store used since Phase 7, not a provider bucket. Browsers still upload and download ciphertext directly with presigned URLs on another host than the application (SF-07-01): Nginx exposes **only** the S3 object paths of the content bucket on a second host name and forwards only signed requests. The master, volume, filer, IAM and admin endpoints are never proxied, and the embedded IAM API is switched off.
4. **Host names and certificates:** two free DuckDNS names (application and storage), owned by the project owner's DuckDNS account, both pointing to the VM. Let's Encrypt certificates (ECDSA P-256, HTTP-01 through Nginx), renewed by the host's certbot timer. Let's Encrypt IP-address certificates are generally available, but one IP address gives only one host, and SF-07-01 needs two.
5. **Images** are built natively for linux/arm64 on the VM from a Git commit that exists on the origin (`cm-deploy`), and in CI on GitHub's native arm64 runner, which runs the whole stack. There is no container registry.
6. **Credentials rule (amends CLAUDE.md section 8):** on a self-hosted database the VM necessarily holds the database cluster, so "never store database migration or database-owner credentials on the VM" becomes:
   - the PostgreSQL **superuser has no password** and is reachable only by peer authentication on the container socket, that is by root on the VM (`docker exec -u postgres`);
   - the **migration role's password never touches the VM's disk**: it is typed or piped from the operator's workstation for one run of `cm-db-init` or `cm-migrate`, which reach PostgreSQL through the ops container in the database container's network namespace;
   - runtime roles connect over TLS only (`hostssl`, SCRAM), and the API still requires `sslmode=verify-full`. The certificate comes from a private CA made on the VM (`cm-pki`), whose private key is deleted once the server certificate is signed.
   The residual risk is stated, not hidden: **root on the VM controls the database and the storage** (L-71, T-42).
7. **Monitoring:** no paid or third-party service. A host collector (`cm-status-collect`, every 5 minutes) writes a sanitized status file from the OCI instance metadata, `docker inspect`, `df`, `/proc/meminfo`, the certificates and the job outcomes. The API reads it read-only and reports it to platform administrators with freshness limits ([platform/status.ts](../../../apps/api/src/platform/status.ts)).
8. **Backups:** a nightly `pg_dump` plus the storage volume and the runtime secrets, encrypted with `age` to the operator's public key (LIB-10). The VM can write backups but cannot read them. A restore drill restores into isolated containers and compares every table digest and every file's ciphertext SHA-256.

## Alternatives Considered

- **Managed PostgreSQL on OCI or another cloud:** keeps the live PaaS example but is not free on OCI. Free external offers add a provider to the runtime path and weaker network restriction. Rejected by the project owner for this delivery; recorded as the first post-delivery change.
- **OCI Object Storage (Always Free, S3 compatibility API):** provider-managed, but browser CORS on the S3 API could not be confirmed, and the 50,000 requests per month quota would cap the demonstration. Kept as an option.
- **Proxying file content through the API:** keeps SeaweedFS fully internal but rewrites the Phase 7 design (body limits, API load, tests). Rejected.
- **Let's Encrypt IP-address certificate:** one host only (SF-07-01 needs two), and a six-day lifetime. Rejected.
- **sslip.io or nip.io names:** not on the Public Suffix List, so every user shares one Let's Encrypt rate limit. DuckDNS is on the list. Rejected.
- **x86 shapes (VM.Standard.E2.1.Micro):** 1 GB of memory is too small for the stack. Rejected; a paid shape is out of scope.
- **Kubernetes, several VMs, load balancer:** complexity without security depth (ADR-006). Rejected.

## Consequences

- One VM is a single point of failure: no high availability, and Oracle may reclaim idle Always Free instances (L-73). Recovery is a restore onto a new VM (`cm-restore`), from a backup copied off the VM.
- The provider-managed controls that ADR-006 assumed (provider backups and point-in-time recovery, bucket versioning, retention locks) are the team's job or absent (L-72, L-74). The anchor bucket of ADR-009 does not exist, which matches the deferral of Phase 12.
- Two external services enter the runtime path at the edge: DuckDNS (name resolution) and Let's Encrypt (certificate issuance). Both are free; an outage of DuckDNS makes the names unresolvable (L-76).
- The evidence items of Phase 18 that name a managed database or a provider bucket are captured for the self-hosted equivalents and say so ([evidence-plan.md](../../report/evidence-plan.md) section 3).

## Security Implications

- **Content confidentiality is unchanged.** The server, the database and the storage still hold only ciphertext and wrapped keys (INV-01, INV-04). A VM compromise now also yields the database and the storage directly, but these are the same ciphertext a database or bucket theft would yield (T-01, T-02).
- **The VM is the security boundary of every server-side asset** (T-19, T-42): SSH hardening, the provider security list, the host firewall, read-only non-root containers without capabilities, internal Docker networks without egress for the database, storage, API and worker, and secrets readable only by root.
- **Transport:** TLS 1.2 and 1.3 at the edge (CP-21); TLS 1.3 with certificate and host-name verification on the database hop (CD-34). The storage hop inside the VM is plain HTTP on an internal Docker network that only Nginx and SeaweedFS join.
- **The platform status is evidence of measured state only.** Missing, malformed or stale data is never reported as healthy (T-44).

## Status

Accepted on 2026-10-14 by the project owner. It is revisited after the university delivery for the managed PostgreSQL and provider object storage options.
