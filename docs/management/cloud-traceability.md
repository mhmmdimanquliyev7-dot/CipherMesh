# Cloud Deployment + Cloud Security Hardening: Traceability

Status: Stage A (repository and rehearsal) complete on branch `infra/CM-T063-oracle-always-free-deployment` (pull request #37), 2026-10-14; Stage B (Oracle Cloud resources) waits for the account owner's approval of the plan in [oracle-always-free.md](../deployment/oracle-always-free.md) section 3. Decision record: [ADR-014](../architecture/adr/ADR-014-cloud-provider-oci-always-free.md). Related: [cloud-security-hardening.md](../deployment/cloud-security-hardening.md), [current-state.md](current-state.md) section 6h.

## 1. Scope and decisions

- Approved by the project owner on 2026-10-14 as one workstream covering Phases 17 to 19 (CM-T063 to CM-T072), before the final ISMS report; Phases 12, 13, 15 and 16 stay deferred.
- Three owner decisions (2026-10-14), recorded in ADR-014: PostgreSQL self-hosted on the VM (supersedes ADR-006's PaaS row and amends the CLAUDE.md credential rule); SeaweedFS reachable only through Nginx on a second host name for signed object requests (keeps SF-07-01); two DuckDNS names with Let's Encrypt.
- Budget $0: Always Free resources only; no resource exists before the account owner approves the plan.

## 2. Backlog items

| Item | Delivered in the repository (Stage A) | Verified in | Stage B (cloud) |
|---|---|---|---|
| CM-T063 Provider selection | ADR-014; service-models section 8; shared-responsibility matrix | Review | Account owner approval of the plan |
| CM-T064 VM baseline | `cm-host-setup` (packages, Docker, SSH drop-in validated by `sshd -t`, timers, layout), `cm-firewall`, the provisioning runbook | Shell scripts exercised in CI where they apply | EV-17-01, EV-17-02, EV-19-01, EV-19-02 |
| CM-T065 Images and Compose | `infrastructure/docker/Dockerfile` (api, web, ops), `compose.cloud.yml`, `.dockerignore`, `cm-deploy` with rollback | CI linux/arm64 stack check (EV-17-06); local rehearsal | EV-17-03, EV-17-05 |
| CM-T066 Nginx, TLS, headers | `infrastructure/nginx/` (TLS, generated headers, rate limits, storage gateway), `cm-tls` | Edge checker in CI (EV-17-06) | EV-17-04, EV-19-12 |
| CM-T067 Database (self-hosted equivalent) | `infrastructure/postgres/`, `cm-pki` (CD-34), `cm-db-init`, `cm-migrate` | Database access rules in CI (EV-17-06) | EV-18-01, EV-18-02 |
| CM-T068 Object storage (self-hosted equivalent) | SeaweedFS service, `cm-secrets` identity, `cm-storage-init`, the Nginx storage gateway | Edge checker storage checks in CI (EV-17-06) | EV-18-03, EV-18-04, EV-18-05 |
| CM-T069 SSH, OS, firewall | `cm-host-setup`, `cm-firewall`, hardening checklist | | EV-19-01, EV-19-02, EV-19-03, EV-19-05 |
| CM-T070 Docker runtime | Daemon configuration, container hardening anchors | `docker inspect` excerpts in CI (EV-17-06) | EV-19-04 |
| CM-T071 Secrets | `cm-secrets`; secrets only as files (`resolveSecretFiles`, `/run/secrets`, uid 10001); migration password only from the workstation; no superuser password | `env.test.ts`; CI stack check | EV-19-06, EV-19-08 |
| CM-T072 Backups, restore, monitoring | `cm-backup` (age, CD-35), `cm-restore-drill`, `cm-restore`, `cm-status-collect`, `cm-worker-run`, systemd timers, measured platform status in the API and the Trust Center | CI backup, drill, full restore and browser decryption (EV-19-10); `status.test.ts`, dashboard tests | EV-19-07, EV-19-11 |

## 3. Code and tests

| Change | Files | Tests |
|---|---|---|
| API bundle with worker and CLI entry points | `apps/api/scripts/build.mjs` | Build, image smoke |
| Measured platform status | `apps/api/src/platform/status.ts`, `routes/admin.ts`, `app.ts`, `packages/shared/src/dashboard.ts`, `packages/validation/src/dashboard.ts` | `apps/api/src/platform/status.test.ts`, `tests/dashboard/security-dashboard.test.ts` (fresh, stale, degraded, unreadable status) |
| Configuration: status file, secrets from files | `apps/api/src/config/env.ts` | `apps/api/src/config/env.test.ts` |
| Trust Center live card and dashboard details | `apps/web/src/trust/platform-status.tsx`, `dashboard-view.tsx`, `app/trust/infrastructure/deployment-status.tsx` | `tests/e2e/trust-center.spec.ts` (restricted for visitors) |
| Deployment smoke and restore check | `playwright.deployment.config.ts`, `tests/deployment/` | Run by the CI stack check in three engines |
| External edge checks | `scripts/cloud/edge-check.mjs` | 41 checks in the CI stack check |
| CI | `.github/workflows/ci.yml` job "Cloud stack (linux/arm64)", `infrastructure/deployment/ci/stack-check.sh` | |

## 4. Findings

| ID | Severity | Where found | Fix |
|---|---|---|---|
| SF-17-01 | Low | First arm64 CI run: rehearsal TLS keys unreadable for Nginx (uid 101) | `cm-rehearsal` sets rehearsal file modes; the VM uses `cm-tls install` |
| SF-17-02 | Low | Review: `cm_psql_superuser` dropped psql options, so backup digests would have been formatted tables | Options passed through; the CI stack check compares manifests |
| (test artifact) | n/a | Local WebKit run: Playwright's screenshot injected a style element that the CSP blocked | The smoke test checks the CSP before taking its screenshot, with `caret: 'initial'` |

## 5. What is not done in Stage A

The cloud resources and all cloud evidence (EV-17-01 to EV-17-05, EV-17-07, EV-17-08, EV-18-01 to EV-18-05, EV-19-01 to EV-19-09, EV-19-11, EV-19-12); the live Trust Center status from the VM; Lynis and Docker Bench; the credential rotation record; MFA screenshots. EV-17-05 (served asset hashes against the release) has no tooling yet.
