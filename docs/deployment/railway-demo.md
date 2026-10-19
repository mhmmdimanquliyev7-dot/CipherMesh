# Railway trial demonstration (19 to 20 October 2026)

Status: a two-day demonstration on a Railway Free Trial, requested by the project owner for the
university Cloud Security presentation. It is **not** the ADR-014 deployment (Oracle Cloud stays
deferred and unverified), it runs only synthetic data, and the project is deleted afterwards.
Never present it as a production deployment.

## Services

| Railway service | Image | Notes |
|---|---|---|
| `web` | `infrastructure/docker/Dockerfile`, `CM_TARGET=web-railway` | The static client and security headers behind Railway's HTTPS edge; plain HTTP on `$PORT`; `/api` goes to `api.railway.internal:4100`. Only service with a public domain. |
| `api` | `CM_TARGET=api-railway` | Private network only. Writes the public database CA from `DB_CA_PEM_B64` at start. |
| `postgres` | `infrastructure/railway/postgres/Dockerfile` | The pinned PostgreSQL 17 image, TLS 1.3 only, a private CA signs its certificate, volume on `/var/lib/postgresql/data`. No TCP proxy. |
| Bucket `cm-files` | Railway Bucket (S3-compatible, Amsterdam) | Encrypted file blobs. Browsers reach it with presigned URLs on its own host (SF-07-01). CORS allows the web origin only (PUT, GET). |
| `db-init` (temporary) | `CM_TARGET=ops-railway` | One run of `infrastructure/railway/db-init.sh`: roles, migrations, then the superuser password is set to NULL. Deleted afterwards. |

## Differences from the ADR-014 stack (honest list)

- TLS to browsers ends at Railway's edge, not at our Nginx; the hop from the edge to `web` is
  plain HTTP inside Railway. Nginx rate limits use the visitor address from `X-Real-IP`, trusted
  only from Railway's proxy range `100.64.0.0/10`.
- The database hop is TLS 1.3 with `sslmode=verify-full` against a private CA created for this
  run (valid 5 days; the CA key was deleted after signing). HBA admits the database roles from any
  address because only services of this project reach the private network; ADR-014 used `samenet`.
- Secrets are Railway service variables (the platform stores them), not files under `/run/secrets`.
  The temporary `db-init` service holds the migration password and a temporary superuser password
  as variables; deleting the service removes them, and the job nulls the superuser password.
  ADR-014 keeps both off the VM; this is a deliberate, time-limited deviation.
- Containers are not read-only and do not drop capabilities (Railway controls the runtime).
- The worker is **not deployed**: expired content is still refused at read time (INV-14), but
  expired objects, abandoned rekey operations and retirement are not cleaned up, and the PC-14
  cryptoperiod is not enforced. The platform host status is NOT_VERIFIED.
- No backups, no restore drill, no host firewall or SSH hardening (Railway-managed).

## Operation

- Build and deploy: `railway up -s <service> -d` from the repository root with the variables above
  (no secret is in Git).
- Platform administrator: a temporary service built with `CM_TARGET=grant-railway` and the variable
  `CM_GRANT_EMAIL` runs `dist/platform-admin.js grant` once against the same database (the account
  needs MFA first, and every grant revokes its sessions); the service is deleted afterwards.
  `railway ssh` was not used because it needs an SSH key registered with the account.
- Delete everything after the demonstration: delete the project `ciphermesh-demo` (Dashboard,
  Project Settings, Danger, Delete Project). This removes services, volume and Bucket.

## Smoke test results (19 October 2026, Chromium, synthetic accounts)

Public URL: `https://web-production-b6156.up.railway.app` (Railway-issued certificate).

- `tests/deployment/cloud-smoke.spec.ts`: registration, login, vault, room, encrypted note and
  encrypted file upload and download through the Bucket (presigned URLs, CORS limited to the web
  origin): passed.
- `tests/deployment/collaboration.spec.ts`: invitation, burn secret, member removal and key
  rotation between two accounts: passed.
- Platform administrator (granted by a temporary one-off service, MFA enrolled first) signed in
  with a TOTP code and opened the ISMS Control Center and the Trust Center: passed.
- Not run: Firefox and WebKit, load tests, the full suites. Not deployed: the worker.

## What was and was not verified

Verified on 19 October 2026: the three smoke runs above, `GET /api/health` through the public
edge, the database migrations (13) applied over the verified TLS connection, presigned PUT and GET
and a browser preflight against the Bucket for the web origin, and the Content-Security-Policy
header of the web service naming the Bucket origin in `connect-src`.

Not verified, and not claimed:

- **Worker:** not deployed and never run on Railway.
- **Backup and restore:** none exist on Railway; the backup and restore tools of ADR-014 were not
  used and no restore drill was run. The data is synthetic and is deleted with the project.
- **Test suites:** the full Vitest, Playwright, negative-control and load suites were not run for
  this deployment. Only the deployment smoke specs listed above ran, in Chromium.
- **Firefox and WebKit** against Railway; **HSTS** is `max-age=0`; the browser-facing TLS
  configuration is Railway's and was not assessed.
- **Cost:** about $0.001 had accrued shortly after deployment; the total over the two days was not
  measured here. No hard usage limit was set (Railway's compute minimum is $10).
- This is not the Oracle Cloud deployment of ADR-014 and its evidence is not cloud evidence for
  controls that name the VM, the host firewall, backups or the worker.
