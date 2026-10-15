# Local Docker Demonstration

Status: the deployment priority since 2026-10-14 (project owner): a complete $0 demonstration on a Windows laptop with Docker Desktop. The Oracle Cloud deployment of [ADR-014](../architecture/adr/ADR-014-cloud-provider-oci-always-free.md) stays prepared ([oracle-always-free.md](oracle-always-free.md)) and is not provisioned. Related: [cloud-security-hardening.md](cloud-security-hardening.md), [backup-and-restore.md](backup-and-restore.md), [../report/live-demo-guide.md](../report/live-demo-guide.md).

## 1. What it is, and what it is not

It **is** the production stack of the cloud design, unchanged: the same three images, `compose.cloud.yml` with its four Docker networks, Nginx with TLS and the generated security headers, PostgreSQL with TLS 1.3 for the runtime roles and no superuser password, SeaweedFS reachable only through Nginx on a second host name, secrets as files, the same operator scripts, encrypted backups and restores, and the measured platform status. Browsers do all content cryptography exactly as in the cloud: files go to storage through presigned URLs on another host name (SF-07-01).

It is **not** a cloud deployment. Everything listens on 127.0.0.1; the certificates come from a throwaway local CA; there is no provider firewall, no public TLS, no SSH hardening, no cloud account and no instance metadata. The application says "Local Docker demonstration", the dashboard shows the cloud as **Not connected** ("The host reported no cloud instance metadata"), and no cloud control is marked verified by this demonstration (L-80).

## 2. Requirements

Windows 10 or 11 with Docker Desktop (WSL 2 backend, about 6 GB of memory for Docker), Git for Windows (Git Bash), Node.js 24 and pnpm 12 (`pnpm install` once). About 6 GB of disk for the images. Ports 8080 and 8443 on 127.0.0.1 must be free.

## 3. One command

```bash
pnpm install          # once
pnpm demo:up          # builds the images the first time (several minutes), then starts the stack
```

Open **https://app.localhost:8443**. The storage host is https://files.localhost:8443 (no page of its own). Stop with `pnpm demo:down` (data is kept); `node scripts/demo.mjs destroy` also deletes the demonstration data.

| Command | What it does |
|---|---|
| `pnpm demo:up` | Builds missing images, creates the local CA and certificates, the database CA, the runtime secrets, initializes PostgreSQL (roles, migrations as `cm_migrator`), creates the bucket, starts the stack, collects the status |
| `pnpm demo:build` | Rebuilds the three images (after a code change) |
| `pnpm demo:health` | Container states, then the 39 external edge checks against the running stack (TLS, headers, `/api/health` and `/api/ready`, storage refusals, closed internal ports) |
| `pnpm demo:status` | Collects the measured host status for the dashboard. The API treats a status older than 15 minutes as Not verified: run it again before showing the dashboard |
| `pnpm demo:admin <email>` | Grants the platform administrator role to a registered account that has turned on two-step sign-in |
| `pnpm demo:worker` | Runs the retention worker once (expiry, cleanup, rekey maintenance) |
| `pnpm demo:backup` | Encrypted backup (age) of the database, the storage volume and the secrets into `~/.ciphermesh-rehearsal/backups` |
| `pnpm demo:drill` | Restore drill of the newest backup into isolated containers: every table digest and every file's ciphertext SHA-256 compared |
| `node scripts/demo.mjs restore` | Full restore of the newest backup, only onto an empty stack (after `node scripts/demo.mjs destroy`): database, storage and secrets, then every table digest and file object compared. `demo:verify` uses it |
| `pnpm demo:verify [dir]` | The full verification of section 6, with evidence files (default `test-results/local-demo-evidence`) |

The work directory `~/.ciphermesh-rehearsal` (outside the repository) holds the demonstration's throwaway secrets, migrator password and backup key. They protect synthetic data only and are never used anywhere else.

### Command sheet for a live session

| Goal | Command or address (tested 2026-10-15 on Windows 11 with Docker Desktop) |
|---|---|
| Start (data kept from the last session) | `pnpm demo:up` (about a minute when the images exist) |
| Check health | `pnpm demo:health`: four containers `(healthy)` and `39 passed, 0 failed` |
| Open the application | https://app.localhost:8443 (Chrome, Edge or Firefox) |
| Trust Center | https://app.localhost:8443/trust (public pages; the live deployment card needs the administrator) |
| Administrator view (dashboard, live card) | Register an account, turn on two-step sign-in under Account, `pnpm demo:admin <email>`, sign out and in with the code, then https://app.localhost:8443/trust/dashboard (security dashboard) and https://app.localhost:8443/trust/infrastructure (live deployment card); for other accounts the API answers 404 and no live data is shown. Run `pnpm demo:status` within 15 minutes before showing it |
| Encrypted backup | `pnpm demo:backup` (archive and manifest in `~/.ciphermesh-rehearsal/backups`) |
| Safe restore drill | `pnpm demo:drill`: isolated containers, the running stack is not touched |
| Full verification (before, never during, a session) | `pnpm demo:verify` (about 17 minutes; it deletes and restores the demonstration volumes) |
| Stop without data loss | `pnpm demo:down` (the volumes stay; never use `destroy` before a session) |

## 4. A browser without certificate warnings (optional)

The local CA is limited by name constraints to `localhost` names, valid for 30 days, and its private key was deleted after the two certificates were signed, so trusting it cannot make any other site trusted. To trust it for your Windows user only:

```powershell
certutil -user -addstore Root $env:USERPROFILE\.ciphermesh-rehearsal\rehearsal-ca.crt
```

Firefox uses its own store: Settings, Privacy & Security, Certificates, View Certificates, Authorities, Import. Remove it after the demonstration with `certutil -user -delstore Root "CipherMesh local demonstration CA (localhost only)"`. Without this step, accept the browser warning once per host name (open https://files.localhost:8443 once as well, or uploads fail).

## 5. Demonstration accounts

Create synthetic accounts in the browser (`@example.test` addresses). For the security dashboard and the live deployment card: register a third account, turn on two-step sign-in under Account, run `pnpm demo:admin <email>`, sign out and in again with the code. No shared or hard-coded administrator exists.

## 6. Verification (`pnpm demo:verify`)

`infrastructure/deployment/ci/stack-check.sh`, the same script CI runs on linux/arm64. It records:

| Check | Evidence file |
|---|---|
| Image architectures and sizes; pinned base images | `images.txt` |
| Containers: user, read-only root, capabilities, security options, memory, published ports; secret files and environment variable names (no secret is an environment variable); the four networks and which are internal | `container-hardening.txt`, `containers.txt` |
| Edge: TLS 1.3, TLS 1.0 and 1.1 refused, unknown names refused, HTTP redirect, CSP and headers, dotfiles and source maps refused, cross-site POST refused, storage paths, listing, forged signatures and cookies refused, internal ports closed | `edge-check.txt`, `edge-check.json` |
| Database: non-TLS login refused by `pg_hba`, superuser network login refused, the API's sessions on TLS 1.3, no superuser password, storage unreachable from the database network | `database-access.txt` |
| Browsers (Chromium, Firefox, WebKit): vault, room, encrypted note and file round trip with no plaintext in any request and no cookie to storage; invitation, burn secret revealed once, removal, key rotation to version 2, removed member locked out | `browser-tests.txt` |
| Worker run and measured status | `host-status.json` |
| Encrypted backup, no plaintext canary in the archive | `backup.txt`, `backup-manifest.json` |
| Restore drill: tables and file objects identical | `restore-drill.txt` |
| Screenshots: vault, room with receipts, Trust Center live card, dashboard, governance | `screenshots/` |
| Full restore onto empty volumes, then the recorded accounts decrypt their note and file again | `restore.txt`, `restore-verify.txt` |

The full restore deletes the demonstration volumes and rebuilds them from the backup it just took; the data comes back identical (the restore checks every table digest), but run `demo:verify` before, not during, a live session.

## 7. Local versus cloud

| Control | Local Docker demonstration | Oracle Cloud |
|---|---|---|
| Client-side encryption, presigned storage path, CSP | Verified (browser tests) | Same code; verified on the VM when deployed |
| Container isolation, internal networks, secrets as files | Verified (`container-hardening.txt`) | Same Compose file; evidence EV-17-03 on the VM |
| Database TLS and access rules | Verified (`database-access.txt`) | EV-18-01, EV-18-02 on the VM |
| Storage gateway refusals | Verified (edge checks) | EV-18-04 on the VM |
| TLS configuration | Verified with the local CA | Public certificate, EV-17-04 |
| Backup, drill, full restore | Verified | EV-19-07 on the VM |
| Provider firewall, host firewall, SSH hardening, public exposure scan, Lynis, Docker Bench, console MFA | **Not applicable locally; not verified** | EV-17-02, EV-19-01 to EV-19-05, EV-19-08 |
| Cost classification, instance metadata | **Not applicable locally** | EV-17-01, EV-17-07 |

## 8. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| First `demo:up` takes long | The images are built once (dependencies, Next.js build); later starts take about a minute |
| Uploads fail in the browser | The browser has not accepted the storage host's certificate: open https://files.localhost:8443 once, or trust the CA (section 4) |
| "Too many requests" after many sign-ins | Nginx's per-address limit for authentication (10 per minute) applies to the laptop too; wait a minute |
| Dashboard shows the cloud and worker "Not verified" | The status is older than 15 minutes: `pnpm demo:status` (and `pnpm demo:worker`) |
| Port 8443 in use | Another program uses it; stop it or change `CM_HTTPS_PORT` and the origins in `~/.ciphermesh-rehearsal/cloud.env` (and rebuild the web image for the storage origin) |
