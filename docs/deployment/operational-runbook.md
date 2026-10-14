# Operational Runbook (Cloud Demonstration)

Status: procedures for the Oracle VM of [ADR-014](../architecture/adr/ADR-014-cloud-provider-oci-always-free.md). Every command runs on the VM as `ubuntu` with `sudo`, from `/srv/ciphermesh/release/infrastructure/deployment/bin`, unless stated otherwise. No procedure prints a secret, deletes a volume or a backup, or changes the OCI account. Related: [oracle-always-free.md](oracle-always-free.md), [backup-and-restore.md](backup-and-restore.md), [cloud-security-hardening.md](cloud-security-hardening.md).

## 1. Responsibilities

| Role | Person | Duties |
|---|---|---|
| Account owner | Project owner | OCI console (MFA), resource creation and deletion, DuckDNS account, cost checks |
| Operator | Project owner (with Claude Code over SSH when asked) | Deployments, backups, restore drills, certificate checks, credential rotation, evidence capture |
| Security reviewer | Project owner | SECURITY REVIEW in Jira; segregation of duties is limited in a one-person project (shared-responsibility.md section 5) |

## 2. Deploy a release

1. CI is green for the commit (including "Cloud stack (linux/arm64)").
2. `sudo ./cm-backup` (a fresh recovery point).
3. `sudo ./cm-deploy <40-hex commit>`: verifies the commit is on the origin, builds the images natively, refuses to start when the release brings migrations.
4. If it reports migrations: `sudo CM_RELEASE=<12-hex> CM_RELEASE_DIR=/srv/ciphermesh/release.new ./cm-migrate < /dev/stdin` (paste the migrator password, Ctrl-D), then rerun step 3.
5. From the workstation: the edge checker and the deployment smoke test (oracle-always-free.md section 7).
6. Record the deployment in Jira with the release (12-hex) and the evidence files.

## 3. Roll back

- **Code only (no migration since the previous release):** `sudo ./cm-deploy --rollback` switches to the previous release's images and runs the smoke check.
- **After a migration:** migrations are forward-only. Restore the backup taken in step 2 of section 2 onto an empty stack (backup-and-restore.md section 3) and deploy the previous commit.

## 4. Platform administrator

The account registers in the browser and enrolls MFA; then `sudo ./cm-platform-admin grant <email>`. Revoke with `revoke`. The CLI refuses an account without MFA and the removal of the last administrator, and revokes the account's sessions (CM-T022). No universal demonstration administrator exists, and no shared password is written anywhere.

## 5. Monitoring and routine checks

| Check | How | Frequency |
|---|---|---|
| Platform status (containers, disk, memory, certificates, firewall, worker, backup, drill) | Security dashboard as administrator; `systemctl list-timers 'ciphermesh-*'` | Daily, and before the demonstration |
| Status freshness | The dashboard marks a host status older than 15 minutes NOT_VERIFIED; then `systemctl status ciphermesh-status.service` | When shown |
| Certificates | `sudo ./cm-tls status`; renewal by certbot's timer | Weekly |
| External exposure | Edge checker from the workstation | After every change of the security list, firewall or Nginx |
| Disk | Dashboard (warning above 85 %); `docker system df` | Weekly |
| Backups | `ls -l /var/backups/ciphermesh`; copy the newest archive off the VM | Weekly |
| Restore drill | `cm-restore-drill` on the newest backup | Before the demonstration and monthly |
| OS updates | Unattended upgrades; `sudo reboot` when `/var/run/reboot-required` exists (the stack restarts by itself) | Weekly |
| Image rebuilds | `cm-deploy` of the current commit picks up rebuilt bases only when their digests are updated in Git | Monthly, through a pull request |
| Cost | OCI Billing & Cost Management: no charges | Weekly |

## 6. Credential rotation (EV-19-06)

| Credential | Procedure |
|---|---|
| `cm_api` or `cm_worker` password | Generate a new value; `ALTER ROLE ... PASSWORD` through `cm_psql_superuser` with statement logging off (as `cm-db-init` does); update the URL in `api.env` or `worker.env`; `cm-deploy <current commit>` to recreate the containers |
| Migration password | On the workstation: new value; on the VM: `ALTER ROLE cm_migrator PASSWORD ...` through `cm_psql_superuser`; update the password manager |
| Storage runtime key | Generate a new pair; update `seaweedfs-identities.json`, `api.env`, `worker.env`; recreate `object-storage`, `api`; outstanding presigned URLs stop working |
| TOTP encryption key | Not rotated in place: stored TOTP secrets are encrypted with it (CP-11); a rotation needs re-enrollment and is out of scope for the demonstration |
| Database CA | `sudo ./cm-pki --renew`, then recreate `postgres`, `api` (before day 397) |
| TLS certificates | Automatic (certbot); manual: `sudo certbot renew` |
| Backup identity | New `age-keygen` on the workstation; update `CM_BACKUP_RECIPIENT`; keep the old identity for older backups |
| SSH key | Add the new public key to `~ubuntu/.ssh/authorized_keys`, log in with it in a second session, then remove the old key |

## 7. Incidents

| Situation | First actions |
|---|---|
| Suspected VM compromise (T-19, T-42) | Do not destroy evidence; snapshot nothing paid; stop public access in the security list (remove 80 and 443); copy the newest backup off the VM; rotate every credential of section 6 from a new VM after a restore; members follow the compromised-identity runbook if keys may be affected |
| Certificate expired | `sudo certbot renew`, `sudo ./cm-tls install`; check DuckDNS records |
| Disk full | `docker system df`; `docker image prune` removes only dangling images (never volumes); old backups beyond retention |
| VM reclaimed or lost (T-43) | New VM from oracle-always-free.md, then `cm-restore` from the off-VM backup |
| Unexpected charge | Stop: identify and terminate the resource, report to the project owner |

## 8. Demonstration checklist

Before the demonstration (the day before and one hour before):

- [ ] Dashboard: every component HEALTHY, measured within the last minutes; certificates valid for more than 14 days
- [ ] `cm-restore-drill` on the newest backup passed today; the result shows on the dashboard
- [ ] Edge checker from the workstation: all PASS (save the output as evidence)
- [ ] Deployment smoke test in three engines: PASS
- [ ] Two synthetic demonstration accounts exist (created in the browser; passwords and Vault Passphrases kept by the presenter, never on screen); one is a platform administrator with MFA
- [ ] Browser: the padlock shows a Let's Encrypt certificate for both host names, no warning
- [ ] Nothing on screen shows the public IP, OCIDs, the operator's address, secrets or passwords

During the demonstration follow [../report/live-demo-guide.md](../report/live-demo-guide.md) (Scenarios A to D).
