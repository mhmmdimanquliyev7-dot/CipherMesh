# Backup and Restore

Status: implemented and tested end to end in the CI stack check on linux/arm64 (EV-19-10); the drill on the deployed VM is EV-19-07. Related: [ADR-014](../architecture/adr/ADR-014-cloud-provider-oci-always-free.md), [operational-runbook.md](operational-runbook.md), crypto decisions LIB-10 and CD-35, limitations L-72, L-74, L-77, threat T-43.

## 1. What a backup contains

`cm-backup` (daily at 03:30 UTC through `ciphermesh-backup.timer`, or on demand) writes `/var/backups/ciphermesh/ciphermesh-<UTC stamp>.tar.age` and a plain `.manifest.json` next to it.

| Part | Content | Why |
|---|---|---|
| `db.dump` | `pg_dump --format=custom --no-owner` of the `ciphermesh` database (schema, migrations table, data) | Accounts, rooms, memberships, envelopes, wrapped keys, note and secret ciphertext, file metadata |
| `tables.txt` | Row count and SHA-256 digest of every table (`lib/table-digests.sql`) | Proves a restore is identical, without reading content |
| `object-storage.tar` | The SeaweedFS data volume | File ciphertext |
| `secrets.tar` | The runtime secret files and `cloud.env` | The TOTP key decrypts the stored TOTP secrets and is not in the database by design; the storage identity |
| `meta.json` | Time, release, sizes | |

The archive is encrypted with **age** to `CM_BACKUP_RECIPIENT` (an X25519 public key). The matching identity (private key) stays offline with the operator, so the VM can write backups but cannot read them, and a copied backup is unreadable without the identity (CD-35). The plaintext staging exists only in a tmpfs directory during the run.

**Consistency:** the API and the object storage are stopped for the seconds of the dump and the volume copy, so the database and the objects match (L-77). **Retention on the VM:** 7 days, never fewer than the newest three. **Off-VM copy:** the operator copies the archive and its manifest to the workstation (`scp`); it stays encrypted there. A Docker volume is not a backup, and the VM is not highly available (L-72, L-73).

## 2. Restore drill (does not touch the live system)

```bash
sudo /srv/ciphermesh/release/infrastructure/deployment/bin/cm-restore-drill \
  /var/backups/ciphermesh/ciphermesh-<stamp>.tar.age < ciphermesh-backup.key   # identity piped from the workstation
```

1. Decrypts the archive into a tmpfs directory with the identity given on standard input.
2. Starts a disposable PostgreSQL and SeaweedFS on an isolated internal Docker network (`ciphermesh-drill`) with their own volumes.
3. Restores the dump and compares the digest of **every table** with the manifest: users, rooms, memberships, key versions and envelopes, wrapped DEKs, note and secret ciphertext.
4. Restores the storage volume and, with `lib/verify-objects.mjs`, fetches every AVAILABLE file object and compares its size and SHA-256 with `ciphertext_size` and `ciphertext_sha256` recorded at upload.
5. Writes the verdict to `/var/lib/ciphermesh/status/restore-drill.json` (shown on the dashboard) and removes the drill containers, volumes and network (`--keep` leaves them for inspection).

Identical ciphertext under identical wrapped keys is exactly what the members' browsers decrypt; the drill holds no key and decrypts nothing.

## 3. Full restore onto an empty stack (lost or rebuilt VM)

```bash
# On a new VM after cm-host-setup, cm-firewall and the release (oracle-always-free.md section 5),
# with the backup copied back from the workstation:
{ cat migrator-password.txt; cat ciphermesh-backup.key; } \
  | ssh ubuntu@<vm> sudo /srv/ciphermesh/release/infrastructure/deployment/bin/cm-restore /var/backups/ciphermesh/ciphermesh-<stamp>.tar.age
```

`cm-restore` refuses to run while live data volumes exist. It restores the runtime secrets (existing ones must be identical), creates the database CA, initializes PostgreSQL without migrations (`cm-db-init --roles-only`), restores the dump, checks every table digest against the manifest, restores the storage volume, starts the stack and checks every file object. Afterwards an account that existed at backup time signs in, unlocks its vault and decrypts its notes and files: the CI stack check does exactly this in Chromium, Firefox and WebKit (`tests/deployment/restore-verify.spec.ts`, EV-19-10).

**Never** restore over a running system to "prove" a backup: use the drill.

## 4. Results

| Date | Where | Backup | Tables identical | Objects matched | Browser decryption after restore | Evidence |
|---|---|---|---|---|---|---|
| 2026-10-14 | CI, linux/arm64 rehearsal | Created by the stack check | Recorded in the artifact | Recorded in the artifact | Chromium, Firefox, WebKit | EV-19-10 |
| | Oracle VM | | | | | EV-19-07 |

## 5. Limits

Recovery point up to 24 hours; recovery time about one hour on a new VM; no point-in-time recovery; no object versioning; a backup taken after an undetected compromise of the VM contains whatever the attacker left (L-71, L-72, L-74).
