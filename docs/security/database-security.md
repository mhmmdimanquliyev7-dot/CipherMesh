# Database Security (Phase 2)

Status: implemented in Phase 2 (CM-T013, CM-T014), awaiting project owner approval. Normative for every later phase that touches PostgreSQL. Related: [../architecture/data-model.md](../architecture/data-model.md), [../architecture/trust-boundaries.md](../architecture/trust-boundaries.md) (TB-05), [../threat-model/threat-model.md](../threat-model/threat-model.md), [limitations.md](limitations.md).

The database is treated as a security boundary, not as trusted storage. The design goal is that a full copy of the database reveals metadata but no content, keys or passwords, and that a compromised API process cannot rewrite the schema, the audit table or its own privileges.

## 1. Components

| Part | Location | Purpose |
|---|---|---|
| Prisma schema | `prisma/schema.prisma` | Schema v1. Every stored field carries a `/// class:` comment with its data-model classification |
| Migrations | `prisma/migrations/` | `20261002000000_schema_v1` (generated, reviewed), `..._integrity_constraints`, `..._audit_append_only`, `..._runtime_role_grants` (hand-written, reviewed) |
| Prisma CLI config | `prisma.config.ts` | Uses `MIGRATION_DATABASE_URL`; the runtime never reads it |
| CLI wrapper | `scripts/db/prisma.mjs` | Allowlist of Prisma commands; telemetry off |
| Provisioning | `scripts/db/bootstrap.mjs`, `scripts/db/lib.mjs` | Local roles and database (`pnpm db:bootstrap`) |
| Forbidden-field checker | `scripts/db/check-schema.mjs` | `pnpm db:check-schema` (EV-02-01) |
| Drift check | `scripts/db/check-drift.mjs` | `pnpm db:drift` |
| Synthetic seed | `scripts/db/seed.ts`, `scripts/db/synthetic.ts` | `pnpm db:seed` |
| API database module | `apps/api/src/db/client.ts` | The only place in the API that may import Prisma or `pg` (ESLint) |
| Tests | `tests/database/`, `tests/security/schema-forbidden-fields.test.ts` | Section 9 |

## 2. Roles and least privilege (CM-T014)

| Role | Used by | Attributes | Where its credential lives |
|---|---|---|---|
| `cm_migrator` | `prisma migrate deploy` only | LOGIN; owns the database, the `public` schema and every object; NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOBYPASSRLS, NOINHERIT | Developer machine (local) or the deployment pipeline. **Never on the VM** (TB-05, CLAUDE.md section 8) |
| `cm_api` | API process | LOGIN; the grants below only; `statement_timeout` 15 s, `idle_in_transaction_session_timeout` 30 s; connection limit 40 | VM secret file (Phase 17), `.env` locally |
| `cm_worker` | Worker process (Phase 12 and later) | As `cm_api`, other grants; connection limit 10 | VM secret file mounted only into the worker |
| `cm_verifier` | Audit verification (Phase 12) | SELECT on `audit_events` only; connection limit 5 | Verifier environment |

Common to all runtime roles: no ownership of any object, no CREATE on the schema or database, no TEMP, no TRUNCATE, REFERENCES or TRIGGER privilege, no column-level grants, no membership in other roles (including predefined roles such as `pg_write_all_data`). `PUBLIC` holds nothing on the database, the schema or any table.

The API configuration accepts only `cm_api` as the `DATABASE_URL` user (`apps/api/src/config/env.ts`), so the API cannot be pointed at the migration role or an administrator by mistake.

### 2.1 Grant matrix

S = SELECT, I = INSERT, U = UPDATE, D = DELETE. Source of truth: `prisma/migrations/20261002000300_runtime_role_grants/migration.sql`. An independent copy in `tests/database/privileges.test.ts` fails CI on any extra or missing privilege.

| Table | cm_api | cm_worker | cm_verifier | Why DELETE where granted |
|---|---|---|---|---|
| users | S I U | | | Tombstones only |
| recovery_codes | S I U D | | | Regeneration replaces the set |
| sessions | S I U | S D | | Worker deletes 30 days after expiry |
| auth_challenges (Phase 3) | S I U | S D | | Worker deletes one day after expiry |
| login_attempts | S I | S D | | 90-day retention |
| user_key_pairs | S I U | | | Tombstones (private key set to NULL) |
| rooms | S I U | S U | | Tombstones |
| room_members | S I U | S | | Rows kept for audit |
| invitations | S I U | S U | | Rows kept |
| room_key_versions | S I U | S U | | Rows kept with commitment |
| rekey_operations | S I U | S U D | | Worker purges 90 days after closing |
| key_envelopes | S I U D | S D | | Envelopes are deleted, never tombstoned |
| encrypted_files | S I U | S U | | Tombstones (wrapped FEK and manifest set to NULL) |
| encrypted_notes | S I U | S U | | Tombstones |
| secrets | S I U | S U | | Tombstones |
| audit_events | S I | S I | S | Never (INV-09) |
| _prisma_migrations | | | | Owned by `cm_migrator` |

The worker grants follow the deferred effects in data-model section 5. They are reviewed again when the worker is implemented (Phase 12); any change is a migration plus an update of the test matrix.

### 2.2 Local roles are not cloud IAM

Locally, `POSTGRES_USER` is the container's superuser and creates the roles. In the managed cloud database (CM-T067, Phase 18), the provider's administrator account is not a true superuser, and provider IAM controls who can reach or reconfigure the instance. The runbook creates the same four roles with the same attributes; the grant migration then applies unchanged. Nothing here claims that a local PostgreSQL role is an identity-provider control.

## 3. Connection security

| Rule | Where enforced |
|---|---|
| `DATABASE_URL` must connect as `cm_api` and include a password | `apps/api/src/config/env.ts`, startup fails otherwise |
| Production requires `sslmode=verify-full` (certificate and host-name verification, CP-21). `require` and `verify-ca` are rejected | Same; `tests/security/startup-config.test.ts`, `env.test.ts` |
| Outside production, a connection without `verify-full` is allowed only to a loopback host | Same |
| The connection string is held in a `SecretValue` that prints `[REDACTED]` in JSON, `String()` and `util.inspect` | `apps/api/src/config/secret.ts` |
| The logger redacts `databaseUrl`, `connectionString`, `dsn`, any key ending in `databaseurl`, and any URL with a password in its user info | `apps/api/src/logging/redact.ts`, tests in `redact.test.ts` |
| No query logging; database errors are logged by class and code only, never by message, in the database module and in the central error handler. Prisma validation errors quote query arguments, which a test proves with a canary | `apps/api/src/db/client.ts`, `apps/api/src/db/errors.ts`, `apps/api/src/http/errors.ts`; `tests/database/client.test.ts` |
| Configuration errors name the variable and the problem, never the value | `ConfigError` |
| `DATABASE_URL` is parsed in one place in the API; tooling parses role URLs only in `scripts/db/lib.mjs` | ESLint forbids `process.env` outside the config module |
| Readiness answers a status word only; why the database is unreachable goes to the log | `GET /api/ready` |

The development container has no TLS: it listens on 127.0.0.1 only, which is why the loopback exception exists. Production TLS requirements are not weakened by it.

## 4. Integrity constraints

Prisma expresses the tables, enums, foreign keys and partial unique indexes. The hand-written migration `..._integrity_constraints` adds 116 CHECK constraints and two write-once triggers (the audit migration adds two more triggers). Highlights:

| Rule | Mechanism | Data model |
|---|---|---|
| One ACTIVE key pair per user; one ACTIVE OWNER per room; one current membership per user and room; one ACTIVE key version per room; one PENDING rekey operation per room; one open invitation per invitee and room | Partial unique indexes (`partialIndexes` preview feature) | 4.5 to 4.9.1 |
| An envelope, secret or invitation key belongs to the named user | Composite foreign key `(key_id, user_id)` to `user_key_pairs(id, user_id)` | 4.8, 4.10, 4.13 |
| Envelopes, files and notes reference an existing key version of the same room | Composite foreign key `(room_id, key_version)` to `room_key_versions(room_id, version)` | 4.10 to 4.12 |
| Memberships and envelopes reference invitations of the same room | Composite foreign key `(invitation_id, room_id)` | 4.7, 4.10 |
| Only Argon2id PHC strings in `password_hash` | `starts_with(password_hash, '$argon2id$v=19$')` | INV-11 |
| RSA-OAEP envelopes and wrapped SEKs are exactly 384 bytes; wrapped DEKs 48 bytes; IVs 12; digests 32; SPKI 422; salt 16 | Length checks | INV-17, CP-01, CP-02 |
| Vault KDF parameters meet the Argon2id floor | `kdf_memory_kib >= 19456 AND kdf_iterations >= 2 AND kdf_parallelism >= 1` | CP-04 |
| Only `CM1` and `RSA-OAEP-3072-SHA256` | Equality checks | CP-18 |
| Deleting a file, note or secret removes wrapped keys and ciphertext together | Status and NULL consistency checks | Section 5, INV-13 |
| A locked room always carries its rekey reasons, an ACTIVE room none | `rooms_key_state_reasons_check` | INV-07, ADR-013 |
| A rekey targets exactly the next version | `target_version = base_version + 1` | ADR-013 |
| The invitation approver is never the inviter | `approved_by_id <> invited_by_id` | 4.8 |
| OWNER cannot be granted by invitation | Separate `InvitationRole` enum | 4.8 |
| A login attempt stores exactly one of account ID or 32-byte identifier HMAC | `num_nonnulls(...) = 1` | 4.4 |
| Identifiers are UUIDv4 | Format check on every primary key | Principle 6 |
| Files at most 50 MiB of plaintext | `ciphertext_size BETWEEN 16 AND 52428816` | CP-19 |
| Public identity keys and key-version commitments are write-once | `BEFORE UPDATE` triggers | 4.5, 4.9, T-25, T-36 |
| No cascading deletes | Every foreign key is `ON DELETE RESTRICT`, except the purge of closed rekey operations (`SET NULL`) | Section 5 |

Constraints are a second layer behind API validation. They do not know whether a 384-byte value really is an RSA-OAEP ciphertext; they only make a whole class of mistakes (plaintext in a ciphertext column, a missing tombstone step) impossible to store.

## 5. Append-only audit table

| Layer | Implemented now | Test |
|---|---|---|
| Grants: runtime roles hold SELECT and INSERT only | Yes | `audit.test.ts`: UPDATE, DELETE, TRUNCATE as `cm_api` fail with `permission denied` |
| Triggers reject UPDATE, DELETE (row level) and TRUNCATE (statement level) for every role, including the owner | Yes | `audit.test.ts`: the owner is refused; a deliberately wrong grant to `cm_api` is still refused |
| No foreign keys, so audit rows outlive the records they describe | Yes | Schema |
| SHA-256 hash chain, chain head, signed checkpoints, verifier | **No, Phase 12** (ADR-009, CM-T054 to CM-T058). The `prev_hash`, `event_hash` and `hash_version` columns exist; nothing computes or verifies them yet | |

Limit: the table owner (`cm_migrator`) or a superuser can disable the trigger or drop the table. The test suite demonstrates this deliberately. That is why the ledger is described as tamper-evident once Phase 12 adds the hash chain and external checkpoints, and why the migration credential never lives on the VM. Nothing in this phase makes the audit table tamper-proof.

## 6. What an attacker learns from a stolen database

The question for T-01: what damage follows if an attacker copies the entire PostgreSQL database (a leaked backup, a stolen `cm_api` credential with network access, or a provider-side exposure)?

| Data | Stored as | What the attacker gets | What stays protected |
|---|---|---|---|
| Account email, display name | Plaintext (PII) | Who uses the system | |
| Password | Argon2id PHC hash (DIG) | Offline guessing of weak passwords (T-03); a cracked password yields a login, not plaintext | Strong passwords; the vault, which uses a separate passphrase |
| TOTP secret | AES-256-GCM under a key held outside the database (SENC) | Nothing without the server key file | TOTP secrets |
| Session tokens, recovery codes | SHA-256 digests of 256-bit and 100-bit random values (DIG) | Nothing usable: the values cannot be recovered from digests of high-entropy secrets | Sessions, recovery codes |
| Login attempts | Account ID or identifier HMAC, IP address, user agent | Login timing and source addresses for 90 days | Unknown identifiers (keyed HMAC) |
| Identity private keys | AES-256-GCM under PKWK, derived in the browser from the Vault Passphrase with Argon2id (CT) | Offline guessing of weak Vault Passphrases (T-22, L-08), at Argon2id cost per guess | Strong passphrases; no server-side verifier exists to speed up guessing |
| Public keys and fingerprints | Plaintext (PUBK, INT) | Nothing secret | |
| Room names, profiles, membership, roles, key versions, timestamps | Plaintext (META) | The social graph and activity metadata (L-05, T-28) | |
| Room key material | Only RSA-OAEP-3072 envelopes per member key (WK) | Nothing without a member's private key | Every room key |
| Key-version commitments | HKDF output (INT) | Nothing about the key: HKDF output does not reveal its input | |
| Files | Database: wrapped FEK, encrypted manifest, size, SHA-256 of ciphertext. Bytes: object storage only | Approximate file sizes and upload times | Content, filename, MIME type, plaintext hash (INV-16) |
| Notes, secrets | Ciphertext and wrapped DEK or SEK | Sizes and timing | Content |
| Audit events | Plaintext metadata, no IP addresses or secrets | Who did what and when | |

Conclusion: a full database copy is a serious metadata and offline-guessing exposure, not a content exposure. The residual damage is concentrated in weak passwords, weak Vault Passphrases and metadata, which is consistent with T-01's residual rating of Medium. Backups contain the same data for their retention period (L-12).

## 7. Index review

| Index | Query it serves | Notes |
|---|---|---|
| `room_members_one_current_membership (room_id, user_id)` partial | Authorization lookup for every room-scoped request (INV-06) | Also enforces uniqueness |
| `room_members (user_id, status)`, `(room_id, status)` | "My rooms", member lists | |
| `key_envelopes (room_id, recipient_user_id)` | Envelope fetch for the caller; envelope deletion on removal | Every envelope query filters by room and recipient |
| `key_envelopes (room_id, key_version, recipient_key_id)` unique | Duplicate prevention | |
| `encrypted_files (room_id, status, created_at)`, `encrypted_notes (room_id, updated_at)`, `secrets (room_id, recipient_user_id, status)` | Room-scoped listings | Room ID first (OL-02) |
| Partial expiry indexes on files, notes, secrets and invitations | Worker sweeps of live rows only | Expiry is still enforced at read time (INV-14) |
| `sessions (user_id, absolute_expires_at)`, `sessions (absolute_expires_at)` | Session list and the 10-session limit; cleanup | |
| `login_attempts (user_id, occurred_at)`, `(identifier_hmac, occurred_at)`, `(occurred_at)` | Rate limiting; 90-day sweep | |
| `rekey_operations_pending_lease_idx` partial, `rekey_operations (closed_at)` | Abandoned-lease sweep; 90-day purge | |
| `audit_events (room_id, seq)`, `(actor_user_id, seq)`, `(occurred_at)` | Room audit view, per-user view, time ranges | |
| Indexes on foreign-key columns (`created_by_id`, `uploader_id`, `author_id`, ...) | Restrict checks on referenced rows | |

No index exists on any ciphertext or wrapped-key column. Indexes on plaintext-derived values would leak equality; none exist because no such values are stored.

## 8. Retention fields

| Table | Field | Rule (data-model section 5) | Enforced by |
|---|---|---|---|
| sessions | `absolute_expires_at`, `revoked_at` | Deleted 30 days after expiry | Worker (Phase 12); grant exists |
| login_attempts | `occurred_at` | Deleted after 90 days | Worker; grant exists |
| rekey_operations | `closed_at` | Deleted 90 days after closing | Worker; FK sets the version's operation reference to NULL |
| encrypted_files, encrypted_notes, secrets, invitations | `expires_at` | Refused at read time; wrapped keys and ciphertext set to NULL | API read path (INV-14) and worker |
| users, rooms | `deleted_at` | Tombstones | API |
| user_key_pairs | `superseded_at`, `revoked_at` | Private key set to NULL | API; CHECK constraint |

Phase 3 added the first retention job, `pnpm worker:retention` (`apps/api/src/db/retention.ts`), which runs as `cm_worker` and deletes sessions 30 days after they ended, pre-authentication states one day after expiry and login attempts after 90 days (`tests/database/retention.test.ts`, which also shows that the API role cannot run it). Scheduling arrives with the worker container.

## 9. Tests

| Suite | What it proves |
|---|---|
| `tests/database/migrations.test.ts` | Migrations apply from an empty database, are idempotent, leave no drift; every live column is declared and classified; drift detection fails when an index is removed outside migrations (negative control) |
| `tests/database/constraints.test.ts` | Partial uniques, composite foreign keys, CHECK constraints and write-once triggers, each asserted by SQLSTATE, as the API role |
| `tests/database/audit.test.ts` | Grant layer and trigger layer of the append-only table, including misconfigured grants; documents the owner's ability to disable the trigger |
| `tests/database/privileges.test.ts` | Role attributes, ownership, the exact grant matrix, no PUBLIC privileges, and what the API role cannot do (DDL, TRUNCATE, role creation, privilege escalation) |
| `tests/database/deletion.test.ts` | No cascades; member removal in one transaction; worker retention deletes |
| `tests/database/client.test.ts` | Lazy connection as `cm_api`, readiness with a real and an unreachable database, no query logs, no row values or URLs in errors and logs, including an unhandled Prisma validation error that quotes a canary |
| `tests/database/seed.test.ts` | Seed is synthetic, idempotent, refuses production, remote hosts and other roles |
| `tests/security/schema-forbidden-fields.test.ts` | The forbidden-field checker passes the real schema and fails on 33 negative controls |
| `apps/api/src/config/env.test.ts`, `tests/security/startup-config.test.ts` | Database URL rules; values never echoed |

## 10. Tooling hazards found in this phase

- **Silent Prisma CLI failure.** `prisma migrate diff` exits 0 with empty output when the schema engine cannot start (for example without a datasource). `pnpm db:drift` therefore requires the explicit "No difference detected." message, and `tests/database/migrations.test.ts` includes a failing negative control.
- **Partial-index predicates and drift.** PostgreSQL rewrites `IN (...)` predicates to `= ANY (ARRAY[...])`, which Prisma 7.10 reports as drift. The schema uses `OR` predicates instead.
- **Telemetry.** The Prisma CLI contacts Prisma's checkpoint service by default. The wrapper sets `CHECKPOINT_DISABLE=1`.
- **Schema engine download.** With install scripts blocked, the CLI downloads its schema engine on first use from `binaries.prisma.sh` with checksum verification. Recorded in the engineering baseline as a supply-chain dependency (T-27).

## 11. Correction recorded in Phase 3

The Phase 2 record stated that `apps/api/src/logging/redact.test.ts` tested the redaction of URLs carrying credentials. The redaction rule existed, but the test had not been written: the scripted edit that should have added it did not match its anchor and changed nothing, and the gap was not noticed because the other tests passed. The test was added in Phase 3 (`redacts URLs that carry credentials`), and later scripted edits check that their anchor exists.

