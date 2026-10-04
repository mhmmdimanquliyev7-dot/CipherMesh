# Phase 2 Traceability

Status: Phase 2 implemented on 2026-10-04, awaiting project owner approval. Covers CM-T013 and CM-T014 and the seed criterion of CM-T011 in [jira-backlog.md](jira-backlog.md). No item is DONE: DONE requires SECURITY REVIEW and TESTING in Jira and the full Definition of Done (CLAUDE.md section 14), including CI on a pull request, which cannot run before a GitHub remote exists.

Branch: `feature/CM-T013-database-prisma`, a **stacked branch** created from the committed Phase 1 branch `feature/CM-T006-application-foundation` (commit `900b664`), because Phase 1 cannot be merged into `main` without a remote and pull request. Phase 1 history was not rewritten, and its CI evidence (EV-01-01 CI run, EV-01-02, EV-01-03) remains pending.

## 1. Work items

| Item | Acceptance criterion | Implementation | Tests | Result |
|---|---|---|---|---|
| CM-T013 Prisma schema v1 and initial migrations | Field names and types follow the data model | `prisma/schema.prisma`: 15 tables, 203 classified fields; deviations recorded in [data-model.md](../architecture/data-model.md) section 7 | `tests/database/migrations.test.ts` (every live column declared and classified) | Met |
| | A script checks that no "must never exist" field is present | `scripts/db/check-schema.mjs` (`pnpm db:check-schema`) | `tests/security/schema-forbidden-fields.test.ts`: real schema passes, 33 negative controls fail, CLI exit codes | Met |
| | Migrations apply cleanly to an empty database | Four migrations: generated schema, integrity constraints, audit append-only, runtime role grants | `migrations.test.ts`: from zero, idempotent, drift check with negative control; CI step | Met |
| | Constraint tests pass (one ACTIVE key pair per user, one OWNER per room, one PENDING rekey operation per room) | Partial unique indexes, composite foreign keys, 116 CHECK constraints, write-once triggers | `tests/database/constraints.test.ts` | Met |
| | Composite indexes support object-level authorization (OL-02) | Room-first indexes; `(room_id, user_id)` membership lookup | Index review in [database-security.md](../security/database-security.md) section 7 | Met; exercised by feature queries from Phase 5 |
| CM-T014 Least-privilege roles and append-only audit protection | Roles for migration, API, worker and read-only verification | `scripts/db/bootstrap.mjs`, grant migration | `tests/database/privileges.test.ts` | Met for local and CI databases; the managed database follows in CM-T067 (Phase 18) |
| | Audit tables with INSERT and SELECT only for runtime roles | Grant migration | `privileges.test.ts`, `audit.test.ts` | Met for `audit_events`. The supporting audit tables are deferred to Phase 12 with the hash chain (data-model section 7.1) |
| | A trigger rejects UPDATE, DELETE and TRUNCATE | `..._audit_append_only` migration | `audit.test.ts`, including the owner | Met |
| | Integration tests prove the API role cannot change schema or modify audit rows | | `privileges.test.ts` (DDL, TRUNCATE, role creation, escalation), `audit.test.ts` | Met |
| | The trigger blocks modification even if grants are misconfigured | | `audit.test.ts` grants UPDATE, DELETE and TRUNCATE to `cm_api` on an isolated database and is still refused | Met |
| CM-T011 Local development environment (remaining criterion) | Synthetic seed data | `scripts/db/seed.ts`, `scripts/db/synthetic.ts` (`pnpm db:seed`) | `tests/database/seed.test.ts` | Met: three disabled accounts on `.test` addresses with a placeholder hash, no credentials and no key material |

## 2. Related changes in this phase

| Change | Why |
|---|---|
| `DATABASE_URL` in the API configuration: `cm_api` only, `verify-full` in production, loopback-only otherwise, held in a redacting `SecretValue` | TB-05, CP-21, INV-10 |
| Redaction of credential URLs and database URL keys in the logger | INV-10, T-16 |
| API database module `apps/api/src/db/client.ts`; readiness includes a database ping; pool closed on shutdown | Prisma client lifecycle |
| ESLint: `Prisma.raw` forbidden; Prisma and `pg` imports only in `apps/api/src/db` | T-14 |
| Prisma CLI wrapper refusing `db push`, `migrate dev`, `migrate reset`, `db execute`; telemetry off | Change control (8.32), T-27 |
| CI: PostgreSQL service, random per-run role passwords, bootstrap, migrations, drift check, seed, database suite | CM-T012 continuation |
| Threat T-39 and limitations L-26 to L-29 | Honest residual risks |

## 3. Security checkpoint (roadmap Phase 2)

| Check | Result |
|---|---|
| Schema reviewed against field classifications and the "must never exist" list | Checker passes; review notes in [database-security.md](../security/database-security.md) sections 4 and 6 and data-model section 7 |
| Grants reviewed per role | Matrix in database-security.md section 2.1, enforced by `privileges.test.ts` |
| Test output showing a rejected UPDATE on the audit table | EV-02-02 |
| Schema pull request through SECURITY REVIEW | **Pending**: needs the GitHub remote and Jira |

## 4. Evidence

Index: [../report/evidence/index.md](../report/evidence/index.md). EV-02-01 to EV-02-06 were captured locally against throwaway databases, with no passwords or connection strings in the files.
