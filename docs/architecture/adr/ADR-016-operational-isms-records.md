# ADR-016: Operational ISMS records in the application

- Status: Accepted (2026-10-15, within the Operational ISMS workstream approved by the project owner)
- Date: 2026-10-15
- Related: [isms-operations.md](../../security/isms-operations.md), [isms-control-mapping.md](../../security/isms-control-mapping.md), [threat-model.md](../../threat-model/threat-model.md) (T-45), [authorization-model.md](../../security/authorization-model.md) section 4, [database-security.md](../../security/database-security.md), ADR-009 (deferred ledger), CM-T088 to CM-T092

## Context

The ISMS of CipherMesh exists as documents: a scope, a risk register of 44 risks, a Statement of Applicability of 48 rows, an evidence register and a public Trust Center generated from them. Nothing records that a management activity happened: no dated re-assessment, treatment decision, verification, audit, finding, corrective action or review. The examiner must see the management system operate, not only be described. Constraints: three days, $0, no new services or frameworks (CLAUDE.md section 4), no weakening of any control, the tamper-evident ledger stays deferred, and no second register may compete with the normative documents.

## Decision

1. **The documents stay the reference.** Risks, assets, Statement of Applicability rows, clauses, the evidence register with capture dates, the policy register, freshness classes and metric definitions are generated from the normative documents into `packages/shared/src/isms-catalogue.ts` by `pnpm trust:generate` (drift fails `pnpm trust:check` and the web build). The API and the web client read the same catalogue; the API refuses any reference that is not in it.
2. **Operational records are rows of two tables.** `isms_records` holds one row per record (kind, human code such as `FND-003`, catalogue reference, status, data as JSON validated by a schema per kind at the API, version for optimistic concurrency, exercise flag, creator and times). `isms_activity` holds one append-only row per creation or transition (actor, action, previous and new status, rationale, data after the change). Kinds: risk assessment, control verification, audit, finding (with its corrective action), management review, scope review, policy review, incident.
3. **Workflows are server-side state machines.** The transitions, their inputs and conditions are pure functions in `packages/shared/src/isms.ts`, applied by the API inside one transaction that locks the record and checks its version (409 on a stale version). No status field can be written directly. Conditions that depend on other records (for example "every linked control is currently verified") are computed from all records in the same transaction.
4. **Assurance and freshness are computed, never stored.** Control assurance, evidence freshness, policy lifecycle, risk views and metrics are derived on request from the records, the catalogue and the time.
5. **Authorization reuses the platform administrator gate.** New matrix actions PA-06 (view), PA-07 (record) and PA-08 (decide, step-up every time) all require PLATFORM_ADMIN with an MFA-verified session; everyone else receives the generic 404.
6. **Honesty is in the data model.** Exercise records are flagged and can only be withdrawn, not deleted; audits carry a declared independence (self-assessment, simulation, internal audit) and the API refuses "internal audit" by the planner; decisions record the approver; the API sets every time.

## Alternatives Considered

- **Typed tables per record kind.** Stronger database constraints per field, but eight tables, migrations, grants and projections for a three-day workstream. The JSON is validated by schemas at the API boundary and the state is checked by the database (status and kind values); chosen for size.
- **Editing the Markdown documents from the application.** Keeps one source, but the API would write to the repository and every activity would need a commit; rejected.
- **A third-party GRC tool.** Adds runtime SaaS and cost; rejected (CLAUDE.md section 4).
- **Recording activity in `audit_events`.** That table is reserved for the hash-chained ledger (INV-09, deferred); rejected.

## Consequences

- One migration (two tables, a trigger, grants), one store, one service, four routes, the Control Center under `/trust/isms`, a new test project `isms`.
- The catalogue grows with the documents; `trust:check` keeps them consistent.
- Single-person operation remains visible: decisions are the project owner's, audits are self-assessments.

## Security Implications

- New asset A-16 (ISMS records) and threat T-45 (unauthorized change or disclosure of ISMS records): PLATFORM_ADMIN with MFA, step-up for decisions, server-side transitions, optimistic concurrency, append-only history, schema validation with unknown fields refused, attachments limited in size and refused when they contain secret material (INV-10).
- The activity history is not tamper-evident (L-81). A database administrator could change it; Phase 12 would detect that.
- Tests: unit tests of every transition and computation, an integration suite through the HTTP API (authorization, step-up, conflicts, malformed input, stale evidence, append-only history), the route inventory and authorization matrix suites, and an E2E lifecycle in three engines.

## Status

Accepted. Review when Phase 12 (the ledger) is approved, when a second person joins the project (independence), or when the ISMS needs more than one organization.
