# Phase 14 + Prompt 16.5 Traceability: Security Dashboard, UI/UX Redesign and Security & Trust Center

Status: implemented on branch `feature/CM-T061-trust-center-redesign` (2026-10-13 and 2026-10-14). Jira: CM-T061, CM-T062 (Phase 14) and the Prompt 16.5 redesign recorded under CM-T061. Related: [project-roadmap.md](project-roadmap.md), [current-state.md](current-state.md), [../architecture/security-dashboard.md](../architecture/security-dashboard.md), [../report/live-demo-guide.md](../report/live-demo-guide.md).

## 1. Approval and scope

- **Baseline.** `main` = `origin/main` = `42474ac` (merge of pull request #33, the Phase 11 handoff; Phase 11 itself is pull request #32, merge commit `31c31ba`). Working tree clean; CI of `main` after #33 green.
- **Owner decision (2026-10-13).** The project owner explicitly approved combining Phase 14 (Security Dashboard, CM-T061, CM-T062) with Prompt 16.5 (complete UI/UX redesign) and deferring **Phase 12 (Tamper-Evident Audit), Phase 13 (Crypto Inspector), Phase 15 (API Hardening) and Phase 16 (Automated Testing consolidation)** until after the university delivery (deadline 2026-10-18). The decision is a scheduling change: no control, test, gate or invariant was weakened. Revised order: (1) this combined phase, (2) Cloud Deployment + Cloud Security Hardening, (3) ISMS evidence, final report and live demonstration.
- **Architectural boundary.** Phase 14 was designed to read the Phase 12 ledger. Without it, the dashboard uses existing tables only and marks the ledger metrics NOT_IMPLEMENTED; the Trust Center labels the audit chain "not implemented". No audit row was written (INV-09).

## 2. Original UI audit (Checkpoint 1)

| Area | Finding before the redesign |
|---|---|
| Routes | `/`, `/login`, `/register`, `/account`, `/vault`, `/rooms`, `/rooms/room?id=` (ADR-011 query routing), `/invitations`, 404 |
| Navigation | One header row of four links; no grouping, no active state, no narrow-screen layout, no skip link |
| Start page | Still listed Phases 6 to 11 as "Not yet available", which was no longer true |
| Rooms | Every feature stacked as one column of about 15 cards with no orientation |
| Design system | 5 lines of CSS, 5 primitives (`Field`, `Button`, `SecondaryButton`, `Alert`, `Card`), no icons, no tokens |
| Constraints | Strict CSP (`style-src 'self'`: no inline styles; no external fonts or scripts), static export, E2E tests that select by accessible names |

## 3. Design direction and information architecture

- **Identity.** Deep navy neutral scale (Tailwind `slate` retuned in `@theme`), one restrained teal accent (`accent`), status colours (emerald, amber, rose, sky) always paired with an icon or text (WCAG 1.4.1). System font stacks, no web fonts. Original inline-SVG icon set and a "three verified nodes in a protected hexagon" mark (`components/icons.tsx`).
- **Information architecture.** Public frame for `/`, `/login`, `/register` (Trust Center, Sign in, Get started). Workspace frame with one responsive navigation landmark: *Workspace* (Overview, Rooms, Invitations), *Security* (Vault, Trust Center), *Settings* (Account); a header with the build label, the vault status and Sign out; a skip link. Files, notes and secrets stay inside rooms (the API is room-scoped; no cross-room endpoint was added). The room page has a sticky section navigation (Key & safety, Files, Notes, Secrets, Members, Key rotation, Security profile, Settings) with every panel still rendered.
- **Components.** `ui.tsx` (Field, SelectField, Button with a danger tone, SecondaryButton, Alert with error, warning, info and success, Card with icon, description, actions and tone, Badge, PageHeader, EmptyState, Loading, Stat, DetailList, Disclosure), `styles.ts` (class constants usable by server components), `buttons.tsx` (the hydration guard of SF-04-01, unchanged), `app-shell.tsx`, `auth-layout.tsx`, `rooms/badges.tsx` (profile, role, key state), `rooms/receipts.tsx` (encryption receipts), `trust/ui.tsx` (Trust Center tabs, evidence and limitation chips, document links).

## 4. Product journeys

| Journey | Change | Behaviour kept |
|---|---|---|
| Sign in and registration | Two-column layout explaining the account password, the Vault Passphrase and two-step sign-in; sign-in lands on the new Overview | Labels, button names, MFA and recovery flows, `form-action 'none'` and the pre-hydration disabled buttons |
| Overview (new, `/overview`) | Notices (vault not set up or locked, MFA off, rooms locked for rotation, invitations), four counts, recent rooms, session facts | Only the user's own session, rooms (first page; "n+" when more exist) and invitations; nothing estimated, no platform data |
| Vault | Status card (unlocked, locked, not set up) and a five-step "how your keys are protected" flow; danger tone for identity replacement | Passphrases read from the form and reset; no new state, storage or request |
| Rooms and room page | Room list with profile, role and key-state badges; room header, breadcrumb, policy version, section navigation; member avatars; tones for leave and delete | Every control still follows the shared matrix as UX only; step-ups unchanged |
| Files, notes, secrets | Upload area, progress, empty states, status badges; **encryption receipts** per item | Protocols, limits, optimistic concurrency and the reveal transaction unchanged; note text rendered as text, the receipt outside the note view |
| Key rotation | Card styling | ADR-013 flow unchanged |
| Account | Two columns, MFA anchor, session list | All step-up requirements unchanged |
| Everywhere | A Sign out control in the header | Locks the vault, then ends the session, as the Account page does |

## 5. Security-sensitive interaction review

| Item | Review |
|---|---|
| New API route | `GET /admin/security-dashboard` only (PA-01): registry administrator gate, 404 for non-administrators, 401 without a session, aggregates only (section 7). No other API change |
| Trust Center | Static pages; data compiled from public repository documents; no runtime file reads, no arbitrary paths, no user data, no storage, no third-party resource; external links to GitHub with `noreferrer` |
| Live checks | Same-origin `HEAD` of the page and the public `/health` and `/ready` probes without credentials; observations labelled as such (L-69) |
| Receipts | Suite, key version, sizes and the browser's own integrity result only; never a key, IV, wrapped key or ciphertext |
| Overview | Reuses existing authorized endpoints; renders text only |
| CSP | Build fails on inline styles; 18 pages generated with 36 inline-script hashes; E2E checks zero violations on every new page in three engines |
| Storage | No `localStorage`, `sessionStorage` or IndexedDB use was added (E2E asserts empty storage on Trust Center pages) |
| Wording | A unit test refuses "unhackable", "military grade", "zero knowledge", "perfect security", "tamper-proof", "fully compliant" and certification claims in the client source, except in negated form |

## 6. Security & Trust Center

| Page | Content | Sources |
|---|---|---|
| `/trust` Summary | The three subjects with counted facts; six claims in the pattern Claim → Mechanism → Verification → Evidence → Limitation; "Not implemented or not connected" (audit ledger, cloud, Crypto Inspector, external links) | `trust/claims.ts`, generated data |
| `/trust/cryptography` Data protection & key management | Encryption flow by zone, what the server stores and never receives, six mechanisms (AES-256-GCM, RSA-OAEP-3072, ECDSA P-256, HKDF, Argon2id, Room Safety Code) with what, why, where, protects, verification, evidence, what it cannot guarantee and the register's parameter text; key hierarchy; rotation lifecycle | `trust/cryptography.ts`, `parameters.json` |
| `/trust/infrastructure` Deployment & infrastructure | Deployment status (cloud not connected, build label, control counts), components and exposure, live checks, control register (Designed, Configured with scope, Verified with scope), shared-responsibility matrix | `trust/infrastructure.ts`, `cloud.json` |
| `/trust/governance` Governance & risk | Scope, clauses, likelihood-impact matrix, risk register with details, Annex A register with evidence coverage, limitations register, governing documents, known gaps | `risks.json`, `isms.json`, `limitations.json`, `trust/governance.ts` |
| `/trust/evidence` Evidence register | Every plan item with subjects, status (Captured, Partly captured, Missing, Deferred, Later workstream), files and captions | `evidence.json` |
| `/trust/walkthrough` | Three journeys (Cryptography, Cloud, ISMS), each step with action, what to point out and evidence | `trust/walkthrough.ts` |
| `/trust/dashboard` | Platform security dashboard (section 7) | API |

**Evidence schema.** `apps/web/scripts/trust-data-lib.mjs` parses the threat model (sections 4 and 5), the limitations, the ISMS mapping (sections 1 to 3), the evidence plan (section 3), the evidence index, the committed files under `docs/report/evidence/phase-NN/` (named `EV-NN-MM…`), the parameter register and the two cloud tables into `apps/web/src/trust/generated/*.json`. An item is *captured* when a committed file or a recorded location exists and no part is pending; *partial* when some part is pending; *deferred* for Phases 12, 13, 15 and 16; *planned* for Phases 17 to 22; otherwise *missing*. The web build runs `--check` and fails when the committed data differs from the documents. Finding during the work: the evidence index has prose for Phase 6 and no rows for Phases 8 to 10 although their files are committed; the committed files are therefore the ground truth, and the index gap is recorded for the ISMS workstream.

## 7. Platform security dashboard (CM-T061, CM-T062)

- API: `apps/api/src/routes/admin.ts`, store `apps/api/src/db/dashboard-store.ts` (Prisma counts and sums; one reviewed parameterized `$queryRaw` for `COUNT(DISTINCT ip_address)`), catalogue `packages/shared/src/dashboard.ts`, schema `packages/validation/src/dashboard.ts` (metric IDs, value keys, non-negative integers, platform component states).
- Implemented: SD-01 to SD-09, SD-13, SD-14. Not implemented (ledger deferred): SD-10, SD-11, SD-12, SD-15, returned as NOT_IMPLEMENTED without value. A value the store did not compute fails the request; there is no placeholder zero.
- Platform contract (provider-neutral, for the cloud workstream): `api` and `database` HEALTHY because the response was computed; `object-storage` and `worker` NOT_VERIFIED; `cloud` NOT_CONNECTED. States UNAVAILABLE, DEGRADED and NOT_CONFIGURED exist for the provider adapter.
- UI: each metric with its definition, the computation time and environment; individual highlights for blocked members, locked rooms and abandoned operations; no score.

## 8. Tests

| Suite | What it proves |
|---|---|
| `apps/web/scripts/trust-data.test.ts` (unit) | Committed data equals the documents; every risk has a section and existing limitations; control statuses are the documented ones and every evidence reference resolves; no capture without a committed file; Phase 12 evidence deferred, cloud evidence planned; subject tags; the parameter register verbatim; parsing rules |
| `apps/web/src/trust/trust-content.test.ts` (unit) | Mechanisms cite existing parameters, captured evidence and limitations; AES-GCM parameters match `@ciphermesh/crypto/params`; RSA never described as encrypting content; key hierarchy complete; configuration sources exist; "verified" only with captured evidence and never in the cloud; claims and walkthrough references resolve and routes exist; governing documents exist; forbidden wording |
| `tests/dashboard/security-dashboard.test.ts` (new Vitest project `dashboard`, own database, one file at a time) | Catalogue order; empty-state zeros; NOT_IMPLEMENTED metrics and platform states; exact values for a scenario built through the API (3 rooms, 2 profiles, 1 file with its ciphertext size, 2 secrets in 24 hours and 7 days, 5 users with 2 MFA and 3 vaults, 1 blocked member, 1 rotation by MEMBER_REMOVED, 1 locked room 5 hours old, 2 failed logins) and independent SQL counts for sessions, throttling, sources and abandoned operations; projection canary; 404 and 401 |
| `tests/security/route-inventory.test.ts` | The dashboard GET is in the reviewed GET list; the platform routes are exactly PA-03 disable and enable and PA-01 |
| `tests/e2e/trust-center.spec.ts` (three engines) | Every Trust Center page under the CSP without violations and without browser storage; live-check outcomes including HSTS absent; no "Verified (cloud)"; missing and deferred evidence visible; risk deep link opens; dashboard refused to signed-out users and non-administrators; Overview notices and sidebar navigation with `aria-current`; narrow-screen menu with Escape and no sideways scroll; skip link (not WebKit, where Tab skips links by default) |
| Existing E2E adapted | Sign-in now lands on Overview (helpers, `auth.spec.ts`, `room-helpers.ts`, `vault.spec.ts`); the start-page test checks the new public frame instead of the removed "Not yet available" list. No assertion was weakened; the note XSS test still asserts that the note view contains no element |
| `tests/e2e/evidence-capture.spec.ts` | On demand only (`CM_CAPTURE_EVIDENCE=1`): EV-14-01 to EV-14-18 from the running application |

Results of the gates are in [current-state.md](current-state.md) section 9 and EV-14-19.

## 9. Accessibility and responsive coverage

- One navigation landmark per frame, `aria-current` on the active page, skip link, focus-visible outline on every control, labels on every form control, native `<details>` for disclosures, `role="tablist"` for journeys, tables with captions and scoped headers, status never by colour alone, `prefers-reduced-motion` honoured, no autoplay.
- Layouts checked at 390 px (no sideways scroll on every Trust Center page, the start page and sign-in; two overflows found and fixed: a no-wrap badge and the key-hierarchy indentation) and at 1440 px. Contrast, computed from the tokens: `slate-300` on the page background 9.2:1, `slate-400` 6.4:1, `slate-500` (small hints) 5.3:1 on the page and 4.65:1 on raised surfaces after it was lightened during the review (it was 4.3:1), primary buttons (dark text on `#27cdbf`) 7.6:1. No automated axe audit was run (no new dependency); WCAG 2.2 AA is the target, not a verified claim.

## 10. Review notes

| ID | Note | Resolution |
|---|---|---|
| R-14-01 | The note receipt was first placed inside the note view, so the XSS test (EV-08-02) counted its icons as elements | Receipt moved outside the untrusted-text container; the test is unchanged |
| R-14-02 | The readiness probe of the live checks did not read the response body, so the request stayed open and pages never became idle | The body (a status word) is drained |
| R-14-03 | `ui.tsx` used a hook and was imported by server components | Split into `styles.ts`, `buttons.tsx` (client) and server-safe components |
| R-14-04 | Two Firefox tests (`secrets` two tabs, `rekey` C) hung in `page.goto` of a second tab once in the full run and passed on rerun | The known E2E navigation-hang item of current-state section 12; not caused by this phase |

No security finding was opened in this phase.

## 11. Limitations and deferrals

L-13 updated; L-68 (Trust Center compiled from documents), L-69 (live checks are observations, not monitoring), L-70 (dashboard without ledger metrics) added. ISMS mapping: 5.33 and 8.15 are now Partial (ledger deferred), 8.16 Partial (no verification runs or alerting), 5.28 notes the evidence register. Deferred: Phases 12, 13, 15 and 16 (owner decision). Not built: P1 items such as PDF evidence export, charts and history in the dashboard, an automated accessibility audit, and light mode.

## 12. What remains for the next workstreams

- **Cloud deployment:** provider selection ADR (ADR-014), VM, production images and Compose, Nginx with TLS and the generated headers, managed PostgreSQL and object storage, then the provider adapter for the platform contract (`cloud` from NOT_CONNECTED to measured states) and `NEXT_PUBLIC_CM_ENVIRONMENT=cloud-demonstration`.
- **Cloud hardening:** firewall, SSH, host hardening, Docker Bench, Lynis, TLS scan, HSTS, backups and a restore test; capture EV-17 to EV-19 and move the infrastructure controls from Designed to Configured and Verified with scope `cloud`.
- **ISMS final evidence and report:** fill the evidence index rows for Phases 6 and 8 to 10; Jira history (EV-00-05, EV-00-06, EV-00-10, EV-01-02, EV-01-03); the general incident procedure, access review and management review (CM-T080); owner acknowledgement of residual High and Accept risks; risk re-rating; the report built from the Trust Center and the evidence register.
