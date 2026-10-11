# Phase 8 Traceability

Status: implemented on 2026-10-11 (Prompt 10): CM-T042, verified on branch `feature/CM-T042-encrypted-notes`, created from `main` at `111a193` (the Phase 7 handoff merge, pull request #25). Merged through its pull request; the pull request number, merge commit and CI run are recorded here after the merge. Backlog item: [jira-backlog.md](jira-backlog.md) (CM-EPIC-08, CM-T042). Specification: [../crypto/cryptographic-architecture.md](../crypto/cryptographic-architecture.md) section 6.2, [../architecture/data-flow.md](../architecture/data-flow.md) DF-12, [../architecture/data-model.md](../architecture/data-model.md) 4.12 and 5, [../security/authorization-model.md](../security/authorization-model.md) section 9.9, crypto-decisions CP-16, CP-28, CD-31.

## 1. Work item

CM-T042 (P1, crypto, frontend, backend; depends on CM-T036). Description: DF-12: fresh NEK per revision, revision number in AAD, optimistic concurrency, edit and delete rights (AZ-19 to AZ-22), expiry rules, note-read audit at EXTENDED and FULL, text-only rendering. Security considerations: T-07, T-12, T-32.

| Requirement | Implementation | Tests | Evidence | Result |
|---|---|---|---|---|
| Fresh NEK per revision, revision number in the AAD | `packages/crypto/src/notes.ts` (`encryptNote`, `openNote`), `note-format.ts`; `cm.note.content` {roomId, noteId, revision} and `cm.dek.wrap` (itemType `note`, the same revision) | `notes.test.ts`; NC-08-01, NC-08-02 | EV-08-04 | Met |
| **AC:** Canary scan finds no note title or body in the database | Title and body canaries in five encodings searched in every table and in the log and security events; browser test searches every request and browser storage | `tests/notes/notes-lifecycle.test.ts`, `tests/e2e/notes.spec.ts`; NC-08-10 | EV-08-01, EV-08-03 | Met |
| **AC:** A stale revision returns 409; ciphertext moved to another revision fails authentication | `NoteService.updateNote`: row lock, expected revision compared on locked state, conditional `UPDATE ... WHERE revision = expected`; guard trigger allows only revision plus one with new key material | `notes-lifecycle.test.ts` (stale, duplicate, concurrent, relabelled and replayed revisions), `notes.test.ts`, `constraints.test.ts`, `notes.spec.ts`; NC-08-01, NC-08-04 | EV-08-04 | Met |
| **AC:** XSS payloads in notes render as text (Playwright) | Note text rendered by React as text only (`whitespace-pre-wrap`), no HTML or Markdown, CSP unchanged | `notes.spec.ts` in Chromium, Firefox and WebKit; NC-08-09 | EV-08-02 | Met |
| Edit and delete rights (AZ-19 to AZ-22) | Five room routes in the registry (`apps/api/src/routes/notes.ts`), the central authorizer with the stored author deciding `own`, the decision repeated on locked state | `notes-access.test.ts`, `tests/authz/bola.test.ts` (27 room routes), `route-inventory.test.ts`, `bola-inventory.test.ts`; NC-08-05, NC-08-06 | | Met |
| Optimistic concurrency | As above; the browser keeps the editor's text on 409 and offers to load the latest revision | `notes-lifecycle.test.ts`, `notes.spec.ts` | EV-08-04 | Met |
| Expiry rules (PC-08) | `NOTE_RULES` (shared), checked at creation on locked state; the expiry cannot be extended; read-time refusal (INV-14); the worker tombstones expired notes | `notes-access.test.ts`, `notes-lifecycle.test.ts`, `profile-requirements.test.ts`; NC-08-08 | | Met |
| Note-read audit at EXTENDED and FULL (PC-13) | `NOTE_READ` security events for list and single reads in CONFIDENTIAL and RESTRICTED rooms (to the log until the Phase 12 chain) | `notes-access.test.ts`, `profile-requirements.test.ts` | | Met |
| Text-only rendering | See the XSS row; titles refuse control and bidirectional characters in the browser and in the crypto package | `notes.test.ts`, `notes.spec.ts` | EV-08-02 | Met |
| Write lock (INV-07, PC-16) and current key version | Creation and update refused while REKEY_REQUIRED or with a stale key version; deletion allowed | `notes-access.test.ts`; NC-08-07 | | Met |

## 2. Architecture-conflict review

The normative sources agree: the NEK per revision (cryptographic-architecture 6 and 6.2, key-hierarchy, key-lifecycle section 2), the contexts `cm.note.content` {roomId, noteId, revision} and `cm.dek.wrap` with itemType `note` (context catalogue, implemented since Phase 4), CP-16 (a DEK encrypts at most two messages; a NEK encrypts one), the data model 4.12 (one ciphertext column holding the encrypted JSON of title and body, the revision in the AAD, tombstones in section 5), DF-12 (expected revision r - 1, optimistic concurrency, authorization by author or OWNER and ADMIN, key version current, key state ACTIVE, only the current revision stored), AZ-19 to AZ-22, PC-08, PC-13 and PC-16. No source contradicts another on a security-relevant detail. Two things were unspecified and are recorded as decisions below: the size limits (D-08-01, now CP-28) and the route shape of the update (D-08-02).

## 3. Decisions and deviations

| ID | Decision | Reason |
|---|---|---|
| D-08-01 | Limits (CP-28): a note document of at most 64 KiB, a title of 1 to 200 UTF-16 code units, revisions 1 to 2^31 - 1, at most 1000 live notes per room, list pages of 20 | No document fixed a note size. 64 KiB keeps the largest request (about 88 KiB as base64url with the other fields) inside the existing 128 KiB body limit, which is unchanged. The note count bounds the database space and the work of one room. Enforced in the crypto package, the schemas, the database CHECK and the service; a test compares them with the register |
| D-08-02 | The update is `POST /rooms/{roomId}/notes/{noteId}/update` with `expectedRevision` instead of DF-12's `PUT` | Every state change of the API is a POST with a verb suffix (rename, delete, complete); the CSRF gate and the route conventions stay uniform. DF-12 records the implemented shape |
| D-08-03 | The note document is the RFC 8785 serialization of `{body, title, v: 1}`, one AES-GCM message; only the canonical serialization is accepted when opening (CD-31) | One message binds title and body together; a version field gives crypto agility; canonical-only parsing leaves no room for two parsers to disagree |
| D-08-04 | The expiry is fixed at creation and an edit cannot change it | PC-08 limits how long content lives; letting every edit move the expiry would let a note live indefinitely in CONFIDENTIAL and RESTRICTED rooms. The guard trigger allows an expiry only to move earlier |
| D-08-05 | The list returns each note's ciphertext; it is ordered by creation time | The title is encrypted inside the document, so the list must carry ciphertext to show titles; creation time does not change on edits, so keyset paging stays stable while notes are edited |
| D-08-06 | Migration `20261008000000_encrypted_notes`: the ciphertext CHECK bounded by CP-28 and the guard trigger `cm_guard_encrypted_note_change` | No column changes and no grant changes; see data-model section 7.1 |
| D-08-07 | The API computes the stored `ciphertext_sha256` itself | It receives the ciphertext, so a client-supplied hash would add nothing; the value is an integrity reference over ciphertext only (CD-09) |
| D-08-08 | A plain-text editor; no Markdown or rich text | Not required by CM-T042; avoids a rendering dependency and keeps T-12 exposure minimal |

No new dependency was added.

## 4. Security review of the Phase 8 change

Answers to the review questions of Prompt 10 section 15, with the evidence:

1. *Can the API read note plaintext?* No. The API receives the document ciphertext, the wrapped NEK and IVs; the title and body are encrypted in the browser (canary scan EV-08-03; request inspection in `notes.spec.ts`).
2. *Can a database administrator read the title or body?* No: both are inside the AES-256-GCM ciphertext under a NEK wrapped under RWK_v, which is never on the server. They see metadata (L-51).
3. *Can PLATFORM_ADMIN decrypt without membership?* No: every note route answers 404 without membership (BOLA suite, PA-05), and they hold no room key.
4. *Can a MEMBER access a note from another room?* No: notes are loaded by note ID and room ID and membership (BOLA class C over five routes; NC-08-05).
5. *Can a malicious server substitute encrypted note content?* Not undetected: a body or wrapped NEK from another note, room, key version or revision fails authentication (`notes.test.ts`, `notes-lifecycle.test.ts`, the substitution test in `notes.spec.ts`). It can delete or withhold notes (denial, not disclosure).
6. *Can the server replay an older revision?* An older revision served under its own number authenticates; the browser flags it only if it saw a newer revision in the same tab (T-32, L-10, `notes.spec.ts`). A revision relabelled with another number fails authentication.
7. *Can two concurrent edits silently overwrite each other?* No: the note row is locked, the expected revision is compared on locked state and the update is conditional; exactly one of two simultaneous saves wins, the other gets 409 and keeps its text (`notes-lifecycle.test.ts`, `notes.spec.ts`; NC-08-04).
8. *Can a note key be reused for another room?* No: each revision has a fresh NEK, and its wrap is bound to the room, key version, note and revision.
9. *Can an invalid room key be accepted?* No: `encryptNote` and `openNote` accept only an `OpenedRoomKey` from the Phase 6 verification rule; a key of another room or version is refused; different key material fails authentication.
10. *Can deleted notes still be obtained from active API endpoints?* No: tombstones have no ciphertext or wrapped NEK, and every read filters them out (`notes-lifecycle.test.ts`).
11. *Can a removed member retrieve new note ciphertext?* No: their requests are 404 at once, and the room refuses new note content until a rekey (L-54).
12. *Can malicious note content execute JavaScript?* No: rendered as text only; the XSS corpus runs nothing in three engines (EV-08-02; NC-08-09). The CSP is unchanged.
13. *Can plaintext appear in browser persistent storage?* No: the E2E test reads localStorage, sessionStorage, IndexedDB and caches (NC-08-10).
14. *Does vault locking clear the decrypted-key state?* Yes: the room keys are dropped (Phase 6) and the panel discards every decrypted title and body at once (`notes.spec.ts`).
15. *Are residual risks documented?* Yes: L-51 to L-54, with L-09, L-10 and L-12.

What authentication guarantees and what the server's checks guarantee are different things: AES-GCM with the context-bound AAD guarantees that a displayed note is exactly what a holder of that room key encrypted for that room, note and revision. The ordering of revisions, the refusal of stale saves, the role rules and the expiry are guarantees of the API and the database, which a malicious server can break by withholding or replaying data, but not by forging content. Nothing protects against an attacker who controls the client application itself (L-01, L-02).

No vulnerability was found in existing code during the review; there is no new security finding.

## 5. Verification

Gates of Prompt 10 on the final Phase 8 code (2026-10-11, local PostgreSQL and storage):

| Gate | Result |
|---|---|
| `pnpm install --frozen-lockfile`, `pnpm format:check`, `pnpm lint`, `pnpm typecheck` | Pass |
| `pnpm test` | 1956 tests in 78 files (Phase 7: 1876 in 75). New suites: `packages/crypto/src/notes.test.ts` (20 tests), `tests/notes` (25: lifecycle 15, access 10); extended: `bola.test.ts` 160 tests over 27 room routes (was 132 over 22), database constraints (note bound and guard trigger), route inventory, BOLA inventory, profile and register drift, export surface |
| `pnpm test:e2e` (three engines, one worker) | 102 passed, 12 skipped by design (single-engine tests); was 83 and 10. `notes.spec.ts`: 7 tests, 19 results, 2 skipped (the cross-engine test runs once from Chromium and drives Firefox and WebKit) |
| `pnpm security:negative-controls` | 79 of 79 caught (ten Phase 3, seventeen Phase 4, twenty-two Phase 5, ten Phase 6, ten Phase 7, ten Phase 8), both baselines pass, 44 source files restored byte for byte |
| `pnpm test:coverage:crypto` | 98.77% statements, 93.85% branches (gate 90%) |
| `pnpm test:coverage:authz` | 97.26% statements, 98.3% branches |
| `pnpm build`, `pnpm smoke:api`, `pnpm sbom:generate`, `db:validate`, `db:check-schema`, `db:drift` | Pass; migrations from zero are exercised by `tests/database/migrations.test.ts` (part of `pnpm test`) |
| `pnpm audit:deps` | Pass (no known vulnerabilities); no dependency added or changed |
| Secret scan (gitleaks) | Staged changes and all commits: see EV-08-05 |

Recorded in EV-08-05. Local note: the full E2E run and the negative controls ran one at a time, E2E with `--workers=1`, as for Phase 7.

## 6. Negative controls

Each control writes one real defect into the working tree, runs the tests that must catch it, and restores the file (`scripts/security/negative-controls.mjs`, EV-08-06). The Vitest controls were run with `--show-failures` to confirm that the intended assertions failed.

| ID | Deliberate defect | Detected by | Result |
|---|---|---|---|
| NC-08-01 | Note content no longer bound to its revision (`cm.note.content` with a fixed revision) | `notes.test.ts` (independent implementation, wrapping-context test) | Caught |
| NC-08-02 | A wrapped NEK uses the file wrapping context (itemType `file`) | `notes.test.ts` | Caught |
| NC-08-03 | Non-canonical note documents accepted | `notes.test.ts` (malicious-member documents) | Caught |
| NC-08-04 | A stale save silently overwrites a newer revision (last writer wins) | `notes-lifecycle.test.ts` (stale revision) | Caught |
| NC-08-05 | One note served without the room and membership filter (BOLA) | `bola.test.ts` (class C) | Caught |
| NC-08-06 | Note update authorized as a read (AZ-20 instead of AZ-21) | `notes-access.test.ts` | Caught |
| NC-08-07 | Note updates accepted while the room is REKEY_REQUIRED | `notes-access.test.ts` (removal) | Caught |
| NC-08-08 | Expired notes served until the worker runs | `notes-lifecycle.test.ts` (expiry) | Caught |
| NC-08-09 | Note bodies rendered as HTML | `notes.spec.ts` XSS test (Chromium) | Caught |
| NC-08-10 | Decrypted note bodies kept in localStorage | `notes.spec.ts` main test (Chromium) | Caught |

## 7. Evidence

In [../report/evidence/phase-08/](../report/evidence/phase-08/), synthetic data only: EV-08-01 (the stored note row with the ciphertext head, and the rendered note), EV-08-02 (the XSS corpus shown as text), EV-08-03 (canary scan), EV-08-04 (revision, conflict and tamper tests), EV-08-05 (gates and secret scans), EV-08-06 (negative controls). Pending: the CI run of the pull request (recorded after the merge) and the Jira history of CM-T042 (backlog not imported yet).
