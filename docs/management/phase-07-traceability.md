# Phase 7 Traceability

Status: implemented on 2026-10-11 (Prompt 09): CM-T037 to CM-T041. Branch `feature/CM-T037-encrypted-files`, created from `main` at `c175d22`. Backlog items: [jira-backlog.md](jira-backlog.md) (CM-EPIC-07). Specification: [../crypto/cryptographic-architecture.md](../crypto/cryptographic-architecture.md) section 6.1, [../architecture/data-flow.md](../architecture/data-flow.md) DF-07 and DF-08, [../architecture/data-model.md](../architecture/data-model.md) 4.11 and 5, [../security/authorization-model.md](../security/authorization-model.md) section 9.8, crypto-decisions CP-19, CP-20, CD-30, LIB-09.

## 1. Work items

| Item | Requirement (acceptance criterion) | Implementation | Tests | Evidence | Result |
|---|---|---|---|---|---|
| CM-T037 Object storage adapter and presigned URLs | Storage interface with an S3 implementation; presigned PUT (at most 5 minutes, fixed size) and GET (at most 60 seconds, attachment headers); HEAD; delete; random object keys; scoped credentials | `apps/api/src/storage/object-store.ts` (`aws4fetch`, LIB-09, imported only there); keys `f/` plus 32 random bytes; the upload URL signs the content length; the download URL forces `attachment` and `application/octet-stream`; the dev emulator has an administrator identity (bucket creation) and a runtime identity that reads and writes objects of one bucket only (`compose.dev.yml`, `pnpm storage:bootstrap` proves its scope) | `tests/files/files-upload.test.ts`, `apps/api/src/config/env.test.ts`; NC-07-06 | EV-07-02, EV-07-06 | Met |
| | Works against the local emulator; expired URLs fail | Real SeaweedFS in every files test; expired PUT and GET refused (403) | `files-upload.test.ts` | EV-07-06 | Met |
| | Presigned URLs never appear in logs | Redaction keys `uploadUrl`, `downloadUrl`, value pattern `X-Amz-Signature`; the log and the security events are searched | `redact.test.ts`, `files-upload.test.ts` | | Met |
| CM-T038 Client-side file encryption and upload | FEK, encrypted manifest, wrap under RWK_v, ciphertext hash, size limit (CP-19), PENDING_UPLOAD to AVAILABLE with completion check, wrap-count increment, current-version and key-state checks, profile expiry rules | `packages/crypto/src/files.ts` and `file-format.ts`; `apps/api/src/files/service.ts`, `routes/files.ts`, `db/file-store.ts`; `apps/web/src/rooms/files.ts`, `file-panel.tsx` | `files.test.ts` (41), `files-upload.test.ts` (18); NC-07-01 to NC-07-03, NC-07-05, NC-07-07 | EV-07-01, EV-07-03 | Met |
| | Canary scan finds no filename or content canary in the database or bucket | Canaries in four encodings searched in every table, the bucket and the log; browser test searches every request and browser storage | `files-upload.test.ts`, `files.spec.ts` | EV-07-05 | Met |
| | `KEY_VERSION_STALE` and `REKEY_REQUIRED` return 409, including at upload completion | Checked at start on locked state and again at completion; a pending upload in a write-locked room is cancelled and its object deleted | `files-upload.test.ts` | | Met |
| | Size mismatch at completion rejects the upload and deletes the object | HEAD before completion; `UPLOAD_SIZE_MISMATCH` (422), tombstone, object deleted | `files-upload.test.ts`; NC-07-05 | | Met |
| CM-T039 Download and authenticated decryption | POST for download URLs, VIEWER restriction in RESTRICTED (PC-12), ciphertext hash check, unwrap, authenticated decryption of manifest and content, plaintext hash check, integrity-error UI, audit at EXTENDED and FULL | `openFile` and `OpenedFile.decrypt`; `FileService.downloadUrl`; `FILE_INTEGRITY_ERROR` message | `files.test.ts`, `files-access.test.ts`, `files.spec.ts`; NC-07-01, NC-07-08 | EV-07-04 | Met |
| | Bit flips in the object, manifest or wrapped FEK produce an integrity error and no plaintext | See the tamper tests; the browser saves nothing | `files.test.ts`, `files-access.test.ts`, `files.spec.ts` | EV-07-04 | Met |
| | Downloaded bytes equal the original (E2E); VIEWERs denied in RESTRICTED | Three engines, a second member downloads 2 MiB of random bytes | `files.spec.ts`, `files-access.test.ts` | | Met |
| CM-T040 Deletion, expiry, cleanup worker | Deletion rights (AZ-18), expiry at read time, worker deletion with retries, abandoned uploads, tombstones, lifecycle rules as a safety net | Tombstone transaction; `db/file-cleanup.ts` run by `pnpm worker:retention`; `object_deleted_at`; a room becomes DELETED only after its objects are gone; the guard trigger | `files-access.test.ts`, `files-cleanup.test.ts`, `constraints.test.ts`; NC-07-09 | | Met, except bucket lifecycle rules (provider configuration, Phase 19) |
| | Expired files are refused immediately; deleted files have no object, wrapped FEK or manifest in the live system | Read queries filter by expiry; tombstone sets wrapped FEK and manifest to NULL and the object is deleted | `files-access.test.ts` | | Met |
| CM-T041 Limits, quotas, safe downloads | Per-room and per-user quotas; forced attachment downloads; preview allowlist (images through blob URLs only); HTML and SVG never rendered; warning for executable types | `FILE_QUOTAS` (D-07-01), pending-upload limit; `PREVIEWABLE_IMAGE_TYPES`; `safeDownloadName`; risky-extension confirmation; CSP `img-src blob:` | `files-upload.test.ts`, `files.spec.ts`; `packages/crypto/src/files.test.ts` (names) | | Met |
| | Playwright confirms HTML and SVG never render inline; filenames with path characters do not influence storage keys | Page and SVG downloads, no frame, no script run, URL unchanged; object keys are server-generated | `files.spec.ts`, `files-upload.test.ts` | | Met |

## 2. Architecture-conflict review

The normative sources agree and no decision was missing for the protocol itself: the FEK, the encrypted manifest, the wrap under RWK_v with `cm.dek.wrap` (itemType `file`, revision 0), the single-shot AES-256-GCM limit (CP-19), the ciphertext hash, the object key rules, the states `PENDING_UPLOAD`, `AVAILABLE` and `DELETED`, the tombstone behaviour and the presigned URL lifetimes (CP-20) are specified in cryptographic-architecture 6.1, key-hierarchy, data-model 4.11 and 5, data-flow DF-07 and DF-08, and the Jira items. Chunking is explicitly out of the baseline (OCD-09). The points the sources leave open are recorded as decisions below, none contradicting a normative source.

## 3. Decisions and deviations

| ID | Decision | Reason |
|---|---|---|
| D-07-01 | Quotas: 1024 MiB of ciphertext per room, 2048 MiB per account, at most 5 uploads in `PENDING_UPLOAD` per account (`FILE_QUOTAS`). Counted over every file that is not DELETED | CM-T041 requires quotas but no document fixes values. The values bound use of the shared bucket and the number of upload capabilities one account holds (T-26); they are code constants and change with the policy catalogue (CM-T046) |
| D-07-02 | An upload not completed within 15 minutes is abandoned (`FILE_LIMITS.completionWindowMs`) | DF-07 says abandoned uploads are removed "after the presigned URL has expired" (5 minutes); a PUT that starts just before expiry on a slow link needs longer to finish, so completion keeps a window beyond the URL lifetime |
| D-07-03 | `GET /files` returns the key material of every readable file | One request lets the browser decrypt names for the list; the data is the same the per-file read returns and is withheld under the same rule (PC-12) |
| D-07-04 | Migration `20261007000000_encrypted_files`: `object_deleted_at`, worker indexes, the stricter object-key CHECK and the guard trigger | See data-model section 7.1. No grant changes |
| D-07-05 | `aws4fetch` 1.0.20 as the request signer (LIB-09) instead of the AWS SDK | Minimal supply-chain surface for four S3 operations; release age and lockfile policies satisfied |
| D-07-06 | The API refuses to start with presigned URLs on the application host | Finding SF-07-01 below |
| D-07-07 | Upload by `fetch` (no progress bar), `credentials: 'omit'` | Same finding; XHR sent the session cookie to storage in WebKit |
| D-07-08 | The CSP gains the storage origin in `connect-src` (set at build time by `CM_STORAGE_ORIGIN`, default `https://localhost:4174`) and `blob:` in `img-src` | Required by presigned URLs and image previews; no `unsafe-inline`, no `unsafe-eval`; the build fails on a wildcard, a path or a non-TLS remote origin |

**Finding SF-07-01 (found by the Phase 7 E2E test, fixed before merge).** Browsers keep cookies by host, not by port. In WebKit, the `__Host-` session cookie was sent to the storage endpoint, which was on the application's host with another port, even for a request made with credentials turned off. The storage endpoint cannot use the session, but a cookie sent to a third party endpoint is a leak of a bearer token to a service outside the API's boundary (INV-12). Fix: presigned URLs must be on a different host than the application (startup rule with a unit test); the E2E storage endpoint is `localhost` while the application is `127.0.0.1`, and refuses any request with a cookie; the upload uses `fetch` with `credentials: 'omit'`. Regression: `tests/e2e/files.spec.ts` asserts that no request to storage carries a cookie or a Referer, in all three engines; `env.test.ts` covers the startup rule.

## 4. Security review of the Phase 7 change

Answers to the review questions of Prompt 09 section 22, with the evidence:

1. *Can the API read plaintext uploaded files?* No. The API receives the wrapped FEK, the encrypted manifest and sizes; file bytes go to storage. Canary scan: EV-07-05.
2. *Can storage administrators read plaintext?* No. Objects are AES-256-GCM ciphertext (EV-07-02). They see sizes and times (L-47).
3. *Can PLATFORM_ADMIN decrypt a file without membership?* No. They receive 404 on every file route (BOLA, PA-05) and hold no room key.
4. *Can a file DEK be obtained without the proper RWK?* No: it exists only wrapped under RWK_v, which only members derive from a verified room key.
5. *Can a wrapped DEK be moved into another room or file?* No: `cm.dek.wrap` binds room, key version, item type, file and revision; tests for each substitution; NC-07-03.
6. *Can an attacker substitute a different object?* A different object fails the stored hash and the AES-GCM tag, which binds room and file ID (tests; NC-07-02). A storage administrator can delete or replace objects (denial, not disclosure).
7. *Can a chunk be modified undetected?* There are no chunks; the single tag covers the whole file.
8. *Can chunks be reordered or truncated undetected?* No chunks; truncation and extension fail the length and the tag.
9. *Can an unauthorized user obtain Room B file content?* No: BOLA suite over six file routes; the storage URL is issued only after authorization and is bound to one object.
10. *Can an attacker abuse a storage identifier?* Keys are random, server-generated, not secret by design (OL-09) and useless without a signed URL; anonymous reads and listings are refused; the runtime credential cannot list.
11. *Can an upload be completed without validation?* No: HEAD size check, uploader-only, state and room checks under locks.
12. *Can an aborted upload leave a publicly readable object?* The bucket is private; an abandoned upload's object is deleted at cancellation or by the worker.
13. *Can sensitive filenames leak through storage paths?* No: keys are random; the database CHECK refuses other forms.
14. *Can the browser persist an unwrapped DEK?* No: the FEK is a non-extractable decrypt-only key held in a closure; nothing is stored (browser storage inspection in E2E, NC-07-10).
15. *Can the system decrypt after the Vault is locked?* No: locking drops the room keys; names disappear and downloads are unavailable at once (E2E).
16. *Can wrong-version key material be accepted?* No: `openFile` refuses a key of another room or version, and a relabelled record fails the AAD (tests).
17. *Can a malicious file become executable trusted page content?* No: downloads are opaque attachments, previews only for four raster types through `blob:`, no inline script or style, CSP unchanged in strictness (E2E, CSP violation checks).
18. *Can a removed member retrieve new ciphertext?* No: removal ends membership and the file routes answer 404; the room is write-locked. What they already downloaded stays with them (L-48).
19. *Are already-downloaded files honestly excluded?* Yes: the Files panel text and L-48.
20. *Did Phase 7 implement later features?* No rekey, notes, secrets, audit chain or policy engine. The write-lock checks are the existing INV-07/PC-16 rules; the `WRAP_LIMIT_REACHED` reason already existed in the schema.

Open items: the CP-19 memory figure and phone behaviour (L-47); bucket lifecycle rules and versioning (Phase 19); per-address rate limits for the new routes arrive with Nginx (Phase 17); audit rows for file events wait for the hash chain (Phase 12): events go to the log through the security-event catalogue.

## 5. Remaining after Phase 7

Notes (Phase 8) and secrets (Phase 9) follow. The rekey (Phase 11) will re-wrap nothing in files (CD-12): old files keep their key version, which is why every file names it and the Files panel opens each with its own version. Phase 16.5 is reserved for the complete UI redesign; the Files panel follows the current style.

## 6. Verification in Prompt 09

Gates on the final Phase 7 code (2026-10-11, local PostgreSQL and storage), recorded in EV-07-08:

| Gate | Result |
|---|---|
| `pnpm install --frozen-lockfile`, `pnpm format:check`, `pnpm lint`, `pnpm typecheck` | Pass |
| `pnpm test` | 1876 tests in 75 files (Phase 6: 1734 in 71). New suites: `packages/crypto/src/files.test.ts` (41 tests), `tests/files` (33: upload 18, access 11, cleanup 4); extended: `bola.test.ts` 132 tests over 22 room routes (was 98 over 16), database constraints, storage configuration, file-rule drift, redaction and CSP tests |
| `pnpm test:e2e` (three engines, one worker) | 83 passed, 10 skipped by design (single-engine tests); was 70 and 8. `files.spec.ts`: 5 tests, 13 results, 2 skipped (the cross-engine test runs once from Chromium) |
| `pnpm security:negative-controls` | 69 of 69 caught (ten Phase 3, seventeen Phase 4, twenty-two Phase 5, ten Phase 6, ten Phase 7), both baselines pass, 38 source files restored byte for byte. One earlier full run printed a failing Vitest baseline whose failures were all `Timeout waiting for worker to respond` in heavy crypto tests (machine load); the same files then passed alone (1422 tests) and a full rerun was clean |
| `pnpm test:coverage:crypto` | 98.7% statements, 93.2% branches (gate 90%) |
| `pnpm test:coverage:authz` | 97.3% statements, 98.3% branches |
| `pnpm build`, `pnpm smoke:api`, `pnpm sbom:generate`, `db:validate`, `db:check-schema`, `db:drift` | Pass; migrations from zero are exercised by `tests/database/migrations.test.ts` |
| `pnpm audit:deps` | Pass (no known vulnerabilities) |
| Secret scan (gitleaks, all commits) | No leaks. The staged-change scan is run before the commit |
| `pnpm bench:files` | 50 MiB in about 150 ms (Chromium, Firefox) to 0.9 s (WebKit); memory not measured (crypto-decisions section 9) |

Local notes: the files suites and the E2E tests need the local storage (`pnpm services:up && pnpm storage:bootstrap`) and the migrated database (`pnpm db:migrate`); run E2E and the negative controls one at a time, E2E with `--workers=1`. The advisory lock in `scripts/db/lib.mjs` fixed a `tuple concurrently updated` race between test projects that prepare the shared roles. A first E2E run found the integrity-error locator ambiguous (Next.js renders an empty route announcer with `role="alert"`); the test now targets the message text.

## 7. Merge and CI

Recorded after the merge by the post-merge handoff pull request: pull request number, CI run, merge commit and evidence EV-07-11.
