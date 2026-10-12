# Phase 9 Traceability

Status: implemented on 2026-10-12 (Prompt 11): CM-T043 and CM-T044, verified on branch `feature/CM-T043-burn-secrets`, created from `main` at `e52f554` (the Phase 8 handoff merge, pull request #27). Merged into `main` through pull request #28, merge commit `208cdd9` (`208cdd946b9acac185a1b5d8adc4b6e228d9670d`; parents `e52f554` and `09584e5`); CI run 38214636993 passed every job on the first attempt (EV-09-08). CM-T045 (external one-time links, P3 stretch) was not built (D-09-13). Backlog items: [jira-backlog.md](jira-backlog.md) (CM-EPIC-08). Specification: [../crypto/cryptographic-architecture.md](../crypto/cryptographic-architecture.md) sections 6.3 and 11, [../architecture/data-flow.md](../architecture/data-flow.md) DF-09, [../architecture/data-model.md](../architecture/data-model.md) 4.13 and 5, [../security/authorization-model.md](../security/authorization-model.md) section 9.10, crypto-decisions CD-06, CD-17, CD-32, CP-02, CP-29, INV-13, INV-14, INV-17.

## 1. Work items

### CM-T043 Recipient-bound secrets with envelope encryption and expiration

P1, crypto, backend, frontend; depends on CM-T036 and CM-T027. Security considerations: CD-06, CD-17; T-05, T-07.

| Requirement | Implementation | Tests | Evidence | Result |
|---|---|---|---|---|
| A fresh SEK per secret; the payload under AES-256-GCM with AAD `cm.secret.payload`; only the 32-byte SEK wrapped with RSA-OAEP to the recipient's ACTIVE key, label `cm.secret.sek-wrap` | `packages/crypto/src/secrets.ts` (`encryptSecret`, `openSecret`), `secret-format.ts`, `importDataKey` in `aead.ts` (CD-32) | `secrets.test.ts` (OpenSSL in both directions); NC-09-01, NC-09-02 | EV-09-04 | Met |
| The recipient must be an ACTIVE member with that key; the room ACTIVE | API: recipient membership and identity locked and checked (OL-03). Browser: the key must be named by the room's verified statements (`authenticateRoomMember`, `authenticateSecretRecipient`); `encryptSecret` accepts nothing else | `secrets-lifecycle.test.ts` (recipient validation), `secrets.test.ts` (substituted key, outsider, forged grant); NC-09-03, NC-09-04 | | Met |
| **AC:** The stored row holds only the AES-256-GCM ciphertext, IV, wrapped SEK, suite and context identifiers (INV-17) | Schema unchanged (no text column); strict request schema; the payload CHECK bounded to 16,400 bytes | `secrets-lifecycle.test.ts` (row contents, canary scan in five encodings over every table, the log and the events), `secrets.spec.ts` (request keys, stored row, browser storage) | EV-09-04, EV-09-05 | Met |
| **AC:** The RSA wrapper rejects anything but a 32-byte key, and no code path RSA-encrypts the payload | `wrap32` unchanged (32 bytes only); `encryptSecret` passes it only the SEK; the payload is AES-GCM output | `rsa-oaep.test.ts` (sizes), `secrets.test.ts` (wrapped SEK is one OAEP block of a 32-byte value; payload length is document plus tag), review of every `wrap32` call site | | Met |
| **AC:** Other members cannot obtain the ciphertext through the API, and a test shows they cannot unwrap the SEK with their own keys | Lists carry metadata only (OL-14); the reveal answers only the stored recipient (OL-06) | `secrets-lifecycle.test.ts` ("only the recipient can reveal", "other members cannot unwrap"), `secrets.test.ts` (relabelled record), `bola.test.ts`; NC-09-08 | | Met |
| **AC:** Lifetime bounds per profile; expired secrets refused; creation refused while write-locked | `SECRET_RULES` (PC-09, PC-10) and `SECRET_LIMITS` (CP-29) checked on locked state; expiry checked at the moment of the reveal (INV-14); `REKEY_REQUIRED` (PC-16) | `secrets-lifecycle.test.ts` (three profiles, minimum, write lock, expiry), `secrets-concurrency.test.ts` (expiry while waiting), `profile-requirements.test.ts`; NC-09-07 | | Met |
| Metadata-only listing | `GET /rooms/{roomId}/secrets` (AZ-32, OL-14) | `secrets-lifecycle.test.ts` (lists), `bola.test.ts` | | Met |
| Revocation (AZ-25) | `POST /rooms/{roomId}/secrets/{secretId}/revoke`, `own` decided by the stored sender | `secrets-lifecycle.test.ts`, `secrets-concurrency.test.ts` (reveal against revocation); NC-09-09 | | Met |

### CM-T044 Atomic burn-after-reading reveal

P1, backend, security, testing; depends on CM-T043. Security considerations: INV-13; L-03 and L-12 shown in the UI and report.

| Requirement | Implementation | Tests | Evidence | Result |
|---|---|---|---|---|
| POST only; locking transaction; payload ciphertext and wrapped SEK set to NULL in the same transaction | `SecretService.revealSecret`: locks the user row, the room, the membership and the secret row (secret ID AND room ID AND recipient = caller), re-checks AZ-24, refuses non-ACTIVE, expired and retired-key secrets, then `releaseSecret` returns the old values and writes REVEALED with NULLs in one conditional statement; the response is built after the commit | `secrets-lifecycle.test.ts`; NC-09-05 | EV-09-01 | Met |
| **AC:** Many parallel reveal requests produce exactly one success | Row locks plus a conditional `UPDATE ... WHERE status = 'ACTIVE'` re-evaluated by PostgreSQL on the newest row version; the guard trigger makes REVEALED final | `secrets-concurrency.test.ts`: two tabs, twenty reveals over two API instances with their own pools (one 200, nineteen 409, one decryptable copy, one event), forced by row-lock barriers; NC-09-06 | EV-09-02 | Met |
| **AC:** GET requests never consume a secret; a second reveal fails | No GET route releases anything (reviewed list in `route-inventory.test.ts`); the reveal is a POST with an empty JSON body through the CSRF gate | `secrets-lifecycle.test.ts` (lists repeated, GET on the reveal path is 404), `secrets.spec.ts` (page load reveals nothing, second reveal 409, also after a reload); NC-09-10 | EV-09-01 | Met |
| **AC:** After reveal, the database row holds no payload ciphertext or wrapped SEK | CHECK `(status = 'ACTIVE') = (wrapped_sek IS NOT NULL)` (schema v1), material removed together; trigger `cm_guard_secret_change` | `secrets-lifecycle.test.ts`, `constraints.test.ts`, `secrets.spec.ts` | EV-09-01 | Met |
| At-most-once delivery; UI warning that the recipient can still copy the text (L-03, L-12) | Explicit, warned reveal; the vault must be unlocked before the request is sent; the card states what the server sees, that copying cannot be prevented and that backups keep ciphertext | `secrets-concurrency.test.ts` (client disconnect: the committed burn is final), `secrets.spec.ts` | EV-09-03 | Met |
| Burn mandatory in RESTRICTED (PC-10) | `BURN_REQUIRED`; the checkbox is fixed on in RESTRICTED rooms | `secrets-lifecycle.test.ts`, `profile-requirements.test.ts` | | Met |

## 2. Architecture-conflict review

The normative sources agree: DF-09 (creation and reveal sequence, POST, locking transaction, NULLing in the same transaction, at-most-once delivery, write lock), cryptographic-architecture 6.3 (fresh SEK, AES-256-GCM with `secret.payload`, RSA-OAEP with `secret.sek-wrap` binding room, secret, recipient user, recipient key and suite), section 11 (burn semantics and their limits), the context catalogue (both contexts implemented since Phase 4), CD-06, CD-17, CP-02, data model 4.13 (fields, statuses, NULL rules) and section 5 (burn, expiry, revoke; expiry sweep), AZ-23 to AZ-25, OL-03 and OL-06, PC-09, PC-10 and PC-16, INV-13, INV-14 and INV-17. No source contradicts another on a security-relevant detail, so no architecture decision was needed before implementation.

Gaps that the documents left open, resolved as recorded decisions (section 3): the behaviour of a secret without burn-after-reading after its first reveal (data model 7.2 deferred it to Phase 9), the action and visibility of the metadata list, size, minimum lifetime and count limits, how a sender's browser authenticates the recipient key (DF-09 says the API checks it; ADR-015 requires browsers not to trust the server's key claims), and what happens to pending secrets when the recipient leaves or replaces their identity.

Recipient mechanism: room-scoped recipients identified by user and identity key, authenticated by session and membership. There is no bearer token, link or anonymous access in Phase 9; those belong to CM-T045 (D-09-13).

## 3. Decisions and deviations

| ID | Decision | Reason |
|---|---|---|
| D-09-01 | Size (CP-29): a secret document (RFC 8785 `{text, v: 1}`) of at most 16 KiB; the text at least one character of well-formed Unicode; only the canonical serialization is accepted when opening | No document fixed a secret size. 16 KiB holds passwords, recovery codes, tokens and PEM keys; the body limit (128 KiB) is unchanged. The format mirrors CD-31 (one message, a version field, canonical-only parsing) |
| D-09-02 | A secret without burn-after-reading stays ACTIVE after a reveal, records the first reveal in `revealed_at`, and can be revealed again until it expires or is revoked | Data model 7.2 left this to Phase 9; PC-10 makes burn optional outside RESTRICTED, which only means something if a non-burn secret survives a reveal. The schema already allowed it; the trigger now forbids a burn-after-reading secret staying ACTIVE once revealed |
| D-09-03 | The expiry is required, at least 5 minutes and at most the PC-09 maximum of the profile; the database refuses anything over 7 days | Data model 4.13 makes the expiry required; a lifetime too short to be read only adds a row. The 7-day CHECK backs PC-09 in the database |
| D-09-04 | At most 100 ACTIVE, unexpired secrets sent per account (across rooms), counted with the sender's user row locked | Bounds the space one account can take (about 1.6 MiB of ciphertext) and the worker's sweep; per-address request limits stay with Nginx (Phase 17), as for files |
| D-09-05 | AZ-25 "unrevealed" means "not REVEALED": any ACTIVE secret, including a non-burn secret that was revealed, can be revoked; revoking cannot take back what was delivered | A sender must be able to stop further reveals of a non-burn secret. The matrix cells are unchanged |
| D-09-06 | Removing or suspending the recipient revokes their ACTIVE secrets in that room (or rooms) in the removal transaction; a vault reset revokes the ACTIVE secrets wrapped to the retired key in the reset transaction. Secrets the departing member sent stay for their recipients | Data model section 5 destroys secrets to a deleted user; a removed member should not regain a secret if reinstated later (CM-T053), and a secret for a retired key can never be opened. The removal and reset transactions keep their lock order (room before the secret rows; identity row before the secret rows) |
| D-09-07 | New matrix action **AZ-32** "View the room's secret metadata" (Y for every role) with OL-14: MEMBER and VIEWER see what they sent or received, OWNER and ADMIN see every secret of the room | The list needs a matrix action and none covered it (as AZ-31 in Phase 6); OWNER and ADMIN need the list to revoke (AZ-25). No ciphertext is listed |
| D-09-08 | `GET /rooms/{roomId}/members/{userId}/identity` (AZ-01) also returns the member's own grant chain and the signers' identities; the browser verifies the recipient key against the room's statements before wrapping (`authenticateRoomMember`) | DF-09 has the API check the recipient key, but ADR-015 requires browsers to verify keys themselves: a key the server merely claims could be substituted (T-25). The room key material carries only the grants of the signers' chain, so the member's own grant had to be served. Served as stored; the browser verifies everything |
| D-09-09 | A caller who is not the recipient gets the generic 404 for a reveal; the recipient gets 409 `SECRET_UNAVAILABLE` for an already revealed, expired, revoked or retired-key secret, without telling which | Non-recipients must not learn that a secret exists (OL-06); the recipient sees the state in their list anyway |
| D-09-10 | The sender cannot be the recipient (`SECRET_RECIPIENT_INVALID`); the recipient may have any role, VIEWER included | "Create secret for an ACTIVE room member" and AZ-24 (any role reveals) |
| D-09-11 | A secret names no room key version: it is not wrapped under RWK_v, so `KEY_VERSION_STALE` does not apply; PC-16 applies through the key state. Reveals and revocations stay allowed while a room is REKEY_REQUIRED | PC-16 blocks new content; a secret that already exists is not new content, and its key is the recipient's identity key, not the room key |
| D-09-12 | The browser refuses to send a reveal while the vault is locked or when the secret names another identity key of the caller | A burn-after-reading secret is destroyed by the request; sending it without the means to decrypt would burn it for nothing |
| D-09-13 | CM-T045 (external one-time links, AZ-26, PC-11, ExternalSecret 4.14) is not implemented | P3 stretch item that depends on CM-T047 (Phase 10); the PC-16 scope question for AZ-26 stays open with it |
| D-09-14 | Secret events (`SECRET_CREATED`, `SECRET_REVEALED`, `SECRET_REVEAL_REFUSED`, `SECRET_REVOKED`) are written at every audit level to the redacted security-event log, with identifiers, flags and reason codes only | DF-09 audits creation and reveal; the hash-chained ledger is Phase 12 (INV-09) |
| D-09-15 | Migration `20261009000000_burn_secrets`: the payload bound, the lifetime bound, REVEALED only with burn, and the guard trigger `cm_guard_secret_change` | No column and no grant changes; see data model 7.1 |

No new dependency was added.

## 4. Security review of the Phase 9 change

Answers to the review questions of Prompt 11 section 24, with the evidence:

1. *Can the API decrypt a burn secret?* No. It receives the payload ciphertext and the RSA-OAEP-wrapped SEK; the SEK is generated, wrapped and dropped in the sender's browser (canary scan EV-09-05; request inspection in `secrets.spec.ts`).
2. *Can a database administrator decrypt it?* No: unwrapping needs the recipient's private key, which never reaches the server. They see metadata (L-55).
3. *Can PLATFORM_ADMIN retrieve plaintext?* No: every secret route answers 404 without membership (BOLA suite, PA-05), and even with membership only the recipient gets ciphertext, which only the recipient's key opens.
4. *Can a different recipient use the intended recipient's envelope?* No: the label names the recipient user and key; another key or a relabelled record fails (`secrets.test.ts`, `secrets-lifecycle.test.ts`).
5. *Can an attacker redeem another room's secret?* No: the secret is loaded by secret ID and room ID and recipient (BOLA class C over four routes; NC-09-08).
6. *Can an identifier leak bypass authorization?* No: no rule relies on an identifier being secret (OL-09); a non-recipient gets 404 whatever ID they hold.
7. *Can a bearer token leak through a request log?* There is no bearer token in Phase 9; authorization is the session cookie (redacted) and membership.
8. *Can a browser preview consume a secret accidentally?* No: no GET releases anything, the reveal is a POST through the same-origin gate, and the UI never reveals on load (NC-09-10).
9. *Can a server or database race allow double redemption?* No: the release is serialized by row locks and a conditional statement that PostgreSQL re-evaluates on the newest row version, across API instances; REVEALED is final in the database (EV-09-02; NC-09-05, NC-09-06).
10. *Can an unauthorized request burn a secret?* No: refusals happen before any write, and every refused mutation in the BOLA suite leaves the `secrets` table unchanged.
11. *Can a replayed request retrieve ciphertext twice?* Not for a burn-after-reading secret: the replay finds REVEALED and gets 409 with no ciphertext. A non-burn secret is meant to be revealed again by its recipient (D-09-02).
12. *Can an expired secret become available again?* No: expiry is checked at the moment of the reveal (INV-14) and the expiry is write-once in the database; the worker removes the material (NC-09-07).
13. *Can a revoked secret be redeemed?* No: REVOKED has no material and is final (`secrets-lifecycle.test.ts`, `constraints.test.ts`).
14. *Can a consumed secret be resurrected?* Not through the API, and not by a writer with the API's grants: the trigger refuses every change to a REVEALED, EXPIRED or REVOKED row (`secrets-lifecycle.test.ts`, `constraints.test.ts`). The table owner can drop triggers (L-26).
15. *Can a failed database transaction leave inconsistent state?* No: the check and the destruction are in one transaction and the response is built after the commit; a transaction that failed released nothing and burned nothing (`secrets-concurrency.test.ts`).
16. *Can the client persist plaintext unexpectedly?* No: text lives in component state only; E2E tests read localStorage, sessionStorage, IndexedDB and caches (NC-09-11). Memory is dropped, not wiped (L-58).
17. *Can modified ciphertext pass authentication?* No: every stored part is authenticated (`secrets.test.ts`; the tampered reveal response in `secrets.spec.ts`).
18. *Can the server substitute recipient keys?* Not without a room member's signature: the sender's browser wraps only to a key the verified room statements name (NC-09-04); an authorized owner colluding with the server remains (L-22, L-07).
19. *Can the platform guarantee that plaintext was viewed?* No. It knows that it released the ciphertext once (L-57).
20. *What happens to already seen or copied secrets?* They stay with the recipient; nothing in CipherMesh can take them back (L-03).
21. *What remains in backups, audit metadata and tombstones?* Backups keep ciphertext and the wrapped SEK until their retention ends (L-12); the tombstone row keeps identifiers, flags and times; events keep identifiers, flags and reason codes (L-55).
22. *Are the residual limitations stated accurately?* Yes: L-03, L-12 and the new L-55 to L-58, shown in the UI where they matter.
23. *Did Phase 9 implement a later feature?* No: no external links (CM-T045), no policy engine, no audit chain, no UI redesign.

A second-order point the review confirmed: the sender of a secret is the server's statement (L-56). The cryptography guarantees that only the intended member can read a secret, not who wrote it.

No vulnerability was found in existing code during the review; there is no new security finding.

## 5. Verification

Gates of Prompt 11 on the final Phase 9 code (2026-10-12, local PostgreSQL and storage), recorded in EV-09-06:

| Gate | Result |
|---|---|
| `pnpm format:check`, `pnpm lint`, `pnpm typecheck` | Pass |
| `pnpm test` | 2044 tests in 81 files (Phase 8: 1956 in 78) |
| `pnpm test:e2e` (three engines, one worker) | 118 passed, 14 skipped by design (was 102 and 12) |
| `pnpm security:negative-controls` | 90 of 90 caught (eleven new), both baselines pass, 49 source files restored byte for byte |
| `pnpm test:coverage:crypto` | 98.79% statements, 94.16% branches (gate 90%) |
| `pnpm test:coverage:authz` | 97.26% statements, 98.3% branches |
| `pnpm build`, `pnpm smoke:api`, `pnpm sbom:generate`, `db:validate`, `db:check-schema`, `db:drift`, `pnpm audit:deps` | Pass; no dependency added or changed |
| Secret scan (gitleaks) | Full history and staged changes: no leaks found |

Two working-tree defects were found and fixed in the final verification, neither in a security control: the unanchored `.gitignore` rule `secrets/` hid `apps/api/src/secrets` and `tests/secrets` from Git (now `/secrets/` and `/infrastructure/**/secrets/`, so credential directories stay ignored and the source directories do not), and `packages/shared/src/authorization.test.ts` still expected AZ-32 to be unknown (it now expects the thirty-two actions; the registry probe uses AZ-99). Those three files had also escaped Prettier while ignored and were formatted.

## 6. Negative controls

Each control writes one real defect into the working tree, runs the tests that must catch it, and restores the file (`scripts/security/negative-controls.mjs`, EV-09-07). The API controls were run with `--show-failures` to confirm that the intended assertions failed.

| ID | Deliberate defect | Detected by | Result |
|---|---|---|---|
| NC-09-01 | The SEK wrap label no longer binds the recipient key | `secrets.test.ts` (OpenSSL decryption with the documented label) | Caught |
| NC-09-02 | The payload AAD no longer binds the secret ID | `secrets.test.ts` (OpenSSL-made secret) | Caught |
| NC-09-03 | Encryption for a recipient that was never authenticated | `secrets.test.ts` | Caught |
| NC-09-04 | Recipient authentication accepts any self-consistent identity (key substitution) | `secrets.test.ts` | Caught |
| NC-09-05 | A burn-after-reading reveal no longer destroys the secret | `secrets-lifecycle.test.ts` (second reveal, row, canary test) | Caught |
| NC-09-06 | The reveal reads without locks and checks state in application memory | `secrets-concurrency.test.ts` (two tabs, twenty racers, removal and expiry races) | Caught |
| NC-09-07 | Expiry not checked at the moment of the reveal | `secrets-lifecycle.test.ts` (expiry) | Caught |
| NC-09-08 | Any member may reveal (recipient rule removed at every layer) | `secrets-lifecycle.test.ts` (only the recipient) | Caught |
| NC-09-09 | Revocation authorized for every member | `secrets-lifecycle.test.ts` (AZ-25) | Caught |
| NC-09-10 | The browser reveals waiting secrets when the list loads | `secrets.spec.ts` main test (Chromium) | Caught |
| NC-09-11 | Revealed text kept in sessionStorage | `secrets.spec.ts` main test (Chromium) | Caught |

## 7. Evidence

In [../report/evidence/phase-09/](../report/evidence/phase-09/), synthetic data only: EV-09-01 (the revealed page; the row after the reveal is asserted by `secrets-lifecycle.test.ts` and `constraints.test.ts`), EV-09-02 (concurrency test output), EV-09-03 (the reveal warning), EV-09-04 (the stored row: payload and a 384-byte wrapped SEK), EV-09-05 (canary scan), EV-09-06 (gates and secret scans), EV-09-07 (negative controls), EV-09-09 (a tampered reveal refused and XSS shown as text). EV-09-08 is the CI run of pull request #28. Pending: the Jira history of CM-T043 and CM-T044 (backlog not imported yet).
