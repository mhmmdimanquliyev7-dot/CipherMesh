# Phase 0 Security Architecture Review

Status: completed 2026-09-28 and approved; kept as the historical record of the Phase 0 review. Jira item: CM-T005. Reviewed material: every document under `docs/`, CLAUDE.md and README.

> **Revised in Phase 0.5.** An external review found that some Phase 0 resolutions claimed too much or were impractical. The rows marked "revised in Phase 0.5" below point to the current design, and the full record is in [architecture-gate-phase-0-5.md](architecture-gate-phase-0-5.md). Summary: the commitment does not protect against a malicious server, so the Room Safety Code was added (ADR-012). The one-transaction remove-and-rotate was replaced by the rekey state machine (ADR-013). Secrets use the common envelope pattern with only the SEK RSA-wrapped. Object storage is no longer called PaaS (ADR-006). The audit signing key now has an explicit trust model (ADR-009).

## 1. Method

1. **Design review** against the checklist requested for Phase 0: cryptographic design mistakes, nonce management, unsafe key storage, circular key dependencies, authorization gaps, misleading security claims, cloud-responsibility confusion and unnecessary complexity.
2. **Cross-document consistency review**: reading the documents against each other for contradictions in rules, values and identifiers.
3. **Automated checks** (scripts run in the review session):
   - every relative Markdown link resolves;
   - every referenced identifier (T, L, CP, CD, OCD, PC, AZ, PA, SS, OL, INV, DF, TB, LIB, SD, CM-T, ADR, EV) exists in its defining document;
   - Mermaid blocks contain no characters known to break rendering, and code fences are balanced;
   - backlog dependencies resolve, contain no cycles and use only approved labels;
   - repeated parameters (session lifetimes, auto-lock, presigned URL lifetimes, cryptoperiods, entropy, bounds, file size) agree everywhere;
   - marketing terms ("unhackable", "military grade", "zero knowledge", "tamper-proof", "perfect security") appear only inside rules that forbid them.

## 2. Results by review category

| Category | Result | Findings |
|---|---|---|
| Cryptographic design mistakes | Six issues found and resolved in the design | AR-01, AR-02, AR-03, AR-05, AR-16, AR-17 |
| Nonce management | Resolved structurally: IVs generated internally, one DEK per item version, usage bounds | AR-04 |
| Unsafe key storage | Four issues found and resolved | AR-06, AR-07, AR-08, AR-18 |
| Circular key dependencies | None; the protection graph is acyclic | AR-09 |
| Authorization gaps | Six issues found and resolved or documented | AR-10 to AR-15 |
| Misleading security claims | Wording corrected; term scan clean | AR-19 to AR-21 |
| Cloud-responsibility confusion | Three issues addressed in the cloud documents | AR-22 to AR-24 |
| Unnecessary complexity | Several options rejected or deferred | AR-28 |

## 3. Findings

| ID | Category | Severity | Finding | Resolution | Where |
|---|---|---|---|---|---|
| AR-01 | Crypto | High | A plaintext SHA-256 of files stored on the server would let anyone with database access confirm guesses about file contents | Plaintext hash kept only inside the encrypted manifest; the server stores the ciphertext hash | INV-16, CD-09 |
| AR-02 | Crypto | Medium | AES-GCM is not key-committing; a malicious ADMIN could give members different room keys so one ciphertext decrypts differently per member | HKDF-derived room-key commitment verified by every member. **Revised in Phase 0.5:** it detects inconsistency only while the server is honest; the Room Safety Code (ADR-012) covers split views when members compare it | CD-13, T-29 |
| AR-03 | Crypto | Medium | Using room keys directly for content concentrates many GCM invocations under one key and prevents per-item deletion | Room key material is only an HKDF input; the derived wrapping key wraps per-item DEKs; wrap-count bound | CD-04, CD-05, CP-16 |
| AR-04 | Nonce | High | Caller-supplied or counter-based IVs risk reuse across devices and edits | IVs generated inside the crypto package, no IV parameter in the API, fresh DEK per item version | INV-02, INV-03 |
| AR-05 | Crypto | Medium | Envelopes and wrapped DEKs could be moved between rooms, versions, users or items | Canonical contexts as OAEP labels, AAD and HKDF info | Cryptographic architecture section 8 |
| AR-06 | Key storage | High | Deriving the vault key from the login password would give the server what it needs to unlock private keys | Separate Vault Passphrase; no server-side verifier | CD-01 |
| AR-07 | Key storage | Medium | A silent fallback from Argon2id to PBKDF2 would weaken vaults unnoticed | No fallback; fail closed | CD-14, INV-15 |
| AR-08 | Key storage | Medium | Persisting unlocked keys in browser storage would expose them after device theft; the vault also stayed unlocked after server-side session revocation | Keys in memory only; auto-lock; lock on logout, tab close and session invalidation | CP-22 |
| AR-09 | Key dependencies | Info | Checked for cycles | Graph is acyclic; server keys form a separate domain | Key hierarchy section 4 |
| AR-10 | Authorization | High | The server cannot rotate keys; a removal without rotation would leave new content under a key the removed member holds | Atomic remove-and-rotate; rotation-pending blocks writes for all other membership losses. **Revised in Phase 0.5:** replaced by the rekey state machine with an immediate write lock (ADR-013) | INV-07, DF-10 |
| AR-11 | Authorization | Medium | Secrets encrypted under the room key would be readable by any member who obtains the ciphertext | Secrets encrypted to the recipient public key. **Revised in Phase 0.5:** the payload is AES-256-GCM under a per-secret SEK, and only the 32-byte SEK is wrapped to the recipient key (INV-17) | CD-06 |
| AR-12 | Authorization | Medium | "Download permission" and "view-only" were at first framed as enforceable, and VIEWER rules were worded inconsistently | Reframed as API-level issuance of key material and ciphertext; wording aligned in PC-12, AZ-17 and the Inspector | PC-12, L-14 |
| AR-13 | Authorization | Medium | No rule covered rooms whose OWNER account is disabled | Documented: ADMINs keep operating, OWNER-only actions wait, PLATFORM_ADMIN cannot reassign ownership; accepted governance limitation | Authorization model section 2.1 |
| AR-14 | Authorization | Medium | PLATFORM_ADMIN powers were not tied to MFA and step-up | MFA mandatory for PLATFORM_ADMIN; step-up for PA-03 and PA-04 | Authorization model section 4 |
| AR-15 | Authorization | High | Without email verification, a look-alike account could be invited instead of the intended person | New threat T-35 and limitation L-21; identifiers labelled unverified; fingerprint and account age shown; confirmation required in RESTRICTED and prompted in CONFIDENTIAL | T-35, L-21, SS-05 |
| AR-16 | Crypto | Medium | The server acts as public-key directory, enabling key substitution | Fingerprints, RESTRICTED confirmation, immutable keys per key ID, audited key changes, fingerprint re-check for pending invitees at rotation | T-25, L-07, OCD-06 |
| AR-17 | Crypto | Low | A client bug could reuse old room key material for a new version and silently defeat rotation | Rotating and receiving browsers check that the new material does not reproduce the previous commitment | Key lifecycle section 1.4 |
| AR-18 | Key storage | Low | Secrets addressed to a superseded identity key would remain stored but undecryptable | Destroyed on vault reset | Key lifecycle section 3 |
| AR-19 | Claims | Medium | "Burn-after-reading" could be read as guaranteed deletion | At-most-once reveal; backup and copying limitations stated in the UI and documents | L-03, L-12 |
| AR-20 | Claims | Medium | A hash chain alone can be regenerated by a database-level attacker | "Tamper-evident" wording; signed checkpoints in retention-locked storage; offline verifier | ADR-009, L-13 |
| AR-21 | Claims | Low | The Crypto Inspector could imply TLS details that scripts cannot observe | Only "secure context over HTTPS" is shown | Crypto Inspector section 3 |
| AR-22 | Cloud | Medium | Provider encryption at rest could be mistaken for the content protection | Distinction documented | Shared responsibility section 3 |
| AR-23 | Cloud | Medium | Docker-published ports can bypass the host firewall | Only Nginx publishes ports; provider firewall primary; `DOCKER-USER` chain | Deployment architecture section 2 |
| AR-24 | Cloud | Low | Secrets in environment variables are visible through container inspection | Secrets mounted as files | Deployment architecture section 5 |
| AR-25 | Application | Medium | Logging raw failed-login identifiers can capture passwords typed into the username field | Store the user ID or a keyed HMAC only | CP-12, DF-01 |
| AR-26 | Application | Medium | A GET-based reveal can be consumed by link previewers | Reveal by POST only | INV-13 |
| AR-27 | Application | Low | Serving user uploads from the application origin could enable stored XSS | Uploads live on the storage origin and are forced downloads; no user content is served from the application origin | T-11, TB-06 |
| AR-28 | Complexity | Info | Candidate additions reviewed for necessity | Rejected or deferred: organizations, microservices, streaming AEAD, per-user signatures, group key agreement (MLS), HPKE dependency, Merkle transparency log, server-side rendering runtime | ADRs, OCD list |
| AR-29 | Consistency | Low | Wording and value conflicts between documents | Fixed: INV-07 wording versus atomic rotation; rotation-reason enums; envelope deletion row; step-up windows; proposed ADRs no longer presented as settled; error code for platform endpoints | Section 4 |

## 4. Contradictions found and fixed

1. INV-07 said every membership loss marks a room rotation-pending, while the removal flow rotates atomically. INV-07 was changed to distinguish the two cases. (Revised in Phase 0.5: every membership loss now write-locks the room until a rekey completes.)
2. PC-12, AZ-17 and the Crypto Inspector disagreed on whether RESTRICTED VIEWERs see file metadata. All now say: server-side metadata only, no key material or ciphertext.
3. Step-up validity was not defined in one place. The policy profiles now define 15 minutes, 5 minutes for downgrades, and step-up in every profile for room deletion and ownership transfer.
4. Room rotation-pending reasons and key-version reasons used different names for the same events. The room enum was aligned.
5. The deletion table lacked envelope deletion. A row was added.
6. CLAUDE.md presented ADR-011 as settled. It now marks ADR-007, ADR-010 and ADR-011 as Proposed.
7. Platform endpoints had no defined response for non-admins. They return 404.
8. The data-flow invitation step required "exactly the allowed versions", which an inviter who joined later cannot satisfy. It now requires the current version and allows older ones where the history rule permits.

## 5. Open decisions for the project owner

| ID | Decision | Recommendation | When |
|---|---|---|---|
| OCD-01 to OCD-11 | Open cryptographic decisions | See [../crypto/crypto-decisions.md](../crypto/crypto-decisions.md) section 6 | Phases 3 to 12 |
| OD-01 | Cloud provider | Choose with the Phase 17 criteria | Phase 17 |
| OD-02 | Managed frontend hosting | Keep same-origin VM hosting unless time allows | Phase 18 |
| OD-03 | Local S3-compatible emulator | Choose after a licence and maintenance check | Phase 1 |
| OD-04 | Email verification or invite-only registration | Invite-only registration by PLATFORM_ADMIN would reduce T-35 without new SaaS; decide before Phase 3 | Before Phase 3 |
| OD-05 | Ownership recovery procedure for rooms with a disabled OWNER | Defer | After Phase 11 |
| OD-06 | Repository licence | Project owner decision | Before publishing the repository |
| OD-07 | Who acts as security reviewer | A different person from the author where possible | Before Phase 1 |

## 6. Accepted residual risks requiring acknowledgement

T-23 (compromised client, residual High) and every risk treated with "Accept" in the risk register, in particular L-02 (malicious code delivery), L-04 (rotation cannot revoke), L-05 (metadata), L-07 (public-key directory) and L-21 (unverified identifiers).

## 7. Sign-off

| Role | Name | Decision | Date |
|---|---|---|---|
| Project owner | | Pending | |
| Security reviewer | | Pending | |
