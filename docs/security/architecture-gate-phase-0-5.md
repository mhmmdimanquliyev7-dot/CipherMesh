# Phase 0.5 Architecture Gate

Status: completed 2026-09-28, awaiting project owner approval (Jira CM-T082). Supersedes the resolutions marked "revised" in [architecture-review.md](architecture-review.md).

## 1. Scope and method

1. **Corrections.** The five corrections from the external architecture review and the session and CSRF review were applied across every affected document, not one document in isolation (section 2).
2. **Consistency review.** Automated checks were run over all Markdown files:
   - every relative link resolves;
   - every referenced identifier exists (T, L, CP, CD, OCD, LIB, INV, PC, AZ, PA, SS, OL, DF, TB, SD, EV, CM-T, ADR);
   - Mermaid blocks are structurally valid (sequence participants, subgraph and alt/end balance, state transitions);
   - backlog dependencies resolve without cycles, and the CSV agrees with the markdown backlog.

   Targeted searches then looked for contradictions on each topic in the brief (section 5).
3. **Attack review.** Each of the 14 areas in the brief was examined by trying to break the design as documented. Findings are recorded with their result, including those that remain open (sections 3 and 4).

## 2. Corrections applied

| Correction | Decision | Main documents changed |
|---|---|---|
| Secret encryption | One envelope pattern for files, notes and secrets. The payload is AES-256-GCM under a per-secret SEK, and only the 32-byte SEK is RSA-OAEP-wrapped to the recipient. RSA never encrypts content (INV-17, CD-06, CD-17) | cryptographic-architecture 6.3 and 6.4, key-hierarchy, data-model (Secret), data-flow DF-09, crypto-decisions, ADR-003, ADR-004, ADR-007, testing plan, backlog CM-T043 and CM-T044 |
| Commitment claim | The commitment detects inconsistent envelopes only while the server is honest. The new **Room Safety Code** lets members detect split views by comparing six words out of band (ADR-012, CP-24, INV-18) | cryptographic-architecture 7.3 to 7.6, ADR-012, key-hierarchy, security-ui, crypto-inspector, trust-boundaries TB-12, threat model T-29, limitations L-22, backlog CM-T085 |
| Member removal and rotation | The one-transaction remove-and-rotate was replaced by a **rekey state machine**: ACTIVE, REKEY_REQUIRED and REKEYING, with leased operations, a server-computed recipient snapshot, atomic activation, idempotent finalize and crash recovery (ADR-013, CP-25, INV-07) | key-lifecycle, ADR-013, data-model (Room, RekeyOperation), data-flow DF-10, authorization model, policy profiles PC-14 to PC-16, threat model T-21 and T-37, backlog CM-T050 and CM-T051 |
| Audit checkpoint trust | Trust model for scenarios A to E. Level 1 key custody on the worker and Level 2 optional provider key. Worker refuses to sign diverged chains. External witness copies. Migration credentials never on the VM | ADR-009, crypto-decisions CP-14 and OCD-13, key-lifecycle, deployment architecture, threat model T-20 and T-38, limitations L-25, backlog CM-T057 and CM-T087 |
| Object storage classification | IaaS is the VM, PaaS is managed PostgreSQL and SaaS is Jira Cloud. Object storage is described as provider-managed storage with its own responsibility profile | ADR-006, service-models, shared-responsibility, system-overview, CLAUDE.md, README, roadmap |
| Sessions and CSRF | Rotation and invalidation table, 10-session limit, logout, password-change policy. CSRF defended by same-origin verification, a custom header and login-CSRF coverage. SameSite is one layer, not the defence (INV-19) | session-and-csrf (new), ADR-008, threat model T-08 and T-13, authorization model, testing plan |
| Jira priorities | P0 is reserved for gates and foundation controls: 11 P0, 66 P1, 8 P2 and 2 P3, down from 49 P0 | jira-backlog, jira-workflow, jira-import-guide, jira-backlog.csv |

## 3. Attack review

| # | Area | Attack attempted | Defences in the design | Result |
|---|---|---|---|---|
| 1 | Key substitution | The server replaces an invitee's or member's public key, or adds its own key to a rekey recipient list, then unwraps the room key and re-wraps it to the real key | Fingerprints; mandatory confirmation in RESTRICTED rooms and a prompt in CONFIDENTIAL; immutable keys per key ID; key changes audited; recipient review with fingerprints before wrapping; key ID bound in the OAEP label | **Partially mitigated.** Users who do not compare fingerprints remain exposed (L-07, L-18). The Safety Code cannot detect it, because everyone ends up with the same key (AG-03) |
| 2 | Different keys between members | (a) A malicious ADMIN wraps different keys for different members. (b) The server gives one member a key of its own with a matching commitment (a split view). (c) The server gives every member the same key of its own | (a) one immutable commitment per version, checked by clients. (b) Room Safety Code comparison. (c) none | (a) **Mitigated** while the server is honest. (b) **Detectable** only when members compare codes (L-22). (c) **Unresolved** (AG-01, T-36) |
| 3 | Stale key envelopes | The server serves a RETIRED version as current, or hides newer envelopes, so a member encrypts under a key a removed member holds | The honest server rejects writes that do not name the current version (`KEY_VERSION_STALE`); envelopes of departed members are deleted; the key version is an input to the Safety Code; the client warns when offered a version older than one already seen in the session | **Mitigated** against honest-server bugs. A malicious server's rollback is detectable only by comparing Safety Codes, or within a session (AG-04) |
| 4 | Replayed rekey operations | Resubmit an old finalize that includes a removed member's envelope; race two finalizes; replay after a timeout | Finalize bound to operation ID, base version and membership epoch; recipient set computed by the server and compared exactly; idempotent replay by payload digest; closed and stale operations rejected; one live operation per room | **Mitigated** (T-37) |
| 5 | Removed users keep future access | Upload during the removal window; reuse old envelopes; convince the server to re-add them; collude with a server-side attacker | Write lock from the moment of loss until activation; pending uploads cancelled; envelopes deleted; the snapshot excludes the member; the reuse check against the previous version | **Mitigated** for an honest server. With server collusion the attacker can inject a key (AG-01). Past knowledge cannot be revoked (L-04) |
| 6 | Server-delivered malicious JavaScript | A compromised VM or build serves code that captures passphrases and plaintext, or shows fake Safety Codes | Static builds from reviewed commits, strict CSP, Subresource Integrity where possible, published release hashes, no third-party scripts, hardened VM | **Unresolved and inherent** to web delivery (L-02, T-24). Detection is after the fact. Stronger options, such as a code-verification extension or a native client, are out of scope |
| 7 | RSA-OAEP limitations | Encrypt content that exceeds the 318-byte limit; exploit the lack of sender authentication; use a decryption oracle (Manger-style); compromise an identity key to open past envelopes | Only 32-byte keys are wrapped (INV-17) and the wrapper rejects other sizes; decryption happens only in the recipient's browser, which stops after a failure; commitments; OAEP labels | Size limit and oracle **mitigated**. No sender authentication is the root of AG-01. There is no forward secrecy: an identity-key compromise exposes every envelope ever wrapped to that key (existing compromise procedure). Not post-quantum (L-16) |
| 8 | AES-GCM nonce misuse | IV reuse through caller-supplied IVs, counters across devices, or many wraps under one key | IVs generated inside the crypto package, no IV parameter, one data key per item version, bound of 2^20 wraps per room key, fresh wrapping key per vault write | **Mitigated structurally.** The residual risk is implementation bugs, covered by known-answer, property and review tests |
| 9 | Session fixation | Plant a token, through a subdomain cookie or a pre-login cookie, and have it promoted at login | The server never accepts a token it did not issue; new token at login, MFA, step-up and password or MFA change; `__Host-` prefix; separate pre-authentication cookie | **Mitigated** |
| 10 | CSRF | Cross-site form posts, `text/plain` JSON bodies, login CSRF, same-site sibling hosts, `Origin: null` | SameSite=Strict; `Sec-Fetch-Site` or exact `Origin` check on every state change including login; JSON only; custom header forcing a preflight; no CORS; no state change on GET | **Mitigated.** XSS bypasses every CSRF control (T-12) |
| 11 | IDOR and BOLA | Use another room's file, secret, invitation or rekey operation ID; submit a recipient list from the client | Object-level rules OL-01 to OL-13; recipient set computed by the server; route registry; BOLA suite covering the new rekey endpoints | **Mitigated by design.** The residual risk is implementation, covered by the route inventory test |
| 12 | Audit-log forgery | Edit anchored history, rewrite the unanchored tail, append fabricated events, forge checkpoints | Append-only grants and trigger; hash chain; anchors fetched from the bucket before signing; retention-locked anchors; external witness copies; offline verifier; migration credentials never on the VM | **Partially mitigated.** Anchored history is protected. The tail since the last checkpoint, events fabricated during a VM compromise and a full cloud-account compromise without external copies remain (L-13) |
| 13 | Signing-key compromise | Steal the Ed25519 key from the VM, a backup or an evidence file, and sign a forged history | Worker-only mount, file permissions, anchors created before the theft, witness copies, revocation list, optional Level 2 provider key | **Accepted at Level 1:** a VM compromise includes the key (L-25, T-38). Level 2 reduces this to misuse during the compromise |
| 14 | Cloud responsibility confusion | Treat provider encryption as content protection; treat object lock as permanent; call object storage PaaS; store owner credentials on the VM | Documented shared-responsibility matrix per component; lock-mode guidance; classification per ADR-006; credential rules | **Resolved in the documentation.** Verified during Phases 17 to 19 |

## 4. Findings of this review

| ID | Severity | Finding | Status |
|---|---|---|---|
| AG-01 | High | **Unauthenticated key distribution.** RSA-OAEP has no sender authentication, public keys are public, and commitments come from the same server. An attacker with database write access or control of API responses can therefore activate a room-key version it knows, wrapped to every member. Commitments and Safety Codes all match | **Open.** Recorded as T-36 and L-23. Decision OCD-12 (CM-T086, P0) must close before Phase 4. Recommended: per-user ECDSA P-256 signing keys covered by the fingerprint, signing key-version packages and envelopes |
| AG-02 | Medium | The Phase 0 commitment claim was too strong: it covered only an honest server | **Fixed** in the documentation. The Room Safety Code was added. Residual: detection needs people to compare (L-22) |
| AG-03 | Medium | **Server-controlled recipient set.** The rekeying client wraps for the recipients the server lists. A hidden extra recipient (a ghost member) or a substituted key receives the new room key | **Partially mitigated** by the recipient review with fingerprints and by RESTRICTED confirmation. OCD-12 and fingerprint pinning (OCD-06) would strengthen it |
| AG-04 | Medium | **Version rollback across sessions.** A malicious server can hide newer key versions from a member who has no memory of them across sessions | **Partially mitigated** by in-session version tracking and the version inside the Safety Code. Storing the highest version seen per room as non-secret browser data is considered together with OCD-06 |
| AG-05 | Medium | Removal and rotation in one transaction (Phase 0) was not realistic, because only a member's browser can create keys | **Fixed** by the rekey state machine (ADR-013) |
| AG-06 | Low | A malicious OWNER or ADMIN can keep a room write-locked by abandoning rekey operations | **Mitigated** by the start rate limit and OWNER cancellation. Residual availability risk (L-24) |
| AG-07 | Low | Referrer-Policy `no-referrer` makes browsers send `Origin: null` for HTML form posts. That would break Origin-based CSRF checks for forms | **Fixed by design:** the client uses fetch() only, Referer is not used, and a test covers the Origin behaviour in three engines |
| AG-08 | Low | Room Safety Code mismatch reports can be abused to create noise | **Mitigated** by rate limits. Reports are statements, not verdicts |
| AG-09 | Medium | At Level 1 the audit signing key lives on the VM | **Accepted** with Level 2 as an option (L-25, OCD-13) |

## 5. Consistency review results

| Topic searched | Result |
|---|---|
| Direct RSA encryption of content | Only prohibitions and correct statements remain. Every content path is AES-256-GCM |
| Room Safety Code | Derivation, 66 bits and six words are consistent in ADR-012, CP-24, the cryptographic architecture, the key hierarchy, security-ui and the backlog |
| Room key commitments | No remaining claim that the commitment protects against the server |
| Member removal, key rotation, write locking, old key versions | The rotation-pending wording was replaced everywhere. Removal never rotates in the same transaction. `REKEY_REQUIRED`, `KEY_VERSION_STALE` and the rekey error codes are used consistently in the authorization model, policy profiles, data flows, ADR-013 and the backlog |
| Audit signing guarantees | Every statement about signatures now names the key-compromise limit |
| Object storage and PaaS | PaaS refers only to managed PostgreSQL, or to optional managed frontend hosting. Object storage is "provider-managed" everywhere |
| Session security | No document says SameSite prevents CSRF on its own |
| Jira priority meanings | One definition, in jira-workflow, used by the backlog, the CSV, the import guide and CLAUDE.md |
| Terminology | Accounts are *disabled*, and their memberships become *SUSPENDED*. Every usage was aligned |

The automated checks passed: every link resolves (after this record was added), no identifier is out of range, all 27 Mermaid diagrams are structurally valid, and the 87 backlog items have no dependency cycles. The CSV has 103 rows (16 epics and 87 tasks), with parents and dependencies that resolve. The CSV and markdown agree on every priority.

## 6. Unresolved risks (recorded, not hidden)

| Risk | Where recorded | Treatment |
|---|---|---|
| Server-injected room key (AG-01) | T-36, L-23, OCD-12 | Decide before Phase 4 (gate CM-T086) |
| Malicious JavaScript from a compromised server | T-24, L-02 | Accepted. Inherent to web delivery |
| Compromised user device | T-23, L-01 | Accepted (residual High) |
| Key substitution and ghost recipients when users skip fingerprint checks | T-25, L-07, L-18, AG-03 | Partially mitigated. OCD-06 and OCD-12 |
| Split views when members skip Safety Code comparison | T-29, L-22 | Accepted as an optional manual control |
| Removed members keep what they already had | T-21, L-04 | Accepted, stated in the UI |
| Audit tail and signing key under VM compromise | T-20, T-38, L-13, L-25 | Level 1 accepted, Level 2 optional |
| Rooms read-only until an OWNER or ADMIN rekeys | L-24 | Accepted, visible on the dashboard |
| Unverified email identifiers | T-35, L-21 | Partially mitigated. Decide on invite-only registration (OD-04) before Phase 3 |

## 7. Open decisions and gates

| Gate | Decision | Before |
|---|---|---|
| CM-T082 | Approval of this Phase 0.5 baseline | Phase 1 |
| OD-07 | Who acts as security reviewer | Phase 1 |
| OD-03 | Local S3-compatible emulator. **Resolved in Phase 1:** SeaweedFS, because the MinIO community edition was archived (engineering-baseline.md section 5) | Phase 1 (CM-T011) |
| OD-04 | Invite-only registration or email verification | Phase 3 |
| OCD-03, OCD-05 | Server Argon2id parameters, pepper | Phase 3 |
| **CM-T086 (OCD-12)** | **Authenticated key versions and envelopes** | **Phase 4** |
| OCD-02, OCD-04 | Browser Argon2id library and parameters; RFC 8785 implementation | Phase 4 |
| OCD-01, LIB-08 | RSA-OAEP labels across browsers; Safety Code word list | Phase 6 |
| OCD-13 | Level 2 audit signing | Phase 19 (optional) |

## 8. Readiness verdict

**READY for application implementation, starting with Phase 1 (Repository and Application Foundation).** Phases 1 to 3 do not depend on the open cryptographic decisions.

The architecture is **not yet ready for Phase 4 (Cryptographic Identity and Vault)**. Gate CM-T086 (OCD-12) must close first, because its outcome may add a signing key to the identity format and signatures to envelopes and key versions. The Phase 2 schema can absorb that change through a migration, but deciding OCD-12 early, in parallel with Phases 1 to 3, avoids rework.

## 9. Sign-off

| Role | Name | Decision | Date |
|---|---|---|---|
| Project owner | | Pending | |
| Security reviewer | | Pending | |
