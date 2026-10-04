# Threat Model and Risk Register

Status: Phase 0.5 revision of the Phase 0 model. Review at the end of every phase and whenever an asset, trust boundary, entry point or data flow changes. Related: [../architecture/trust-boundaries.md](../architecture/trust-boundaries.md), [../architecture/data-flow.md](../architecture/data-flow.md), [../security/limitations.md](../security/limitations.md), [../security/security-testing-plan.md](../security/security-testing-plan.md).

## 1. Method

- **Scope:** the CipherMesh web client, API, worker, managed PostgreSQL, object storage, VM and the management SaaS used to build it.
- **Approach:** asset-centric analysis over the trust boundaries (TB-xx) and data flows (DF-xx). STRIDE categories are assigned where they fit naturally. Some threats (for example removed members or metadata exposure) are described directly rather than forced into a category.
- **Risk rating:** qualitative, in the style of ISO/IEC 27005. Likelihood and impact are rated Low, Medium or High.

| Likelihood / Impact | Low | Medium | High |
|---|---|---|---|
| **High** | Medium | High | Critical |
| **Medium** | Low | Medium | High |
| **Low** | Low | Low | Medium |

- **Treatment:** Mitigate, Accept (documented in [limitations.md](../security/limitations.md)), Transfer (to a provider under shared responsibility), or Avoid (remove the feature).
- **Inherent risk** is the rating without CipherMesh-specific controls. **Residual risk** is the rating with the listed controls working as designed.

## 2. Assets

| ID | Asset | Security property |
|---|---|---|
| A-01 | Room content plaintext (files, notes, secrets) | Confidentiality, integrity |
| A-02 | Room content ciphertext, wrapped DEKs, key envelopes | Integrity, availability |
| A-03 | Encrypted private keys and Vault Passphrases | Confidentiality |
| A-04 | Room key material (RKM) | Confidentiality |
| A-05 | Account credentials: passwords, Argon2id hashes, TOTP secrets, recovery codes | Confidentiality |
| A-06 | Session tokens | Confidentiality |
| A-07 | Metadata: room names, membership, sizes, timestamps, IP addresses | Confidentiality (privacy) |
| A-08 | Audit ledger and checkpoints | Integrity |
| A-09 | Server secrets: TOTP key, HMAC key, audit signing key, TLS key, cloud and database credentials | Confidentiality |
| A-10 | Application code, build pipeline and dependencies | Integrity |
| A-11 | Infrastructure and service availability | Availability |
| A-12 | Project-management data in Jira and GitHub | Confidentiality, integrity |

## 3. Adversaries

| ID | Adversary | Capabilities |
|---|---|---|
| ADV-1 | External unauthenticated attacker | Network access to public endpoints |
| ADV-2 | Authenticated non-member | Valid account, no membership in the target room |
| ADV-3 | Malicious member | Valid membership with some role |
| ADV-4 | Removed member | Former membership, possibly cached keys and plaintext |
| ADV-5 | Data thief | Read access to a database copy, backups or object storage |
| ADV-6 | Database-level attacker | Read and write access to the database |
| ADV-7 | Server compromiser | Root on the VM, including served code and server secrets |
| ADV-8 | Cloud-account attacker | Control of cloud console or API credentials |
| ADV-9 | Supply-chain attacker | Malicious code in a dependency, base image or CI action |
| ADV-10 | Device attacker | Malware or physical access on a user device |

## 4. Threats

### T-01 Stolen database
- **STRIDE:** Information disclosure
- **Assets:** A-02, A-03, A-05, A-06, A-07, A-08
- **Threat:** An attacker (ADV-5) obtains a copy of the PostgreSQL database.
- **Attack scenario:** Database credentials leak from the VM or CI, a provider snapshot or backup export is exposed, or the database endpoint is reachable from the internet with a weak password. The attacker dumps all tables.
- **Security controls:** Client-side encryption of content, filenames, note titles and secrets; room keys stored only as RSA-OAEP envelopes; Argon2id password hashes; session tokens and recovery codes stored as SHA-256 digests; TOTP secrets encrypted under a key held outside the database; database reachable only from the VM; TLS with certificate verification; least-privilege database roles; provider encryption at rest.
- **Residual risk:** Metadata is disclosed (L-05). Weak passwords and Vault Passphrases can be attacked offline (T-03, T-22).
- **Testing strategy:** Canary scan: E2E tests store unique canary strings in files, filenames, notes and secrets, then a test searches a database dump for them and must find none. Schema review against the "must never exist" list. Connectivity test that non-allowlisted and non-TLS connections fail.
- **Rating:** Likelihood Medium, Impact High, inherent **High**. Treatment: Mitigate. Residual: **Medium**.

### T-02 Stolen object-storage data
- **STRIDE:** Information disclosure
- **Assets:** A-02, A-07
- **Threat:** An attacker reads or copies the content bucket.
- **Attack scenario:** A bucket is made public by mistake, storage keys leak, or a provider-side incident exposes objects.
- **Security controls:** Only AES-256-GCM ciphertext is stored; FEKs are wrapped and live in the database, not in storage; object keys are random and never derived from filenames; public access blocked; presigned URLs short-lived and scoped; storage credential restricted to one bucket.
- **Residual risk:** Object count and sizes are disclosed. An attacker with write access can delete objects (availability), mitigated by versioning.
- **Testing strategy:** Canary scan of the bucket; anonymous GET and LIST attempts must fail; expired presigned URLs must fail.
- **Rating:** Likelihood Medium, Impact High, inherent **High**. Treatment: Mitigate. Residual: **Low**.

### T-03 Stolen password hashes
- **STRIDE:** Information disclosure, then Spoofing
- **Assets:** A-05
- **Threat:** Offline cracking of Argon2id password hashes after T-01.
- **Attack scenario:** The attacker runs a GPU-based guessing attack against the dumped hashes and logs in as users with weak passwords.
- **Security controls:** Argon2id with memory-hard parameters and per-hash salts (CP-05); minimum length and blocklist (CP-06); MFA; the auth password does not unlock the vault, so a cracked password yields no plaintext; parameters upgradeable by rehash on login.
- **Residual risk:** Weak passwords of users without MFA fall eventually, giving access to metadata and ciphertext but not plaintext.
- **Testing strategy:** Unit test that stored hashes use the registered parameters; test that login with outdated parameters triggers a rehash; test that password policy rejects blocklisted passwords.
- **Rating:** Likelihood Medium, Impact Medium, inherent **Medium**. Treatment: Mitigate. Residual: **Low**.

### T-04 Malicious authenticated member
- **STRIDE:** Elevation of privilege, Tampering, Repudiation
- **Assets:** A-01, A-02, A-07
- **Threat:** A member (ADV-3) abuses legitimate access.
- **Attack scenario:** A MEMBER tries to promote themselves, remove others, edit or delete content of others, send spam secrets, or exfiltrate plaintext.
- **Security controls:** Authorization matrix with least privilege; ownership rules (OL-04); ADMINs cannot create ADMINs; two-person approval for ADMIN invitations in CONFIDENTIAL and RESTRICTED; rate limits; audit trail with content-access events at EXTENDED and FULL levels; AAD binding stops ciphertext swapping between items.
- **Residual risk:** A member can copy everything their role lets them read (L-03). Attribution of content to an individual relies on the server (L-09).
- **Testing strategy:** Matrix tests for every action and role; privilege-escalation tests (role fields in bodies rejected, MEMBER role changes denied); tests that MEMBERs cannot edit or delete others' items.
- **Rating:** Likelihood Medium, Impact High, inherent **High**. Treatment: Mitigate and Accept. Residual: **Medium**.

### T-05 Unauthorized room access by a non-member
- **STRIDE:** Information disclosure, Elevation of privilege
- **Assets:** A-01, A-02, A-04, A-07
- **Threat:** An authenticated non-member (ADV-2) reaches room data.
- **Attack scenario:** The attacker guesses or learns a room ID and calls room endpoints, requests envelopes, or asks for presigned URLs.
- **Security controls:** Membership check first on every room route (OL-01); 404 for non-members; envelopes served only to their recipient (OL-05); presigned URLs only after authorization (OL-07); envelopes are useless to anyone except the holder of the matching private key.
- **Residual risk:** An authorization bug could expose ciphertext and metadata, but not plaintext, because the attacker has no envelope wrapped to their key.
- **Testing strategy:** Integration tests calling every room endpoint as a non-member; PLATFORM_ADMIN treated as a non-member in tests.
- **Rating:** Likelihood Medium, Impact High, inherent **High**. Treatment: Mitigate. Residual: **Low**.

### T-06 Broken object-level authorization (BOLA / IDOR)
- **STRIDE:** Elevation of privilege, Information disclosure, Tampering
- **Assets:** A-01, A-02, A-07
- **Threat:** A member of room A manipulates identifiers to act on objects of room B or of other users.
- **Attack scenario:** The attacker calls `/api/rooms/A/files/<fileId of room B>`, changes a room ID in a body, reveals a secret addressed to someone else, or revokes another user's invitation.
- **Security controls:** Every object is loaded by (ID, room ID) (OL-02); body identifiers validated against the room (OL-03); ownership from the database (OL-04); scoped repository functions; route registry forces an action declaration for every route.
- **Residual risk:** New endpoints added without tests. Mitigated by the route inventory test.
- **Testing strategy:** Automated cross-room identifier-swap tests for every resource type and endpoint, expecting 404 and no side effects; route inventory test.
- **Rating:** Likelihood High, Impact High, inherent **Critical**. Treatment: Mitigate. Residual: **Low**.

### T-07 Ciphertext modification
- **STRIDE:** Tampering
- **Assets:** A-01, A-02
- **Threat:** An attacker with write access to storage or the database (ADV-6) modifies, truncates, swaps or replays ciphertext or wrapped keys.
- **Attack scenario:** The attacker flips bits in a file object, swaps wrapped FEKs between two files, moves an envelope to another room, or restores an older note revision.
- **Security controls:** AES-GCM authentication with context-bound AAD for every ciphertext and wrapped key; OAEP labels binding envelopes to room, version, user and key; room-key commitments; ciphertext SHA-256 as an early storage check; decryption fails closed with no partial plaintext; files are immutable.
- **Residual risk:** Tampering destroys availability of the affected item. Rollback of mutable items is not always detectable (L-10).
- **Testing strategy:** Tamper tests: bit flips in content, manifest, wrapped DEK and envelope; swaps between items, rooms and versions; each must fail authentication and show no plaintext.
- **Rating:** Likelihood Low, Impact Medium, inherent **Low**. Treatment: Mitigate. Residual: **Low**.

### T-08 Session theft
- **STRIDE:** Spoofing
- **Assets:** A-06, A-07
- **Threat:** An attacker obtains and uses a valid session.
- **Attack scenario:** Cookie theft through XSS, network interception, session fixation, token leakage in logs or URLs, or an unattended unlocked device.
- **Security controls:** 256-bit opaque tokens in `__Host-` cookies with HttpOnly, Secure and SameSite=Strict; only SHA-256 digests stored; the server never accepts a token it did not issue; rotation at login, MFA verification, step-up and password or MFA changes; other sessions revoked on password, MFA or vault changes; idle and absolute timeouts; at most 10 sessions per user; session list with revocation; tokens never in URLs or logs; HSTS ([../security/session-and-csrf.md](../security/session-and-csrf.md)). A stolen session still cannot decrypt, because unlocking needs the Vault Passphrase.
- **Residual risk:** A live stolen session can perform non-cryptographic actions such as deleting content. Step-up requirements limit destructive actions.
- **Testing strategy:** The `session` suite: cookie attributes; a planted token is not promoted at login (fixation); each rotation and invalidation event; revoked and expired tokens rejected; idle and absolute expiry; session-limit eviction; log search for token values.
- **Rating:** Likelihood Medium, Impact High, inherent **High**. Treatment: Mitigate. Residual: **Low**.

### T-09 Credential stuffing
- **STRIDE:** Spoofing
- **Assets:** A-05, A-07
- **Threat:** Automated login attempts with username and password pairs leaked from other services.
- **Attack scenario:** A botnet tries thousands of leaked pairs from many IP addresses.
- **Security controls:** Rate limits per IP in Nginx and per account and per identifier HMAC in the API; progressive backoff; generic error messages; MFA (mandatory for CONFIDENTIAL and RESTRICTED rooms); password blocklist; failed-login metrics on the Security Dashboard; optional breached-password check deferred.
- **Residual risk:** Distributed low-rate attacks against STANDARD-only users without MFA. Success gives metadata and ciphertext, not plaintext.
- **Testing strategy:** Scripted login bursts must hit 429 and backoff; tests that login attempts are recorded; dashboard shows the spike.
- **Rating:** Likelihood High, Impact Medium, inherent **High**. Treatment: Mitigate. Residual: **Medium**.

### T-10 Online brute force of passwords, TOTP codes and recovery codes
- **STRIDE:** Spoofing
- **Assets:** A-05
- **Threat:** Targeted guessing against one account.
- **Attack scenario:** The attacker guesses a known user's password, then tries all 6-digit TOTP codes or recovery codes.
- **Security controls:** Per-account progressive backoff (no permanent lockout, to avoid lockout denial of service); at most 5 TOTP attempts per pre-auth state and per time window; TOTP replay protection; recovery codes with at least 100 bits of entropy, single use; audit events for failures.
- **Residual risk:** Backoff slows but does not stop a patient attacker against a weak password; MFA covers this.
- **Testing strategy:** Tests for TOTP attempt limits, replay rejection, recovery code reuse rejection, and backoff timing.
- **Rating:** Likelihood Medium, Impact Medium, inherent **Medium**. Treatment: Mitigate. Residual: **Low**.

### T-11 Malicious file upload
- **STRIDE:** Tampering, Elevation of privilege (on other clients), Denial of service
- **Assets:** A-01, A-11
- **Threat:** A member uploads malware, active content (HTML, SVG with scripts) or oversized files.
- **Attack scenario:** The attacker hopes the platform renders the file inline in the application origin (stored XSS), that another member runs it, or that storage fills up.
- **Security controls:** The server never parses, renders or executes content (it only sees ciphertext); filenames are encrypted and never used as storage paths; downloads are forced to `application/octet-stream` with `Content-Disposition: attachment`; client-side previews limited to an allowlist of image types rendered from blob URLs, never HTML or SVG inline; CSP; size limits (CP-19) and quotas; warning for executable types.
- **Residual risk:** The server cannot scan encrypted files for malware (L-11); members can share malware with each other.
- **Testing strategy:** Upload HTML and SVG payloads and verify they are never rendered inline; path-traversal filenames do not affect storage keys; size-limit and quota tests.
- **Rating:** Likelihood Medium, Impact Medium, inherent **Medium**. Treatment: Mitigate and Accept. Residual: **Medium**.

### T-12 Cross-site scripting (XSS)
- **STRIDE:** Elevation of privilege, Information disclosure
- **Assets:** A-01, A-03, A-04, A-06
- **Threat:** Attacker-controlled script runs in the CipherMesh origin.
- **Attack scenario:** A display name, room name, note or filename contains a script payload that is rendered unsafely. The script runs where the vault is unlocked, reads decrypted content and uses (but cannot export) non-extractable keys.
- **Security controls:** React escaping; no `dangerouslySetInnerHTML`; user content rendered as text only; strict CSP (`script-src 'self'` plus hashes, `'wasm-unsafe-eval'` only, `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`); no third-party scripts; HttpOnly cookies; non-extractable keys; Trusted Types considered in Phase 15.
- **Residual risk:** Any successful XSS compromises everything the victim has unlocked in that tab. This is why XSS is treated as critical for a client-side encryption design.
- **Testing strategy:** XSS payload corpus injected into every user-controlled field and rendered in Playwright with a dialog and console listener; CSP header tests; CSP violation reporting during assessment; DAST scan.
- **Rating:** Likelihood Medium, Impact High, inherent **High**. Treatment: Mitigate. Residual: **Medium**.

### T-13 Cross-site request forgery (CSRF)
- **STRIDE:** Spoofing, Tampering
- **Assets:** A-02, A-07
- **Threat:** Another site makes the victim's browser send state-changing requests with the victim's cookie.
- **Attack scenario:** A malicious page auto-submits a form to remove a member or revoke a secret, or signs the victim into an attacker's account (login CSRF).
- **Security controls:** SameSite=Strict as one layer, not the defence. Same-origin verification on every state-changing request, including login and registration: `Sec-Fetch-Site: same-origin`, otherwise an exact `Origin` match, and requests with neither header are rejected. JSON-only bodies and a required `X-CipherMesh-Request` header, which forces a CORS preflight the API never approves. No state changes on GET; no CORS ([../security/session-and-csrf.md](../security/session-and-csrf.md)).
- **Residual risk:** Low. XSS in the CipherMesh origin bypasses every CSRF defence (T-12). Moving the web client to another origin would require a synchronizer token and an ADR.
- **Testing strategy:** The `csrf` suite: cross-site form posts and foreign-origin fetches; missing custom header; `Sec-Fetch-Site` cross-site and same-site; `Origin: null`; neither header present; login CSRF; content-type rejection; GET handlers without side effects; `Origin` behaviour under `no-referrer` in three browser engines.
- **Rating:** Likelihood Medium, Impact Medium, inherent **Medium**. Treatment: Mitigate. Residual: **Low**.

### T-14 Injection
- **STRIDE:** Tampering, Information disclosure, Elevation of privilege
- **Assets:** A-02, A-05, A-07, A-11
- **Threat:** Untrusted input is interpreted as code or query structure.
- **Attack scenario:** SQL injection through a raw query, prototype pollution through JSON keys such as `__proto__`, log injection with newline characters, command injection, or server-side request forgery.
- **Security controls:** Prisma parameterized queries; lint rule forbidding `$queryRawUnsafe`, `eval`, `new Function` and `child_process`; strict schemas that reject unknown keys; structured logging that escapes values; the server never fetches user-supplied URLs; no user-controlled file paths.
- **Residual risk:** Low, as long as lint rules and review hold.
- **Testing strategy:** Injection payload fuzzing on all string inputs; prototype-pollution tests; lint rules enforced in CI; DAST.
- **Rating:** Likelihood Medium, Impact High, inherent **High**. Treatment: Mitigate. Residual: **Low**.

### T-15 Sensitive information disclosure through the application
- **STRIDE:** Information disclosure
- **Assets:** A-05, A-07, A-09
- **Threat:** The application leaks data through errors, over-broad responses, logs, headers or enumeration.
- **Attack scenario:** An endpoint returns a full user object including `passwordHash`; a production error shows a stack trace; the user lookup reveals which emails are registered; source maps expose internals; the server version header helps an attacker.
- **Security controls:** Explicit response projections with output schemas; generic errors with request IDs; no stack traces in production; exact-match, rate-limited user lookup; server tokens hidden in Nginx; dotfiles denied; source maps not served publicly.
- **Residual risk:** Registration and user lookup reveal whether an email is registered, rate-limited and accepted.
- **Testing strategy:** Output-schema tests failing on unknown fields; tests searching responses for forbidden field names; production-mode error tests; header checks.
- **Rating:** Likelihood Medium, Impact Medium, inherent **Medium**. Treatment: Mitigate and Accept. Residual: **Low**.

### T-16 Exposed environment secrets
- **STRIDE:** Information disclosure
- **Assets:** A-09
- **Threat:** Server secrets leak from the repository, images, CI logs, screenshots or tickets.
- **Attack scenario:** A `.env` file is committed; a secret is baked into an image layer; `docker inspect` shows environment variables; a screenshot in the evidence folder shows credentials.
- **Security controls:** `.gitignore` rules; secret scanning in CI and optionally as a pre-commit hook; secrets mounted as files at runtime, never in Dockerfiles or image layers; `.dockerignore`; CI secret masking; evidence redaction rules; least-privilege credentials; rotation procedure.
- **Residual risk:** Human error in screenshots and tickets; mitigated by review before commit.
- **Testing strategy:** Secret scan of the full git history in CI; image history inspection; evidence review checklist.
- **Rating:** Likelihood Medium, Impact High, inherent **High**. Treatment: Mitigate. Residual: **Low**.

### T-17 Compromised cloud credentials
- **STRIDE:** Spoofing, Elevation of privilege
- **Assets:** A-02, A-09, A-10, A-11
- **Threat:** An attacker (ADV-8) controls the cloud console account, API tokens or deployment credentials.
- **Attack scenario:** Phishing of the cloud account, a leaked API token, or reuse of a personal password.
- **Security controls:** MFA on cloud, GitHub and Jira accounts; no daily use of root or owner accounts; per-component credentials with minimal scope; credential inventory and rotation; billing and activity alerts where the provider offers them; client-side encryption keeps stored content confidential even under this attack unless malicious code is deployed (T-24).
- **Residual risk:** Full infrastructure destruction or code replacement is possible. Backups and the ability to rebuild from the repository reduce the impact.
- **Testing strategy:** Configuration review evidence (MFA enabled, scoped keys); test that the storage credential cannot access other buckets.
- **Rating:** Likelihood Low, Impact High, inherent **Medium**. Treatment: Mitigate and Transfer (provider controls). Residual: **Medium**.

### T-18 Misconfigured object storage
- **STRIDE:** Information disclosure, Tampering
- **Assets:** A-02, A-11
- **Threat:** Storage configuration exposes or endangers objects.
- **Attack scenario:** Public-read ACLs, listing enabled, CORS allowing any origin, presigned URLs valid for days, no versioning, or the anchor bucket writable by the API credential.
- **Security controls:** Block-public-access settings; private ACLs; CORS limited to the application origin and to PUT and GET; presigned lifetimes from CP-20; versioning and lifecycle rules for old versions; separate anchor bucket with retention lock and a write-only credential; storage configuration recorded as evidence and verified by a script.
- **Residual risk:** Provider features differ; some controls may be approximated on the chosen provider.
- **Testing strategy:** Anonymous access tests; CORS preflight from a foreign origin must fail; presigned expiry tests; attempt to delete an anchored checkpoint must fail.
- **Rating:** Likelihood Medium, Impact Medium, inherent **Medium**. Treatment: Mitigate. Residual: **Low**.

### T-19 Compromised VM
- **STRIDE:** Elevation of privilege, all categories
- **Assets:** A-01 (for users active during compromise), A-05, A-06, A-07, A-08, A-09, A-10
- **Threat:** An attacker (ADV-7) gains root on the VM.
- **Attack scenario:** An unpatched service, stolen SSH key or container escape gives root. The attacker reads server secrets, reads and writes the database, and replaces the served JavaScript.
- **Security controls:** Hardening (SSH keys only, no root login, allowlisted SSH sources, automatic security updates, minimal packages); only 80 and 443 public; non-root, read-only containers without the Docker socket; secrets as files with restrictive permissions; least-privilege database and storage credentials; audit checkpoints anchored outside the VM; backups; rebuild-from-scratch incident procedure. Migration and database-owner credentials are never stored on the VM, so the attacker cannot disable the append-only audit protection.
- **Residual risk:** **High while compromised.** Users who load the application during the compromise can have passphrases and plaintext captured (L-02). Content at rest stays encrypted for users who do not log in during that window. The attacker also holds the Level 1 audit signing key (T-38) and can activate room-key versions of its own (T-36).
- **Testing strategy:** CIS-guided hardening review with a Lynis report; external port scan; SSH configuration tests (password login refused); Docker Bench for Security report.
- **Rating:** Likelihood Medium, Impact High, inherent **High**. Treatment: Mitigate and Accept. Residual: **Medium**.

### T-20 Audit-record modification
- **STRIDE:** Tampering, Repudiation
- **Assets:** A-08
- **Threat:** An attacker changes or deletes audit events to hide activity.
- **Attack scenario:** A database-level attacker (ADV-6) edits an event, deletes a range, or recomputes the whole chain after editing.
- **Security controls:** API and worker database roles have no UPDATE or DELETE on audit tables, and a trigger rejects such statements; SHA-256 hash chain over canonical records; gap-free sequence numbers; hourly verification; Ed25519-signed checkpoints exported to a retention-locked bucket with a write-only credential; offline verifier that fetches checkpoints independently; the worker refuses to sign when the chain no longer matches the last anchored checkpoint; checkpoints after security-critical events; weekly external witness copies; migration credentials never on the VM. The trust model per compromise scenario is in ADR-009 section 8.
- **Residual risk:** Events after the last anchored checkpoint can be rewritten or truncated by an attacker with full database access; a compromised server can stop recording events (L-13). Signed checkpoints prove nothing once the signing key is compromised, which at Level 1 includes a VM compromise (L-25, T-38).
- **Testing strategy:** Tamper test on a copy: edit, delete and reorder events; recompute the chain without the signing key; the verifier must report the first broken sequence number or the checkpoint mismatch.
- **Rating:** Likelihood Medium, Impact Medium, inherent **Medium**. Treatment: Mitigate. Residual: **Low**.

### T-21 Removed room member
- **STRIDE:** Information disclosure, Elevation of privilege
- **Assets:** A-01, A-04
- **Threat:** A removed or departed member (ADV-4) keeps or regains access to content created after they left.
- **Attack scenario:** The removed member keeps cached keys and downloaded plaintext. They try to use old envelopes or to upload during the removal window. Later they obtain a database leak and try to decrypt new content with the old key.
- **Security controls:**
  - Removal, leaving, suspension and deletion delete all of the member's envelopes and end their API access in one transaction, which also sets the room to REKEY_REQUIRED (INV-07, ADR-013).
  - The room is write-locked until a new version is activated, and pending uploads are cancelled.
  - The server computes the rekey recipient set, excluding the departed member, and finalize rejects any other set.
  - Writes that name an old version fail with `KEY_VERSION_STALE`.
  - The RESTRICTED history rule (PC-07) limits what new members receive.
- **Residual risk:** Information already obtained cannot be revoked (L-04). Old content stays decryptable with old keys if its ciphertext leaks later. Re-encryption is deferred (OCD-07). A server-side attacker colluding with the former member could activate a key version of its own (T-36). The room is read-only until an OWNER or ADMIN completes the rekey (L-24).
- **Testing strategy:** After removal, every room endpoint returns 404 for the removed user. Writes return 409 until finalize. The recipient snapshot excludes the removed user, and a finalize that includes them is rejected. New items use v+1. A test holding the old RKM cannot unwrap DEKs created after the rekey.
- **Rating:** Likelihood High, Impact Medium, inherent **High**. Treatment: Mitigate and Accept. Residual: **Medium**.

### T-22 Stolen encrypted private key
- **STRIDE:** Information disclosure
- **Assets:** A-03, then A-04 and A-01
- **Threat:** Offline guessing of a Vault Passphrase using the encrypted private key from a database copy.
- **Attack scenario:** After T-01, the attacker runs Argon2id with candidate passphrases and the stored salt and parameters, and uses the AES-GCM tag to recognize a correct guess.
- **Security controls:** Argon2id memory-hard parameters with a server-enforced floor (CP-04); passphrase minimum length and blocklist (CP-06); per-vault salt; no server-side verifier; parameters upgradeable.
- **Residual risk:** Weak passphrases fall to targeted attacks (L-08). A cracked vault exposes every room key ever wrapped to that key and every secret sent to it.
- **Testing strategy:** RFC 9106 known-answer tests; client refuses to create or unlock vaults below the floor; API rejects vault uploads below the floor; benchmark documented as evidence.
- **Rating:** Likelihood Medium, Impact High, inherent **High**. Treatment: Mitigate and Accept. Residual: **Medium**.

### T-23 Compromised client or browser
- **STRIDE:** Information disclosure, Spoofing
- **Assets:** A-01, A-03, A-04, A-06
- **Threat:** Malware, a malicious extension or physical access on the user device (ADV-10).
- **Attack scenario:** A keylogger records the Vault Passphrase; an extension reads decrypted notes; someone uses an unlocked, unattended laptop.
- **Security controls:** Keys only in memory; non-extractable keys; vault auto-lock (CP-22); session idle timeout; no plaintext persistence; guidance for RESTRICTED rooms.
- **Residual risk:** **High and accepted.** CipherMesh cannot protect a device that is itself compromised (L-01).
- **Testing strategy:** Playwright checks that no key material or plaintext appears in localStorage, sessionStorage, IndexedDB or cookies after unlock and use; auto-lock timer test.
- **Rating:** Likelihood Medium, Impact High, inherent **High**. Treatment: Accept. Residual: **High** (accepted, documented).

### T-24 Malicious application code delivery
- **STRIDE:** Tampering, Information disclosure
- **Assets:** A-10, then A-01, A-03, A-04
- **Threat:** Users receive modified JavaScript that exfiltrates passphrases or plaintext.
- **Attack scenario:** An attacker controlling the VM (T-19), the TLS key, the build pipeline or a dependency (T-27) serves modified code.
- **Security controls:** Static assets built in CI from reviewed commits; content-hashed immutable filenames; strict CSP; Subresource Integrity where the build supports it; no third-party runtime scripts; published build hashes per release; hardened VM and pipeline.
- **Residual risk:** Inherent to web delivery (L-02). There is no general browser mechanism for users to pin application code.
- **Testing strategy:** CSP and SRI presence checks; CI records and publishes artifact hashes; a comparison script checks that deployed assets match the release hashes.
- **Rating:** Likelihood Low, Impact High, inherent **Medium**. Treatment: Mitigate and Accept. Residual: **Medium**.

### T-25 Public-key substitution
- **STRIDE:** Spoofing, Information disclosure
- **Assets:** A-04, then A-01
- **Threat:** An attacker with control of the server or write access to the database substitutes a user's public key so that room keys are wrapped to the attacker.
- **Attack scenario:** Before an ADMIN invites Bob, the attacker replaces Bob's public key with their own. The ADMIN browser wraps RKM to the attacker key; the attacker unwraps it and decrypts room content.
- **Security controls:** Fingerprints shown in the UI; mandatory fingerprint confirmation in RESTRICTED rooms, checked by the API against the current key; immutable keys per key ID; key changes audited and surfaced to room administrators; recipient key ID bound into the OAEP label.
- **Residual risk:** Users who skip out-of-band verification are exposed to an active server-side attacker (L-07, L-18). Fingerprint pinning is tracked as OCD-06. The Room Safety Code does not detect substitution when the attacker re-wraps the real key to the victim, because everyone then holds the same key.
- **Testing strategy:** In a test database, replace a public key before invitation; the RESTRICTED flow must reject the confirmation; key-change events must appear in the audit log.
- **Rating:** Likelihood Low, Impact High, inherent **Medium**. Treatment: Mitigate and Accept. Residual: **Medium**.

### T-26 Denial of service and resource exhaustion
- **STRIDE:** Denial of service
- **Assets:** A-11
- **Threat:** Attackers exhaust CPU, memory, storage or database capacity.
- **Attack scenario:** Floods of login requests (each costing an Argon2id computation), large or many uploads, audit-log flooding, expensive list queries.
- **Security controls:** Nginx rate limits and body-size limits; API rate limits per user and IP; a concurrency limit for Argon2id computations; upload size limits and quotas; pagination limits; container resource limits.
- **Residual risk:** Volumetric attacks beyond VM capacity (L-20).
- **Testing strategy:** Rate-limit tests; a small load test of the login endpoint to confirm the Argon2id concurrency limit protects memory.
- **Rating:** Likelihood Medium, Impact Medium, inherent **Medium**. Treatment: Mitigate and Accept. Residual: **Medium**.

### T-27 Dependency and supply-chain compromise
- **STRIDE:** Tampering, Elevation of privilege
- **Assets:** A-10, then A-01 and A-09
- **Threat:** Malicious code enters through an npm package, base image or CI action (ADV-9).
- **Attack scenario:** A maintainer account of a popular package is phished and a malicious version is published, as happened to widely used npm packages in 2025. The update steals CI secrets or injects exfiltration code into the web bundle.
- **Security controls:** Few dependencies, each justified in review; lockfile with integrity hashes; dependency lifecycle scripts blocked unless allowlisted; automated vulnerability scanning and dependency review; CI actions pinned to commit SHAs; least-privilege CI tokens; SBOM generation; base images pinned by digest; crypto libraries wrapped behind interfaces and covered by known-answer tests.
- **Residual risk:** A malicious release that passes review and scanning. Delaying adoption of brand-new releases reduces exposure.
- **Testing strategy:** CI audit gate; SBOM artifact per release; review evidence for dependency additions; secret scan of CI configuration.
- **Rating:** Likelihood Medium, Impact High, inherent **High**. Treatment: Mitigate. Residual: **Medium**.

### T-28 Metadata leakage
- **STRIDE:** Information disclosure
- **Assets:** A-07
- **Threat:** The server or a data thief learns sensitive facts from metadata.
- **Attack scenario:** Room names reveal projects; membership reveals relationships; file sizes and timing reveal activity; IP addresses in sessions reveal locations.
- **Security controls:** Encrypted filenames, MIME types and note titles; plaintext hashes only in encrypted manifests; random object keys; room-name warning in the UI; retention limits for sessions and login attempts; no IP addresses in audit details; aggregate-only dashboard for PLATFORM_ADMIN.
- **Residual risk:** Accepted and documented (L-05).
- **Testing strategy:** Schema review; canary scan for filenames; review of dashboard and audit outputs for unnecessary personal data.
- **Rating:** Likelihood High, Impact Low, inherent **Medium**. Treatment: Mitigate and Accept. Residual: **Medium**.

### T-29 Room-key equivocation (different keys for different members)
- **STRIDE:** Tampering, Spoofing
- **Assets:** A-01, A-04
- **Threat:** Members of the same room are made to hold different key material for the same version, so one party can read or alter what others encrypt.
- **Attack scenario:**
  1. A malicious ADMIN wraps RKM_a for Alice and RKM_b for Bob while the server behaves honestly.
  2. A server-side attacker gives Bob a key of its own, with a matching commitment and an envelope. RSA-OAEP needs only Bob's public key. Alice keeps the honest key, and Bob's uploads become readable by the attacker (a split view).
- **Security controls:**
  - One immutable commitment per version, stored server-side and checked by every client. This defeats scenario 1 while the server is honest.
  - Room Safety Code comparison over an independent channel (ADR-012). This detects scenario 2 when members compare.
  - Mismatch reports are audited, and the Security Dashboard counts them (SD-12, SD-15).
- **Residual risk:** Scenario 2 goes undetected for members who never compare codes (L-22). A server-side attacker that gives the same key to everyone is detected by neither control (T-36).
- **Testing strategy:** An envelope with a different RKM is rejected by the commitment check. A test harness serves two browsers different keys and commitments, and their Safety Codes differ. Known-answer vectors for the Safety Code derivation.
- **Rating:** Likelihood Low, Impact High, inherent **Medium**. Treatment: Mitigate and Accept. Residual: **Medium**.

### T-30 Abuse of account recovery and MFA management
- **STRIDE:** Spoofing, Elevation of privilege
- **Assets:** A-05
- **Threat:** An attacker bypasses MFA through recovery or administrative reset.
- **Attack scenario:** The attacker guesses recovery codes, disables MFA from a stolen session, or persuades a PLATFORM_ADMIN to reset MFA.
- **Security controls:** Recovery codes with at least 100 bits of entropy, single use, rate limited; disabling MFA needs step-up (password and current TOTP); administrator-assisted resets follow a documented identity check, need step-up by the admin and are audited; resets never touch the vault, so they grant no plaintext access; no email-based reset exists.
- **Residual risk:** Social engineering of the administrator. The procedure and audit trail make it detectable.
- **Testing strategy:** Tests for recovery-code reuse and rate limits; MFA disable without step-up is rejected; admin reset produces audit events.
- **Rating:** Likelihood Low, Impact High, inherent **Medium**. Treatment: Mitigate. Residual: **Low**.

### T-31 Transport-layer attacks
- **STRIDE:** Information disclosure, Tampering
- **Assets:** A-05, A-06, A-10
- **Threat:** Interception or modification of traffic.
- **Attack scenario:** TLS stripping on first visit, weak cipher suites, mixed content, or an unverified database TLS connection vulnerable to interception.
- **Security controls:** TLS 1.2 and 1.3 only with a modern configuration (CP-21); HTTP redirected to HTTPS; HSTS; no mixed content; database connections verify the provider certificate; object storage accessed over HTTPS only.
- **Residual risk:** First-visit exposure before HSTS is cached, unless the domain is preloaded.
- **Testing strategy:** External TLS scan (for example testssl.sh or SSL Labs) as evidence; test that database connections fail with an untrusted certificate.
- **Rating:** Likelihood Low, Impact High, inherent **Medium**. Treatment: Mitigate. Residual: **Low**.

### T-32 Server-side rollback or withholding
- **STRIDE:** Tampering, Denial of service
- **Assets:** A-02
- **Threat:** The server serves older versions of mutable data or hides items.
- **Attack scenario:** A database-level attacker restores an older note revision or an older vault record, or hides a member from the member list.
- **Security controls:** Revision numbers in AAD; optimistic concurrency; the browser remembers the highest revision seen during a session and warns on regression; audit events for changes.
- **Residual risk:** Not fully detectable without trusted client-side state (L-10).
- **Testing strategy:** Test that a stored revision with a mismatched AAD revision fails; session-level regression warning test.
- **Rating:** Likelihood Low, Impact Low, inherent **Low**. Treatment: Accept. Residual: **Low**.

### T-33 Leakage of external one-time links (stretch feature)
- **STRIDE:** Information disclosure
- **Assets:** A-01
- **Threat:** Someone other than the intended recipient opens an external link first.
- **Attack scenario:** The link is posted in a chat that stores history, or is seen over a shoulder.
- **Security controls:** Only in STANDARD rooms (PC-11); the secret's AES-256-GCM key (SEK) travels only in the URL fragment; POST-to-reveal; burn-after-reading mandatory; maximum 24 hours; `Referrer-Policy: no-referrer`; the recipient sees an "already opened" message, which reveals interception.
- **Residual risk:** Accepted for STANDARD content only.
- **Testing strategy:** Tests that the fragment is never sent to the server, that GET does not consume the secret, and that a second reveal fails.
- **Rating:** Likelihood Medium, Impact Medium, inherent **Medium**. Treatment: Mitigate and Accept. Residual: **Medium**.

### T-34 Leakage through project-management SaaS
- **STRIDE:** Information disclosure
- **Assets:** A-09, A-12
- **Threat:** Sensitive information leaks through Jira or GitHub.
- **Attack scenario:** A ticket or pull request contains a credential, a database dump or a working exploit for an unfixed finding, and the project is visible to more people than intended.
- **Security controls:** Team-only project permissions; MFA; redaction rules; restricted detail for open security findings; secret scanning on the repository.
- **Residual risk:** Low; depends on team discipline.
- **Testing strategy:** Periodic review of permissions and of open security findings; secret scan.
- **Rating:** Likelihood Low, Impact Medium, inherent **Low**. Treatment: Mitigate and Transfer (platform security). Residual: **Low**.

### T-35 Identity spoofing through unverified account identifiers
- **STRIDE:** Spoofing
- **Assets:** A-01, A-04
- **Threat:** An attacker registers an account with another person's email address or a confusable name and receives invitations or secrets meant for that person.
- **Attack scenario:** Knowing that Bob will be invited, the attacker registers Bob's address first; the baseline has no email verification. The inviter looks up the address, sees a plausible display name and invites the attacker, whose browser then receives the room key legitimately.
- **Security controls:** Identifiers are treated and labelled as unverified; the lookup shows the key fingerprint and the account creation date; fingerprint confirmation is required in RESTRICTED rooms and prompted in CONFIDENTIAL rooms; OWNER approval of ADMIN invitations (PC-04); invitation and membership events are audited.
- **Residual risk:** In STANDARD rooms, and where users skip the prompted comparison, an impersonator can be invited by mistake (L-21). Email verification would need an email service, which is new runtime SaaS and requires an ADR.
- **Testing strategy:** Lookup responses and UI label the identifier as unverified; a RESTRICTED invitation without a matching confirmed fingerprint is rejected.
- **Rating:** Likelihood Medium, Impact High, inherent **High**. Treatment: Mitigate and Accept. Residual: **Medium**.

### T-36 Injected room-key version or envelope by a server-side attacker
- **STRIDE:** Spoofing, Information disclosure
- **Assets:** A-04, then A-01
- **Threat:** An attacker who can write to the database or control API responses distributes a key it knows. RSA-OAEP has no sender authentication, public keys are public, and commitments come from the same server. Clients therefore cannot tell that no authorized member created the key.
- **Attack scenario:** Through SQL injection or a compromised VM, the attacker inserts version v+1 with its own RKM. It adds envelopes for every member and a matching commitment, and marks the version current. All members encrypt new content under a key the attacker knows. All Safety Codes match, because everyone holds the same key. A variant injects a single envelope for a newly invited member.
- **Security controls (baseline):**
  - Server-side authorization of rekey operations. It helps only while the server is honest.
  - Parameterized queries and least-privilege database roles, which limit database write access.
  - Audit events for every key version, which a database-level attacker could also forge in the unanchored tail.
  - The UI shows who created each version (server-asserted), and the rekey review lists recipients.
- **Residual risk:** **Unresolved in the baseline** (L-23). Planned mitigation OCD-12: authenticate key-version packages and envelopes cryptographically. The recommended option is per-user ECDSA P-256 signing keys covered by the fingerprint. The alternative is an authenticator chained to the previous room key. Decision gate before Phase 4 (CM-T086).
- **Testing strategy:** Until OCD-12 is implemented, a documented demonstration in a test environment. Afterwards, tests that clients reject unsigned, forged or wrongly attributed versions and envelopes.
- **Rating:** Likelihood Low, Impact High, inherent **Medium**. Treatment: Mitigate (planned); accepted until OCD-12 is implemented. Residual: **Medium**.

### T-37 Rekey operation abuse and incomplete rekeys
- **STRIDE:** Tampering, Denial of service, Elevation of privilege
- **Assets:** A-04, A-11
- **Threat:** Rekey requests are replayed, raced or left incomplete. A removed member could keep access, a stale key could be activated, or a room could stay write-locked.
- **Attack scenario:** An ADMIN's browser repeats a finalize after a timeout. Two ADMINs rekey at the same time. An old finalize payload that includes the removed member's envelope is submitted again. The rekeying browser crashes. A malicious ADMIN keeps starting operations to hold the room locked.
- **Security controls:**
  - One live operation per room with a 10-minute lease, and at most 10 starts per room per hour (CP-25).
  - Finalize is bound to the operation ID, base version and membership epoch.
  - The envelope set must equal the server's recipient snapshot.
  - Replays are idempotent by payload digest, and stale, expired or superseded operations are rejected.
  - Reads continue while locked, the OWNER can cancel another admin's operation, and every transition is audited.
- **Residual risk:** A malicious OWNER or ADMIN can delay a rekey, which harms availability, or leak keys, an insider risk outside the cryptographic model. Rooms without an active OWNER or ADMIN stay read-only (L-24).
- **Testing strategy:** The `rekey` suite: replay, concurrent start, stale epoch, expired lease, wrong recipient set, crash recovery, old-version writes, rate limit.
- **Rating:** Likelihood Medium, Impact Medium, inherent **Medium**. Treatment: Mitigate. Residual: **Low**.

### T-38 Audit checkpoint signing-key compromise
- **STRIDE:** Spoofing, Repudiation
- **Assets:** A-08, A-09
- **Threat:** The checkpoint signing key is stolen and used to sign checkpoints for a forged history.
- **Attack scenario:** The key file is read from the VM (Level 1), or leaked through a backup or an evidence file. The attacker signs checkpoints over a rewritten chain and presents them as proof.
- **Security controls:**
  - The key is mounted only into the worker container, protected by file permissions, and never placed in images, CI or evidence.
  - Anchors created before the compromise cannot be replaced (retention lock), and weekly witness copies are kept outside the cloud account.
  - Revoked key IDs are listed in the repository.
  - Optional Level 2 uses a provider-managed, non-exportable key (OCD-13).
- **Residual risk:** At Level 1 a VM compromise includes the key. Signatures made after the compromise prove nothing, and detection relies on earlier anchors and witness copies (L-25, ADR-009 section 8).
- **Testing strategy:** The verifier rejects checkpoints signed with a revoked key after the revocation time and reports conflicting checkpoints for the same sequence number. The hardening checklist verifies the key file's location and permissions.
- **Rating:** Likelihood Medium, Impact Medium, inherent **Medium**. Treatment: Mitigate and Accept. Residual: **Medium** at Level 1, **Low** at Level 2.

### T-39 Over-privileged database roles and schema drift
- **STRIDE:** Elevation of privilege, Tampering
- **Assets:** A-02, A-05, A-07, A-08
- **Threat:** A runtime database role holds more privileges than it needs, or the live schema differs from the reviewed migrations, so a compromised or buggy API process can change the schema, the audit table, other roles or data it should never touch.
- **Attack scenario:** The API connects as the migration role or an administrator because of a configuration mistake; a manual hotfix adds a column or drops an index outside the migrations; a later migration grants DELETE or TRUNCATE broadly. An attacker with code execution in the API container then alters tables, disables the audit trigger or deletes tombstoned records.
- **Security controls:** Four roles with fixed attributes (no superuser, CREATEDB, CREATEROLE, BYPASSRLS, membership or ownership for runtime roles); an explicit grant matrix in a reviewed migration; the API configuration accepts only `cm_api`; migration credentials never on the VM; statement and idle-transaction timeouts for runtime roles; a Prisma CLI wrapper that refuses `db push`, `migrate dev` and `migrate reset`; a drift check in CI that requires an explicit "no difference" result.
- **Residual risk:** The migration role and the provider administrator still hold full control (L-26, L-28). A reviewed migration can widen grants, so the protection relies on review and on the privilege test failing first.
- **Testing strategy:** `tests/database/privileges.test.ts` compares live privileges with an independent copy of the matrix and checks role attributes, ownership and escalation attempts; `tests/database/migrations.test.ts` runs the drift check with a negative control; `tests/security/startup-config.test.ts` rejects other roles in `DATABASE_URL`.
- **Rating:** Likelihood Medium, Impact High, inherent **High**. Treatment: Mitigate. Residual: **Low**.

## 5. Risk register summary

| ID | Threat | Likelihood | Impact | Inherent | Treatment | Residual | Related limitation |
|---|---|---|---|---|---|---|---|
| T-01 | Stolen database | M | H | High | Mitigate | Medium | L-05, L-08 |
| T-02 | Stolen object storage | M | H | High | Mitigate | Low | L-05 |
| T-03 | Stolen password hashes | M | M | Medium | Mitigate | Low | |
| T-04 | Malicious member | M | H | High | Mitigate, Accept | Medium | L-03, L-09 |
| T-05 | Non-member room access | M | H | High | Mitigate | Low | |
| T-06 | BOLA / IDOR | H | H | Critical | Mitigate | Low | |
| T-07 | Ciphertext modification | L | M | Low | Mitigate | Low | L-10 |
| T-08 | Session theft | M | H | High | Mitigate | Low | |
| T-09 | Credential stuffing | H | M | High | Mitigate | Medium | |
| T-10 | Online brute force | M | M | Medium | Mitigate | Low | |
| T-11 | Malicious file upload | M | M | Medium | Mitigate, Accept | Medium | L-11 |
| T-12 | XSS | M | H | High | Mitigate | Medium | L-01 |
| T-13 | CSRF | M | M | Medium | Mitigate | Low | |
| T-14 | Injection | M | H | High | Mitigate | Low | |
| T-15 | Information disclosure | M | M | Medium | Mitigate, Accept | Low | L-05 |
| T-16 | Exposed environment secrets | M | H | High | Mitigate | Low | |
| T-17 | Compromised cloud credentials | L | H | Medium | Mitigate, Transfer | Medium | L-06 |
| T-18 | Misconfigured storage | M | M | Medium | Mitigate | Low | |
| T-19 | Compromised VM | M | H | High | Mitigate, Accept | Medium | L-02 |
| T-20 | Audit modification | M | M | Medium | Mitigate | Low | L-13, L-25 |
| T-21 | Removed member | H | M | High | Mitigate, Accept | Medium | L-04, L-24 |
| T-22 | Stolen encrypted private key | M | H | High | Mitigate, Accept | Medium | L-08 |
| T-23 | Compromised client | M | H | High | Accept | High | L-01 |
| T-24 | Malicious code delivery | L | H | Medium | Mitigate, Accept | Medium | L-02 |
| T-25 | Public-key substitution | L | H | Medium | Mitigate, Accept | Medium | L-07, L-18 |
| T-26 | Denial of service | M | M | Medium | Mitigate, Accept | Medium | L-20 |
| T-27 | Supply-chain compromise | M | H | High | Mitigate | Medium | L-02 |
| T-28 | Metadata leakage | H | L | Medium | Mitigate, Accept | Medium | L-05 |
| T-29 | Room-key equivocation | L | H | Medium | Mitigate, Accept | Medium | L-22 |
| T-30 | Recovery and MFA abuse | L | H | Medium | Mitigate | Low | |
| T-31 | Transport attacks | L | H | Medium | Mitigate | Low | |
| T-32 | Rollback or withholding | L | L | Low | Accept | Low | L-10 |
| T-33 | External link leakage | M | M | Medium | Mitigate, Accept | Medium | L-03 |
| T-34 | Management SaaS leakage | L | M | Low | Mitigate, Transfer | Low | |
| T-35 | Identity spoofing via unverified identifiers | M | H | High | Mitigate, Accept | Medium | L-21 |
| T-36 | Injected room-key version by a server-side attacker | L | H | Medium | Mitigate (planned, OCD-12), Accept until then | Medium | L-23 |
| T-37 | Rekey abuse and incomplete rekeys | M | M | Medium | Mitigate | Low | L-24 |
| T-38 | Audit signing-key compromise | M | M | Medium | Mitigate, Accept | Medium (Level 1) | L-25 |
| T-39 | Over-privileged database roles and schema drift | M | H | High | Mitigate | Low | L-26, L-28 |

Residual risks rated **High** (T-23) and every **Accept** decision require explicit acknowledgement by the project owner at the end of Phase 0 and again before the final report.

## 6. STRIDE coverage

| Category | Threats |
|---|---|
| Spoofing | T-03, T-08, T-09, T-10, T-13, T-17, T-23, T-25, T-29, T-30, T-35, T-36, T-38 |
| Tampering | T-04, T-06, T-07, T-11, T-13, T-14, T-18, T-20, T-24, T-27, T-29, T-31, T-32, T-37, T-39 |
| Repudiation | T-04, T-20, T-38 |
| Information disclosure | T-01, T-02, T-05, T-06, T-12, T-14, T-15, T-16, T-18, T-21, T-22, T-23, T-24, T-25, T-28, T-31, T-33, T-34, T-36 |
| Denial of service | T-11, T-26, T-32, T-37 |
| Elevation of privilege | T-04, T-05, T-06, T-11, T-12, T-14, T-17, T-19, T-21, T-27, T-30, T-37, T-39 |

## 7. Maintenance

- Update this model when a change adds an asset, trust boundary, entry point or data flow (CLAUDE.md, section 11).
- Every security finding from testing is linked to an existing threat or creates a new one.
- Re-rate residual risks after Phase 12 (all controls implemented), after Phase 19 (cloud hardening) and after Phase 21 (remediation).

## 8. Phase 2 implementation check (database)

Phase 2 implemented the data layer behind TB-05. It adds no new trust boundary or external entry point: PostgreSQL, its roles and the API-to-database flow were already in the model. It adds one threat (T-39) and makes the following controls real. Ratings are unchanged until the re-rating after Phase 12.

| Threat | What Phase 2 implemented | What is still missing |
|---|---|---|
| T-01 Stolen database | Schema stores ciphertext, wrapped keys, digests and metadata only; forbidden-field checker; CHECK constraints on sizes and NULL rules; analysis in [../security/database-security.md](../security/database-security.md) section 6 | The canary scan of database dumps needs real client-side encryption (Phase 6 onward); TLS and network restriction of the managed database (CM-T067, Phase 18) |
| T-03 Stolen password hashes | `password_hash` accepts only Argon2id PHC strings | Hashing itself and parameters (Phase 3) |
| T-14 Injection | Lint bans `Prisma.raw` and database imports outside `apps/api/src/db`; the readiness query is a tagged template | No feature queries exist yet |
| T-15, T-16 Disclosure of secrets | `DATABASE_URL` held in a redacting wrapper; logger redacts credential URLs; driver errors logged without messages; readiness reveals a status word only | |
| T-20 Audit modification | Append-only grants and triggers, tested with misconfigured grants | Hash chain, checkpoints, verifier (Phase 12). Until then an owner-level change is undetectable (L-26) |
| T-21 Removed member | Membership, envelope deletion and REKEY_REQUIRED fit in one transaction for the API role (tested) | The removal endpoint (Phase 5) |
| T-25 Public-key substitution | A stored public key and fingerprint cannot be changed in place (trigger) | A new key row is still possible for an attacker with API write access; detection relies on fingerprints (L-07) |
| T-26 Denial of service | Statement and idle-transaction timeouts for runtime roles; bounded pool | |
| T-27 Supply chain | Prisma install scripts denied; telemetry off; pinned versions with release-age delay | The schema engine is downloaded at first use (checksum-verified) |
| T-36 Injected key version | A key version's commitment cannot change once written | Injection of a new version by a server-side attacker (OCD-12) is unchanged |
| T-37 Rekey abuse | One PENDING operation per room; target is base + 1; locked rooms carry reasons | The state machine (Phase 5 or 6) |
| T-39 Over-privileged roles, drift | Implemented as described in T-39 | Managed database provisioning (CM-T067, Phase 18) |
