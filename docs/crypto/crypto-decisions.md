# Crypto Decisions, Parameter Register and Library Register

Status: Phase 0.5 baseline, updated in Phase 3 (CP-05, CP-06, CP-11, LIB-04, LIB-06) and Phase 4 (CP-04, CP-06, CP-15 to CP-18, CP-26, CP-27, LIB-01 to LIB-03, LIB-05, LIB-07, CD-11, CD-22 to CD-27, OCD-02, OCD-04, OCD-10, OCD-12). **This file is the single source of truth for algorithms and parameters.** Other documents refer to entries by ID (CP-xx, LIB-xx, CD-xx, OCD-xx). Changing an entry requires an ADR update, tests and a Jira item in SECURITY REVIEW.

## 1. Parameter register

| ID | Item | Value | Notes |
|---|---|---|---|
| CP-01 | Symmetric AEAD | AES-256-GCM, 256-bit keys, 96-bit IV, 128-bit tag | IV from a CSPRNG, generated inside `packages/crypto`; AAD is a canonical context (CP-15). [ADR-003](../architecture/adr/ADR-003-aes-256-gcm.md) |
| CP-02 | Asymmetric key wrapping | RSA-OAEP, 3072-bit modulus, e = 65537, SHA-256 for OAEP and MGF1, OAEP label = canonical context | **Proposed**, [ADR-007](../architecture/adr/ADR-007-asymmetric-key-wrapping.md). Maximum message 318 bytes. Used only on 32-byte random values: room key material, SEKs and the vault pair-check value. Never used on content (INV-17) |
| CP-03 | Key derivation for key separation | HKDF-SHA-256 (RFC 5869), salt = 32 zero bytes, info = canonical context, output 256 bits | Inputs are uniformly random (RKM) or Argon2id output (VRK) |
| CP-04 | Vault KDF (browser) | Argon2id v1.3 (RFC 9106), 128-bit random salt per vault write, 256-bit output used only as HKDF input keying material. **Target** (every new vault and upgrade): m = 65536 KiB, t = 3, p = 1. **Floor** (lowest accepted): m = 19456 KiB, t = 2, p = 1. **Ceiling** (highest accepted): m = 262144 KiB, t = 10, p = 4 | **Final, Phase 4** (benchmark in section 8). At the target one derivation in a fresh Web Worker took a median 263 ms in Chromium, 299 ms in Firefox and 321 ms in WebKit on the development laptop. No phone was measured (L-37); mid-range phones are expected to be several times slower, which is why the target was not raised to fill the 0.5 to 1.5 s band on the laptop. The ceiling bounds the work a modified record can make a browser do. The browser and the API both refuse records outside floor and ceiling. A vault below the target is offered an upgrade after unlock (ADR-010). [ADR-010](../architecture/adr/ADR-010-browser-argon2id.md) |
| CP-05 | Server password hashing | Argon2id v1.3 (RFC 9106), 128-bit random salt, 256-bit output, PHC string. **Final (Phase 3): m = 65536 KiB, t = 3, p = 4** (the target, RFC 9106 second recommended option). **Floor** for accepting stored hashes: m = 19456 KiB, t = 2, p = 1 | Adopted after the Phase 3 benchmark (section 7): 294 ms median on a 2-vCPU, 2 GiB container at the API's concurrency limit of 2, under the 500 ms rule. Hashes with other parameters are rehashed at the next successful login. The API runs at most min(4, CPUs) computations at once with 32 queued; beyond that it answers 503 (T-26). Re-run `pnpm bench:argon2` on the production VM in Phase 17 and record it here |
| CP-06 | Secret input policy | Auth password 12 to 128 characters. Vault Passphrase 16 to 256 characters. Both checked against a local blocklist; no composition rules; Unicode NFKC normalization before hashing or derivation | Normalization keeps derivation identical across devices and input methods. **Auth password implemented in Phase 3:** lengths in Unicode code points after NFKC, never truncated; lone surrogates refused; local blocklist of 30,402 breached passwords of 12 or more characters (UK NCSC top 100,000 and the Pwdb top one million, SecLists, pinned and checksum-verified, built by `scripts/auth/build-password-blocklist.mjs`); passwords containing the email local part, display name or product name refused. Nothing is sent to a third party. **Vault Passphrase implemented in Phase 4** (`packages/crypto/src/passphrase.ts`): the same length rules with 16 to 256 code points, whitespace kept as typed; a local blocklist of 3,350 entries of 16 or more characters from the same pinned sources; the same identity checks. It runs only in the browser, at setup and change, never at unlock, because the passphrase never reaches the server |
| CP-07 | Hash function | SHA-256 (FIPS 180-4) | Fingerprints, ciphertext hashes, audit chain, digests of high-entropy tokens. Never for passwords |
| CP-08 | Sessions | 256-bit random token, base64url, stored as SHA-256 digest. Idle timeout 30 minutes, absolute lifetime 12 hours, at most 10 active sessions per user, pre-authentication (MFA pending) state 5 minutes | Rotation and invalidation events in [session-and-csrf.md](../security/session-and-csrf.md). [ADR-008](../architecture/adr/ADR-008-server-side-sessions.md) |
| CP-09 | TOTP | RFC 6238, HMAC-SHA-1, 6 digits, 30-second step, accept plus or minus 1 step, 160-bit secret, replay protection by last used step | SHA-1 is kept for authenticator-app compatibility. HMAC-SHA-1 does not depend on SHA-1 collision resistance |
| CP-10 | Recovery codes | 10 codes, each at least 100 bits of entropy, stored as SHA-256 digests, single use | High-entropy random values may use a fast hash; passwords may not |
| CP-11 | Server-side encryption of TOTP secrets | AES-256-GCM under `TOTP_ENCRYPTION_KEY` (32 bytes, secret file), random 96-bit IV, AAD = canonical context with user ID, key ID stored for rotation | The only server-decryptable user secret. **Implemented in Phase 3:** stored as IV, ciphertext and tag (48 bytes for a 160-bit secret); AAD is the context `cm.srv.totp` with `keyId` and `userId`; any mismatch fails closed. One active key; rotating it needs a re-encryption tool that does not exist yet (L-31) |
| CP-12 | Login identifier HMAC | HMAC-SHA-256 under `IDENTIFIER_HMAC_KEY` over the NFKC-normalized, lower-cased identifier | Lets rate limiting correlate unknown identifiers without storing them |
| CP-13 | Audit hash chain | eventHash = SHA-256(ASCII "CM-AUDIT-v1", byte 0x00, JCS(record)). The record contains `seq` and `prevHash`; `prevHash` of seq 1 is 64 hex zeros | [ADR-009](../architecture/adr/ADR-009-tamper-evident-audit-ledger.md) |
| CP-14 | Audit checkpoint signature | Level 1 (baseline): Ed25519 (RFC 8032) via Node.js `crypto`, private key in a secret file mounted only into the worker container, public keys and revoked key IDs committed to the repository. Level 2 (optional): provider-managed non-exportable signing key (OCD-13). Checkpoints hourly, after security-critical events and on demand; external witness copy at least weekly | Trust model in [ADR-009](../architecture/adr/ADR-009-tamper-evident-audit-ledger.md) section 8. Optional RFC 3161 timestamp token (OCD-08) |
| CP-15 | Canonical encoding | RFC 8785 JSON Canonicalization Scheme. Allowed values: strings, safe integers, booleans, null, objects, arrays. No floating-point numbers. Timestamps as ISO 8601 UTC with milliseconds. 64-bit integers as decimal strings. Binary as unpadded base64url strings | Used for AAD, OAEP labels, HKDF info, signed statements and audit records. **Phase 4:** implemented in the repository for this subset (LIB-05); context objects are built only by `packages/crypto/src/contexts.ts`, which fixes the field set of every context and validates each field |
| CP-16 | Key usage bounds | A DEK encrypts at most 2 messages (file content and manifest). RWK_v wraps at most 2^20 DEKs (server-enforced `wrapCount`, then rotation). Each private-key wrapping key (one per private key, CP-27) wraps exactly one key per vault write; every write uses a fresh salt and therefore new wrapping keys | NIST SP 800-38D limits random-IV GCM to 2^32 invocations per key. CipherMesh stays far below |
| CP-17 | Identity fingerprint | SHA-256 over the RFC 8785 serialization of the context `cm.identity.fingerprint` {suite, encryptionKeySpki, signingKeySpki} (both DER SPKI encodings as base64url), displayed as 64 hex characters in 16 groups of 4, always compared in full | **Revised by ADR-015 before any identity existed.** One comparison covers both public keys. Each client computes the fingerprint from the keys it actually uses and never displays a server-supplied value as verified |
| CP-18 | Algorithm suite `CM1` | CP-01 + CP-02 + CP-03 + CP-04 + CP-07 + CP-26 | Stored on every encrypted record. CP-26 joined the suite through ADR-015 before any CM1 record existed |
| CP-19 | Maximum file size (single-shot encryption) | 50 MiB in the baseline | Raising it requires a browser memory benchmark. Much larger files need the chunked design in OCD-09 |
| CP-20 | Presigned URL lifetime | Upload (PUT) at most 5 minutes, download (GET) at most 60 seconds | |
| CP-21 | TLS | TLS 1.2 and 1.3 only, Mozilla "intermediate" configuration, HSTS max-age one year after a staged rollout | Database connections verify the provider certificate |
| CP-22 | Vault auto-lock | 15 minutes without user activity, and on logout, tab close or session invalidation | Client-side behaviour; cannot be enforced by the server |
| CP-23 | Randomness | Browser: `crypto.getRandomValues` and WebCrypto `generateKey`. Server: `crypto.randomBytes`, `crypto.randomUUID` | `Math.random` forbidden |
| CP-24 | Room Safety Code | RSC_v = HKDF-SHA-256(IKM = RKM_v, salt = 32 zero bytes, info = context `cm.room.safety-code` with roomId and keyVersion, 32 bytes). Display the first 66 bits as six 11-bit indices into a fixed 2048-word list (LIB-08), with the key version; numeric alternative: the same 66 bits as 20 decimal digits | Computed only in the browser, never sent or stored (INV-18). [ADR-012](../architecture/adr/ADR-012-room-safety-code.md) |
| CP-25 | Rekey operations | Lease 10 minutes; at most one PENDING operation per room; at most 10 operation starts per room per hour; at most 100 members plus pending invitees per room, which bounds a finalize request to 100 envelopes | [ADR-013](../architecture/adr/ADR-013-rekey-state-machine.md) |
| CP-26 | Identity signing key | ECDSA on P-256 with SHA-256 (FIPS 186-5), signatures in IEEE P1363 form (r and s, 64 bytes), public key as a 91-byte DER SPKI with an uncompressed point | **Phase 4, ADR-015.** Signs only canonical statements: `cm.identity.binding`, `cm.vault.rewrap`, and the room statements of Phase 6. Never encrypts or wraps. Nonces come from WebCrypto or Node.js, never from CipherMesh code. Imported public keys must re-export byte for byte |
| CP-27 | Vault format, version 1 | VRK = Argon2id(NFKC passphrase, salt, CP-04), imported at once as a non-extractable HKDF key. One wrapping key per private key: HKDF(VRK, info = `cm.vault.pk-wrap` {userId, keyId, purpose}). Each private key is wrapped as PKCS#8 with AES-256-GCM, AAD = `cm.vault.private-key` {userId, keyId, purpose, fingerprint, suite, vaultVersion}. Unlock imports both keys as non-extractable and runs pair checks | **Phase 4.** Records with another version or suite are refused (no downgrade). Wrapped sizes: encryption key 1,700 to 2,048 bytes, signing key 64 to 256 bytes. Specification: [vault.md](vault.md) |

## 2. Canonical contexts

Every AAD, OAEP label and HKDF info value is the RFC 8785 serialization of an object with a fixed field set. The `ctx` field provides domain separation; `v` is the context version. The full table is in [cryptographic-architecture.md](cryptographic-architecture.md) section 8.

## 3. Library register

| ID | Purpose | Status | Candidates and criteria |
|---|---|---|---|
| LIB-01 | Browser cryptography | Approved | WebCrypto (SubtleCrypto): AES-GCM (including `wrapKey` and `unwrapKey` of PKCS#8 private keys), RSA-OAEP, ECDSA P-256 (Phase 4, CP-26), HKDF, SHA-256 |
| LIB-02 | Server cryptography | Approved | Node.js built-in `crypto` and WebCrypto: SHA-256, HMAC, AES-GCM, Ed25519, ECDSA P-256 verification (identity binding and vault re-wrap, Phase 4), CSPRNG, `timingSafeEqual`. The API verifies with the same `packages/crypto` code the browsers run |
| LIB-03 | Browser Argon2id (WASM) | **Selected, Phase 4** | `argon2id` 1.0.1 (MIT, no dependencies, no install scripts), maintained by the OpenPGP.js team and used for Argon2 in current OpenPGP.js releases (6.3.2, September 2026); its last own release is from August 2023. Argon2id runs in JavaScript with the block function in WebAssembly: two builds (4,416 bytes with SIMD, 3,667 without) compiled from one C file shipped in the package. CipherMesh embeds both as base64 (`scripts/crypto/embed-argon2id-wasm.mjs`, SHA-256 `50647e10...4b0e` and `1f16d8de...4f8e`), and a unit test compares them with the installed package. Passes the RFC 9106 Argon2id test vector, with both the SIMD and the non-SIMD build, and matches Node.js `crypto.argon2` (OpenSSL) at the floor and the target. **Review finding:** the library's password and salt length checks compare the arrays themselves instead of their lengths, so they never fire for multi-byte input; CipherMesh validates every length before calling it (`kdf/protocol.ts`, `kdf/derive.ts`, the unlock minimum), and a test pins the library behaviour so that an update triggers a new review. Chosen over `hash-wasm` 4.12.0 (sound and slightly faster in Chromium and Firefox, but a multi-algorithm library; the documented replacement), `@noble/hashes` 2.4.0 (pure JavaScript, six to seven times slower, which would force much weaker parameters) and `argon2-browser` 1.18.0 (no release since 2022, needs a bundler-specific loader). Benchmark in section 8 |
| LIB-04 | Server Argon2id | **Selected, Phase 3** | Node.js built-in `crypto.argon2` (Node 24.7 or later, backed by OpenSSL 3.5). Chosen over `argon2` and `@node-rs/argon2` because it adds no dependency, no native build and no install script, and comes from the already approved LIB-02 runtime. Reproduces the RFC 9106 Argon2id test vector (benchmark script and unit tests). The PHC string encoding is in `apps/api/src/auth/password.ts` |
| LIB-05 | RFC 8785 canonicalization | **Selected, Phase 4: in-repo** | `packages/crypto/src/canonical.ts` (85 lines) implements the CP-15 subset: strings, safe integers, booleans, null, objects and arrays, with members sorted by UTF-16 code units (RFC 8785 section 3.2.3). It refuses floating-point numbers, lone surrogates, `undefined`, non-plain objects, cycles and nesting deeper than 32. Verified against the RFC 8785 sorting example and byte dump and against the Phase 3 `cm.srv.totp` bytes (CD-22). Chosen over `canonicalize` because the subset needs no number serialization, and an implementation that refuses everything outside the subset is safer for cryptographic contexts than one that accepts any JSON value |
| LIB-06 | TOTP | **Selected, Phase 3** | `otpauth` 9.5.2 (MIT; one dependency, `@noble/hashes` 2.4.0; released 2026-09-03). Chosen over `otplib` 13 (six internal packages). Passes the RFC 6238 SHA-1 test vectors (`apps/api/src/auth/totp.test.ts`). Codes are compared by the library in constant time |
| LIB-07 | Password strength estimation | Not adopted in Phase 4 | Candidate: `zxcvbn-ts`. Phase 4 relies on length, the blocklist and the identity checks (CP-06) and on guidance in the UI. Revisit if usability tests show a need |
| LIB-08 | Room Safety Code word list | Open, Phase 6 | A public list of exactly 2048 distinct, short, phonetically distinct words with a licence that permits redistribution, stored as a data file with its source and checksum |

Rules for every library: pinned through the lockfile, reviewed in a pull request, scanned in CI, wrapped behind a CipherMesh interface so it can be replaced, and covered by known-answer tests.

## 4. Forbidden algorithms and practices

- MD5 and SHA-1, except HMAC-SHA-1 inside TOTP (CP-09).
- DES, 3DES, RC4, Blowfish, and any cipher not listed in the parameter register.
- AES-ECB, and AES-CBC or AES-CTR without authentication. Unauthenticated encryption of any kind.
- RSA PKCS#1 v1.5 encryption, RSA without padding, new RSA keys shorter than 3072 bits.
- RSA encryption of content, or of anything other than 32-byte random values (INV-17).
- Fast hashes (SHA-2, SHA-3, BLAKE) for passwords or passphrases.
- Silent fallback from Argon2id to a weaker KDF (INV-15).
- `Math.random`, time-based seeds, or UUIDv1 for anything secret.
- Caller-managed, counter-based or reused IVs.
- XOR "encryption", base64 as protection, or any home-made scheme.
- JWT-based sessions, `alg: none`, or algorithm negotiation driven by untrusted input.

## 5. Decision log

| ID | Decision | Rationale |
|---|---|---|
| CD-01 | The authentication password and the Vault Passphrase are separate secrets | The server sees the auth password at login. Deriving vault keys from it would give the server what it needs to decrypt private keys. Cracking a stolen password hash also does not unlock content |
| CD-02 | AES-256-GCM for all symmetric encryption and key wrapping | Native in WebCrypto, AEAD with associated data, well understood. See ADR-003 |
| CD-03 | RSA-OAEP-3072 with SHA-256 for room-key and secret-key distribution | Native in WebCrypto, standardized, easy to explain, no custom composition. Proposed; see ADR-007 for the comparison with HPKE and ECDH |
| CD-04 | One fresh DEK per item version | Makes IV reuse structurally impossible across items and edits, and allows per-item crypto-shredding |
| CD-05 | Room key material is an HKDF input; the wrapping key, a public commitment and the Room Safety Code are derived from it with separate contexts | Key separation. The commitment and the Safety Code support consistency checks with the limits stated in CD-13 and CD-18 |
| CD-06 | Secrets use the same envelope encryption as files and notes: the payload is encrypted with AES-256-GCM under a fresh per-secret SEK, and only the 32-byte SEK is wrapped to the recipient's public key with RSA-OAEP | Consistent content path. Only the recipient can unwrap the SEK, so other members cannot decrypt the secret even if they obtain the ciphertext |
| CD-07 | Single-shot file encryption with a 50 MiB limit | Avoids designing a streaming AEAD construction in the baseline |
| CD-08 | Identifiers used in contexts are client-generated UUIDv4 values, validated by the server | The client must know the ID before encrypting; the server rejects malformed or duplicate IDs |
| CD-09 | The plaintext file hash exists only inside the encrypted manifest | A clear plaintext hash would allow confirmation-of-file attacks |
| CD-10 | Ed25519 for audit checkpoints | Deterministic signatures with no per-signature nonce risk; runs only on the server, so browser support is irrelevant |
| CD-11 | **Superseded in Phase 4 by CD-23.** Originally: no per-user signing keys in the baseline | Was chosen to keep the design explainable; OCD-12 showed that it leaves room-key versions unauthenticated (T-36) |
| CD-12 | No automatic re-encryption of old content on rotation | Rotation protects future content. Re-encryption of history is deferred (OCD-07) |
| CD-13 | AES-GCM is not key-committing. Each room key version has one public commitment, stored once and never changed; the vault has none | The commitment detects envelopes that do not match the stored value, for example a malicious member or ADMIN wrapping different keys for different members while the server behaves honestly. It does **not** protect against a server that shows different commitments and envelopes to different members, because the commitment comes from the same server. That case is detected only by comparing Room Safety Codes (CD-18). For the vault, an attacker able to exploit non-commitment already holds the encrypted private key and can guess offline, so a commitment adds nothing |
| CD-14 | No KDF fallback | If Argon2id WASM cannot run, vault creation and unlock fail with a clear message |
| CD-15 | NFKC normalization of passwords and passphrases | The same passphrase typed on different devices must derive the same key |
| CD-16 | Non-extractable keys where the API allows; room key material is handled as raw bytes only while wrapping it for other members | Sharing a key requires the sharer to hold its bytes. Everyday decryption uses non-extractable keys |
| CD-17 | RSA-OAEP wraps only 32-byte random values; every item's content is encrypted with AES-256-GCM under its own data key | RSA-OAEP-3072 accepts at most 318 bytes and is slow. Authenticated symmetric encryption is the right tool for content. One envelope pattern for files, notes and secrets keeps the design consistent and lets one set of tamper tests cover every content path |
| CD-18 | Room Safety Code for manual cross-member key consistency checks | Detects split views only when members compare it over an independent channel. Six words (66 bits) make brute-force matching impractical. Never presented as automatic protection (ADR-012) |
| CD-19 | Rekey is a client-driven, server-validated state machine; the room is write-locked from the moment a member is lost until a new version is activated | The server cannot create keys, so it enforces the lock and validates the result instead. The lease and idempotent finalize make interrupted rekeys recoverable (ADR-013) |
| CD-20 | No server-side password pepper in the baseline (OCD-05) | A pepper helps only if the database leaks without the application secrets. The deployment keeps the TOTP and HMAC keys in secret files on the same VM, so the main leak paths (backup, provider-side exposure) are covered by Argon2id cost, the password policy and MFA. A pepper would add a key that can never be rotated without every user logging in. Revisit if the database moves to a separate trust domain |
| CD-21 | Server Argon2id comes from Node.js crypto (LIB-04) | No third-party code in the password path; the implementation is OpenSSL's, maintained with the runtime. Verified against RFC 9106 |
| CD-22 | The server builds its own canonical context `cm.srv.totp` for a flat object of strings and safe integers | The general RFC 8785 implementation is a Phase 4 decision (OCD-04). For this restricted subset, RFC 8785 serialization equals JSON.stringify of each value with sorted keys; the builder refuses anything else. Phase 4 test vectors must reproduce these bytes. **Migrated in Phase 4:** the API builds `cm.srv.totp` with the shared builder from `@ciphermesh/crypto/contexts`, and a unit test opens a ciphertext sealed by the Phase 3 code, which proves identical bytes |
| CD-23 | Each identity has an ECDSA P-256 signing key next to its RSA-OAEP encryption key, under one key ID and one fingerprint (OCD-12) | Lets members verify who created a room-key version, who granted a membership and that a vault re-wrap came from the identity itself. Ed25519 was rejected because one tested engine lacks it. [ADR-015](../architecture/adr/ADR-015-identity-signing-keys.md) |
| CD-24 | Room-key envelopes are authenticated through the signed key commitment, not by a signature per envelope (Phase 6) | The recipient recomputes RKC_v from the decrypted key material and compares it with the signed value; key material with the same commitment would break HKDF-SHA-256. ADR-015 section 4 |
| CD-25 | One HKDF-derived wrapping key per private key and vault write (CP-27) | Each AES-GCM key encrypts exactly one message, so an IV collision is impossible by construction. The purpose appears in both the HKDF info and the AAD, so the two wrapped keys cannot be swapped |
| CD-26 | A vault re-wrap is signed by the identity and applied by compare-and-swap on the previous salt; after a lost passphrase, a reset creates a new identity | A session thief, even with the account password, cannot replace the wrapped keys of an identity, and replays fail. A reset cannot be signed, so it is visible as a new fingerprint and ends the user's other sessions |
| CD-27 | Argon2id runs in a fresh dedicated Web Worker per derivation, one derivation at a time per page, with a 120-second timeout. The WebAssembly is embedded in the bundle; the CSP adds only `'wasm-unsafe-eval'` | Keeps the page responsive, releases the WebAssembly memory after each derivation, refuses (KDF_BUSY) instead of queuing so repeated clicks or a script cannot stack up 64 MiB derivations, and needs no extra file type or `connect-src` change |

## 6. Open crypto decisions

| ID | Question | Recommended direction | Decide by |
|---|---|---|---|
| OCD-01 | Confirm RSA-OAEP-3072 or adopt HPKE (RFC 9180) for key distribution | Keep RSA-OAEP-3072 unless the Phase 6 cross-browser test of OAEP labels fails | Before Phase 6 |
| OCD-02 | Browser Argon2id library and final parameters | **Closed in Phase 4:** LIB-03 and CP-04 above, benchmark in section 8. Only the laptop was measured; the phone measurement remains open (L-37) | Phase 4 |
| OCD-03 | Server Argon2id library and final parameters | **Closed in Phase 3:** LIB-04 and CP-05 above, benchmark in section 7. The production VM re-run is a Phase 17 task | Phase 3 |
| OCD-04 | RFC 8785 implementation | **Closed in Phase 4:** in-repo implementation (LIB-05), RFC 8785 test data in CI | Phase 4 |
| OCD-05 | Server-side password pepper | **Decided in Phase 3: no pepper in the baseline** (CD-20) | Phase 3 |
| OCD-06 | Fingerprint pinning (trust on first use): keep the public fingerprints a user has seen in browser storage and warn when one changes | Stretch goal; stores only public data | After Phase 12 |
| OCD-07 | Re-encryption of historical content after removal in RESTRICTED rooms | Stretch goal; document cost and benefit | After Phase 11 |
| OCD-08 | RFC 3161 trusted timestamps for audit checkpoints | Recommended enhancement if a free TSA is reliable | Phase 12 |
| OCD-09 | Chunked streaming encryption for large files | Only if the file limit proves too small; needs an ADR based on an established streaming AEAD design | When needed |
| OCD-10 | Printable Vault recovery key | Optional second wrap of the private keys under a random 256-bit recovery key shown once. **Not implemented in Phase 4:** a lost passphrase leads to a vault reset with a new identity (L-17). Any later design must remain user-held: no server escrow, no account-password derivation | Later stretch |
| OCD-11 | WebAuthn passkeys as a second factor | Stretch; stronger phishing resistance than TOTP | After Phase 3 |
| OCD-12 | Authenticate room-key versions and envelopes so that a server-side attacker cannot distribute a key of its own (T-36) | Recommended: per-user ECDSA P-256 signing keys (native in WebCrypto) held in the vault; the fingerprint covers both public keys; key-version packages and envelopes are signed and verified against the creator's key and role. Fallback: an authenticator over each new version computed with a key derived from the previous version's key material, which stops attackers who never held a room key but not former members colluding with the server | **Closed: [ADR-015](../architecture/adr/ADR-015-identity-signing-keys.md) accepted on 2026-10-05.** Identity format implemented in Phase 4; room statements in Phases 6 and 11. CM-T086 |
| OCD-13 | Level 2 audit signing with a provider-managed, non-exportable signing key | Optional hardening after provider selection; requires the checkpoint format to record the algorithm | Phase 19, CM-T087 |

## 7. Phase 3 benchmark (CP-05, OCD-03)

`pnpm bench:argon2` (`scripts/bench/argon2.mjs`) first checks the RFC 9106 Argon2id test vector, then measures each parameter set with 1, 2, 4 and 8 concurrent hashes (8 rounds each). Runtime: Node.js 24.19.0, OpenSSL 3.5.7. Raw output: [../report/evidence/phase-03/EV-03-02_argon2-benchmark.txt](../report/evidence/phase-03/EV-03-02_argon2-benchmark.txt).

**VM-sized environment** (container limited to 2 CPUs and 2 GiB on an Intel Core i7-12700H, image `node:24.19.0-alpine`), median latency in ms:

| Parameters | 1 at a time | 2 concurrent | 4 concurrent | 8 concurrent |
|---|---|---|---|---|
| Floor: m = 19456, t = 2, p = 1 | 35 | | 90 | 184 |
| m = 65536, t = 3, p = 1 | 183 | 193 | 426 | 865 |
| **Target: m = 65536, t = 3, p = 4** | **104** | **294** | 701 | 1380 |

**Decision.** The target meets the "about 500 ms at expected concurrency" rule only if concurrency is bounded, so the API limits Argon2id computations to one per CPU (at most four) and queues at most 32; further requests get 503 with `Retry-After: 1`. On a 2-vCPU VM that means 294 ms median and about 7 hashes per second, with at most 128 MiB of Argon2 memory in use. Per-address limits and per-account backoff (CM-T018) keep unauthenticated traffic far below that rate. With p = 1 the same memory and passes give similar per-guess cost to an attacker and better throughput under contention; the RFC option was kept because it meets the rule and is the documented target.

The development laptop (20 logical CPUs) measured 139 ms for one hash and 223 ms at concurrency 4. The production VM size is not fixed yet: the benchmark must be repeated there (Phase 17) and this section updated.

## 8. Phase 4 benchmark (CP-04, OCD-02, LIB-03)

Hardware: the development laptop (Intel Core i7-12700H, 20 logical CPUs, 31.6 GiB RAM, Windows 11), Playwright browsers Chromium 153, Firefox 155 and WebKit 26.6, Node.js 24.19.0. No phone was available; Chromium's CPU throttling (x4 and x6) did not slow the worker proportionally (about 350 to 400 ms at the target), so it was not used as a phone estimate (L-37).

**Library comparison** (scratch harness, each library in a Web Worker under a CSP that adds only `'wasm-unsafe-eval'`; median in ms, `hash-wasm` / `argon2id` / `@noble/hashes`):

| Parameters | Chromium | Firefox | WebKit |
|---|---|---|---|
| Floor: m = 19456 KiB, t = 2, p = 1 | 40 / 45 / 195 | 51 / 64 / 365 | 74 / 48 / 330 |
| **Target: m = 65536 KiB, t = 3, p = 1** | 214 / **251** / 1754 | 227 / **266** / 1804 | 370 / **441** / 2562 |
| m = 65536 KiB, t = 4 (`hash-wasm` / `argon2id`) | 545 / 514 | 284 / 406 | 924 / 590 |
| m = 131072 KiB, t = 3 (`hash-wasm` / `argon2id`) | 779 / 829 | 468 / 562 | 1437 / 977 |

In Node.js at the target: OpenSSL (`crypto.argon2`) 182 ms, `hash-wasm` 219 ms, `argon2id` 258 ms, `@noble/hashes` 1621 ms. The selected library's output equals OpenSSL's at the floor and the target (`packages/crypto/src/argon2id.test.ts`).

**The selected code in the browsers** (`pnpm bench:vault`, `scripts/bench/vault-browsers.mjs`): the real `packages/crypto` code and its worker, bundled and served under the production CSP. Median, with minimum and maximum. Raw output: [../report/evidence/phase-04/EV-04-03_vault-benchmark.txt](../report/evidence/phase-04/EV-04-03_vault-benchmark.txt).

| Operation | Chromium | Firefox | WebKit |
|---|---|---|---|
| Argon2id at the floor, fresh worker (n = 3) | 60 ms (60 to 62) | 79 ms (75 to 115) | 78 ms (76 to 81) |
| **Argon2id at the target, fresh worker (n = 5)** | **263 ms** (260 to 298) | **299 ms** (270 to 358) | **321 ms** (308 to 349) |
| Vault setup: RSA-3072 and ECDSA keys, Argon2id, wrapping, self-check (n = 5) | 558 ms (269 to 1085) | 438 ms (402 to 590) | 2029 ms (802 to 3955) |
| Vault unlock: Argon2id, unwrapping, pair checks (n = 5) | 424 ms (408 to 456) | 308 ms (296 to 327) | 664 ms (644 to 721) |
| Passphrase change: two derivations, re-wrap, signature (n = 3) | 883 ms (837 to 903) | 605 ms (600 to 610) | 1277 ms (1218 to 1282) |
| Longest main-thread timer gap during a target derivation | 17 ms | 11 ms | 19 ms |
| Second concurrent derivation | refused (KDF_BUSY) | refused | refused |
| CSP violations | none | none | none |

**Decision.** `argon2id` was selected (LIB-03): it is single-purpose and small enough to review, it is used for the same job in OpenPGP.js, and it was clearly faster than `hash-wasm` in WebKit at higher costs, the engine where headroom is smallest. The target stays at m = 65536 KiB, t = 3, p = 1: on the laptop it costs 0.26 to 0.32 s per derivation and 0.3 to 0.7 s per unlock, and the margin is kept for slower phones, which were not measured. Raising t or m later is a parameter upgrade that existing vaults accept through the offered re-wrap. Setup time in WebKit is dominated by RSA-3072 key generation (up to 4 s), which happens once per identity. The page stays responsive during a derivation (timer gaps under 20 ms) because Argon2id runs in the worker.
