# Crypto Decisions, Parameter Register and Library Register

Status: Phase 0.5 baseline. **This file is the single source of truth for algorithms and parameters.** Other documents refer to entries by ID (CP-xx, LIB-xx, CD-xx, OCD-xx). Changing an entry requires an ADR update, tests and a Jira item in SECURITY REVIEW.

## 1. Parameter register

| ID | Item | Value | Notes |
|---|---|---|---|
| CP-01 | Symmetric AEAD | AES-256-GCM, 256-bit keys, 96-bit IV, 128-bit tag | IV from a CSPRNG, generated inside `packages/crypto`; AAD is a canonical context (CP-15). [ADR-003](../architecture/adr/ADR-003-aes-256-gcm.md) |
| CP-02 | Asymmetric key wrapping | RSA-OAEP, 3072-bit modulus, e = 65537, SHA-256 for OAEP and MGF1, OAEP label = canonical context | **Proposed**, [ADR-007](../architecture/adr/ADR-007-asymmetric-key-wrapping.md). Maximum message 318 bytes. Used only on 32-byte random values: room key material, SEKs and the vault pair-check value. Never used on content (INV-17) |
| CP-03 | Key derivation for key separation | HKDF-SHA-256 (RFC 5869), salt = 32 zero bytes, info = canonical context, output 256 bits | Inputs are uniformly random (RKM) or Argon2id output (VRK) |
| CP-04 | Vault KDF (browser) | Argon2id v1.3 (RFC 9106), 128-bit random salt per vault, 256-bit output. **Floor:** m = 19456 KiB, t = 2, p = 1. **Target:** m = 65536 KiB, t = 3, p = 1 | Final values chosen in Phase 4 from a benchmark and recorded here. [ADR-010](../architecture/adr/ADR-010-browser-argon2id.md) |
| CP-05 | Server password hashing | Argon2id v1.3, 128-bit salt, 256-bit output, PHC string. **Floor:** m = 19456 KiB, t = 2, p = 1. **Target:** m = 65536 KiB, t = 3, p = 4 | Target is the RFC 9106 second recommended option, adopted if the VM benchmark keeps a hash under about 500 ms at expected concurrency. Rehash on login when parameters change |
| CP-06 | Secret input policy | Auth password 12 to 128 characters. Vault Passphrase 16 to 256 characters. Both checked against a local blocklist; no composition rules; Unicode NFKC normalization before hashing or derivation | Normalization keeps derivation identical across devices and input methods |
| CP-07 | Hash function | SHA-256 (FIPS 180-4) | Fingerprints, ciphertext hashes, audit chain, digests of high-entropy tokens. Never for passwords |
| CP-08 | Sessions | 256-bit random token, base64url, stored as SHA-256 digest. Idle timeout 30 minutes, absolute lifetime 12 hours, at most 10 active sessions per user, pre-authentication (MFA pending) state 5 minutes | Rotation and invalidation events in [session-and-csrf.md](../security/session-and-csrf.md). [ADR-008](../architecture/adr/ADR-008-server-side-sessions.md) |
| CP-09 | TOTP | RFC 6238, HMAC-SHA-1, 6 digits, 30-second step, accept plus or minus 1 step, 160-bit secret, replay protection by last used step | SHA-1 is kept for authenticator-app compatibility. HMAC-SHA-1 does not depend on SHA-1 collision resistance |
| CP-10 | Recovery codes | 10 codes, each at least 100 bits of entropy, stored as SHA-256 digests, single use | High-entropy random values may use a fast hash; passwords may not |
| CP-11 | Server-side encryption of TOTP secrets | AES-256-GCM under `TOTP_ENCRYPTION_KEY` (32 bytes, secret file), random 96-bit IV, AAD = canonical context with user ID, key ID stored for rotation | The only server-decryptable user secret |
| CP-12 | Login identifier HMAC | HMAC-SHA-256 under `IDENTIFIER_HMAC_KEY` over the NFKC-normalized, lower-cased identifier | Lets rate limiting correlate unknown identifiers without storing them |
| CP-13 | Audit hash chain | eventHash = SHA-256(ASCII "CM-AUDIT-v1", byte 0x00, JCS(record)). The record contains `seq` and `prevHash`; `prevHash` of seq 1 is 64 hex zeros | [ADR-009](../architecture/adr/ADR-009-tamper-evident-audit-ledger.md) |
| CP-14 | Audit checkpoint signature | Level 1 (baseline): Ed25519 (RFC 8032) via Node.js `crypto`, private key in a secret file mounted only into the worker container, public keys and revoked key IDs committed to the repository. Level 2 (optional): provider-managed non-exportable signing key (OCD-13). Checkpoints hourly, after security-critical events and on demand; external witness copy at least weekly | Trust model in [ADR-009](../architecture/adr/ADR-009-tamper-evident-audit-ledger.md) section 8. Optional RFC 3161 timestamp token (OCD-08) |
| CP-15 | Canonical encoding | RFC 8785 JSON Canonicalization Scheme. Allowed values: strings, safe integers, booleans, null, objects, arrays. No floating-point numbers. Timestamps as ISO 8601 UTC with milliseconds. 64-bit integers as decimal strings. Binary as unpadded base64url strings | Used for AAD, OAEP labels, HKDF info and audit records |
| CP-16 | Key usage bounds | A DEK encrypts at most 2 messages (file content and manifest). RWK_v wraps at most 2^20 DEKs (server-enforced `wrapCount`, then rotation). PKWK is used once per vault write | NIST SP 800-38D limits random-IV GCM to 2^32 invocations per key. CipherMesh stays far below |
| CP-17 | Public-key fingerprint | SHA-256 over the DER SPKI encoding, displayed as 64 hex characters in 16 groups of 4, always compared in full | |
| CP-18 | Algorithm suite `CM1` | CP-01 + CP-02 + CP-03 + CP-04 + CP-07 | Stored on every encrypted record |
| CP-19 | Maximum file size (single-shot encryption) | 50 MiB in the baseline | Raising it requires a browser memory benchmark. Much larger files need the chunked design in OCD-09 |
| CP-20 | Presigned URL lifetime | Upload (PUT) at most 5 minutes, download (GET) at most 60 seconds | |
| CP-21 | TLS | TLS 1.2 and 1.3 only, Mozilla "intermediate" configuration, HSTS max-age one year after a staged rollout | Database connections verify the provider certificate |
| CP-22 | Vault auto-lock | 15 minutes without user activity, and on logout, tab close or session invalidation | Client-side behaviour; cannot be enforced by the server |
| CP-23 | Randomness | Browser: `crypto.getRandomValues` and WebCrypto `generateKey`. Server: `crypto.randomBytes`, `crypto.randomUUID` | `Math.random` forbidden |
| CP-24 | Room Safety Code | RSC_v = HKDF-SHA-256(IKM = RKM_v, salt = 32 zero bytes, info = context `cm.room.safety-code` with roomId and keyVersion, 32 bytes). Display the first 66 bits as six 11-bit indices into a fixed 2048-word list (LIB-08), with the key version; numeric alternative: the same 66 bits as 20 decimal digits | Computed only in the browser, never sent or stored (INV-18). [ADR-012](../architecture/adr/ADR-012-room-safety-code.md) |
| CP-25 | Rekey operations | Lease 10 minutes; at most one PENDING operation per room; at most 10 operation starts per room per hour; at most 100 members plus pending invitees per room, which bounds a finalize request to 100 envelopes | [ADR-013](../architecture/adr/ADR-013-rekey-state-machine.md) |

## 2. Canonical contexts

Every AAD, OAEP label and HKDF info value is the RFC 8785 serialization of an object with a fixed field set. The `ctx` field provides domain separation; `v` is the context version. The full table is in [cryptographic-architecture.md](cryptographic-architecture.md) section 8.

## 3. Library register

| ID | Purpose | Status | Candidates and criteria |
|---|---|---|---|
| LIB-01 | Browser cryptography | Approved | WebCrypto (SubtleCrypto): AES-GCM, RSA-OAEP, HKDF, SHA-256 |
| LIB-02 | Server cryptography | Approved | Node.js built-in `crypto` and WebCrypto: SHA-256, HMAC, AES-GCM, Ed25519, CSPRNG, `timingSafeEqual` |
| LIB-03 | Browser Argon2id (WASM) | Open, Phase 4 (OCD-02) | Candidates: `hash-wasm`, `argon2-browser`, `@noble/hashes` (pure JavaScript, slower). Must pass RFC 9106 test vectors, run in a Web Worker, be actively maintained, have a permissive licence and no install scripts |
| LIB-04 | Server Argon2id | Open, Phase 3 (OCD-03) | Candidates: `argon2` (bindings to the reference implementation), `@node-rs/argon2`. Same criteria plus prebuilt binaries for the production image |
| LIB-05 | RFC 8785 canonicalization | Open, Phase 4 (OCD-04) | Candidates: `canonicalize` (reference implementation by an RFC author) or a small in-repo implementation of the restricted subset in CP-15, verified against the RFC 8785 test vectors |
| LIB-06 | TOTP | Open, Phase 3 | Candidates: `otplib`, `otpauth`. Must pass RFC 6238 test vectors |
| LIB-07 | Password strength estimation | Optional, Phase 4 | Candidate: `zxcvbn-ts` |
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
| CD-11 | No per-user signing keys in the baseline | Keeps the design explainable. Consequence: attribution of content to an individual member relies on the server (limitation L-09). Revisit in OCD-12 |
| CD-12 | No automatic re-encryption of old content on rotation | Rotation protects future content. Re-encryption of history is deferred (OCD-07) |
| CD-13 | AES-GCM is not key-committing. Each room key version has one public commitment, stored once and never changed; the vault has none | The commitment detects envelopes that do not match the stored value, for example a malicious member or ADMIN wrapping different keys for different members while the server behaves honestly. It does **not** protect against a server that shows different commitments and envelopes to different members, because the commitment comes from the same server. That case is detected only by comparing Room Safety Codes (CD-18). For the vault, an attacker able to exploit non-commitment already holds the encrypted private key and can guess offline, so a commitment adds nothing |
| CD-14 | No KDF fallback | If Argon2id WASM cannot run, vault creation and unlock fail with a clear message |
| CD-15 | NFKC normalization of passwords and passphrases | The same passphrase typed on different devices must derive the same key |
| CD-16 | Non-extractable keys where the API allows; room key material is handled as raw bytes only while wrapping it for other members | Sharing a key requires the sharer to hold its bytes. Everyday decryption uses non-extractable keys |
| CD-17 | RSA-OAEP wraps only 32-byte random values; every item's content is encrypted with AES-256-GCM under its own data key | RSA-OAEP-3072 accepts at most 318 bytes and is slow. Authenticated symmetric encryption is the right tool for content. One envelope pattern for files, notes and secrets keeps the design consistent and lets one set of tamper tests cover every content path |
| CD-18 | Room Safety Code for manual cross-member key consistency checks | Detects split views only when members compare it over an independent channel. Six words (66 bits) make brute-force matching impractical. Never presented as automatic protection (ADR-012) |
| CD-19 | Rekey is a client-driven, server-validated state machine; the room is write-locked from the moment a member is lost until a new version is activated | The server cannot create keys, so it enforces the lock and validates the result instead. The lease and idempotent finalize make interrupted rekeys recoverable (ADR-013) |

## 6. Open crypto decisions

| ID | Question | Recommended direction | Decide by |
|---|---|---|---|
| OCD-01 | Confirm RSA-OAEP-3072 or adopt HPKE (RFC 9180) for key distribution | Keep RSA-OAEP-3072 unless the Phase 6 cross-browser test of OAEP labels fails | Before Phase 6 |
| OCD-02 | Browser Argon2id library and final parameters | Benchmark candidates on a mid-range laptop and phone; target 0.5 to 1.5 seconds | Phase 4 |
| OCD-03 | Server Argon2id library and final parameters | Benchmark on the production VM size | Phase 3 |
| OCD-04 | RFC 8785 implementation | Either option in LIB-05, with RFC test vectors in CI | Phase 4 |
| OCD-05 | Server-side password pepper | Defer. It helps only against database-only theft and adds key-management burden | Phase 3 |
| OCD-06 | Fingerprint pinning (trust on first use): keep the public fingerprints a user has seen in browser storage and warn when one changes | Stretch goal; stores only public data | After Phase 12 |
| OCD-07 | Re-encryption of historical content after removal in RESTRICTED rooms | Stretch goal; document cost and benefit | After Phase 11 |
| OCD-08 | RFC 3161 trusted timestamps for audit checkpoints | Recommended enhancement if a free TSA is reliable | Phase 12 |
| OCD-09 | Chunked streaming encryption for large files | Only if the file limit proves too small; needs an ADR based on an established streaming AEAD design | When needed |
| OCD-10 | Printable Vault recovery key | Optional second wrap of the private key under a random 256-bit recovery key shown once | Phase 4 stretch |
| OCD-11 | WebAuthn passkeys as a second factor | Stretch; stronger phishing resistance than TOTP | After Phase 3 |
| OCD-12 | Authenticate room-key versions and envelopes so that a server-side attacker cannot distribute a key of its own (T-36) | Recommended: per-user ECDSA P-256 signing keys (native in WebCrypto) held in the vault; the fingerprint covers both public keys; key-version packages and envelopes are signed and verified against the creator's key and role. Fallback: an authenticator over each new version computed with a key derived from the previous version's key material, which stops attackers who never held a room key but not former members colluding with the server | **Before Phase 4** (identity key format), CM-T086 |
| OCD-13 | Level 2 audit signing with a provider-managed, non-exportable signing key | Optional hardening after provider selection; requires the checkpoint format to record the algorithm | Phase 19, CM-T087 |
