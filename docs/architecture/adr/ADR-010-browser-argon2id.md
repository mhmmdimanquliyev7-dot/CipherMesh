# ADR-010: Argon2id in the browser for the Vault

- Status: **Accepted** (2026-10-05, Phase 4: library, parameters and benchmark recorded; OCD-02 closed)
- Date: 2026-09-28, updated 2026-10-05
- Related: [crypto-decisions.md](../../crypto/crypto-decisions.md) CP-04, CP-06, CP-27, LIB-03, CD-27 and section 8; [cryptographic-architecture.md](../../crypto/cryptographic-architecture.md) section 5; [vault.md](../../crypto/vault.md); T-22; L-08, L-37

## Context
The Vault Passphrase must be turned into a key in the browser, because it must never reach the server. The encrypted private key is stored on the server so users can unlock it on any device, which means anyone who steals the database can attempt offline guessing. The cost of each guess is therefore the main protection. WebCrypto offers only PBKDF2 and HKDF, neither of which is memory-hard.

## Decision
- Use **Argon2id version 1.3 (RFC 9106)** through a vetted WebAssembly implementation running in a **Web Worker**.
- Per-vault 128-bit random salt; 256-bit output used only as HKDF input keying material.
- Parameters: floor m = 19456 KiB, t = 2, p = 1; target m = 65536 KiB, t = 3, p = 1 (CP-04). Final values come from a benchmark in Phase 4 on a mid-range laptop and a mid-range phone, aiming for 0.5 to 1.5 seconds per derivation.
- Parameters are stored with each vault. The browser refuses parameters below the floor; the API rejects vault uploads below the floor. When a vault uses parameters below the current target, the browser re-wraps it with the target parameters after a successful unlock.

### Phase 4 outcome

- **Library (LIB-03): `argon2id` 1.0.1** from the OpenPGP.js project (MIT, no dependencies, no install scripts). Its two WebAssembly builds (with and without SIMD, 4,416 and 3,667 bytes) are embedded in the bundle as base64 by `scripts/crypto/embed-argon2id-wasm.mjs`, and a unit test compares their SHA-256 with the installed package. It passes the RFC 9106 Argon2id test vector and matches Node.js `crypto.argon2` (OpenSSL) at the floor and the target. The comparison with `hash-wasm`, `@noble/hashes` and `argon2-browser` is in crypto-decisions LIB-03 and section 8.
- **Parameters (CP-04): the target stays m = 65536 KiB, t = 3, p = 1; the floor stays m = 19456 KiB, t = 2, p = 1; a ceiling of m = 262144 KiB, t = 10, p = 4 is added**, so a modified record cannot make a browser run an unbounded derivation. The browser and the API both refuse records outside floor and ceiling.
- **Benchmark** (`pnpm bench:vault`, the real `packages/crypto` code under the production CSP, development laptop): one derivation at the target takes a median 263 ms in Chromium, 299 ms in Firefox and 321 ms in WebKit; a full unlock 308 to 664 ms. The page stays responsive (main-thread timer gaps under 20 ms).
- **Deviation: no phone was measured.** No device was available, and Chromium's CPU throttling did not slow the worker proportionally, so it is no substitute. The laptop result is below the 0.5 to 1.5 s band; the target was not raised, to keep a margin for slower phones. Measuring a mid-range phone remains open (L-37).
- **Deviation: the upgrade is offered, not automatic.** A re-wrap must be signed by the identity and needs a recent step-up (ADR-015 section 3), so after unlock the vault page offers the upgrade and the user confirms it. Vaults created in Phase 4 already use the target, so this matters only after a future target increase.
- **Worker design (CD-27):** a fresh dedicated module worker per derivation, terminated afterwards to release the WebAssembly memory; one derivation at a time per page (`KDF_BUSY`); a 120-second timeout.
- Passphrases are NFKC-normalized before derivation (CP-06).
- **No fallback.** If the WASM module cannot load or run, vault creation and unlock fail with a clear message (INV-15).
- The Content Security Policy adds `'wasm-unsafe-eval'` so WebAssembly can compile; nothing else is relaxed.
- Library selection criteria (LIB-03): passes RFC 9106 test vectors in CI, actively maintained, permissive licence, no install scripts, works in Chromium, Firefox and WebKit, acceptable size, handles memory limits with a clear error.

## Alternatives Considered
- **PBKDF2-HMAC-SHA-256 through WebCrypto:** native and simple; OWASP recommends at least 600,000 iterations. It is not memory-hard, so GPU and ASIC guessing is far cheaper than against Argon2id.
- **scrypt through a library:** memory-hard and a sound choice; Argon2id is preferred as the Password Hashing Competition winner with an RFC and current guidance favouring it.
- **Server-assisted hardening (OPAQUE or an oblivious PRF):** would let the server rate-limit guessing without learning the passphrase, but it is a substantial protocol to implement and explain; out of scope.
- **Deriving on the server:** violates the rule that the passphrase never reaches the server.

## Consequences
- A WebAssembly dependency in the security core, wrapped behind an interface and covered by known-answer tests.
- Unlock takes around a second; mobile devices with little memory may need parameters near the floor.
- CSP must allow WebAssembly compilation.

## Security Implications
- Raises the cost of offline guessing after database theft (T-22) but cannot save a weak passphrase (L-08); passphrase length and strength feedback remain essential.
- The absence of fallback prevents a silent downgrade (INV-15).

## Status
Accepted on 2026-10-05. The library evaluation and the benchmark are recorded in the parameter register (LIB-03, CP-04, section 8). Confirming tests: `packages/crypto/src/argon2id.test.ts` (RFC 9106, OpenSSL differential, embedded bytes, parameter limits, `KDF_BUSY`), the E2E vault tests in three engines under the production CSP, and negative control NC-04-08. Review when a phone benchmark is available (L-37), when browsers ship native Argon2, or if the library stops being used by OpenPGP.js.
