# ADR-010: Argon2id in the browser for the Vault

- Status: **Proposed** (library and final parameters selected in Phase 4, OCD-02)
- Date: 2026-09-28
- Related: [crypto-decisions.md](../../crypto/crypto-decisions.md) CP-04, CP-06, LIB-03; [cryptographic-architecture.md](../../crypto/cryptographic-architecture.md) section 5; T-22; L-08

## Context
The Vault Passphrase must be turned into a key in the browser, because it must never reach the server. The encrypted private key is stored on the server so users can unlock it on any device, which means anyone who steals the database can attempt offline guessing. The cost of each guess is therefore the main protection. WebCrypto offers only PBKDF2 and HKDF, neither of which is memory-hard.

## Decision
- Use **Argon2id version 1.3 (RFC 9106)** through a vetted WebAssembly implementation running in a **Web Worker**.
- Per-vault 128-bit random salt; 256-bit output used only as HKDF input keying material.
- Parameters: floor m = 19456 KiB, t = 2, p = 1; target m = 65536 KiB, t = 3, p = 1 (CP-04). Final values come from a benchmark in Phase 4 on a mid-range laptop and a mid-range phone, aiming for 0.5 to 1.5 seconds per derivation.
- Parameters are stored with each vault. The browser refuses parameters below the floor; the API rejects vault uploads below the floor. When a vault uses parameters below the current target, the browser re-wraps it with the target parameters after a successful unlock.
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
Proposed. Becomes Accepted when the Phase 4 library evaluation and benchmark are recorded in the parameter register.
