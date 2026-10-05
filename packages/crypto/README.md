# packages/crypto

Client-side cryptography for CipherMesh: narrow, tested wrappers around WebCrypto (AES-256-GCM, RSA-OAEP, ECDSA P-256, HKDF, SHA-256), the browser Argon2id integration, the canonical context builders (AAD, OAEP labels, HKDF info and signed statements), the cryptographic identity and the vault format.

Status: implemented in Phase 4 (CM-T023 to CM-T028, CM-T086). Specifications: [docs/crypto/cryptographic-architecture.md](../../docs/crypto/cryptographic-architecture.md), [docs/crypto/vault.md](../../docs/crypto/vault.md), [ADR-010](../../docs/architecture/adr/ADR-010-browser-argon2id.md), [ADR-015](../../docs/architecture/adr/ADR-015-identity-signing-keys.md). Parameters: [docs/crypto/crypto-decisions.md](../../docs/crypto/crypto-decisions.md).

## Entry points

| Import | For | Contents |
|---|---|---|
| `@ciphermesh/crypto` | The web client | Vault setup, unlock, passphrase change and upgrade; identity verification and fingerprints; the passphrase policy; the worker runner; wire codecs; error codes |
| `@ciphermesh/crypto/identity` | The API | Identity and signature verification, the re-wrap statement, wire codecs and limits. No key generation, KDF or worker code |
| `@ciphermesh/crypto/contexts` | The API | The canonical context builder (used for `cm.srv.totp`) |
| `@ciphermesh/crypto/params` | `packages/validation` | Sizes and limits from the parameter register |

The export surface is fixed by `src/boundary.test.ts`. Browser code may not import `src/**` directly (ESLint).

## Rules

- No custom primitives or modes. Only the constructions specified in `docs/crypto/`.
- Parameters come only from the parameter register (`src/params.ts` mirrors it).
- No function accepts an IV, an algorithm choice or a raw AAD. IVs are generated inside `src/aead.ts`; AAD, labels, HKDF info and signed statements are `CanonicalBytes` from `src/contexts.ts`.
- No function returns private-key bytes. Private keys are wrapped and unwrapped inside WebCrypto and are non-extractable after unlock.
- The RSA-OAEP wrapper accepts only 32-byte values (INV-17). The signing key signs only canonical statements.
- Every failure is a `CryptoError` with a fixed code; library error texts are dropped. Missing primitives fail closed with `CRYPTO_UNAVAILABLE` (INV-15).
- The Room Safety Code will be derived here and never leave the browser (INV-18, Phase 6).
- This package must not import Node.js modules or server code and never holds server secrets.

## Layout

| File | Purpose |
|---|---|
| `src/aead.ts`, `src/hkdf.ts`, `src/hash.ts`, `src/rsa-oaep.ts`, `src/signing.ts` | Primitive wrappers |
| `src/canonical.ts`, `src/contexts.ts` | RFC 8785 for the CP-15 subset (LIB-05) and the context catalogue |
| `src/identity.ts`, `src/fingerprint.ts` | The identity bundle of ADR-015 |
| `src/kdf/` | Argon2id: library loader, embedded WebAssembly (generated), worker, worker protocol, runner, derivation |
| `src/passphrase.ts`, `src/passphrase-blocklist.ts` (generated) | Vault Passphrase policy (CP-06) |
| `src/vault.ts`, `src/vault-format.ts` | Vault flows and the format version 1 codec |
| `src/internal/raw.ts` | Test-only seam with fixed IVs and raw operations for known-answer tests; not exported |
| `vectors/` | Published test vectors with their sources and checksums ([vectors/README.md](vectors/README.md)) |

## Tests

`pnpm test:unit` runs the suites next to the code: known answers from FIPS 180-2, RFC 5869, the GCM specification, Wycheproof, RFC 6979, RFC 8785 and RFC 9106, OpenSSL differential tests, tamper and swap tests, fail-closed tests and the boundary test. `pnpm test:coverage:crypto` enforces at least 90% coverage (CLAUDE.md section 10). `pnpm bench:vault` measures the package in three browser engines under the production CSP.

Generated files: `src/kdf/argon2id-wasm.ts` (`node scripts/crypto/embed-argon2id-wasm.mjs`) and `src/passphrase-blocklist.ts` (`node scripts/auth/build-password-blocklist.mjs`). Do not edit them by hand.
