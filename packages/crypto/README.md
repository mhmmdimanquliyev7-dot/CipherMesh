# packages/crypto

Client-side cryptography for CipherMesh: thin, well-tested wrappers around WebCrypto (AES-256-GCM, RSA-OAEP, HKDF, SHA-256), the browser Argon2id integration, and the canonical context (AAD / OAEP label / HKDF info) builders.

Status: package boundary only (Phase 1). The package exports nothing usable, and a test keeps it that way until Phase 4. Implementation starts in Phase 4.

Rules:
- No custom primitives or modes. Only the constructions specified in docs/crypto/.
- Parameters come only from the parameter register in docs/crypto/crypto-decisions.md.
- Encryption functions generate IVs internally and never accept an IV from the caller.
- Every wrapper ships with known-answer tests and tamper tests.
- The RSA-OAEP wrapper accepts only 32-byte keys. There is no general-purpose RSA encryption function (INV-17).
- The Room Safety Code is derived here and never leaves the browser (INV-18).
- This package must not import server-only modules and must never hold server secrets.
