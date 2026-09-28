# ADR-003: AES-256-GCM for symmetric encryption

- Status: Accepted
- Date: 2026-09-28
- Related: [crypto-decisions.md](../../crypto/crypto-decisions.md) CP-01 and CP-16, [cryptographic-architecture.md](../../crypto/cryptographic-architecture.md) sections 8 and 9

## Context
CipherMesh needs authenticated encryption in every major browser without additional libraries, for content and for wrapping keys under symmetric keys. It must bind ciphertext to its context (room, item, version) and detect tampering.

## Decision
Use **AES-256-GCM** for all symmetric encryption and symmetric key wrapping: content (files, notes and secret payloads), manifests, DEK wrapping under the room wrapping key, private-key wrapping under the vault key, and server-side encryption of TOTP secrets.
- 256-bit keys, 96-bit IVs from a CSPRNG generated inside the crypto module, 128-bit tags.
- AAD is always the canonical context for the operation.
- Decryption fails closed; no plaintext is released before the tag is verified.
- Invocation bounds per key are defined in CP-16.

## Alternatives Considered
- **AES-CBC with HMAC (encrypt-then-MAC):** secure when built correctly, but it is a composition with more ways to go wrong (MAC ordering, key separation, padding oracles).
- **ChaCha20-Poly1305 or XChaCha20-Poly1305:** excellent and faster without AES hardware, and XChaCha has a larger nonce that makes random nonces safer. Not available in WebCrypto, so it would need a library.
- **AES-GCM-SIV:** resistant to nonce misuse, but not available in WebCrypto.
- **AES-KW (RFC 3394) for key wrapping:** deterministic and needs no nonce, but has no associated data, so it cannot bind a wrapped key to its context.

## Consequences
- IV uniqueness is critical. The crypto module generates IVs internally and never accepts them from callers; each DEK is used for at most two encryptions.
- WebCrypto AES-GCM is one-shot, which limits single-file size (CP-19).
- AES-GCM is not key-committing. Room keys get a commitment and a Room Safety Code, whose limits are stated in CD-13 and ADR-012.

## Security Implications
- Confidentiality and integrity for T-01, T-02 and T-07.
- A nonce reuse would break confidentiality and allow forgeries under that key; the design makes reuse structurally unlikely and tests check it.
- Proven by known-answer tests, tamper tests and context-separation tests.

## Status
Accepted. Review if WebCrypto adds a nonce-misuse-resistant or committing AEAD, or if the chunked file design (OCD-09) is needed.
