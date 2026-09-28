# ADR-007: RSA-OAEP-3072 for room-key and secret-key distribution

- Status: **Proposed** (confirm before Phase 6, OCD-01)
- Date: 2026-09-28
- Related: [crypto-decisions.md](../../crypto/crypto-decisions.md) CP-02, [cryptographic-architecture.md](../../crypto/cryptographic-architecture.md) section 7, T-25, T-29

## Context
Room key material (32 bytes) must be delivered to each member so that only that member can recover it, and secret keys must be delivered to one recipient. The mechanism must work in all major browsers, use standardized constructions, and be explainable in a cryptography course. The project rules forbid inventing an ECIES-like protocol.

## Options evaluated

| Criterion | A. RSA-OAEP-3072, SHA-256 (WebCrypto) | B. HPKE, RFC 9180 (library) | C. JWE ECDH-ES+A256KW (library) | D. Own ECDH + HKDF + AES-KW composition |
|---|---|---|---|---|
| Standardized as a whole | Yes (PKCS #1 v2.2, RFC 8017) | Yes | Yes (RFC 7516, RFC 7518) | No, only its parts |
| Native in WebCrypto | Yes | No; needs a library | No; library on top of WebCrypto | Parts only |
| Composition designed by us | None | None | None | **Yes: forbidden** |
| Explainability for the course | High: "encrypt the key with the recipient's public key" | Medium: KEM, key schedule, modes | Medium: JOSE headers and algorithms | Medium |
| Public key and envelope size | 384-byte modulus, 384-byte envelope | 32 to 65 bytes | Small | Small |
| Performance | Slow key generation (once per vault), fast wrapping | Fast | Fast | Fast |
| Sender authentication | No | Optional (authenticated mode) | No | Possible |
| Context binding | OAEP label | `info` and AAD | Protected header | HKDF `info` |
| New dependency | None | Yes, a cryptographic one | Yes, with known JOSE pitfalls such as algorithm confusion | None |
| Post-quantum | No | No (post-quantum KEMs emerging) | No | No |

## Decision
Use **RSA-OAEP with a 3072-bit modulus, public exponent 65537, SHA-256 for OAEP and MGF1**, through WebCrypto, to wrap 32-byte key material only: room key material and per-secret keys (SEKs). It never encrypts content (INV-17). Content always uses AES-256-GCM under a per-item key. The OAEP **label** carries the canonical context (room, version, recipient user, recipient key ID, suite), so an envelope cannot be moved to another context.

Reasons: it is native in every major browser, fully standardized, needs no composition by the team and no new cryptographic dependency, and it is the clearest demonstration of public-key encryption for the course. 3072 bits gives roughly 128-bit security, matching the rest of the design. The size and key-generation cost are acceptable at this scale.

**HPKE (option B)** is the preferred alternative if a switch becomes necessary, for example if cross-browser testing shows inconsistent OAEP label support.

## Consequences
- RSA key generation takes noticeable time on slow devices, once per vault; the UI shows progress.
- Envelopes are 384 bytes each; storage cost is negligible.
- RSA-OAEP gives no sender authentication. Anyone with a recipient's public key can create a valid envelope, including the server. Who created an envelope is known only from the authenticated API session (L-09). A server-side attacker can therefore inject key material of its own (T-36, L-23). OCD-12 decides how key versions are authenticated.
- Phase 6 must run a cross-browser test (Chromium, Firefox, WebKit) of OAEP labels and of decrypting into HKDF keys.

## Security Implications
- **Key substitution (T-25):** RSA-OAEP cannot prevent the server from handing out a wrong public key. Fingerprints, mandatory confirmation in RESTRICTED rooms and audited key changes mitigate this.
- **Equivocation (T-29):** the commitment catches inconsistent envelopes while the server is honest. Split views created by the server are detected only when members compare Room Safety Codes (ADR-012).
- **Plaintext size:** RSA-OAEP-3072 with SHA-256 accepts at most 318 bytes. Restricting it to 32-byte keys keeps every use far inside that limit.
- **Chosen-ciphertext oracles (Manger-style attacks):** decryption happens only in the recipient's browser, WebCrypto returns one generic error for every failure, and the client stops and reports after a failed envelope instead of retrying, which denies an attacker the many adaptive queries such attacks need.
- **Quantum:** envelopes recorded today could be decrypted by a future large quantum computer (L-16). The suite identifier allows migration to a post-quantum KEM when browsers support one.

## Status
Proposed. Becomes Accepted when the project owner approves Phase 0 and the Phase 6 cross-browser test passes. Superseded by a new ADR if HPKE or a post-quantum KEM is adopted.
