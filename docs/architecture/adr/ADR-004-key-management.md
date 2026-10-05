# ADR-004: Key-management approach

- Status: Accepted (revised in Phase 0.5; the asymmetric mechanism is decided in ADR-007, key-version authentication in [ADR-015](ADR-015-identity-signing-keys.md))
- Date: 2026-09-28
- Related: [key-hierarchy.md](../../crypto/key-hierarchy.md), [key-lifecycle.md](../../crypto/key-lifecycle.md), [ADR-012](ADR-012-room-safety-code.md), [ADR-013](ADR-013-rekey-state-machine.md), T-21, T-22, T-25, T-29, T-36

## Context

Rooms have changing membership. Content must be shareable with all current members, protected from the server, deletable per item, and protected from removed members going forward. The server must never hold usable content keys.

## Decision

A layered envelope-encryption hierarchy:

1. **Vault:** the Vault Passphrase goes through Argon2id (in the browser) and HKDF to a private-key wrapping key. That key protects the user's RSA-OAEP private key with AES-256-GCM. The encrypted private key is stored on the server so every device of the user can unlock it.
2. **Room key versions:** each version has 32 random bytes of room key material (RKM_v), generated in a member's browser. RKM_v is distributed as one RSA-OAEP envelope per member key. Plaintext RKM_v is never stored server-side.
3. **Key separation and consistency checks:** HKDF derives three values from RKM_v, each with its own context:
   - the room wrapping key RWK_v;
   - the public commitment RKC_v, stored once per version;
   - the locally computed Room Safety Code (ADR-012).

   The commitment catches envelopes that do not match the stored value while the server is honest. Split views created by the server itself are detected only when members compare Safety Codes over an independent channel.
4. **One envelope pattern for all content:** every file, note revision and secret is encrypted with AES-256-GCM under its own random 256-bit data key (FEK, NEK, SEK). Only the data key is wrapped, and the audience decides how:
   - file and note keys are wrapped under RWK_v with AES-256-GCM;
   - a secret's SEK is wrapped to the recipient's public key with RSA-OAEP.

   RSA-OAEP never encrypts content (INV-17).
5. **Versioning and rekey:** losing a member (removal, leaving, suspension, deletion), cryptoperiod expiry, the wrap bound or a reported compromise immediately write-locks the room (REKEY_REQUIRED). An OWNER or ADMIN browser then produces version v+1 for exactly the remaining recipients. The server validates it and activates it atomically (ADR-013). Writes that use an old version are rejected.
6. **Algorithm suite identifiers** on every encrypted record.

## Alternatives Considered

- **One room key encrypting content directly:** simpler, but concentrates many encryptions under one key (nonce risk) and makes per-item crypto-shredding impossible.
- **Wrapping every item key directly to every member's public key:** no shared room key, but envelopes grow with members times items, and new members or rekeys would need every item re-wrapped.
- **Encrypting secret content directly with RSA-OAEP:** limited to 318 bytes per operation, slow, and a second content path to secure and test. Rejected in favour of the uniform envelope pattern.
- **Group key agreement such as the Messaging Layer Security protocol (RFC 9420):** strong forward secrecy and post-compromise security, but a large protocol that is hard to implement correctly and explain in this project.
- **Server-side key-management service:** the server could decrypt, which contradicts ADR-002.

## Consequences

- Rekeys are performed by a browser that holds the keys. The server enforces the write lock and validates the result.
- Removed members keep what they had (L-04). History for new members is set by the profile (PC-07).
- Recovery without escrow: a user who loses the passphrase depends on re-sharing by room admins (L-17).

## Security Implications

- The hierarchy is acyclic ([key-hierarchy.md](../../crypto/key-hierarchy.md) section 4).
- The commitment defeats inconsistent envelopes from a malicious member while the server is honest. The Room Safety Code detects server-made split views only when compared (T-29, L-22).
- **Gap closed by design in ADR-015:** RSA-OAEP has no sender authentication, and public keys are public, so without signatures a server-side attacker could create a key version of its own and wrap it to every member (T-36, L-23). ADR-015 (accepted 2026-10-05) gives every identity an ECDSA P-256 signing key (implemented in Phase 4) and makes key versions signed by their creator (implemented in Phase 6).
- Public-key substitution by a server-side attacker is mitigated by fingerprints, not eliminated (T-25, L-07).
- Tests: rekey suite, commitment and Safety Code tests, context-separation tests, the RSA input restriction, canary scans.

## Status

Accepted. OCD-12 was decided by ADR-015. Review if re-encryption on rekey (OCD-07) is adopted.
