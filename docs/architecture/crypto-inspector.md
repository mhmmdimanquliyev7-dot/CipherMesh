# Crypto Inspector (design)

Status: Phase 0.5 design. Implementation: Phase 13 (CM-T059, CM-T060). Related: [../crypto/cryptographic-architecture.md](../crypto/cryptographic-architecture.md), [../security/authorization-model.md](../security/authorization-model.md) (AZ-27), [../security/limitations.md](../security/limitations.md).

## 1. Purpose

The Crypto Inspector explains how an item is protected, using real metadata and real verification results, **without exposing any key**. It is both a user-facing transparency feature and a teaching aid for the cryptography demonstration.

## 2. Views

| View | Opened from | Shows |
|---|---|---|
| Item view | A file, note or secret | How that item is encrypted, which key version protects it, integrity results, lifetime and who has cryptographic access |
| Room view | Room settings | Profile and controls, key state and rekey status, key-version history, Room Safety Code |
| Identity view | Account settings | The user's key fingerprint, algorithm and vault KDF parameters |

## 3. Item view fields

| Field | Example | Source | Notes |
|---|---|---|---|
| Client-side encrypted | Yes, encrypted in the uploader's browser | Server: record has a suite | Fixed wording per suite |
| Algorithm suite | CM1 | Server | Links to the suite definition (CP-18) |
| Content encryption | AES-256-GCM (authenticated encryption) | Derived from suite | |
| Content key | Unique 256-bit key for this item | By design (INV-03) | Never the key itself |
| Key wrapping | Content key wrapped with room key version 4 (ACTIVE) | Server: `keyVersion`, version status | Secrets: "secret key (SEK) wrapped to the recipient's public key with RSA-OAEP-3072; content encrypted with AES-256-GCM" |
| Room key distribution | RSA-OAEP-3072 with SHA-256, one envelope per member key | Derived from suite | |
| Room key commitment | `3f9a0c1e...` matches the key this device holds | Server value, client check | Detects inconsistent envelopes while the server is honest. Does not by itself detect a malicious server: see the Room Safety Code in the room view |
| Integrity | Authentication tag verified on this device | Client, after decryption | "Not decrypted yet" before download |
| Ciphertext fingerprint | SHA-256 `9f2c...`, matches downloaded ciphertext | Server value, client check | Hash of ciphertext, not plaintext |
| Plaintext fingerprint | SHA-256 `1ab3...`, computed locally, never uploaded | Client only | Shown only after decryption |
| IVs | 96-bit random, for example `a1b2c3...` | Server | Not secret; shows that each encryption has its own IV |
| Ciphertext size | 2.4 MB | Server | Illustrates metadata exposure (L-05) |
| Created, uploader | 2026-10-12 14:03 UTC, alice | Server | Uploader attribution comes from the authenticated session (L-09) |
| Expiration | Expires in 23 h 12 min | Server | Burn-after-reading status for secrets |
| Members with cryptographic access to version 4 | 3 | Server: ACTIVE envelopes for the version | |
| Members currently authorized to read | 3 | Server: ACTIVE members with read permission | Differences are explained |
| Former members who could have received version 4 | 1 | Server: removed or departed members whose membership overlapped the version's active period | Honest reminder of L-04 |
| Transport | Page loaded in a secure context over HTTPS | Client: `isSecureContext` and protocol | The browser cannot report the TLS version to scripts; no TLS version is claimed |
| Room profile | RESTRICTED | Server | Links to the profile controls |

Every item view ends with a **"What this does not protect"** section: metadata visible to the server, copying by authorized members, compromised devices, malicious code delivery, a room key distributed by a compromised server (T-36), and the fact that key consistency is only checked when members compare Safety Codes, each linked to [limitations.md](../security/limitations.md).

## 4. Room and identity views

**Room view:** profile and its key controls; key state (ACTIVE, REKEY_REQUIRED or REKEYING) with its reasons and any pending rekey operation; key versions with status, reasons, creation time, creator, commitment prefix and envelope count; the Room Safety Code for the current version, computed locally, with the member's comparison status ([security-ui.md](security-ui.md) section 2.3); time left in the cryptoperiod for CONFIDENTIAL and RESTRICTED rooms; the global audit-integrity status.

**Identity view:** key ID, algorithm, full fingerprint in 16 groups of 4, creation date, Argon2id parameters of the vault, vault state (locked or unlocked), date of the last re-wrap.

## 5. Never shown

Private keys, room key material, room wrapping keys, DEKs, vault-derived keys, the Vault Passphrase, password hashes, TOTP secrets, recovery codes, session tokens, server secrets, presigned URLs. Wrapped keys and envelopes are ciphertext and would be safe to show, but they add no explanatory value, so they are excluded to keep the allowlist minimal.

## 6. Data flow and authorization

1. The browser calls the inspection endpoint for the item. Authorization is identical to reading the item (AZ-27), including profile gates; non-members receive 404.
2. The API builds the response from an **explicit allowlist projection**. It never serializes database records directly.
3. The browser adds client-side results (tag verification, commitment check, plaintext hash, Room Safety Code) that exist only in memory and are never sent to the server.

## 7. Wording rules

- Use "client-side encrypted", "authenticated encryption", "verified on this device".
- Never say "unbreakable", "military grade", "zero knowledge" or "tamper-proof".
- When a check has not run (for example before decryption), say so instead of showing a green state.

## 8. Tests

- Response-schema test that fails on any field outside the allowlist.
- DOM scan in Playwright with known test keys: none of their encodings appear in the page.
- Network test: neither the plaintext fingerprint nor the Room Safety Code appears in any request.
- Authorization tests: non-members receive 404; VIEWERs in RESTRICTED rooms see only server-side fields, with no wrapped key, manifest or download capability.
