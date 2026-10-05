# Vault Specification (format version 1)

Status: Phase 4 (CM-T023 to CM-T028, CM-T086). Normative. Algorithms and parameters come only from [crypto-decisions.md](crypto-decisions.md): CP-01 to CP-04, CP-06, CP-15 to CP-18, CP-22, CP-26 and CP-27. Decisions: [ADR-010](../architecture/adr/ADR-010-browser-argon2id.md) (browser Argon2id) and [ADR-015](../architecture/adr/ADR-015-identity-signing-keys.md) (identity signing keys). Related: [cryptographic-architecture.md](cryptographic-architecture.md) section 5, [key-lifecycle.md](key-lifecycle.md) section 3, [../architecture/data-flow.md](../architecture/data-flow.md) DF-03 and DF-04.

The Vault holds the private keys of a user's cryptographic identity, encrypted in the browser under keys derived from the Vault Passphrase. The server stores the encrypted vault so that the user can open it on any device. It can never open the vault itself.

## 1. Two secrets

| | Account Password | Vault Passphrase |
|---|---|---|
| Proves or protects | The account, to the server (login, step-up) | The identity's private keys |
| Leaves the browser | Yes, over TLS, at registration, login and step-up | **Never.** Not in requests, URLs, cookies, browser storage or logs |
| Server keeps | An Argon2id hash (CP-05) | Nothing: no hash, no verifier, no attempt counter |
| Policy (CP-06) | 12 to 128 code points, checked by the API | 16 to 256 code points, checked only in the browser |
| If lost | An administrator can reset it; no content is lost | Nobody can recover the private keys. A vault reset creates a new identity (section 6.6, L-17) |

The UI names the two secrets differently on every screen, explains the difference on the vault page, and never fills one from the other. Step-up for vault changes asks for the Account Password (and the MFA code); the vault itself asks only for the Vault Passphrase.

## 2. Identity bundle (ADR-015)

One identity consists of two key pairs under one key ID, generated together in the browser:

| Field | Content | Size |
|---|---|---|
| `keyId` | Random UUIDv4 generated in the browser | |
| `suite` | `CM1` (CP-18) | |
| Encryption key | RSA-OAEP-3072, e = 65537, SHA-256 (CP-02). Receives 32-byte values only (INV-17) | SPKI 422 bytes |
| Signing key | ECDSA P-256 with SHA-256 (CP-26). Signs canonical statements only | SPKI 91 bytes |
| `bindingSignature` | ECDSA signature by the signing key over `cm.identity.binding` {userId, keyId, suite, encryptionKeySpki, signingKeySpki} | 64 bytes (P1363) |
| `fingerprint` | SHA-256 of `cm.identity.fingerprint` {suite, encryptionKeySpki, signingKeySpki} (CP-17), lower-case hex | 64 characters, shown as 16 groups of 4 |

`verifyPublicIdentity` in `packages/crypto` is the single verification function. The browser runs it on its own record and on every directory result; the API runs the same code (`@ciphermesh/crypto/identity`) before storing an identity. It requires:

- the suite `CM1`;
- both SPKIs of the exact size and algorithm (RSA-OAEP-3072 with e = 65537; P-256 with an uncompressed point), each re-exporting byte for byte after import, so only one encoding of a key is accepted;
- a valid binding signature for the user ID and key ID it is presented with, so keys copied to another account fail;
- a fingerprint that equals the value recomputed from the two keys.

Any failure is `IDENTITY_INVALID`. A fingerprint received from the server is never displayed as verified: the browser shows only the value it computed itself.

## 3. Key derivation and wrapping (CP-27)

```
VRK              = Argon2id(NFKC(passphrase), salt, m, t, p)        32 bytes, in a Web Worker (CP-04)
                   imported at once as a non-extractable HKDF key; the bytes are wiped
PKWK_purpose     = HKDF-SHA-256(VRK, salt = 32 zero bytes,
                     info = cm.vault.pk-wrap {userId, keyId, purpose})   purpose = encryption | signing
                   non-extractable AES-256-GCM key, usages wrapKey and unwrapKey only
wrapped_purpose  = AES-256-GCM wrapKey("pkcs8", private key, PKWK_purpose, fresh 96-bit IV,
                     AAD = cm.vault.private-key {userId, keyId, purpose, fingerprint, suite, vaultVersion})
```

Every context is the RFC 8785 serialization of `{ctx, v, ...fields}` built by `packages/crypto/src/contexts.ts`. For example, the HKDF info of the encryption key's wrapping key is the UTF-8 bytes of

```
{"ctx":"cm.vault.pk-wrap","keyId":"<uuid>","purpose":"encryption","userId":"<uuid>","v":1}
```

Why each element is there:

| Element | Protects against |
|---|---|
| Argon2id with a per-write random salt | Fast offline guessing after a database theft (T-22); precomputation across users |
| One wrapping key per private key (CD-25) | IV reuse: each AES-GCM key encrypts exactly one message per vault write |
| `purpose` in the HKDF info and in the AAD | Swapping the two wrapped keys, or using one as the other |
| `userId` and `keyId` in both | Moving a wrapped key to another account or identity |
| `fingerprint` in the AAD | A server that pairs the wrapped keys with different public keys: unwrapping fails |
| `vaultVersion` and `suite` in the AAD | Reinterpreting a record under another format |
| `wrapKey` / `unwrapKey` inside WebCrypto | Private-key bytes appearing in JavaScript: the PKCS#8 encoding exists only inside the browser's crypto implementation |

AES-GCM is not key-committing (CD-13). An attacker who could exploit that already holds the encrypted record and can guess offline, so the vault has no separate commitment; the pair checks in section 6.2 tie the opened keys to the public identity.

## 4. Stored record and wire format

The API accepts and returns this JSON (strict schemas in `packages/validation/src/vault.ts`: unknown fields are refused at every level, so a request cannot carry anything else, such as a passphrase). Binary values are canonical unpadded base64url with exact lengths.

```json
{
  "vaultVersion": 1,
  "identity": {
    "keyId": "<uuid v4>",
    "suite": "CM1",
    "encryptionPublicKey": "<base64url, 422 bytes>",
    "signingPublicKey": "<base64url, 91 bytes>",
    "bindingSignature": "<base64url, 64 bytes>",
    "fingerprint": "<64 hex>"
  },
  "kdf": {
    "algorithm": "argon2id",
    "version": 19,
    "memoryKiB": 65536,
    "iterations": 3,
    "parallelism": 1,
    "salt": "<base64url, 16 bytes>"
  },
  "wrappedEncryptionKey": { "iv": "<base64url, 12 bytes>", "ciphertext": "<base64url, 1700 to 2048 bytes>" },
  "wrappedSigningKey": { "iv": "<base64url, 12 bytes>", "ciphertext": "<base64url, 64 to 256 bytes>" }
}
```

Storage: one row in `user_key_pairs` per identity (data-model section 4.5). The wrapped keys and their IVs, the KDF parameters and salt, both SPKIs, the binding signature, the fingerprint, the format version and the status are stored. Database CHECK constraints repeat the sizes and the KDF ceiling, a partial unique index allows one ACTIVE identity per user, and a trigger makes the identity columns write-once and a retired status final ([../security/database-security.md](../security/database-security.md)). Nothing in the row is secret on its own; the wrapped keys are protected by the passphrase and Argon2id (L-08).

Acceptance rules, applied by the browser before any derivation and again by the API:

- `vaultVersion` must be 1 and `suite` must be `CM1`. Anything else is refused (`UNSUPPORTED_VAULT_VERSION`, no downgrade).
- `kdf.algorithm` must be `argon2id`, version 19, with parameters between the floor and the ceiling of CP-04 (`KDF_PARAMETERS_OUT_OF_RANGE`). The ceiling bounds how much work a modified record can demand.
- All sizes and encodings must match exactly (`INVALID_VAULT_FORMAT`).
- The record must belong to the signed-in user, and its identity must verify (section 2).

## 5. Where Argon2id runs (ADR-010, CD-27)

- Library: `argon2id` 1.0.1 (LIB-03). Its two WebAssembly builds are embedded in the bundle as base64; a unit test compares their SHA-256 with the installed package.
- Each derivation runs in a fresh dedicated module Web Worker (`packages/crypto/src/kdf/argon2id.worker.ts`). The passphrase bytes are transferred to the worker, which validates the request, derives, transfers the 32-byte result back, wipes its copy of the passphrase and closes. The worker is terminated afterwards, which releases its WebAssembly memory.
- One derivation at a time per page: a second request while one runs is refused with `KDF_BUSY` instead of being queued, so repeated clicks or a script cannot stack up 64 MiB derivations. A derivation that takes longer than 120 seconds is treated as failed.
- No fallback. Without WebCrypto, WebAssembly or Web Workers in a secure context, vault setup and unlock fail with `CRYPTO_UNAVAILABLE` (INV-15). The CSP adds only `'wasm-unsafe-eval'`.

## 6. Flows

### 6.1 Setup (DF-03, CM-T025)

1. The user is signed in and confirms the account with a recent step-up (standard window). The page explains the two secrets and requires the user to acknowledge that a lost Vault Passphrase cannot be recovered.
2. The browser checks the new passphrase against the policy (CP-06) locally.
3. In parallel: it generates the identity (section 2) and derives the VRK with the target parameters and a new salt.
4. It derives the two wrapping keys and wraps both private keys (section 3).
5. `POST /api/vault` sends the record of section 4. The API validates it (section 7), verifies the identity, and stores it if the user has no ACTIVE identity yet (`VAULT_ALREADY_EXISTS` otherwise).
6. The browser opens the record the server stored with the keys it still holds, as non-extractable keys, and runs the pair checks. Only then is the vault shown as unlocked. The extractable key objects from generation go out of scope.

### 6.2 Unlock (DF-04, CM-T026)

1. `GET /api/vault` returns the user's own ACTIVE record (404 `VAULT_NOT_FOUND` if none). The route takes no identifier: the owner is always the session user (OL-10).
2. The browser applies the acceptance rules of section 4 and verifies the identity against its own user ID.
3. It derives the VRK and the two wrapping keys, and unwraps both private keys as **non-extractable** keys: the encryption key with usages `decrypt` and `unwrapKey`, the signing key with `sign`.
4. Pair checks: an RSA-OAEP round trip of a random 32-byte value under the label `cm.vault.pair-check` {userId, keyId, suite}, and an ECDSA signature over `cm.vault.signing-check` {userId, keyId, challenge} with a random 32-byte challenge, verified with the public key. They detect public keys that do not belong to the private keys.
5. A wrong passphrase, a modified ciphertext, IV, salt or parameter, a substituted identity and a failed pair check all produce the same `VAULT_UNLOCK_FAILED`: the browser cannot tell a wrong passphrase from a damaged record and does not try to. Unlock attempts are local; the server never learns of them and cannot count them.

### 6.3 Lock and auto-lock (CP-22)

Unlocked keys exist only as `CryptoKey` objects in the memory of the tab. Nothing unlocked is written to cookies, localStorage, sessionStorage, IndexedDB or the Cache API, and each tab unlocks separately. The vault locks:

- after 15 minutes without trusted user input (keyboard, pointer or touch events generated by the user; events created by scripts do not count);
- when the user selects "Lock now" or signs out;
- when the page is hidden for navigation or closed (`pagehide`);
- when any API answer reports the session as ended (401), checked at least every 60 seconds while the user is active;
- after a vault reset.

Locking drops every reference to the keys. A lock requested while a vault operation is running takes effect when it finishes, and results that arrive after a lock are discarded. The keys exist only while the vault is shown as unlocked: every other state drops them. A background refresh that fails (network, rate limit) leaves an unlocked vault as it is, so the auto-lock keeps running (R-04-01). JavaScript cannot wipe memory (L-15), and the lock is client-side behaviour that the server cannot enforce (L-38).

### 6.4 Passphrase change (CM-T028)

1. The user confirms the account (standard step-up window) and enters the current and the new Vault Passphrase. The new one must pass the policy.
2. The browser opens the vault with the current passphrase. Only in this flow are the private keys unwrapped as extractable, because the same keys must be wrapped again.
3. It derives new wrapping keys from the new passphrase and a **new salt**, with parameters equal to the stronger of the stored ones and the target, and wraps the same private keys again. The key ID and the fingerprint do not change.
4. It signs `cm.vault.rewrap` with the identity's signing key. The statement covers the user ID, key ID, suite, format version, previous salt, all new KDF parameters and the new salt, and both new IVs and ciphertexts.
5. `POST /api/vault/rewrap` sends the new values, the previous salt and the signature. The API refuses the request if the key ID or the previous salt is not the stored one (`VAULT_CONFLICT`), if the parameters are weaker than the stored ones or the salt is reused (`INVALID_VAULT_FORMAT`), or if the signature does not verify under the stored signing key (`VAULT_SIGNATURE_INVALID`). It applies the change with a compare-and-swap on the previous salt, so replays and concurrent changes fail.
6. The browser opens the stored result with the new keys before it reports success.

A stolen session, even together with the Account Password, therefore cannot replace the wrapped keys of an identity. A passphrase change does not help against someone who already holds an old copy of the record and the old passphrase (L-40); that case needs a reset.

### 6.5 Parameter upgrade (ADR-010)

If the stored parameters are below the target, the vault page offers an upgrade after unlock. It is the flow of section 6.4 with the same passphrase, and the passphrase policy is not re-applied so that a stronger derivation is never blocked. The upgrade needs a step-up and is not automatic.

### 6.6 Reset after a lost passphrase

1. The user confirms the account with a strict step-up (5 minutes) and acknowledges that the old identity is lost.
2. The browser creates a new identity and vault (section 6.1, steps 2 to 4).
3. `POST /api/vault/reset` names the current identity (`supersedesKeyId`) and sends the new record. In one transaction the API marks the old identity SUPERSEDED, sets both of its wrapped private keys to NULL (its public keys stay for verification of earlier statements), stores the new identity, revokes the user's other sessions and rotates the current one.
4. The new identity has a new fingerprint. A reset cannot be signed by the lost key, so it is visible: contacts see the fingerprint change, and from Phase 6 room administrators are notified and re-share room keys (key-lifecycle section 3).

There is no recovery path: no server escrow, no administrator key, no recovery derived from the Account Password. A PLATFORM_ADMIN cannot open any vault.

### 6.7 Public-key directory (CM-T027)

`POST /api/directory/lookup` with an exact email address returns the user ID, display name, account creation time, `emailVerified: false` (L-21) and the public identity (keys, binding signature, fingerprint, creation time) of an ACTIVE identity. Unknown addresses, users without a vault and disabled accounts all get the same 404. The caller must have a vault of its own, and lookups are rate-limited per user. The response never contains wrapped keys, salts, IVs, KDF parameters or the email address. The browser verifies the identity and computes the fingerprint itself before showing it.

## 7. Server-side validation

The server cannot verify that ciphertext is ciphertext (L-27), but it refuses everything it can check:

- strict schemas with exact base64url lengths and no unknown fields, for request bodies, the query string (none allowed) and responses;
- the KDF floor and ceiling and the format version;
- full identity verification with the shared code (section 2);
- ownership from the session only (OL-10); no route accepts a user ID;
- step-up windows: standard (15 minutes) for setup, re-wrap and upgrade; strict (5 minutes) for reset;
- signature verification and compare-and-swap for re-wraps;
- rate limits per user: vault reads 60 per 15 minutes, vault writes 10 per hour, directory lookups 20 per 10 minutes;
- security events with identifiers and counts only (`VAULT_CREATED`, `VAULT_REWRAPPED`, `VAULT_RESET`, `VAULT_REJECTED`, `DIRECTORY_LOOKUP_THROTTLED`); request bodies of vault routes are never logged, and the redaction list covers vault field names (INV-10).

## 8. Versioning and migration

Every record carries `vaultVersion` and `suite`, and both are inside the AAD. A future format (for example other KDF parameters bound into the AAD, a post-quantum KEM or Ed25519 signatures) gets a new version and suite. Migration is a signed re-wrap: the browser opens the old record and writes the new one through the flow of section 6.4. Browsers refuse versions they do not know, and the API refuses writes of unknown or older versions, so a record is never downgraded.

## 9. What the vault does not provide

- Protection against malicious JavaScript served by a compromised server, or against a compromised device (L-01, L-02).
- Protection of a weak passphrase against offline guessing by someone with the record, such as a database thief or the holder of a valid session (L-08, L-39).
- Recovery of a lost passphrase (L-17).
- Server-enforced locking (L-38) or reliable memory wiping (L-15).
- Revocation of old copies after a passphrase change (L-40).

## 10. Tests

| Property | Tests |
|---|---|
| Known answers for every primitive | `packages/crypto/src/primitives.test.ts` (SHA-256, HKDF, AES-GCM), `rsa-oaep.test.ts` and `signing.test.ts` (Wycheproof), `argon2id.test.ts` (RFC 9106, OpenSSL), `canonical.test.ts` (RFC 8785) |
| Identity verification and fingerprint | `packages/crypto/src/identity.test.ts` |
| Vault format, unlock failures, tamper and swap, re-wrap and upgrade | `packages/crypto/src/vault.test.ts` |
| API setup, re-wrap, reset, directory, BOLA and leakage | `tests/vault/*.test.ts`, `tests/auth/csrf.test.ts`, `tests/security/route-inventory.test.ts` |
| Browsers: no passphrase in requests or storage, cross-engine unlock, tampered record, auto-lock, sign-out lock | `tests/e2e/vault.spec.ts` in Chromium, Firefox and WebKit |
| The tests can fail | Negative controls NC-04-01 to NC-04-14 (`pnpm security:negative-controls`) |
| Performance under the production CSP | `pnpm bench:vault` (crypto-decisions section 8) |
