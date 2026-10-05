# Key Hierarchy

Status: Phase 0.5 baseline, updated in Phase 4 (identity signing key, ADR-015; one wrapping key per private key, CP-27). Normative. Parameters: [crypto-decisions.md](crypto-decisions.md). Mechanisms: [cryptographic-architecture.md](cryptographic-architecture.md). Lifecycle: [key-lifecycle.md](key-lifecycle.md).

In the diagrams, a solid arrow from A to B means "A protects or derives B". A dotted arrow means "A authenticates B" (a signature); it adds no confidentiality.

## 1. Client-side hierarchy (room content)

```mermaid
flowchart TD
  VP(["Vault Passphrase<br/>user memory only"])
  VRK["VRK<br/>Argon2id output<br/>ephemeral"]
  PKWKE["PKWK_encryption<br/>HKDF-derived AES-256-GCM<br/>ephemeral"]
  PKWKS["PKWK_signing<br/>HKDF-derived AES-256-GCM<br/>ephemeral"]
  KP["User encryption key pair<br/>RSA-OAEP-3072<br/>private half stored only wrapped"]
  SK["User signing key pair<br/>ECDSA P-256 (ADR-015)<br/>private half stored only wrapped"]
  VP -->|"Argon2id, per-write salt"| VRK
  VRK -->|"HKDF ctx vault.pk-wrap<br/>purpose encryption"| PKWKE
  VRK -->|"HKDF ctx vault.pk-wrap<br/>purpose signing"| PKWKS
  PKWKE -->|"AES-256-GCM wrap of private half"| KP
  PKWKS -->|"AES-256-GCM wrap of private half"| SK
  SK -.->|"binding signature over both public keys"| KP

  RKM["RKM_v<br/>32 random bytes per room key version"]
  RWK["RWK_v<br/>HKDF-derived AES-256-GCM"]
  RKC["RKC_v<br/>HKDF-derived commitment<br/>public, stored once per version"]
  RSC["RSC_v Room Safety Code<br/>HKDF-derived, shown to members<br/>never sent or stored"]
  KP -->|"RSA-OAEP envelope per member key"| RKM
  SK -.->|"key-version statement with RKC_v<br/>(signed by its creator, Phase 6)"| RKC
  RKM -->|"HKDF ctx room.dek-wrap-key"| RWK
  RKM -->|"HKDF ctx room.commitment"| RKC
  RKM -->|"HKDF ctx room.safety-code"| RSC

  FEK["FEK<br/>one per file"]
  NEK["NEK<br/>one per note revision"]
  SEK["SEK<br/>one per secret"]
  RWK -->|"AES-256-GCM wrap"| FEK
  RWK -->|"AES-256-GCM wrap"| NEK
  KP -->|"RSA-OAEP wrap of the 32-byte SEK<br/>to the recipient key"| SEK

  FC[("File content and manifest")]
  NC[("Note title and body")]
  SC[("Secret payload")]
  FEK -->|"AES-256-GCM"| FC
  NEK -->|"AES-256-GCM"| NC
  SEK -->|"AES-256-GCM"| SC
```

Every content item follows the same envelope pattern: its own data key, AES-256-GCM, and then a key wrap chosen by the audience. RSA-OAEP only ever wraps 32-byte keys: room key material, SEKs and the vault pair-check value (INV-17). The signing key never encrypts or wraps anything; it only signs canonical statements (CP-26).

## 2. Server-side keys (separate domain)

These keys never protect room content, and client keys never protect them.

```mermaid
flowchart LR
  TOTPK["TOTP_ENCRYPTION_KEY<br/>AES-256-GCM"] -->|"encrypts"| TS[("TOTP secrets")]
  HMACK["IDENTIFIER_HMAC_KEY"] -->|"HMAC"| LI[("Unknown login identifiers")]
  ASK["Audit signing key<br/>Ed25519, Level 1 on the worker<br/>optional Level 2 provider key"] -->|"signs"| CP[("Audit checkpoints")]
  TLSK["TLS private key"] -->|"authenticates"| HTTPS(["HTTPS endpoint"])
```

## 3. Key inventory

| Key or value | Type | Created by | Protected by | Stored | Lifetime | Destroyed |
|---|---|---|---|---|---|---|
| Vault Passphrase | Secret string | User | User memory | Never | Until changed | Not applicable |
| VRK | 256-bit Argon2id output | Browser Web Worker | Derived | Never | Seconds | Immediately after deriving PKWK |
| PKWK_encryption, PKWK_signing | AES-256-GCM, non-extractable, one per private key | Browser (HKDF) | Derived | Never | Duration of unlock or wrap | After use |
| User encryption private key | RSA-OAEP-3072 | Browser at vault setup | PKWK_encryption (AES-256-GCM) | PostgreSQL as ciphertext; memory while unlocked | Until identity reset | Ciphertext set to NULL on reset or account deletion |
| User signing private key | ECDSA P-256 | Browser at vault setup, with the encryption key | PKWK_signing (AES-256-GCM) | PostgreSQL as ciphertext; memory while unlocked | Same as the encryption key | Same as the encryption key |
| User public keys, binding signature, fingerprint | SPKIs (422 and 91 bytes), ECDSA signature, SHA-256 hex | Browser | Public; verified by every client and by the API | PostgreSQL | Same as the private keys | Kept, so earlier signatures stay verifiable |
| RKM_v | 256 random bits | Browser of the room creator or the rekeying OWNER or ADMIN | Member key pairs (RSA-OAEP envelopes) | PostgreSQL as envelopes only | While version v is ACTIVE or RETIRED | Envelopes deleted when the version is destroyed, or per member when that member leaves the room |
| RWK_v | AES-256-GCM, non-extractable | Each member's browser (HKDF) | Derived | Never | In memory while the vault is unlocked | On vault lock |
| RKC_v | 256-bit commitment | Browser (HKDF) | Public value | PostgreSQL in clear, immutable | With version v | Kept |
| RSC_v (Room Safety Code) | 256-bit HKDF output, 66 bits displayed | Each member's browser (HKDF) | Derived; displaying it reveals nothing useful about RKM_v | Never; displayed only | While the room view is open | On vault lock or navigation |
| FEK | AES-256 | Uploader's browser | RWK_v | PostgreSQL, wrapped | Lifetime of the file | Wrapped FEK set to NULL on delete or expiry |
| NEK | AES-256 | Author's browser, per revision | RWK_v | PostgreSQL, wrapped | Until the next revision | Replaced on save; NULL on delete |
| SEK | AES-256 | Sender's browser | Recipient key pair (RSA-OAEP wrap of the 32-byte key) | PostgreSQL, wrapped | Until reveal or expiry | Wrapped SEK set to NULL on burn, expiry or revoke |
| Session token | 256 random bits | Server | Bearer secret in cookie | Cookie; PostgreSQL stores SHA-256 digest | At most 12 hours | Revocation or expiry |
| TOTP secret | 160 random bits | Server | TOTP_ENCRYPTION_KEY | PostgreSQL, server-encrypted | Until MFA is disabled | Set to NULL |
| TOTP_ENCRYPTION_KEY | AES-256 | Operator | File permissions, VM hardening | Secret file on the VM | Rotated yearly or on suspicion | Old key kept only until re-encryption completes |
| IDENTIFIER_HMAC_KEY | 256 random bits | Operator | File permissions | Secret file on the VM | Rotated yearly | Old HMACs age out with the 90-day retention |
| Audit signing key | Ed25519 | Operator workstation (Level 1) or provider key service (Level 2) | Level 1: file permissions, worker-only mount. Level 2: non-exportable provider key | Level 1: secret file on the VM plus offline backup; public key in the repository | Until compromise or planned rotation | Revoked key IDs listed in the repository with revocation time |
| TLS private key | Certificate key | Certificate automation | File permissions | VM | Short-lived, renewed automatically | On renewal |

## 4. No circular dependencies

The protection relation forms a directed acyclic graph:

1. Vault Passphrase -> VRK -> PKWK_encryption -> encryption private key, and VRK -> PKWK_signing -> signing private key.
2. User key pair -> RKM_v (envelopes) and user key pair -> SEK (wrapped SEKs).
3. RKM_v -> RWK_v, RKM_v -> RKC_v and RKM_v -> RSC_v. RKC_v and RSC_v are leaves: they protect nothing.
4. RWK_v -> FEK and NEK.
5. FEK, NEK and SEK -> content.
6. Server keys protect only server-side secrets and have no edges into or out of the client hierarchy.
7. Signatures (dotted arrows) authenticate statements and protect nothing, so they add no edge to this graph.

No key protects one of its ancestors. Room keys never protect user keys, content keys never protect other keys, and no stored secret is needed to recover the key that protects it. Two practical consequences:

- **Losing a Vault Passphrase does not destroy rooms.** Other members still hold RKM_v and can re-share it to the user's new key pair. A rekey also wraps the new version to the new key automatically.
- **Losing a room does not affect identities.** Deleting a room removes only its envelopes and content keys.

## 5. Compromise impact

| If an attacker obtains | They can | They cannot | Response |
|---|---|---|---|
| One DEK | Read that one item version, given its ciphertext | Read any other item | Delete the item |
| RKM_v or RWK_v | Read every item wrapped under version v, given ciphertext access | Read other versions or other rooms | Rekey; consider re-encryption (OCD-07) |
| A user's encryption private key | Unwrap every RKM version wrapped to that key and every SEK sent to it, given envelope access | Read rooms the user never joined | Identity reset, then a rekey of every room of the user |
| A user's signing private key | Sign statements as that user: re-wraps of that user's vault and, from Phase 6, membership grants and key versions within that user's role | Decrypt anything | Identity reset (CM-T053, R5) |
| The Vault Passphrase only | Nothing without the encrypted private key | | Change the passphrase |
| The Vault Passphrase and the database | Everything a private-key compromise gives | | As for a private key |
| A displayed Room Safety Code | Nothing: it is derived one-way and is designed to be read aloud | Recover or narrow down RKM_v | None needed |
| The auth password | Log in unless MFA is enabled; see metadata and ciphertext; perform non-cryptographic actions. With a strict step-up it can reset the vault, which destroys the victim's identity (availability) and shows a new fingerprint | Decrypt anything, because the vault stays locked; replace the wrapped keys of the existing identity, because re-wraps must be signed by it | Reset the password, revoke sessions, reset the vault again and re-verify fingerprints |
| A session token | Act as the user within that session for non-cryptographic actions; download the user's encrypted vault record and guess the passphrase offline (L-39) | Decrypt, because unlocking needs the Vault Passphrase; change or reset the vault without a fresh step-up | Revoke the session; change the passphrase if it may be weak |
| TOTP_ENCRYPTION_KEY and the database | Recover TOTP secrets and bypass MFA where the password is also known | Decrypt content | Rotate the key, force MFA re-enrollment |
| Audit signing key | Sign forged checkpoints | Change checkpoints already in the retention-locked bucket or the external witness copies | Revoke and rotate the key, publish the new public key, investigate (ADR-009 section 8) |
| TLS private key plus a network position | Impersonate the server and deliver malicious JavaScript (L-02) | Decrypt stored content directly | Revoke and reissue the certificate |
| Write access to the database or control of API responses | Until Phase 6: nothing room-related, because no rooms exist. From Phase 6: substitute identities that users do not verify (T-25), withhold data (T-32) | From Phase 6: distribute a room-key version of its own, because clients require a valid signature by an authorized member (ADR-015, T-36); open any vault | Treat as a server compromise |
