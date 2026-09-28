# ADR-009: Tamper-evident audit ledger with signed, anchored checkpoints

- Status: Accepted (trust model and key-custody levels added in Phase 0.5)
- Date: 2026-09-28
- Related: [crypto-decisions.md](../../crypto/crypto-decisions.md) CP-13, CP-14, CP-15, OCD-08, OCD-13; [data-flow.md](../data-flow.md) DF-11; T-19, T-20, T-38; L-13, L-25; CM-T054 to CM-T058, CM-T087

## Context

Security-relevant actions must be accountable, and later modification of the record must be detectable, including by an attacker with database access. The design must define deterministic serialization, must not use a blockchain, and must not be described as tamper-proof. It must also state honestly what the checkpoint signatures prove, because the signing key lives somewhere an attacker might reach.

## Decision

### 1. Hash chain

- One global, append-only chain in PostgreSQL. Each event has a gap-free sequence number `seq`.
- `eventHash_n = SHA-256("CM-AUDIT-v1" || 0x00 || JCS(record_n))`, where `record_n.prevHash = eventHash_(n-1)`. The `prevHash` of the first event is 64 hex zeros.
- This is the conceptual chain `H1 = HASH(canonical(E1))`, `Hn = HASH(canonical(En) || Hn-1)`, with the previous hash placed inside the canonical record so the encoding is unambiguous.

### 2. Canonical serialization

- RFC 8785 JSON Canonicalization Scheme (CP-15) over a fixed field set per `hashVersion`: `seq`, `id`, `occurredAt`, `actorType`, `actorUserId`, `action`, `outcome`, `roomId`, `targetType`, `targetId`, `requestId`, `details`, `prevHash`, `hashVersion`.
- Absent optional fields are serialized as `null`, never omitted. `occurredAt` uses ISO 8601 UTC with three fractional digits, and `seq` is a decimal string.
- `details` allows only strings, safe integers, booleans, null, arrays and objects with allowlisted keys per action. There are no floating-point numbers and no NUL characters, so the database round trip is lossless. Property tests confirm it.

### 3. Appending

- The event is written in the same database transaction as the action it records, after locking the single chain-head row.
- Denied requests are recorded in their own transaction.
- The API and worker roles have INSERT and SELECT only on audit tables, and a trigger rejects UPDATE, DELETE and TRUNCATE. Only the migration role can change the schema. Migration and database-owner credentials are never stored on the VM. The operator uses them from the workstation during deployments only.

### 4. Verification

- The worker verifies new events every hour and the full chain daily, and stores the result. The Security Dashboard shows the latest result.
- Before signing a new checkpoint, the worker fetches the previous checkpoint from the anchor bucket, not from the database, and confirms that the chain still reproduces its head hash. If it does not, the worker refuses to sign and records an INVALID verification run.

### 5. Checkpoints and anchoring (no blockchain)

- A checkpoint is `{seq, headHash, createdAt, deploymentId, keyId, algorithm}`, signed over `"CM-AUDIT-CHECKPOINT-v1" || 0x00 || JCS(checkpoint)`.
- Checkpoints are created every hour when new events exist, immediately after `REKEY_COMPLETED`, role changes, profile downgrades and disabled accounts, and on demand. Frequent checkpoints shorten the unanchored tail for the events that matter most.
- Each checkpoint is stored in the database and written as an immutable object to a separate anchor bucket. The bucket uses a retention lock in compliance mode where the provider offers it, because governance-mode locks can be bypassed by privileged users. The worker's credential can write objects but cannot delete or overwrite them.
- **External witness.** At least weekly, and at every release, the operator copies the latest checkpoint (sequence number, head hash, signature) to a place outside the cloud account: the GitHub repository or release notes, plus an offline copy.
- Optional strengthening: an RFC 3161 timestamp from an external timestamp authority over each checkpoint (OCD-08).

### 6. Offline verifier

The command-line verifier reads events through a read-only role or an export. It recomputes the chain and verifies checkpoint signatures with public keys from the repository. It fetches anchored checkpoints and external witness copies independently, reports the first mismatching sequence number, and reports conflicting checkpoints for the same sequence number.

### 7. Signing-key custody

| Level | Key custody | What it adds | Limitation |
|---|---|---|---|
| **Level 1: project baseline** | Ed25519 key generated on the operator workstation, backed up offline, and deployed as a secret file (mode 0400) mounted read-only into the worker container only. The API container has no access. The public key and key ID are committed to the repository. The repository also lists revoked key IDs with their revocation time. The key is rotated yearly or on suspicion | Signed checkpoints that anyone can verify with the repository key | **A compromise of the VM is also a compromise of the signing key.** From then on, signatures prove nothing (L-25) |
| **Level 2: optional hardened deployment** | A provider-managed signing key (a KMS or HSM-backed service) whose private key cannot be exported. The worker's identity may only call "sign" on that key. Key administration belongs to a separate, MFA-protected role. The provider logs every signing operation | The key cannot be copied. Misuse is limited to the period of control and is visible in the provider's logs. The key can be disabled centrally | An attacker in control of the VM can still request signatures during the compromise. A full cloud-account compromise includes the key service. Algorithm support varies by provider (Ed25519 or ECDSA P-256), so checkpoints record the algorithm |

Level 2 is **not** part of the application implementation. It is a hardening option, decided after provider selection (OCD-13, CM-T087).

### 8. Trust model

| Scenario | Attacker capabilities | Still detected | Not detected |
|---|---|---|---|
| **A. Database-only compromise** | Read and write access to the database, without VM secrets or the anchor credential. Through the API role (for example by SQL injection), the attacker can only append. With owner rights, the attacker can also modify or delete | Any modification, deletion, insertion or reordering of events covered by an anchored checkpoint. The recomputed head no longer matches the anchor, and the worker refuses to sign. Forged checkpoints in the database fail signature verification | Changes to events after the last anchored checkpoint, because the attacker can recompute that tail and the next checkpoint would sign the altered tail. Fabricated events appended through the API role. Reading data leaves no trace in the chain |
| **B. Object-storage compromise** | Control of the content and anchor buckets | The chain in the database is intact, so verification still works. Forged anchor objects fail signature verification. Deleted anchors appear as gaps against the checkpoint list in the database | Where retention is not in compliance mode, deleting anchors removes evidence needed after a later database attack. Content ciphertext can be deleted, which harms availability; tampering is detected by AES-GCM |
| **C. Application VM compromise** | Root on the VM: the runtime database roles, the Level 1 signing key, the anchor write credential, and control of served code | Rewrites of events recorded before the compromise, because runtime roles cannot update or delete audit rows and earlier anchors cannot be replaced. Conflicting signed checkpoints for the same sequence number | Events fabricated or suppressed during the compromise. Checkpoints signed during the compromise, which are genuine signatures over whatever the attacker wrote. Anything the served JavaScript does in users' browsers (L-02) |
| **D. Signing-key compromise** | The private key only | Database and anchors are unchanged, so existing checkpoints remain evidence. A checkpoint forged and shown out of band is missing from the anchor bucket and conflicts with the anchored checkpoint for its sequence number | Until the key is revoked, a signature alone no longer proves that a checkpoint is genuine. Evidence must come from the anchors and witness copies |
| **E. Full cloud-account compromise** | VM, database administration, storage (including lock settings the mode allows) and any provider key service | Only differences against trust anchors outside the account: the repository public keys, external witness copies and optional RFC 3161 tokens. Compliance-mode anchors created before the compromise survive until their retention ends | A fully consistent rewritten history with fresh anchors, if no external copies exist |

## Alternatives Considered

- **Plain append-only table:** no tamper evidence against a database-level attacker.
- **Per-room chains:** independent verification per room, but more complex concurrency. The global chain with filtered views is enough.
- **Merkle-tree transparency log:** efficient proofs, but much more complex to build and explain.
- **Keyed HMAC chain:** only key holders can verify, and a server compromise exposes the key.
- **Blockchain:** excluded by requirement and unnecessary. Anchoring to independent storage and external witnesses gives the needed property.
- **External log service (SIEM):** good for detection and retention, but adds runtime SaaS. Optional later.

## Consequences

- Audited transactions briefly serialize on the chain head, which is acceptable at this scale.
- Audit records cannot be erased for privacy reasons, so they hold minimal personal data (user IDs, no IP addresses).
- The anchor bucket, the offline verifier and the weekly witness copy must be operated.

## Security Implications

- The ledger is **tamper-evident, not tamper-proof**. It detects changes to anchored history. It cannot detect everything an attacker does after gaining control, or changes to the unanchored tail (L-13).
- Signed checkpoints do **not** protect against an attacker who also holds the signing key. At Level 1, that includes anyone who compromises the VM (L-25, T-38).
- An attacker who can modify the database and every trust anchor, including the external copies, can regenerate a consistent chain.
- Tests: tamper suite (edit, delete, reorder, recompute without the key), checkpoint conflicts, revoked-key handling, anchor deletion denied, and simulations of scenarios A to D.

## Status

Accepted. Level 2 is optional and pending OCD-13. Review if a transparency-log design or an external log service becomes necessary.
