# Runbook: compromised or lost identity key (CM-T053)

Status: Phase 11 (2026-10-13). Audience: a CipherMesh user, a room OWNER or ADMIN, and the platform operator. Related: [key-lifecycle.md](../crypto/key-lifecycle.md) section 3 (R5), [ADR-013](../architecture/adr/ADR-013-rekey-state-machine.md), [ADR-015](../architecture/adr/ADR-015-identity-signing-keys.md), [authorization-model.md](authorization-model.md) section 9.12, threats T-21, T-25 and T-36 in [threat-model.md](../threat-model/threat-model.md), limitations L-04, L-64 and L-65.

This runbook covers two cases that look alike in the application and differ in what an attacker may hold.

| Case | What happened | What the attacker may hold | Flag to use |
|---|---|---|---|
| A. Lost passphrase | The user forgot the Vault Passphrase; nobody else has the vault | Nothing | none |
| B. Suspected compromise | A device, a browser profile, a copy of the vault record plus the passphrase, or an unlocked session may be in someone else's hands | Every room key wrapped to the old RSA-OAEP key, and the ability to sign as the old identity until the old identity is superseded | "Someone else may have my current keys or this device" (`identityCompromised`) |

If in doubt, treat the event as case B. Case B costs a rekey of each room; case A done as case B is safe, the reverse is not.

## 1. What the system does and does not do

| Fact | Consequence |
|---|---|
| The server holds no private key and no room key material (INV-01, INV-04). It can only delete envelopes, change state and refuse requests | Nothing here recovers a lost passphrase. A user who has lost the passphrase and the old keys cannot read old content until an OWNER or ADMIN re-shares it |
| A vault reset supersedes the old identity: its encrypted private keys are set to NULL, its public keys stay, and a new ACTIVE identity is created in the browser | The old keys can no longer be unwrapped from the server's copy, but a copy already taken stays usable offline (L-04, L-40) |
| In the same transaction the reset deletes every envelope wrapped to the old key in every room of the user, advances each room's membership epoch (a rekey snapshot naming the old key becomes STALE) and revokes open invitations and unrevealed secrets addressed to the old identity | The user is shown as a member of each room but holds no key there until a re-share or a rekey |
| With the compromise flag the same transaction sets every one of those rooms to REKEY_REQUIRED (R5) | New content and invitations are refused (INV-07) until an OWNER or ADMIN finalizes a rekey |
| Rooms are not unlocked by the reset, by a re-share or by the passage of time. Only a validated rekey finalize makes a new key version current | A compromised key cannot be "fixed" by re-sharing |
| A rekey protects future content only (L-04). Whatever the attacker already decrypted or downloaded stays with them | Treat all content of the affected rooms up to the rekey as exposed |

## 2. Steps for the user

1. Stop using the suspected device. From a trusted device sign in with the account password and MFA.
2. Sign out all other sessions (account page, "Sign out all other sessions"). A vault reset does this too, but doing it first limits the time an attacker has.
3. Open the vault page and choose **Reset vault**. Complete the strict step-up. Choose a new Vault Passphrase of a quality that survives offline guessing (case B: assume the attacker has the old vault record and is guessing).
4. In case B tick **Someone else may have my current keys or this device**. The reset then lists the number of rooms affected.
5. Tell the OWNER or an ADMIN of each room, through a channel other than CipherMesh, that your key changed. Read your new key fingerprint to them aloud or from a trusted device (T-25). Do not accept a re-share that a stranger asks for.
6. After an OWNER or ADMIN re-shares, open the room and check the Room Safety Code against the other members (INV-18). A different code means your view of the key differs from theirs: stop and tell the administrators.
7. Change the account password and the MFA factors if the device also held them. Recovery codes that were stored on the device are to be regenerated.

## 3. Steps for a room OWNER or ADMIN

Order matters. The rekey comes before any re-share of old versions.

1. **Recognise the event.** The room shows REKEY_REQUIRED and the audit view shows `MEMBER_IDENTITY_REPLACED` (with `compromised: true` in case B) followed by `REKEY_REQUIRED` with reason `IDENTITY_KEY_COMPROMISED`. An unexpected `MEMBER_IDENTITY_REPLACED` without a message from that member is a possible key substitution (T-25): do not re-share to that member until you have confirmed the new fingerprint with them through another channel.
2. **Confirm the new fingerprint** with the member (RESTRICTED rooms require this confirmation in the re-share dialog, PC-05).
3. **Start the rekey** from the room's rekey panel (AZ-13; RESTRICTED rooms need a step-up within five minutes, PC-03). Your browser reviews the recipient snapshot before making any key: every identity must verify and be signed by the room's authority; a key the room has never signed (the reset member's new key) is flagged for your decision. Make the new version, check the Room Safety Code, finalize. The recipient snapshot holds each member's current identity, so version `v+1` is wrapped to the member's new key and never to the old one; a member who was not in the snapshot (for example an account that is still SUSPENDED) gets no key.
4. **Re-share to the member** (AZ-14) only after the rekey (a locked room refuses it with 409 `REKEY_REQUIRED`) and only to the current identity (a stale identity is refused with 409 `IDENTITY_KEY_CHANGED`). The rekey already gives the member the new version, so the re-share is needed only for older versions and for reinstating a SUSPENDED member (409 `RESHARE_NOT_NEEDED` when nothing is missing). In STANDARD and CONFIDENTIAL rooms you may choose to also share retained older versions; in RESTRICTED rooms only the current version is shared (PC-07). Re-sharing an older version gives the new identity access to content the attacker may already have read; share it only if the member needs it.
5. **If the member is an ADMIN**, the OWNER performs the re-share (an ADMIN cannot re-share to an ADMIN, and nobody can re-share to the OWNER because an OWNER grant needs an OWNER signature). **If the member is the OWNER**, AZ-14 is refused; the OWNER receives keys through the next rekey, whose recipient snapshot includes the new identity once the starting administrator has confirmed its fingerprint. Statements signed by an old identity stay verifiable through the recorded grant history.
6. **Compare Safety Codes** with the other members once the version is current.
7. **Record** the event in the Jira security-finding issue (section 5).

If the starter's browser crashes, the operation is ABANDONED after its ten-minute lease and anyone with AZ-13 can start again. The room stays locked until a finalize succeeds; it never unlocks by expiry.

## 4. Steps for the platform operator

The operator cannot read content or keys and cannot unlock a room. The operator can:

1. Disable the account (PA-03) if the account itself is compromised. Memberships become SUSPENDED, envelopes are deleted and rooms enter REKEY_REQUIRED (R3). Re-enabling later does not restore access: each membership needs an explicit re-share (AZ-14).
2. Confirm in the redacted application log that the reset ran (`VAULT_RESET` with the number of rooms, `MEMBER_IDENTITY_REPLACED`, `REKEY_REQUIRED`). Events go to the redacted log until the hash-chained ledger exists (L-33, Phase 12).
3. Check that the worker is running: it abandons expired operations and records cryptoperiod expiry. A stopped worker leaves a crashed operation holding the lock until the next start.
4. If a database or object-storage credential may be exposed, follow the credential rotation table in key-lifecycle section 4. That is a different procedure from this one.

## 5. Record keeping (ISMS)

Open a Jira issue with label `security-finding` and the finding template. Record: time of detection, case (A or B), the affected rooms (IDs only), the actions in sections 2 to 4 with timestamps, the request IDs of the reset and the rekeys, and the result of the Safety Code comparison. Do not record passphrases, fingerprints beyond what the template requires, tokens, envelopes or any key. Link the issue from the incident entry in the risk register.

## 6. Verification after the procedure

| Check | Expected |
|---|---|
| Room state | ACTIVE, current key version greater than before the event |
| The user's old identity | SUPERSEDED, no envelopes |
| The user in each room | Holds an envelope for the current version under the new identity only |
| Safety Code | Equal for all members who compare |
| Audit view | `MEMBER_IDENTITY_REPLACED`, `REKEY_REQUIRED` (case B), `REKEY_STARTED`, `REKEY_COMPLETED`, `KEYS_RESHARED` |
| Writes | Accepted again, with the new key version only; writes naming the old version are refused (INV-07) |

These checks are exercised by `tests/rekey/identity-reshare.test.ts` and `tests/e2e/rekey.spec.ts` (evidence EV-11-01 to EV-11-07).

## 7. Limits of this procedure

- It does not undo what an attacker decrypted before the reset (L-04).
- It does not detect a key substitution by the server. Members detect it only by comparing Safety Codes and fingerprints (L-22, L-23, T-36).
- It does not help if the attacker holds both the old vault record and the passphrase and also controls the account: disable the account and re-create trust out of band.
- Backups keep deleted envelopes until the retention of the backup ends (L-12).
