# Security UI Design

Status: Phase 0.5 design. Implementation: Phases 3 to 14 (see the related backlog items). Related: [crypto-inspector.md](crypto-inspector.md), [ADR-012](adr/ADR-012-room-safety-code.md), [ADR-013](adr/ADR-013-rekey-state-machine.md), [../security/limitations.md](../security/limitations.md).

This document defines the security-relevant parts of the user interface. The rest of the UI is designed in the implementation phases.

## 1. Principles

1. **Show real state.** Every indicator reflects either server state (profile, key state, rekey status) or a check this browser actually ran (tag verification, commitment check). There are no decorative padlocks and no invented scores.
2. **Never overclaim.** Wording follows the honest-claims rule in [../security/limitations.md](../security/limitations.md). A check that has not run is shown as "not checked yet", never as green.
3. **Fail closed, visibly.** After an integrity or consistency failure, no plaintext or partial preview is shown, and the next step is explained.
4. **Keys never appear on screen.** The only derived values shown are designed to be public or read aloud: public-key fingerprints, commitment prefixes (in the Crypto Inspector) and the Room Safety Code.
5. **Advice is labelled as advice.** Prompts the system cannot enforce, such as comparing Safety Codes, say so.
6. **Accessible.** Status is conveyed by text, not colour alone. Codes have a numeric alternative, and every control works with the keyboard.

## 2. Elements

### 2.1 Vault status (global header)

- The header shows whether the vault is locked or unlocked, and the time left until auto-lock (CP-22). It offers "Lock now".
- Locking clears decrypted views and caches immediately.

### 2.2 Identity and fingerprints

- **Account settings** show the user's key fingerprint (16 groups of 4 hex characters), key ID and creation date, with a short explanation of how to compare it.
- **User lookup while inviting** shows the display name, the email marked **unverified** (T-35), the account creation date and the fingerprint.
- **Fingerprint confirmation** is mandatory in RESTRICTED rooms and prompted in CONFIDENTIAL rooms. The inviter confirms after comparing the fingerprint out of band. The API checks the confirmed value against the invitee's current key.
- **Key-change notice:** when a member's identity key changes, room admins see a notice and are asked to compare the new fingerprint before re-sharing keys.

### 2.3 Room Safety Code panel

- **Location:** the room header ("Safety Code") and the room view of the Crypto Inspector.
- **Content:**
  - The current key version and six words in two rows of three, computed in this browser (CP-24). A toggle shows the numeric alternative.
  - Guidance: "Compare these words with each member in person or on a voice or video call. Do not paste them into CipherMesh or a group chat before everyone has read their own."
  - Explanation: "The Safety Code checks that you and another member hold the same room key. It does not show who else holds the key, and it only helps if you compare it."
- **Actions:**
  - "We compared, they match" records a confirmation holding the key version only (AZ-30).
  - "They don't match" opens the mismatch flow.
- **Status line:** "You recorded a comparison for version 4 on 12 October" or "Not compared yet for version 4".
- **Profile-dependent prompts (advisory):**

  | Profile | Prompt after a new key version |
  |---|---|
  | STANDARD | None; the panel is always available |
  | CONFIDENTIAL | A reminder badge on the room |
  | RESTRICTED | A dismissible dialog asking members to compare |

- **Mismatch flow:**
  1. Explain that the two members hold different keys, which can indicate an attack involving the server.
  2. Ask the member to stop adding content and to alert the OWNER through the independent channel.
  3. Pause uploads in this room for the current session until the member explicitly chooses to continue.
  4. Send a mismatch report that holds the key version only.

### 2.4 Key state banners

| Room state | All members see | OWNER and ADMIN also see |
|---|---|---|
| REKEY_REQUIRED | "This room is read-only until an owner or admin updates the room key. Reason: a member was removed." | "Update room key now" button (asks to unlock the vault if needed) |
| REKEYING | "Room key update in progress by Dana, expires in 8 minutes." | OWNER: "Cancel update" |
| Completed | "Room key updated to version 5." RESTRICTED rooms add the Safety Code prompt | |
| Stale operation | | "Membership changed during the update. Starting again." The client restarts once automatically, then asks |

Write controls are disabled while the room is locked. The API enforces the lock regardless (PC-16).

### 2.5 Rekey recipient review

Before wrapping, the rekeying admin sees:
- every recipient, meaning members and pending invitees, with name, role and fingerprint;
- flags for keys that changed since the admin last saw them in this session, and for recipients without a recorded fingerprint confirmation;
- a summary, for example "Wrapping the new key for 6 people. Not included: Mallory (removed)".

The admin confirms before the browser creates envelopes. This is where an unexpected recipient would become visible (T-36).

### 2.6 Integrity and consistency alerts

| Event | Message | Behaviour |
|---|---|---|
| AES-GCM tag failure | "This item failed its integrity check and was not opened." | No plaintext or preview. "Report" sends a security event |
| Commitment mismatch | "The room key you received does not match the room's record. It was not used." | Key discarded, event reported (AZ-29) |
| Key version older than one seen in this session | "The server offered an older room key than one you already have." | Writes paused; event reported |
| RSA wrapper given anything other than a 32-byte key | Not shown to users | Programming error, fails closed (INV-17) |

### 2.7 Secrets and expiry

- **Before sending:** "The recipient can copy this secret. Burn after reading removes CipherMesh's copy after the first view. Backups keep an encrypted copy until their retention ends."
- **Before revealing:** "This secret can be shown once. If the connection drops, it cannot be shown again."
- **Expiring items** show a countdown and the profile's maximum lifetime.

### 2.8 Step-up and freshness prompts

A dialog asks for the password and a TOTP code and names the reason, for example "RESTRICTED rooms require recent verification to reveal secrets". It never asks for the Vault Passphrase, which is only for unlocking the vault.

### 2.9 Profile badges

Each profile badge opens the list of controls that apply to the room, taken from the policy catalogue. A badge without its controls would be decoration.

### 2.10 Sessions

The session list shows each browser and operating system, last activity and an approximate location from the IP address. It offers revoke per session and "sign out other sessions" ([../security/session-and-csrf.md](../security/session-and-csrf.md)).

## 3. Wording rules

- Use "client-side encrypted", "authenticated encryption", "verified on this device", "not checked yet".
- Never use "unbreakable", "military grade", "zero knowledge", "tamper-proof" or "fully secure".
- Say "removed members cannot read new content" only together with "they keep what they already had".

## 4. Tests

- The Room Safety Code is computed locally, never appears in any network request, and changes after a rekey.
- A test harness gives two browsers different keys, and they show different Safety Codes.
- Banners follow the server's key state. Write controls are disabled while the room is locked, and forced requests still receive 409.
- No plaintext is rendered after a tag failure or a commitment mismatch.
- Unverified labels and fingerprints appear in the invitation flow, and RESTRICTED rooms cannot skip the confirmation.
