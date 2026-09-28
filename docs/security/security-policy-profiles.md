# Security Policy Profiles

Status: Phase 0.5 baseline. **This file is the single source of truth for profile values.** Implementation: a versioned, code-defined catalogue in `packages/shared` (see [../architecture/data-model.md](../architecture/data-model.md) section 4.16), enforced by the API. Related: [authorization-model.md](authorization-model.md), [../crypto/key-lifecycle.md](../crypto/key-lifecycle.md).

## 1. Purpose

Every Secure Room has exactly one security profile: **STANDARD**, **CONFIDENTIAL** or **RESTRICTED**. The profiles are an **information-classification scheme** in the sense of ISO/IEC 27001:2022 Annex A 5.12 (classification), 5.13 (labelling) and 5.15 (access control). Each classification level carries handling rules that the **backend enforces**. Changing the profile changes real behaviour, not a badge.

| Profile | Intended content | Example |
|---|---|---|
| STANDARD | Internal collaboration material of moderate sensitivity | Project notes, drafts, shared non-critical files |
| CONFIDENTIAL | Sensitive material whose disclosure would cause harm | Credentials for shared test systems, contracts, assessment results |
| RESTRICTED | Highly sensitive material with strict need-to-know | Incident evidence, private keys, personal data |

## 2. Controls

| ID | Control | STANDARD | CONFIDENTIAL | RESTRICTED | Enforcement point |
|---|---|---|---|---|---|
| PC-01 | MFA-verified session required for any room access | No | Yes | Yes | Room access gate: `session.mfaVerifiedAt` must be set |
| PC-02 | Maximum time since last password authentication for room access | 12 hours | 4 hours | 1 hour | Room access gate: `session.authenticatedAt`; otherwise 401 `REAUTH_REQUIRED` |
| PC-03 | Step-up (password and TOTP) required within the last 15 minutes for sensitive actions: reveal secret, file download URL, invite, approve, remove member, start a rekey, change profile, delete room | No | No | Yes | Action gate: `session.stepUpAt`; otherwise 401 `STEP_UP_REQUIRED` |
| PC-04 | Invitations created by an ADMIN need approval by the OWNER (two-person rule) | No | Yes | Yes | Invitation starts as PENDING_APPROVAL; approver must be OWNER and differ from the inviter |
| PC-05 | Inviter confirms the invitee key fingerprint | Optional | Optional, prompted | Required | Confirmed value must equal the current fingerprint of the invitee key |
| PC-06 | Invitation validity | 7 days | 72 hours | 24 hours | `expiresAt` set by the server; clients cannot choose it |
| PC-07 | Key history given to new members | All retained versions | All retained versions | Current version only | Invitation and re-share validation rejects older versions in RESTRICTED |
| PC-08 | Expiry of files and notes | Optional, no maximum | Required, maximum 90 days, default 30 days | Required, maximum 30 days, default 7 days | Create and update validation |
| PC-09 | Secret lifetime (default in brackets) | Maximum 7 days (24 hours) | Maximum 72 hours (24 hours) | Maximum 24 hours (1 hour) | Secret creation validation |
| PC-10 | Burn-after-reading for secrets | Optional, on by default | Optional, on by default | Mandatory | Secret creation rejects `burnAfterReading = false` in RESTRICTED |
| PC-11 | External one-time secret links (stretch feature) | Allowed, burn mandatory, maximum 24 hours | Not allowed | Not allowed | External-link endpoint returns 403 outside STANDARD |
| PC-12 | VIEWER may obtain file key material and ciphertext (download) | Yes | Yes | No | The file key-material endpoint (wrapped FEK, encrypted manifest) and the download-URL endpoint deny VIEWER in RESTRICTED; the file list then shows only server-side metadata |
| PC-13 | Audit level | BASELINE | EXTENDED | FULL | Audit emitter consults the profile (section 3) |
| PC-14 | Room-key cryptoperiod | Event-driven only | 180 days | 90 days | Worker sets REKEY_REQUIRED (reason CRYPTOPERIOD_EXPIRED) when the ACTIVE version is older; members see a reminder 14 days before |
| PC-15 | Rekey after losing a member (removal, leaving, suspension, deletion) | Mandatory | Mandatory | Mandatory | The loss sets REKEY_REQUIRED in the same transaction. Only a validated rekey finalize makes the room writable again (INV-07, ADR-013) |
| PC-16 | Content writes and invitations while REKEY_REQUIRED or REKEYING | Blocked | Blocked | Blocked | All write and invitation endpoints check `keyState`. Every write must also name the current key version (`KEY_VERSION_STALE` otherwise) |

Global settings that apply to every profile: session idle timeout 30 minutes and absolute lifetime 12 hours (CP-08), vault auto-lock after 15 minutes (CP-22), maximum file size (CP-19). A step-up (password and TOTP) is valid for 15 minutes, except for a profile downgrade, which needs a step-up within the last 5 minutes. Deleting a room and transferring ownership require a step-up in every profile (AZ-04, AZ-05).

Creating a room with a given profile requires the creator to meet that profile's access requirements (for example an MFA-verified session for CONFIDENTIAL and RESTRICTED).

## 3. Audit levels

| Level | Events recorded |
|---|---|
| BASELINE | Room creation and deletion, profile changes, invitations (created, approved, accepted, declined, revoked, expired), membership and role changes, rekey state changes and operations (required, started, completed, abandoned, cancelled, stale, rejected), key-commitment mismatches, Room Safety Code confirmations and mismatch reports, content creation and deletion, secret creation, reveal and expiry, denied privileged actions |
| EXTENDED | BASELINE plus file download-URL issuance and note reads |
| FULL | EXTENDED plus envelope fetches, member-list views and every denied request in the room |

Platform-level events (registration, login success and failure, MFA changes, session revocation, vault creation and reset, account enable and disable) are recorded for every user regardless of room profile.

## 4. Changing a room profile

| Change | Who | Requirements | Effects |
|---|---|---|---|
| Upgrade (to a stricter profile) | OWNER | OWNER meets the new access requirements | Takes effect immediately. Existing expiry dates are shortened to at most the upgrade time plus the new maximum. Pending invitations that break the new rules are revoked. Members without MFA lose access until they enable it. Audit event `PROFILE_UPGRADED` |
| Downgrade (to a weaker profile) | OWNER | Step-up within the last 5 minutes, regardless of profile | Existing expiry dates are not extended. Audit event `PROFILE_DOWNGRADED` with high severity, highlighted on the Security Dashboard |

Profile changes do not re-encrypt content. Profiles govern access, handling and lifetime; the cryptographic protection is the same for every profile.

## 5. What profiles cannot enforce

Being honest about these limits is part of the design (see [limitations.md](limitations.md)):

- **Copying after decryption.** "View-only" cannot be enforced. PC-12 controls whether the API hands out ciphertext at all. Anyone who can decrypt can save the plaintext.
- **Vault auto-lock** runs in the browser. A modified client can ignore it.
- **Out-of-band fingerprint comparison.** The API can check that a fingerprint was confirmed and that it matches; it cannot prove the humans compared it.
- **Backups.** Expiry and burn remove data from the live system, not from backups before their retention ends.
- **Device hygiene.** Guidance for RESTRICTED rooms (dedicated browser profile, no extensions, locked screen) is advice, not enforcement.
- **Room Safety Code comparisons.** RESTRICTED rooms prompt members to compare codes after every new key version, and CONFIDENTIAL rooms show a reminder. Whether people compare, and over which channel, is outside the system's control. The prompts are advisory UI, not a policy control (ADR-012).
- **Rekey timing.** A room stays write-locked until an OWNER or ADMIN completes the rekey (L-24). The profile cannot force someone to do it.

## 6. Evaluation order for a room-scoped request

1. For state-changing requests, pass the same-origin and request-header checks (INV-19). Then authenticate the session (valid, not revoked, not idle-expired).
2. Load the room and the membership of the caller. Not an active member: 404.
3. Apply profile access gates: PC-01, PC-02.
4. Apply the authorization matrix for the action and role ([authorization-model.md](authorization-model.md)).
5. Apply action-specific profile gates: PC-03, PC-04, PC-05, PC-07, PC-10, PC-11, PC-12, PC-16.
6. Validate profile-bounded values: PC-06, PC-08, PC-09.
7. Execute, then emit audit events according to PC-13.

Each gate fails closed with a stable error code. Gates never read role or profile information from the request body.

## 7. Testing

The policy test matrix (Jira CM-T049) generates, for every control and profile, one allowed and one denied request against a real database and asserts the status code, error code and audit event. The matrix is part of the security regression suite and runs on every pull request.
