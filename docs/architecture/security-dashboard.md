# Security Dashboard (design)

Status: Phase 0.5 design. Implementation: Phase 14 (CM-T061, CM-T062). Related: [../security/authorization-model.md](../security/authorization-model.md) (PA-01), [data-model.md](data-model.md).

## 1. Purpose and audience

The Security Dashboard gives the PLATFORM_ADMIN (acting as security officer) a factual view of the security state of the platform. It supports monitoring and measurement in the sense of ISO/IEC 27001:2022 clause 9.1 and control 8.16.

## 2. Principles

1. **Real data only.** Every value comes from a documented query over application data. Empty data produces an empty state, never a placeholder number.
2. **No composite scores.** There is no "security score", grade or traffic-light summary that would imply precision the data does not have.
3. **Definitions visible.** Each metric shows its definition and the time it was computed.
4. **Aggregates only.** No room names, content, member lists or per-user activity timelines. The dashboard is not a surveillance tool.
5. **Server-side authorization.** Only PLATFORM_ADMIN can call the metrics API (PA-01). Hiding the page is not the control.

## 3. Metrics

| ID | Metric | Definition | Source |
|---|---|---|---|
| SD-01 | Encrypted files | Files with status AVAILABLE; total ciphertext bytes | EncryptedFile |
| SD-02 | Secure rooms | Rooms with status ACTIVE | Room |
| SD-03 | Security-policy distribution | ACTIVE rooms per profile | Room |
| SD-04 | Expiring secrets | ACTIVE secrets expiring within 24 hours and within 7 days | Secret |
| SD-05 | Failed login attempts | Attempts with an outcome other than SUCCESS in the last 24 hours and 7 days; distinct source addresses; currently throttled accounts | LoginAttempt, User |
| SD-06 | MFA coverage | ACTIVE users with MFA enabled divided by ACTIVE users; members of CONFIDENTIAL or RESTRICTED rooms currently blocked for missing MFA | User, RoomMember, Room |
| SD-07 | Key rotations | Key versions created in the last 30 days with a reason other than INITIAL, grouped by reason | RoomKeyVersion |
| SD-08 | Rooms write-locked for rekey | Rooms in REKEY_REQUIRED or REKEYING, grouped by reason, with the age of the oldest; rekey operations abandoned in the last 7 days | Room, RekeyOperation |
| SD-09 | Active sessions | Sessions neither revoked nor expired | Session |
| SD-10 | Audit integrity status | Result, time and range of the latest verification run; sequence number and time of the latest anchored checkpoint | AuditVerificationRun, AuditCheckpoint |
| SD-11 | Profile downgrades | Downgrade events in the last 30 days | AuditEvent |
| SD-12 | Key-commitment mismatch reports | Mismatch events in the last 30 days (expected to be zero) | AuditEvent |
| SD-13 | Vault adoption | ACTIVE users with an ACTIVE key pair divided by ACTIVE users | User, UserKeyPair |
| SD-14 | Invitations awaiting approval | Invitations with status PENDING_APPROVAL | Invitation |
| SD-15 | Room Safety Code reports | Mismatch reports (expected to be zero) and recorded comparisons in the last 30 days, per profile | AuditEvent |

## 4. Implementation notes

- Metrics are computed on request with aggregate queries and cached for at most 60 seconds. Each response carries an "as of" timestamp.
- Queries run under the API role with read access only to the needed tables; they never select content, ciphertext or key columns.
- The UI highlights SD-08, SD-10 (when not VALID), SD-11, SD-12 and SD-15 mismatch reports because they need action, without converting them into a score.
- Historical charts are out of scope for the baseline. Seven-day and thirty-day counts are enough for the demonstration.

## 5. Tests

- Seeded scenarios with exact expected values for every metric.
- Empty database produces empty states.
- Non-admin users receive 404 from the metrics API.
- Responses contain no room names, content or keys (projection test).
