# Live Demonstration Guide

Status: Phase 14 + Prompt 16.5 (2026-10-14). For the project owner presenting CipherMesh. Order: **Cryptography → Cloud & Cloud Security → ISMS**, about 25 minutes plus questions. The same journeys are built into the application at `/trust/walkthrough`. Related: [evidence-plan.md](evidence-plan.md) section 5, [../management/phase-14-traceability.md](../management/phase-14-traceability.md).

## 1. Before the session (15 minutes)

1. Start the local stack: `pnpm services:up`, `pnpm storage:bootstrap`, `pnpm build`, then `node tests/e2e/static-server.mjs` (serves `https://127.0.0.1:4173` with the production security headers and the API behind `/api`). Accept the self-signed certificate once. Until the cloud workstream is done this is a **local development build**; say so.
2. Open two browser windows (for example Chromium and Firefox, or one normal and one private window).
3. Window A: register **Alice** (a synthetic `@example.test` address), sign in, create the vault, create a STANDARD room "Demo room".
4. Window B: register **Bob**, sign in, create the vault. In window A invite Bob as Member; in window B accept on the Invitations page.
5. Optional, for the dashboard: register a third account, turn on two-step sign-in under Account, then on the server run `pnpm admin:platform-role grant <email>` and sign in again with the code.
6. Never use real names, real email addresses or real content. Never show the Account page while an authenticator QR code or recovery codes are on screen.

## 2. Cryptography (10 minutes)

| Step | Where | Say and show |
|---|---|---|
| 1 | Window A, Vault | The Vault Passphrase is a second secret, never sent. Point at the status card and the five-step flow: Argon2id in a Web Worker, HKDF, AES-256-GCM, non-extractable keys. The fingerprint is computed here from the public keys. |
| 2 | Room, Key & safety | "Room key version 1 verified on this device": the browser opened its RSA-OAEP envelope and verified the creator's ECDSA signature and the commitment. |
| 3 | Room, Notes | Create a note with synthetic text. Open **Encryption details**: suite CM1, a fresh key for this revision wrapped under the room key of version 1, and "Verified on this device". |
| 4 | Trust Center, Evidence, subject Cryptography | Open EV-08-01 (note row next to the rendered note) and EV-07-01 (file hex dump): the server holds ciphertext, IVs and wrapped keys. The canary scans (EV-07-05, EV-08-03, EV-09-05) find no plaintext anywhere. |
| 5 | Room, Secrets | Alice sends Bob a secret. Bob reveals it once; reload: it is gone. Only Bob's identity key can unwrap its key; the reveal returns and destroys it in one transaction. Say: Bob can still copy what he saw (L-03). |
| 6 | Both windows, Key & safety | Read the six Safety Code words aloud: they match, so both hold the same room key. It is computed in each browser and never sent. It helps only when people compare it. |
| 7 | Window A, Members, then Key rotation | Remove Bob: the room is locked for new content. Rotate the key: review the recipients and fingerprints, then "Create and share the new key". Version 2 is current; Bob's window gets "does not exist" (404). Say: rotation protects new content only (L-04). |
| 8 | Trust Center, Data protection | The key hierarchy and each mechanism with "what it cannot guarantee". Parameters are the register's own text (CP-01, CP-02, CP-26). |

## 3. Cloud & cloud security (7 minutes)

| Step | Where | Say and show |
|---|---|---|
| 1 | Trust Center, Infrastructure | The designed deployment: Nginx on an IaaS VM is the only public component; the API, worker, managed PostgreSQL (PaaS) and object storage are private. Show the network exposure table. |
| 2 | Same page, Live checks | This browser checks HTTPS, the security headers of this response, API liveness and readiness. HSTS shows "Not configured here": it belongs to the TLS edge of the cloud deployment. These are observations, not monitoring (L-69). |
| 3 | Same page, Control register | Each control separates Designed, Configured (a file in this repository) and Verified (captured evidence, in a named environment). Nothing is claimed for the cloud yet: "Cloud deployment: Not connected". |
| 4 | Same page, Shared responsibility | Provider versus team, per service model; "managed does not mean secure by default". |
| 5 | Evidence, subject Cloud security | Captured: loopback-only development services, database role grants, expiring presigned URLs. Planned for the cloud workstream: firewall, TLS scan, hardening, restore test. |

## 4. ISMS & governance (7 minutes)

| Step | Where | Say and show |
|---|---|---|
| 1 | Trust Center, Governance & risk | Scope and the ISO/IEC 27001:2022 clauses with the document that meets each. A learning-oriented mapping in the style of a Statement of Applicability, not a certification. |
| 2 | Risk register | Open T-06 (broken object-level authorization): inherent Critical, residual Low, its controls and testing strategy. The matrix counts risks per likelihood and impact. |
| 3 | Control register | Open 8.3 (information access restriction): its text names the BOLA suite; evidence EV-05-02 is captured. |
| 4 | Risk register and limitations | Open T-23 (compromised client): residual High, accepted, documented in L-01. Limitations are part of the model. |
| 5 | Room, Security profile | The profile is the information classification (5.12); the rules shown come from the versioned catalogue the API enforces. |
| 6 | Evidence, status Missing and Deferred | Missing items (for example Jira screenshots) and the deferred audit-ledger evidence are visible. 5.33 and 8.15 are Partial because Phase 12 was deferred. |
| 7 | Security dashboard (administrator) | Aggregates from the database with definitions; SD-10, SD-11, SD-12 and SD-15 say "Not implemented"; no score. Everyone else gets 404. |

## 5. What not to claim

- Not "unhackable", "military grade", "zero knowledge", "tamper-proof" or "ISO 27001 compliant or certified".
- Not "deployed in the cloud": the cloud deployment is the next workstream.
- Not "tamper-evident audit ledger": it is designed (ADR-009) but deferred; security events go to the redacted log.
- The Safety Code and the commitment do not protect against a key that every member received from a compromised server (T-36, OCD-12).

## 6. Questions to expect

| Question | Short answer and where to show it |
|---|---|
| What if the server is compromised? | It can withhold or roll back data and serve malicious code (L-02, L-10), but it cannot read stored content or make members accept its own room key (T-36, signed statements). Trust Center summary, claim "key injection". |
| Why RSA and AES together? | RSA-OAEP only delivers 32-byte keys to people; AES-256-GCM encrypts content (INV-17). Data protection, mechanisms. |
| What does the server know? | Metadata: room names, membership, sizes, times (L-05). Data protection, "What the server stores". |
| How do you know a control works? | Each claim links to a test report or screenshot; missing evidence is listed as missing. Evidence register. |

## 7. Screenshots for the report

`CM_CAPTURE_EVIDENCE=1 pnpm exec playwright test evidence-capture --project chromium` captures EV-14-01 to EV-14-18 from the running application into `docs/report/evidence/phase-14/` with synthetic accounts. Cloud screenshots taken now show the not-connected state; the connected state is captured in the cloud workstream.
