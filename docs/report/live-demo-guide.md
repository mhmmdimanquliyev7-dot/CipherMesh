# Live Demonstration Guide

Status: Phase 14 + Prompt 16.5, updated for the cloud deployment of ADR-014 (2026-10-14). For the project owner presenting CipherMesh. Order: **Cryptography → Cloud & Cloud Security → ISMS**, about 25 minutes plus questions. The same journeys are built into the application at `/trust/walkthrough`. Related: [evidence-plan.md](evidence-plan.md) section 5, [../management/phase-14-traceability.md](../management/phase-14-traceability.md).

## 1. Before the session (15 minutes)

1. **Cloud (preferred):** open the application host over HTTPS (the DuckDNS name of [oracle-always-free.md](../deployment/oracle-always-free.md)); go through the demonstration checklist of [operational-runbook.md](../deployment/operational-runbook.md) section 8 first. **Fallback without the cloud:** `infrastructure/deployment/bin/cm-rehearsal up` serves the same stack at `https://app.localhost:8443` with a throwaway local CA, or the development build (`pnpm services:up`, `pnpm storage:bootstrap`, `pnpm build`, `node tests/e2e/static-server.mjs`); say plainly that this is **not** the cloud deployment.
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

Scenario B (infrastructure) and Scenario C (cloud security). Everything shown is measured or captured; nothing on screen shows the public IP, OCIDs, the operator's address or a credential.

| Step | Where | Say and show |
|---|---|---|
| 1 | Browser padlock on both host names | Let's Encrypt certificate (ECDSA), TLS 1.3, no warning; the storage host is a different host name so the session cookie never reaches it (SF-07-01). |
| 2 | Trust Center, Infrastructure (as the platform administrator) | "Cloud deployment (live)": Healthy, VM.Standard.A1.Flex in the home region, measured minutes ago. Without the administrator role the card says "Administrators only" and claims nothing (L-78). |
| 3 | Security dashboard, Cloud deployment | Shape, 2 OCPUs and 12 GB, aarch64, Ubuntu 24.04, the deployed commit, every container healthy, disk and memory, certificate expiry, the last worker run, backup and restore drill. Each component shows when it was measured; data older than 15 minutes would say "Not verified" (T-44). |
| 4 | Infrastructure, network exposure table and diagram | Only Nginx publishes ports; the API, worker, PostgreSQL and SeaweedFS sit on internal Docker networks without egress; PostgreSQL accepts the API only over TLS 1.3 and has no superuser password; the storage host forwards only signed object requests. Say that PostgreSQL and storage are containers on the VM for the $0 budget (ADR-014) and that root on the VM controls them (L-71). |
| 5 | Terminal on the workstation | Run `node scripts/cloud/edge-check.mjs --app https://<app host> --files https://<files host>`: TLS versions, headers, CSRF through the proxy, refused storage paths, closed database and storage ports, all PASS (EV-17-04, EV-18-04, EV-19-05). |
| 6 | Evidence, subject Cloud security | Security list and host firewall (EV-17-02, EV-19-02), `sshd -T` (EV-19-01), container hardening (EV-17-03), the restore drill report (EV-19-07), the linux/arm64 CI stack check with backup, restore and browser decryption (EV-17-06, EV-19-10). |
| 7 | Infrastructure, Shared responsibility | Self-hosting moves the provider's database and storage duties to the team; "managed does not mean secure by default" and "self-hosted is not the same as managed". |
| 8 | Limitations | L-71 to L-80: one VM, no high availability, possible reclamation of idle Always Free instances, backups are the team's, 24-hour recovery point. |

## 4. ISMS & governance (7 minutes)

| Step | Where | Say and show |
|---|---|---|
| 1 | Trust Center, Governance & risk | Scope and the ISO/IEC 27001:2022 clauses with the document that meets each. A learning-oriented mapping in the style of a Statement of Applicability, not a certification. |
| 2 | Risk register | Open T-06 (broken object-level authorization): inherent Critical, residual Low, its controls and testing strategy. The matrix counts risks per likelihood and impact. |
| 3 | Control register | Open 8.3 (information access restriction): its text names the BOLA suite; evidence EV-05-02 is captured. |
| 4 | Risk register and limitations | Open T-23 (compromised client): residual High, accepted, documented in L-01. Limitations are part of the model. |
| 4b | Risk register, cloud (Scenario D) | Open T-42 (data services on the application host): the control list names the security list, host firewall, internal networks, TLS-only database roles and the signed-object storage gateway; the evidence links show them verified on the VM; residual Medium, accepted in ADR-014 and L-71. The treatment decision is the owner's $0 decision, recorded in the ADR. |
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
