# Live Demonstration Guide

Status: Phase 14 + Prompt 16.5, updated for the cloud deployment of ADR-014 (2026-10-14). For the project owner presenting CipherMesh. Order: **Cryptography → Cloud & Cloud Security → ISMS**, about 25 minutes plus questions. The same journeys are built into the application at `/trust/walkthrough`. Related: [evidence-plan.md](evidence-plan.md) section 5, [../management/phase-14-traceability.md](../management/phase-14-traceability.md).

## 1. Before the session (15 minutes)

1. **Local Docker demonstration (the plan since 2026-10-14):** `pnpm demo:up`, then open https://app.localhost:8443 (setup, optional CA trust and troubleshooting: [local-docker-demo.md](../deployment/local-docker-demo.md)). Run `pnpm demo:status` (and `pnpm demo:worker`) shortly before showing the dashboard. Say plainly: this is the production stack on a laptop, **not** a cloud deployment. If the Oracle VM is deployed later, use its host name and the checklist in [operational-runbook.md](../deployment/operational-runbook.md) section 8 instead.
2. Open two browser windows (for example Chromium and Firefox, or one normal and one private window).
3. Window A: register **Alice** (a synthetic `@example.test` address), sign in, create the vault, create a STANDARD room "Demo room".
4. Window B: register **Bob**, sign in, create the vault. In window A invite Bob as Member; in window B accept on the Invitations page.
5. Optional, for the dashboard: register a third account, turn on two-step sign-in under Account, then run `pnpm demo:admin <email>` (on the cloud VM: `cm-platform-admin grant <email>`) and sign out and in again with the code.
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

Scenario B (infrastructure) and Scenario C (cloud security) on the **local Docker demonstration**. Show what runs and what is verified locally, and name what only a cloud VM can prove. Nothing on screen shows a password, passphrase, authenticator secret or key.

| Step | Where | Say and show |
|---|---|---|
| 1 | Browser address bar on both host names | HTTPS with TLS 1.3 from a local CA limited to localhost names; the storage host is a different host name, so the session cookie never reaches it (SF-07-01). Say: in the cloud this would be a Let's Encrypt certificate (not verified yet). |
| 2 | Application header and Trust Center, Infrastructure | "Local Docker demonstration" label. As the platform administrator: "Cloud deployment (live)" says **Not connected**, because the host reported no cloud instance metadata. That is the correct answer for a laptop (T-44, L-80). |
| 3 | Security dashboard, Platform components and Cloud deployment | API, database and object storage measured seconds ago; worker and host from the collector with their times; containers healthy; the last backup and restore drill. Data older than 15 minutes would say "Not verified". |
| 4 | Infrastructure, network exposure table and diagram | One VM design: only Nginx publishes ports (here on 127.0.0.1); the API, worker, PostgreSQL and SeaweedFS sit on internal Docker networks without egress; PostgreSQL accepts the API only over TLS 1.3 and has no superuser password; the storage gateway forwards only signed object requests. Same Compose file as for the cloud (ADR-014). |
| 5 | Terminal | `node scripts/cloud/edge-check.mjs --app https://app.localhost:8443 --files https://files.localhost:8443 --connect 127.0.0.1 --ca %USERPROFILE%/.ciphermesh-rehearsal/rehearsal-ca.crt --http-port 8080 --ports 9333,8888,4100,2375`: all PASS. |
| 6 | Evidence, subject Cloud security | EV-17-09 (local verification: container hardening, database rules, storage refusals, browser tests, backup and restore), EV-19-13 (screenshots), EV-17-06 and EV-19-10 (the same checks on linux/arm64 in CI). Cloud items (firewall, SSH, public TLS, external scan, Lynis) are shown as planned, not verified. |
| 7 | Terminal, optional | `pnpm demo:backup` then `pnpm demo:drill`: the drill restores into isolated containers and reports every table and file object identical. |
| 8 | Infrastructure, Shared responsibility and Limitations | Who would own what in the cloud; L-71 to L-80, including L-80 (local and CI evidence is not cloud evidence). |

## 4. ISMS & governance (7 minutes)

| Step | Where | Say and show |
|---|---|---|
| 1 | Trust Center, Governance & risk | Scope and the ISO/IEC 27001:2022 clauses with the document that meets each. A learning-oriented mapping in the style of a Statement of Applicability, not a certification. |
| 2 | Risk register | Open T-06 (broken object-level authorization): inherent Critical, residual Low, its controls and testing strategy. The matrix counts risks per likelihood and impact. |
| 3 | Control register | Open 8.3 (information access restriction): its text names the BOLA suite; evidence EV-05-02 is captured. |
| 4 | Risk register and limitations | Open T-23 (compromised client): residual High, accepted, documented in L-01. Limitations are part of the model. |
| 4b | Risk register, cloud (Scenario D) | Open T-42 (data services on the application host): the control list names the security list, host firewall, internal networks, TLS-only database roles and the signed-object storage gateway; the evidence links show the internal networks, database rules and storage gateway verified in the local Docker demonstration and in CI (EV-17-09, EV-17-06), while the security list and host firewall stay planned until a VM exists; residual Medium, accepted in ADR-014 and L-71. The treatment decision is the owner's $0 decision, recorded in the ADR. |
| 5 | Room, Security profile | The profile is the information classification (5.12); the rules shown come from the versioned catalogue the API enforces. |
| 6 | Evidence, status Missing and Deferred | Missing items (for example Jira screenshots) and the deferred audit-ledger evidence are visible. 5.33 and 8.15 are Partial because Phase 12 was deferred. |
| 7 | Security dashboard (administrator) | Aggregates from the database with definitions; SD-10, SD-11, SD-12 and SD-15 say "Not implemented"; no score. Everyone else gets 404. |

## 4a. Operational ISMS: the ISMS Control Center (8 minutes)

Before the session: sign in as the platform administrator (section 1, step 5) and open **Trust Center → ISMS Control Center** (`/trust/isms`). The demonstration data contains one labelled EXERCISE set from the evidence capture (EV-22-04 to EV-22-16); records you make yourself during the session are real project-owner records unless you tick "This is a demonstration exercise". Decisions ask for your account password and authentication code. Say once: "This is an academic ISO/IEC 27001:2022-aligned ISMS for a one-person project, not a certified one; the badges at the top say where it runs."

| Scenario | Where | Do and say |
|---|---|---|
| A Foundation | Overview, then Scope & context, Assets, Policies & roles | The lifecycle strip is the management system: context, assets, risk, treatment, controls, verification, audit, corrective action, review, improvement. Scope revision 2 names exactly what is in scope (the local Docker demonstration) and what is designed but not deployed (Oracle). Show the interested parties and the assets with owners and classification. In Policies, show that a policy is "documented" until a decision adopts it; adopt POL-03 live if you wish (a real decision). |
| B Risk | Risk register, open T-06 | The matrix is computed from the register with the threat model's 3x3 method. T-06: affected assets, threat, scenario, inherent Critical, the controls that treat it with their live assurance, the treatment record, residual Medium and who accepted it ("project owner decision, no independent approver"). |
| C Control assurance | Control assurance, open 8.3 and 8.8 | "Implemented" is not "verified": 8.3 is verified by a record that cites EV-05-02, valid until its freshness rule expires. 8.8: EV-01-07 is stale under the 7-day vulnerability rule; the verification shows the attached dependency-audit output and its SHA-256. |
| D Audit and improvement | Audits & findings, Corrective actions | The self-assessment declares that it is not independent; its observation (19 Annex A numbers not covered) became a finding. The 8.8 finding walks Open → Analyzed → Action planned → Implemented → Awaiting effectiveness → Closed, and the effectiveness check is recorded as self-verified. Status cannot be set directly. |
| E Management review | Management review | The inputs were computed by the server when the draft was made (metrics, open findings, stale evidence). Decisions and the follow-up action, which became an improvement finding. Optionally prepare a real one-person review now. |
| F Continual improvement | Improvement & activity, then Overview | The activity history shows who changed what, when and why; it is append-only but not tamper-evident (L-81). Back on the Overview the measured objectives changed with the records. |

Optional security proof (1 minute): open `/trust/isms` in a private window with an ordinary account: the page and the API refuse it (404). A decision without a recent identity confirmation is refused until you confirm.

## 5. What not to claim

- Not "unhackable", "military grade", "zero knowledge", "tamper-proof" or "ISO 27001 compliant or certified".
- Not "deployed in the cloud": the cloud deployment is the next workstream.
- Not "ISO/IEC 27001 certified", "audited" or "independently reviewed": the ISMS is operated and self-assessed by one person (L-82) for days, not months (L-83); exercise records are labelled.
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
