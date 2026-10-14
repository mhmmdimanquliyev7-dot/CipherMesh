import type { IconName } from '../components/icons';

/**
 * The guided security walkthrough (Phase 14 + Prompt 16.5, CM-T061): three journeys through the
 * real application for a live demonstration of Cryptography, Cloud security and the ISMS. Each
 * step names what to do in the product and what it shows; nothing is simulated, no step bypasses
 * sign-in, the vault or a role, and every action uses synthetic accounts and content.
 * trust-content.test.ts checks that every route exists and every evidence ID is in the plan.
 */

export interface Step {
  readonly title: string;
  readonly href: string;
  readonly action: string;
  readonly show: string;
  readonly evidence?: readonly string[];
}

export interface Journey {
  readonly id: 'cryptography' | 'cloud' | 'isms';
  readonly title: string;
  readonly icon: IconName;
  readonly summary: string;
  readonly prepare: string;
  readonly steps: readonly Step[];
}

export const JOURNEYS: readonly Journey[] = [
  {
    id: 'cryptography',
    title: 'Cryptography in action',
    icon: 'key',
    summary:
      'Follow one piece of content from plaintext in the browser to ciphertext on the server and back, then rotate the room key.',
    prepare:
      'Two synthetic accounts (for example Alice and Bob) in two browser windows, each with a vault. Alice owns a STANDARD room and has invited Bob.',
    steps: [
      {
        title: 'Unlock the vault',
        href: '/vault',
        action: 'As Alice, unlock the vault with the Vault Passphrase.',
        show: 'The status changes to unlocked. The passphrase is stretched with Argon2id in this browser and never sent; the fingerprint is computed here from the public keys.',
        evidence: ['EV-04-01', 'EV-04-04'],
      },
      {
        title: 'Open the room and its verified key',
        href: '/rooms',
        action: 'Open the room. Look at "Room key" in the Key & safety section.',
        show: 'The browser opened the RSA-OAEP envelope with Alice’s private key and verified the signed key-version statement and commitment before showing "verified on this device".',
        evidence: ['EV-06-01', 'EV-06-03'],
      },
      {
        title: 'Create an encrypted note',
        href: '/rooms',
        action: 'In Notes, create a note with synthetic text and save it. Open "Encryption details" on the note.',
        show: 'The receipt names the suite, the key version and the revision, and reports that authenticated decryption succeeded on this device. The server received ciphertext and a wrapped key only.',
        evidence: ['EV-08-01', 'EV-08-03'],
      },
      {
        title: 'Show what the server stores',
        href: '/trust/evidence',
        action: 'Open the evidence register, subject Cryptography, and the note-row and file hex-dump evidence.',
        show: 'Database rows and stored objects contain ciphertext, IVs and wrapped keys; the canary scans find no plaintext anywhere.',
        evidence: ['EV-07-01', 'EV-08-01', 'EV-07-05'],
      },
      {
        title: 'Send a burn-after-reading secret',
        href: '/rooms',
        action: 'As Alice, send Bob a secret. As Bob, reveal it once, then reload.',
        show: 'Only Bob’s identity key can unwrap the secret key. The reveal returns and destroys the ciphertext in one transaction; a second reveal is impossible.',
        evidence: ['EV-09-01', 'EV-09-04'],
      },
      {
        title: 'Compare the Room Safety Code',
        href: '/rooms',
        action: 'Read the six words aloud between the two windows.',
        show: 'Matching codes mean both members hold the same room key. It is computed in each browser and never sent; it helps only when people compare it.',
        evidence: ['EV-06-05'],
      },
      {
        title: 'Remove a member and rotate the key',
        href: '/rooms',
        action:
          'As Alice, remove Bob. The room is locked for new content. Start and finish the key rotation in the Key rotation section.',
        show: 'Bob’s envelopes are gone and he gets 404. Version 2 is made in Alice’s browser for the remaining members and signed; Bob’s old key cannot open anything new.',
        evidence: ['EV-11-01', 'EV-11-02', 'EV-11-03'],
      },
      {
        title: 'Explain the key hierarchy and its limits',
        href: '/trust/cryptography',
        action: 'Open Data Protection & Key Management.',
        show: 'Every key and where it lives, the algorithms with their parameters from the register, and what each mechanism cannot guarantee.',
      },
    ],
  },
  {
    id: 'cloud',
    title: 'Cloud & cloud security',
    icon: 'cloud',
    summary:
      'Explain the designed deployment, what is configured and verified today, and what the cloud workstream will add.',
    prepare:
      'The running application. Say which environment it is: the Oracle VM (live status on the dashboard) or a local rehearsal.',
    steps: [
      {
        title: 'Architecture and trust boundaries',
        href: '/trust/infrastructure',
        action: 'Open Deployment & Infrastructure.',
        show: 'Which components are public (Nginx on 443 and 80), private (API, database, object storage) or have no inbound traffic (worker); all run in containers on one IaaS VM (ADR-014), and the PaaS design is explained, not deployed.',
      },
      {
        title: 'Live checks from this browser',
        href: '/trust/infrastructure',
        action: 'Run the live checks.',
        show: 'This browser checks HTTPS, the security headers of this response, API liveness and readiness. Each result is labelled with where it was measured.',
        evidence: ['EV-01-04', 'EV-01-06'],
      },
      {
        title: 'Designed, configured, verified',
        href: '/trust/infrastructure',
        action: 'Walk through the control register.',
        show: 'Each control states separately whether it is designed, configured in this repository and verified by captured evidence. No cloud-side control is claimed yet.',
        evidence: ['EV-01-08', 'EV-02-03', 'EV-07-06'],
      },
      {
        title: 'Shared responsibility',
        href: '/trust/infrastructure',
        action: 'Show the responsibility matrix.',
        show: 'What the provider secures and what the team must configure for the VM, the managed database, the object storage, Jira and GitHub.',
      },
      {
        title: 'Evidence still to capture',
        href: '/trust/evidence',
        action: 'Filter the evidence register by Cloud security.',
        show: 'Local and CI evidence is captured; firewall, TLS, hardening and restore evidence is planned for the cloud workstream.',
        evidence: ['EV-17-02', 'EV-17-04', 'EV-19-07'],
      },
    ],
  },
  {
    id: 'isms',
    title: 'ISMS & governance',
    icon: 'governance',
    summary:
      'Show how risks, controls, decisions and evidence connect, including what is accepted and what is missing.',
    prepare: 'No account needed for the documents. A platform administrator account shows the security dashboard.',
    steps: [
      {
        title: 'Scope and management system',
        href: '/trust/governance',
        action: 'Open Governance & Risk.',
        show: 'The ISMS scope and how each ISO/IEC 27001:2022 clause is met by a project document or practice. This is a learning-oriented mapping, not a certification.',
      },
      {
        title: 'A risk from the register',
        href: '/trust/governance',
        action: 'Open T-06 (broken object-level authorization) in the risk register.',
        show: 'Likelihood and impact give an inherent Critical rating; the controls and the testing strategy bring the residual rating to Low.',
      },
      {
        title: 'Its control and evidence',
        href: '/trust/governance',
        action: 'Find Annex A control 8.3 in the control register and open its evidence.',
        show: 'The control text names the BOLA and IDOR suite; its evidence item is captured and links to the committed test report.',
        evidence: ['EV-05-02'],
      },
      {
        title: 'Accepted risk and limitations',
        href: '/trust/governance',
        action: 'Open T-23 (compromised client) and limitation L-01.',
        show: 'A High residual risk accepted with a documented reason and mitigations; limitations are part of the security model, not hidden.',
      },
      {
        title: 'Classification in the product',
        href: '/rooms',
        action: 'Open a room’s Security profile section.',
        show: 'The profile is the information classification (control 5.12); the rules shown come from the same versioned catalogue the API enforces.',
        evidence: ['EV-10-01', 'EV-10-04'],
      },
      {
        title: 'Missing evidence is visible',
        href: '/trust/evidence',
        action: 'Filter by status Missing and Deferred.',
        show: 'Items not captured yet, such as the Jira board screenshots, and the deferred audit-ledger evidence are listed as such.',
      },
      {
        title: 'Monitoring with real data',
        href: '/trust/dashboard',
        action: 'As a platform administrator, open the security dashboard.',
        show: 'Aggregates computed from the database on request, each with its definition; audit-ledger metrics are marked not implemented.',
        evidence: ['EV-14-01', 'EV-14-02'],
      },
    ],
  },
];
