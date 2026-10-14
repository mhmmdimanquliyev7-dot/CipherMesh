import type { IconName } from '../components/icons';

/**
 * Security claims in the pattern Claim -> Mechanism -> Verification -> Evidence -> Limitation
 * (Phase 14 + Prompt 16.5, CM-T061). Each claim is what the implementation does today, with its
 * limit stated next to it. trust-content.test.ts checks that the evidence is captured and the
 * limitations exist.
 */
export interface Claim {
  readonly id: string;
  readonly subject: 'CRY' | 'CLD' | 'ISMS' | 'APP';
  readonly icon: IconName;
  readonly claim: string;
  readonly mechanism: string;
  readonly verification: string;
  readonly evidence: readonly string[];
  readonly limitation: string;
  readonly limitations: readonly string[];
}

export const CLAIMS: readonly Claim[] = [
  {
    id: 'browser-encryption',
    subject: 'CRY',
    icon: 'lock',
    claim: 'Files, notes and secrets are encrypted in the browser before they are uploaded.',
    mechanism:
      'Each item gets its own AES-256-GCM key in packages/crypto; only ciphertext and wrapped keys leave the browser.',
    verification:
      'Canary scans search the database, object storage, logs and every browser request for the plaintext in several encodings and find none.',
    evidence: ['EV-07-05', 'EV-08-03', 'EV-09-05'],
    limitation:
      'Malicious JavaScript delivered by a compromised server, or a compromised device, can read plaintext while it is decrypted.',
    limitations: ['L-02', 'L-01'],
  },
  {
    id: 'integrity',
    subject: 'CRY',
    icon: 'checkCircle',
    claim: 'Changed ciphertext is detected and never shown.',
    mechanism:
      'AES-GCM authentication tags over the ciphertext and a canonical context (room, item, key version); decryption fails closed.',
    verification: 'Tamper tests flip bits, swap contexts and change key versions on every decrypt path.',
    evidence: ['EV-07-04', 'EV-08-04', 'EV-09-09'],
    limitation: 'Detection is not prevention: the server can still withhold or roll back content it stores.',
    limitations: ['L-10'],
  },
  {
    id: 'key-injection',
    subject: 'CRY',
    icon: 'signature',
    claim: 'A server-side attacker cannot get members to accept a room key it made.',
    mechanism:
      'Key versions and grants are signed with members’ ECDSA identity keys; browsers verify the signatures and the commitment before using a key (ADR-015).',
    verification:
      'The key-injection suite: unsigned, forged, wrongly attributed and unauthorized versions are refused.',
    evidence: ['EV-06-03', 'EV-04-06'],
    limitation: 'Identity substitution that users do not detect by comparing fingerprints remains possible.',
    limitations: ['L-07'],
  },
  {
    id: 'removal',
    subject: 'CRY',
    icon: 'rotate',
    claim: 'A removed member cannot read content created after the key rotation.',
    mechanism:
      'Removal deletes their envelopes and write-locks the room; a new key version is made in a browser for the remaining members only.',
    verification:
      'The old room key material cannot unwrap data keys created after the rekey; the removed member gets 404 on every room route.',
    evidence: ['EV-11-01', 'EV-11-02', 'EV-11-03'],
    limitation: 'What the member already downloaded or decrypted cannot be taken back.',
    limitations: ['L-04'],
  },
  {
    id: 'authorization',
    subject: 'APP',
    icon: 'members',
    claim: 'Every room request is authorized on the server against the stored membership.',
    mechanism: 'A central room authorizer and a shared matrix run before every handler; non-members get 404.',
    verification: 'The authorization matrix and BOLA/IDOR suites call every room route as every role and as outsiders.',
    evidence: ['EV-05-01', 'EV-05-02'],
    limitation: 'The server still sees metadata such as room names, sizes and membership.',
    limitations: ['L-05'],
  },
  {
    id: 'classification',
    subject: 'ISMS',
    icon: 'trust',
    claim: 'Security profiles act as an information-classification scheme enforced by the API.',
    mechanism:
      'A versioned, frozen policy catalogue governs access, step-up, invitations, expiry and secret handling per room profile.',
    verification: 'The policy matrix sends allowed and denied requests for every control.',
    evidence: ['EV-10-01', 'EV-10-02'],
    limitation:
      'One catalogue control (PC-11, external one-time links) has no feature yet, and profile events go to the redacted log, not to an audit ledger.',
    limitations: ['L-62'],
  },
];

/** What is designed but not implemented. Shown plainly wherever it could be assumed. */
export const NOT_IMPLEMENTED: readonly { readonly name: string; readonly text: string }[] = [
  {
    name: 'Tamper-evident audit ledger',
    text: 'Not implemented: Phase 12 was deferred by the project owner on 2026-10-13. Security events go to the redacted application log; the audit table refuses updates and deletes, but no hash chain or signed checkpoint exists.',
  },
  {
    name: 'Cloud deployment',
    text: 'Not deployed yet. ADR-014 chose one Oracle Cloud Always Free VM; the images, Compose stack, Nginx, hardening scripts, encrypted backups and the measured platform status are in the repository and run on linux/arm64 in CI (a rehearsal with a throwaway certificate authority). The VM waits for the account owner to approve the resource plan.',
  },
  {
    name: 'Standalone Crypto Inspector',
    text: 'Deferred with Phase 13. Encryption details of each item are shown in the room instead.',
  },
  {
    name: 'External one-time links',
    text: 'Not built (CM-T045, a stretch feature). Secrets are exchanged between room members only.',
  },
];
