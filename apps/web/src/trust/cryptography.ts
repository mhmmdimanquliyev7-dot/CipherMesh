import type { IconName } from '../components/icons';

/**
 * Explanations of the cryptography CipherMesh actually uses (Phase 14 + Prompt 16.5, CM-T061).
 * Curated text, so every entry cites its sources: parameter rows (CP-xx in
 * docs/crypto/crypto-decisions.md, whose values the page shows verbatim), evidence items (EV-xx)
 * and limitations (L-xx). apps/web/src/trust/trust-content.test.ts resolves every reference and
 * refuses forbidden marketing terms. Nothing here is a live measurement.
 */

export interface Mechanism {
  readonly id: string;
  readonly name: string;
  readonly icon: IconName;
  readonly parameters: readonly string[];
  /** What it is, in one or two sentences for a non-specialist. */
  readonly what: string;
  readonly why: string;
  readonly where: string;
  readonly protects: string;
  readonly verification: string;
  readonly evidence: readonly string[];
  readonly cannot: string;
  readonly limitations: readonly string[];
}

export const MECHANISMS: readonly Mechanism[] = [
  {
    id: 'aead',
    name: 'AES-256-GCM authenticated encryption',
    icon: 'lock',
    parameters: ['CP-01', 'CP-16'],
    what: 'A symmetric cipher with a built-in integrity check. The same 256-bit key encrypts and decrypts; a 128-bit authentication tag lets the receiver detect any change to the ciphertext or its context.',
    why: 'Every file, note revision and secret is encrypted once under its own data key, so one key never protects two items (INV-03). The tag makes tampering detectable instead of silently producing wrong plaintext.',
    where:
      'In the browser, through WebCrypto inside packages/crypto. The 96-bit IV is generated there from a CSPRNG for every message; no caller can choose it (INV-02).',
    protects:
      'File contents and their encrypted name and type, note titles and bodies, secret payloads, and the wrapped data keys and private keys.',
    verification:
      'Known-answer tests, bit-flip, wrong-context and wrong-key-version tamper tests on every decrypt path; canary scans find no plaintext in the database, storage, logs or browser storage.',
    evidence: ['EV-04-07', 'EV-07-01', 'EV-07-04', 'EV-08-04', 'EV-09-09', 'EV-07-05'],
    cannot:
      'It does not hide sizes, timestamps, room names or who is a member, and it cannot protect content on a compromised device where it is decrypted.',
    limitations: ['L-05', 'L-01'],
  },
  {
    id: 'oaep',
    name: 'RSA-OAEP-3072 key wrapping',
    icon: 'key',
    parameters: ['CP-02'],
    what: 'Public-key encryption: anyone can wrap a value to a public key, only the holder of the matching private key can unwrap it.',
    why: 'It delivers keys to people: each member receives the room key material in an envelope only their identity key opens, and a secret key (SEK) is wrapped to exactly one recipient.',
    where:
      'In the browser. Used only on 32-byte random values: room key material, secret keys and the vault pair-check value. Content is never RSA-encrypted (INV-17).',
    protects: 'Room key material per member and key version, and each secret key for its single recipient.',
    verification:
      'Cross-browser envelope tests in Chromium, Firefox and WebKit; an engine difference (SF-11-01) was found by these tests and fixed with a regression test.',
    evidence: ['EV-06-01', 'EV-06-04', 'EV-09-04', 'EV-11-03'],
    cannot:
      'Wrapping says nothing about who wrapped the key, and it cannot help if the server hands out a substituted public key that nobody compares.',
    limitations: ['L-07'],
  },
  {
    id: 'signatures',
    name: 'ECDSA P-256 digital signatures',
    icon: 'signature',
    parameters: ['CP-26', 'CP-17'],
    what: 'A signature proves that a statement was made with a particular private key and was not changed afterwards.',
    why: 'Encryption alone cannot show who created a room key. Every key version, recipient list and membership grant is signed by an authorized member, and browsers refuse keys whose signatures do not verify (ADR-015).',
    where: 'Signing and verification run in members’ browsers; the API also verifies statements before storing them.',
    protects:
      'The authenticity of identity bindings, room key versions, recipient lists and grants, against a server that tries to inject a key it knows (T-36).',
    verification:
      'Wycheproof ECDSA vectors and the key-injection suite: unsigned, forged, wrongly attributed and unauthorized versions are refused.',
    evidence: ['EV-04-06', 'EV-06-03'],
    cannot:
      'A valid signature proves possession of a key, not a real-world identity. Only comparing fingerprints out of band shows that a key belongs to the person you think.',
    limitations: ['L-07', 'L-21'],
  },
  {
    id: 'hkdf',
    name: 'HKDF-SHA-256 key separation',
    icon: 'layers',
    parameters: ['CP-03'],
    what: 'A key derivation function that turns one secret into several independent keys, each bound to a stated purpose.',
    why: 'One room key version yields the wrapping key for data keys, the public commitment and the Room Safety Code, without any of them revealing the others.',
    where:
      'In the browser. Context labels are built only by the canonical context builders (RFC 8785), never by string concatenation.',
    protects:
      'Separation between keys: a value derived for display (the Safety Code) or publication (the commitment) gives no way back to the wrapping key.',
    verification:
      'Known-answer tests for every derivation, including the published Safety Code vector reproduced in three browser engines.',
    evidence: ['EV-04-07', 'EV-06-05'],
    cannot: 'Derived keys are only as secret as the room key material they come from.',
    limitations: ['L-04'],
  },
  {
    id: 'argon2id',
    name: 'Argon2id password-based key derivation',
    icon: 'vault',
    parameters: ['CP-04', 'CP-05'],
    what: 'A deliberately slow, memory-hard function that turns a human secret into a key, so each guess costs an attacker real time and memory.',
    why: 'The Vault Passphrase protects your private keys, and the account password protects your sign-in. Both must resist guessing if a database copy leaks.',
    where:
      'Vault Passphrase: in the browser, in a Web Worker (64 MiB, 3 passes). Account password: on the server, stored only as an Argon2id hash.',
    protects: 'The encrypted private keys stored on the server, and the stored password hashes.',
    verification:
      'Benchmarks in three browsers and on the server container chose the parameters; the browser and API refuse records outside the floor and ceiling.',
    evidence: ['EV-04-03', 'EV-03-01', 'EV-03-02'],
    cannot: 'A short or common passphrase can still be guessed offline by someone who holds a database copy.',
    limitations: ['L-08'],
  },
  {
    id: 'safety-code',
    name: 'Room Safety Code',
    icon: 'fingerprint',
    parameters: ['CP-24'],
    what: 'Six words (or 20 digits) derived in each member’s browser from the room key of one version.',
    why: 'If two members compare their codes and they match, they hold the same room key. A server that gave members different keys would make the codes differ.',
    where:
      'Computed only in the browser from decrypted room key material. Never sent to the server, stored or logged (INV-18).',
    protects: 'Detection of split views between members who compare the code.',
    verification:
      'A test harness gives two browsers different keys: the commitment check passes but the Safety Codes differ.',
    evidence: ['EV-06-05', 'EV-06-06'],
    cannot:
      'It is not automatic protection: it helps only when people compare it, and it cannot detect a key every member received from a compromised server.',
    limitations: ['L-22'],
  },
];

/** The encryption flow of one item, as implemented (DF-06 to DF-09). */
export const FLOW: readonly {
  readonly icon: IconName;
  readonly title: string;
  readonly text: string;
  readonly zone: 'browser' | 'network' | 'server';
}[] = [
  {
    icon: 'browser',
    zone: 'browser',
    title: 'Plaintext stays in your browser',
    text: 'You write a note, choose a file or type a secret. The vault is unlocked, the room key is verified on this device.',
  },
  {
    icon: 'key',
    zone: 'browser',
    title: 'A fresh data key per item',
    text: 'The browser creates a random 256-bit key for this item only and encrypts the content with AES-256-GCM.',
  },
  {
    icon: 'layers',
    zone: 'browser',
    title: 'The data key is wrapped',
    text: 'For files and notes, with the room wrapping key of the current key version. For a secret, with RSA-OAEP to the recipient’s identity key.',
  },
  {
    icon: 'network',
    zone: 'network',
    title: 'Only ciphertext travels',
    text: 'Over HTTPS the API receives ciphertext, the wrapped key, the IVs and metadata. File ciphertext goes straight to object storage through a short-lived presigned URL.',
  },
  {
    icon: 'server',
    zone: 'server',
    title: 'The server authorizes and stores',
    text: 'The API checks the session, membership, role, security profile and key version, then stores what it received. It holds no key that can open it.',
  },
  {
    icon: 'checkCircle',
    zone: 'browser',
    title: 'An authorized member decrypts locally',
    text: 'Their browser unwraps the data key with their verified room key and checks the authentication tag. Any change to the ciphertext or its context fails closed.',
  },
];

/** The key hierarchy (docs/crypto/key-hierarchy.md section 1). Solid relations only. */
export interface KeyNode {
  readonly name: string;
  readonly detail: string;
  readonly stored: string;
  readonly children?: readonly KeyNode[];
}

export const KEY_HIERARCHY: readonly KeyNode[] = [
  {
    name: 'Vault Passphrase',
    detail: 'Your memory only',
    stored: 'Never',
    children: [
      {
        name: 'Vault root key (VRK)',
        detail: 'Argon2id output, seconds in memory',
        stored: 'Never',
        children: [
          {
            name: 'Private-key wrapping keys',
            detail: 'HKDF, one per private key',
            stored: 'Never',
            children: [
              {
                name: 'Identity key pairs',
                detail: 'RSA-OAEP-3072 for envelopes, ECDSA P-256 for signatures',
                stored: 'Private halves only as AES-256-GCM ciphertext',
                children: [
                  {
                    name: 'Room key material, per version (RKM_v)',
                    detail: '32 random bytes in an RSA-OAEP envelope per member',
                    stored: 'Only as envelopes',
                    children: [
                      {
                        name: 'Room wrapping key (RWK_v)',
                        detail: 'HKDF from RKM_v; in memory while unlocked',
                        stored: 'Never',
                        children: [
                          { name: 'File key (FEK)', detail: 'One per file and its manifest', stored: 'Wrapped' },
                          { name: 'Note key (NEK)', detail: 'One per note revision', stored: 'Wrapped' },
                        ],
                      },
                      { name: 'Commitment (RKC_v)', detail: 'HKDF, public, signed by the creator', stored: 'In clear' },
                      { name: 'Room Safety Code', detail: 'HKDF, shown to members', stored: 'Never' },
                    ],
                  },
                  {
                    name: 'Secret key (SEK)',
                    detail: 'One per secret, RSA-OAEP-wrapped to the recipient',
                    stored: 'Wrapped',
                  },
                ],
              },
            ],
          },
        ],
      },
    ],
  },
];

/** Room key lifecycle (ADR-013, key-lifecycle.md), as the room page shows it. */
export const ROTATION_STEPS: readonly { readonly state: string; readonly text: string }[] = [
  { state: 'ACTIVE', text: 'Version v is current. New files and notes are encrypted under its wrapping key.' },
  {
    state: 'REKEY_REQUIRED',
    text: 'A member left, was removed or suspended, an identity was reported compromised, or the cryptoperiod ended. The removed member’s envelopes are deleted in the same transaction and the room refuses new content and invitations.',
  },
  {
    state: 'REKEYING',
    text: 'An owner or admin starts an operation. The server fixes the recipient snapshot; the starter’s browser makes RKM_v+1 and wraps it for exactly those members, after reviewing their fingerprints.',
  },
  {
    state: 'Finalize',
    text: 'The browser signs the new key-version statement with the commitment and recipient list. The API accepts it only for the exact recipient set, from the starter, within the lease.',
  },
  {
    state: 'ACTIVE (v+1)',
    text: 'Members verify the signed version before using it. Version v is retired: it still opens old content, but nothing new is written under it.',
  },
];
