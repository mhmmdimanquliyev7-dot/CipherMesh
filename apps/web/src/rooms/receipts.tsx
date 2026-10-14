import { FILE_TAG_BYTES } from '@ciphermesh/shared';
import type { ReactNode } from 'react';
import { Icon } from '../components/icons';
import { Badge, Disclosure } from '../components/ui';
import type { FileEntry } from './files';
import type { NoteEntry } from './notes';
import type { SecretMetadataView } from '@ciphermesh/validation';

/**
 * Encryption receipts (Phase 14 + Prompt 16.5, CM-T061): what protects one item, in plain words.
 * Every row is either a fixed property of the CM1 suite (CP-18, docs/crypto/key-hierarchy.md) or
 * a field of the item's API view, and the integrity row reports only what this browser itself
 * checked. Nothing here reveals key material: no key, IV, wrapped key or ciphertext is shown.
 */

type Check = { readonly state: 'verified' | 'failed' | 'unchecked'; readonly text: string };

const CHECK_BADGE = {
  verified: { tone: 'success', icon: 'checkCircle', label: 'Verified on this device' },
  failed: { tone: 'danger', icon: 'xCircle', label: 'Integrity check failed' },
  unchecked: { tone: 'neutral', icon: 'dashedCircle', label: 'Not checked here' },
} as const;

function Receipt({
  testId,
  check,
  rows,
}: {
  readonly testId: string;
  readonly check: Check;
  readonly rows: readonly { readonly term: string; readonly value: ReactNode }[];
}) {
  const badge = CHECK_BADGE[check.state];
  return (
    <Disclosure
      testId={testId}
      summary={
        <span className="flex flex-wrap items-center gap-2">
          <Icon name="lock" className="size-3.5 text-accent-300" />
          Encryption details
          <Badge tone={badge.tone} icon={badge.icon}>
            {badge.label}
          </Badge>
        </span>
      }
    >
      <dl className="grid gap-x-6 gap-y-2 text-xs sm:grid-cols-[max-content_1fr]">
        {rows.map((row) => (
          <div key={row.term} className="contents">
            <dt className="text-slate-400">{row.term}</dt>
            <dd className="min-w-0 break-words text-slate-200">{row.value}</dd>
          </div>
        ))}
        <div className="contents">
          <dt className="text-slate-400">Integrity</dt>
          <dd className="text-slate-200">{check.text}</dd>
        </div>
      </dl>
    </Disclosure>
  );
}

const SUITE_TEXT = (suite: string) => `${suite}: AES-256-GCM, RSA-OAEP-3072, HKDF-SHA-256, ECDSA P-256`;

export function FileReceipt({ entry }: { readonly entry: FileEntry }) {
  const { view } = entry;
  const check: Check =
    entry.damaged === true
      ? { state: 'failed', text: 'The encrypted name and type failed authenticated decryption. Nothing was shown.' }
      : entry.opened !== undefined
        ? {
            state: 'verified',
            text: 'The encrypted name and type passed authenticated decryption here. The content is checked the same way when you download or preview it.',
          }
        : { state: 'unchecked', text: 'This device has not decrypted the file (vault locked or no key).' };
  return (
    <Receipt
      testId="file-receipt"
      check={check}
      rows={[
        { term: 'Algorithm suite', value: SUITE_TEXT(view.suite) },
        {
          term: 'Content',
          value: 'AES-256-GCM under a key made for this file only (FEK), with a 128-bit authentication tag',
        },
        {
          term: 'File key',
          value: `Wrapped with AES-256-GCM under the room wrapping key of key version ${String(view.keyVersion)}`,
        },
        {
          term: 'Stored ciphertext',
          value: `${String(view.ciphertextSize)} bytes, of which ${String(FILE_TAG_BYTES)} are the tag`,
        },
        {
          term: 'Server holds',
          value: 'Ciphertext in object storage; the wrapped key and the encrypted name and type in the database',
        },
      ]}
    />
  );
}

export function NoteReceipt({ entry }: { readonly entry: NoteEntry }) {
  const { view } = entry;
  const check: Check =
    entry.problem === 'damaged'
      ? { state: 'failed', text: 'This revision failed authenticated decryption. Nothing was shown.' }
      : entry.problem === 'unsupported'
        ? { state: 'failed', text: 'This revision decrypted but its format is not supported. Nothing was shown.' }
        : entry.opened !== undefined
          ? { state: 'verified', text: 'Title and body passed authenticated decryption on this device.' }
          : { state: 'unchecked', text: 'This device has not decrypted the revision (vault locked or no key).' };
  return (
    <Receipt
      testId="note-receipt"
      check={check}
      rows={[
        { term: 'Algorithm suite', value: SUITE_TEXT(view.suite) },
        {
          term: 'Content',
          value: `Revision ${String(view.revision)}: title and body as one AES-256-GCM message under a fresh key (NEK)`,
        },
        {
          term: 'Note key',
          value: `Wrapped with AES-256-GCM under the room wrapping key of key version ${String(view.keyVersion)}`,
        },
        {
          term: 'Concurrency',
          value: `The server stores revision ${String(view.revision + 1)} only while revision ${String(view.revision)} is current`,
        },
        { term: 'Server holds', value: 'The ciphertext and the wrapped key; it cannot read the title or the body' },
      ]}
    />
  );
}

export function SecretReceipt({ view, revealed }: { readonly view: SecretMetadataView; readonly revealed: boolean }) {
  const check: Check = revealed
    ? { state: 'verified', text: 'The payload passed authenticated decryption on this device.' }
    : { state: 'unchecked', text: 'Only the recipient can decrypt this secret, on their own device.' };
  return (
    <Receipt
      testId="secret-receipt"
      check={check}
      rows={[
        { term: 'Algorithm suite', value: SUITE_TEXT('CM1') },
        { term: 'Content', value: 'One AES-256-GCM message under a key made for this secret only (SEK)' },
        {
          term: 'Secret key',
          value:
            'The 32-byte SEK is wrapped with RSA-OAEP-3072 to the recipient’s identity key, verified by the sender’s browser',
        },
        {
          term: 'Release',
          value: view.burnAfterReading
            ? 'At most once: the reveal returns the ciphertext and destroys it in the same database transaction'
            : 'Until expiry or revocation',
        },
        { term: 'Expires', value: new Date(view.expiresAt).toLocaleString() },
      ]}
    />
  );
}
