import type { Metadata } from 'next';
import Link from 'next/link';
import { Icon } from '../../../components/icons';
import { Badge, buttonClass, Disclosure, PageHeader } from '../../../components/ui';
import { FLOW, KEY_HIERARCHY, MECHANISMS, ROTATION_STEPS, type KeyNode } from '../../../trust/cryptography';
import { parameter } from '../../../trust/data';
import { DocumentLink, EvidenceChips, LimitationChip, SectionHeading } from '../../../trust/ui';

export const metadata: Metadata = { title: 'Data protection & key management' };

/**
 * Data Protection & Key Management (Phase 14 + Prompt 16.5, CM-T061). Explains the implemented
 * cryptography from the normative documents; parameter values are the register's own text. No
 * key, ciphertext or user data appears on this page.
 */

const ZONE = {
  browser: { label: 'Your browser', style: 'border-accent-500/40 bg-accent-500/5', badge: 'accent' },
  network: { label: 'Network', style: 'border-sky-500/30 bg-sky-500/5', badge: 'info' },
  server: { label: 'CipherMesh servers', style: 'border-indigo-400/30 bg-indigo-400/5', badge: 'violet' },
} as const;

const SERVER_HOLDS = [
  'Ciphertext of files, notes and secrets, with their IVs',
  'Wrapped data keys and RSA-OAEP envelopes',
  'Encrypted private keys (vault records) and public keys',
  'Signed key-version statements and public commitments',
  'Metadata: room names, membership, roles, sizes, timestamps',
];
const SERVER_NEVER = [
  'Your Vault Passphrase or any key derived from it',
  'Private keys, room key material or data keys in plaintext',
  'File contents, file names and types, note text, secret text',
  'The Room Safety Code',
];

function HierarchyNode({ node, depth }: { readonly node: KeyNode; readonly depth: number }) {
  const neverStored = node.stored === 'Never';
  return (
    <li className="space-y-2">
      <div className="flex flex-wrap items-start gap-x-3 gap-y-1 rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2">
        <Icon name={depth === 0 ? 'account' : 'key'} className="mt-0.5 size-4 text-accent-300" />
        <span className="min-w-0 flex-1">
          <span className="block text-sm font-medium text-white">{node.name}</span>
          <span className="block text-xs text-slate-400">{node.detail}</span>
        </span>
        <Badge tone={neverStored ? 'success' : node.stored === 'In clear' ? 'neutral' : 'accent'}>
          Stored: {node.stored}
        </Badge>
      </div>
      {node.children === undefined ? null : (
        <ul className="ml-1.5 space-y-2 border-l border-dashed border-slate-700 pl-2.5 sm:ml-4 sm:pl-4">
          {node.children.map((child) => (
            <HierarchyNode key={child.name} node={child} depth={depth + 1} />
          ))}
        </ul>
      )}
    </li>
  );
}

export default function CryptographyPage() {
  return (
    <div className="space-y-14">
      <PageHeader
        eyebrow="Cryptography"
        title="Data protection & key management"
        description="CipherMesh encrypts room content in members’ browsers with authenticated encryption, delivers keys with public-key wrapping, and authenticates every room key with digital signatures. Here is how, with the parameters from the register and what each mechanism cannot guarantee."
        actions={
          <Link className={buttonClass.secondary} href="/trust/walkthrough#cryptography">
            <Icon name="play" className="size-4" />
            See it in the product
          </Link>
        }
      />

      <section aria-labelledby="flow-heading" className="space-y-5">
        <SectionHeading eyebrow="Encryption flow" title="From plaintext to ciphertext and back">
          The path of one note, file or secret. The colour of each step shows where it runs.
        </SectionHeading>
        <h3 id="flow-heading" className="sr-only">
          Encryption flow
        </h3>
        <ol className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {FLOW.map((step, index) => (
            <li key={step.title} className={`space-y-2 rounded-xl border p-4 ${ZONE[step.zone].style}`}>
              <div className="flex items-center justify-between gap-2">
                <span className="flex items-center gap-2">
                  <span className="grid size-7 place-items-center rounded-md bg-slate-900 font-mono text-xs text-slate-300">
                    {index + 1}
                  </span>
                  <Icon name={step.icon} className="size-4 text-slate-200" />
                </span>
                <Badge tone={ZONE[step.zone].badge}>{ZONE[step.zone].label}</Badge>
              </div>
              <p className="font-medium text-white">{step.title}</p>
              <p className="text-sm leading-relaxed text-slate-300">{step.text}</p>
            </li>
          ))}
        </ol>
        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-2 rounded-xl border border-line bg-surface/90 p-5">
            <p className="flex items-center gap-2 text-sm font-semibold text-white">
              <Icon name="server" className="size-4 text-indigo-300" />
              What the server stores
            </p>
            <ul className="space-y-1.5 text-sm text-slate-300">
              {SERVER_HOLDS.map((item) => (
                <li key={item} className="flex gap-2">
                  <Icon name="dashedCircle" className="mt-0.5 size-4 text-slate-500" />
                  {item}
                </li>
              ))}
            </ul>
            <p className="flex flex-wrap items-center gap-1.5 text-xs text-slate-500">
              Metadata stays visible to the server: <LimitationChip id="L-05" />
            </p>
          </div>
          <div className="space-y-2 rounded-xl border border-emerald-500/25 bg-emerald-500/5 p-5">
            <p className="flex items-center gap-2 text-sm font-semibold text-white">
              <Icon name="lock" className="size-4 text-emerald-300" />
              What the server never receives (INV-01, INV-16, INV-18)
            </p>
            <ul className="space-y-1.5 text-sm text-slate-300">
              {SERVER_NEVER.map((item) => (
                <li key={item} className="flex gap-2">
                  <Icon name="checkCircle" className="mt-0.5 size-4 text-emerald-300" />
                  {item}
                </li>
              ))}
            </ul>
            <p className="flex flex-wrap items-center gap-1.5 text-xs text-slate-500">
              This holds while the delivered code is genuine: <LimitationChip id="L-02" />
            </p>
          </div>
        </div>
      </section>

      <section className="space-y-5">
        <SectionHeading id="mechanisms" eyebrow="Mechanisms" title="The cryptography in use">
          For each mechanism: what it is, why CipherMesh uses it, where it runs, what it protects, how it is verified
          and what it cannot guarantee.
        </SectionHeading>
        <div className="grid gap-4 xl:grid-cols-2">
          {MECHANISMS.map((mechanism) => (
            <article
              key={mechanism.id}
              id={mechanism.id}
              className="scroll-mt-24 space-y-4 rounded-2xl border border-line bg-surface/90 p-6"
              data-testid="mechanism"
            >
              <header className="flex items-start gap-3">
                <span className="grid size-10 shrink-0 place-items-center rounded-xl border border-accent-500/30 bg-accent-500/10 text-accent-300">
                  <Icon name={mechanism.icon} />
                </span>
                <div className="space-y-1">
                  <h3 className="text-base font-semibold text-white">{mechanism.name}</h3>
                  <p className="text-sm leading-relaxed text-slate-300">{mechanism.what}</p>
                </div>
              </header>
              <dl className="grid gap-3 text-sm sm:grid-cols-2">
                {(
                  [
                    ['Why CipherMesh uses it', mechanism.why],
                    ['Where it operates', mechanism.where],
                    ['What it protects', mechanism.protects],
                    ['How it is verified', mechanism.verification],
                  ] as const
                ).map(([term, text]) => (
                  <div key={term} className="space-y-1">
                    <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">{term}</dt>
                    <dd className="leading-relaxed text-slate-300">{text}</dd>
                  </div>
                ))}
              </dl>
              <div className="space-y-1.5 rounded-lg border border-amber-500/25 bg-amber-500/5 p-3 text-sm">
                <p className="text-xs font-medium uppercase tracking-wide text-amber-300/90">
                  What it cannot guarantee
                </p>
                <p className="text-slate-300">{mechanism.cannot}</p>
                <p className="flex flex-wrap gap-1">
                  {mechanism.limitations.map((id) => (
                    <LimitationChip key={id} id={id} />
                  ))}
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
                Evidence: <EvidenceChips ids={mechanism.evidence} />
              </div>
              <Disclosure summary="Parameters from the register">
                <dl className="space-y-3 text-xs">
                  {mechanism.parameters.map((id) => {
                    const row = parameter(id);
                    return (
                      <div key={id} className="space-y-0.5">
                        <dt className="font-mono text-accent-300">
                          {id} · {row?.name}
                        </dt>
                        <dd className="leading-relaxed text-slate-300">{row?.value}</dd>
                      </div>
                    );
                  })}
                </dl>
              </Disclosure>
            </article>
          ))}
        </div>
      </section>

      <section className="grid gap-8 xl:grid-cols-[1.2fr_1fr]">
        <div className="min-w-0 space-y-5">
          <SectionHeading id="hierarchy" eyebrow="Key hierarchy" title="Which key protects which">
            Each key is protected by the one above it. Only the passphrase is remembered; everything marked “Never”
            exists only in memory. Source:{' '}
            <DocumentLink path="docs/crypto/key-hierarchy.md">key-hierarchy.md</DocumentLink>
          </SectionHeading>
          <ul className="space-y-2" aria-label="Key hierarchy">
            {KEY_HIERARCHY.map((node) => (
              <HierarchyNode key={node.name} node={node} depth={0} />
            ))}
          </ul>
        </div>
        <div className="min-w-0 space-y-5">
          <SectionHeading id="rotation" eyebrow="Key rotation" title="Rotating a room key">
            Losing a member locks the room until a new key version exists. Source:{' '}
            <DocumentLink path="docs/architecture/adr/ADR-013-rekey-state-machine.md">ADR-013</DocumentLink>
          </SectionHeading>
          <ol className="space-y-3">
            {ROTATION_STEPS.map((step, index) => (
              <li key={step.state} className="flex gap-3">
                <span className="flex flex-col items-center">
                  <span className="grid size-7 place-items-center rounded-full border border-accent-500/40 bg-accent-500/10 font-mono text-xs text-accent-200">
                    {index + 1}
                  </span>
                  {index < ROTATION_STEPS.length - 1 ? (
                    <span className="flow-connector mt-1 w-px flex-1" aria-hidden="true" />
                  ) : null}
                </span>
                <span className="space-y-1 pb-2">
                  <span className="block font-mono text-xs font-semibold text-white">{step.state}</span>
                  <span className="block text-sm leading-relaxed text-slate-300">{step.text}</span>
                </span>
              </li>
            ))}
          </ol>
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
            Evidence: <EvidenceChips ids={['EV-11-01', 'EV-11-03', 'EV-11-04', 'EV-11-07']} />
          </div>
          <p className="flex flex-wrap items-center gap-1.5 text-xs text-slate-500">
            Rotation protects new content only: <LimitationChip id="L-04" />
          </p>
        </div>
      </section>

      <section className="space-y-3 rounded-2xl border border-line bg-surface/90 p-6">
        <h2 className="flex items-center gap-2 text-lg font-semibold text-white">
          <Icon name="evidence" className="size-5 text-accent-300" />
          Encryption details on every item
        </h2>
        <p className="max-w-3xl text-sm leading-relaxed text-slate-400">
          In a room, every file, note and secret has an “Encryption details” panel. It shows the algorithm suite, the
          room key version and what the server holds, and it reports only the integrity check this browser ran itself.
          It never shows keys, IVs or ciphertext.
        </p>
      </section>
    </div>
  );
}
