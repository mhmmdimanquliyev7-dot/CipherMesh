'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import type { ReactNode } from 'react';
import { Icon, type IconName } from '../components/icons';
import { Badge } from '../components/ui';
import {
  documentUrl,
  evidenceItem,
  EVIDENCE_STATUS_LABEL,
  EVIDENCE_STATUS_TONE,
  limitation,
  type EvidenceStatus,
} from './data';

/** Shared parts of the Security & Trust Center pages (Phase 14 + Prompt 16.5, CM-T061). */

const TABS: readonly { readonly href: string; readonly label: string; readonly icon: IconName }[] = [
  { href: '/trust', label: 'Summary', icon: 'trust' },
  { href: '/trust/cryptography', label: 'Data protection', icon: 'key' },
  { href: '/trust/infrastructure', label: 'Infrastructure', icon: 'cloud' },
  { href: '/trust/governance', label: 'Governance & risk', icon: 'governance' },
  { href: '/trust/evidence', label: 'Evidence', icon: 'evidence' },
  { href: '/trust/walkthrough', label: 'Walkthrough', icon: 'play' },
  { href: '/trust/dashboard', label: 'Security dashboard', icon: 'overview' },
  { href: '/trust/isms', label: 'ISMS Control Center', icon: 'governance' },
];

export function TrustNav() {
  const pathname = usePathname();
  return (
    <nav aria-label="Trust Center sections" className="-mx-4 overflow-x-auto px-4 sm:mx-0 sm:px-0">
      <ul className="flex min-w-max gap-1 border-b border-slate-800">
        {TABS.map((tab) => {
          const active = pathname === tab.href;
          return (
            <li key={tab.href}>
              <Link
                href={tab.href}
                aria-current={active ? 'page' : undefined}
                className={`-mb-px flex items-center gap-1.5 border-b-2 px-3 py-2.5 text-sm font-medium transition-colors ${
                  active
                    ? 'border-accent-400 text-white'
                    : 'border-transparent text-slate-400 hover:border-slate-600 hover:text-slate-200'
                }`}
              >
                <Icon name={tab.icon} className="size-4" />
                {tab.label}
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

export function EvidenceStatusBadge({ status }: { readonly status: EvidenceStatus }) {
  const icon =
    status === 'captured'
      ? 'checkCircle'
      : status === 'partial'
        ? 'minusCircle'
        : status === 'pending'
          ? 'xCircle'
          : 'dashedCircle';
  return (
    <Badge tone={EVIDENCE_STATUS_TONE[status]} icon={icon}>
      {EVIDENCE_STATUS_LABEL[status]}
    </Badge>
  );
}

/** An evidence ID with its status, linking to the evidence register entry. */
export function EvidenceChip({ id }: { readonly id: string }) {
  const item = evidenceItem(id);
  const status: EvidenceStatus = item?.status ?? 'pending';
  const tone =
    status === 'captured'
      ? 'border-emerald-500/40 text-emerald-200 hover:border-emerald-400'
      : status === 'pending'
        ? 'border-rose-500/40 text-rose-200 hover:border-rose-400'
        : 'border-slate-700 text-slate-300 hover:border-slate-500';
  return (
    <Link
      href={`/trust/evidence#${id}`}
      className={`inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 font-mono text-[11px] transition-colors ${tone}`}
      title={item === undefined ? 'Not in the evidence plan' : `${item.evidence} (${EVIDENCE_STATUS_LABEL[status]})`}
    >
      {id}
      <span className="sr-only">: {EVIDENCE_STATUS_LABEL[status]}</span>
    </Link>
  );
}

export function EvidenceChips({ ids }: { readonly ids: readonly string[] }) {
  if (ids.length === 0) return <span className="text-xs text-slate-500">No evidence item</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {ids.map((id) => (
        <EvidenceChip key={id} id={id} />
      ))}
    </span>
  );
}

/** A limitation ID with its title as a tooltip, linking to the limitations register. */
export function LimitationChip({ id }: { readonly id: string }) {
  const item = limitation(id);
  return (
    <Link
      href={`/trust/governance#${id}`}
      className="inline-flex items-center rounded-md border border-amber-500/40 px-1.5 py-0.5 font-mono text-[11px] text-amber-200 hover:border-amber-400"
      title={item?.limitation}
    >
      {id}
    </Link>
  );
}

export function DocumentLink({ path, children }: { readonly path: string; readonly children?: ReactNode }) {
  return (
    <a
      href={documentUrl(path)}
      target="_blank"
      rel="noreferrer noopener"
      className="inline-flex items-center gap-1 text-accent-300 hover:text-accent-200"
    >
      {children ?? path}
      <Icon name="external" className="size-3" />
      <span className="sr-only">(opens GitHub in a new tab)</span>
    </a>
  );
}

export function SectionHeading({
  id,
  eyebrow,
  title,
  children,
}: {
  readonly id?: string;
  readonly eyebrow?: string;
  readonly title: string;
  readonly children?: ReactNode;
}) {
  return (
    <div id={id} className="scroll-mt-24 space-y-1.5">
      {eyebrow === undefined ? null : (
        <p className="text-xs font-semibold uppercase tracking-[0.14em] text-accent-300">{eyebrow}</p>
      )}
      <h2 className="text-xl font-semibold tracking-tight text-white">{title}</h2>
      {children === undefined ? null : (
        <div className="max-w-3xl text-sm leading-relaxed text-slate-400">{children}</div>
      )}
    </div>
  );
}
