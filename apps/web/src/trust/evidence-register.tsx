'use client';

import { useEffect, useState } from 'react';
import { Icon } from '../components/icons';
import { Badge, controlClass } from '../components/ui';
import {
  documentUrl,
  evidence,
  EVIDENCE_STATUS_LABEL,
  evidenceSummary,
  SUBJECT_LABEL,
  type EvidenceStatus,
  type SubjectTag,
} from './data';
import { EvidenceStatusBadge } from './ui';

/**
 * The evidence register (Phase 14 + Prompt 16.5, CM-T061): every item of the evidence plan with
 * its subjects and its status, derived from the committed evidence files and the index. Missing
 * items are listed as missing; deferred and later-workstream items are labelled as such.
 * Links open the committed, redacted files on GitHub; nothing is fetched by this page.
 */

const SUBJECTS: readonly SubjectTag[] = ['CRY', 'CLD', 'ISMS', 'APP'];
const STATUSES: readonly EvidenceStatus[] = ['captured', 'partial', 'pending', 'deferred', 'planned'];

export function EvidenceRegister() {
  const [subject, setSubject] = useState<'all' | SubjectTag>('all');
  const [status, setStatus] = useState<'all' | EvidenceStatus>('all');

  // A link such as /trust/evidence#EV-05-02 scrolls to that item (the filters start empty).
  useEffect(() => {
    const id = decodeURIComponent(window.location.hash.slice(1));
    if (id !== '') document.getElementById(id)?.scrollIntoView({ block: 'center' });
  }, []);

  const scoped = evidence.filter((item) => subject === 'all' || item.tags.includes(subject));
  const shown = scoped.filter((item) => status === 'all' || item.status === status);
  const counts = evidenceSummary(scoped);

  return (
    <div className="space-y-5">
      <div className="grid gap-3 sm:grid-cols-5" aria-label="Evidence status counts">
        {STATUSES.map((s) => (
          <button
            key={s}
            type="button"
            aria-pressed={status === s}
            onClick={() => {
              setStatus(status === s ? 'all' : s);
            }}
            className={`space-y-1 rounded-xl border p-3 text-left transition-colors ${
              status === s
                ? 'border-accent-400/60 bg-accent-500/10'
                : 'border-line bg-surface/80 hover:border-slate-600'
            }`}
          >
            <span className="block text-xs uppercase tracking-wide text-slate-400">{EVIDENCE_STATUS_LABEL[s]}</span>
            <span className="tabular block text-2xl font-semibold text-white">{counts[s]}</span>
          </button>
        ))}
      </div>
      <div className="flex flex-wrap items-end gap-3">
        <label className="space-y-1 text-xs text-slate-400">
          <span className="block">Subject</span>
          <select
            className={`${controlClass} w-auto`}
            value={subject}
            onChange={(e) => {
              setSubject(e.target.value as 'all' | SubjectTag);
            }}
            data-testid="evidence-subject"
          >
            <option value="all">All subjects</option>
            {SUBJECTS.map((tag) => (
              <option key={tag} value={tag}>
                {SUBJECT_LABEL[tag]}
              </option>
            ))}
          </select>
        </label>
        <label className="space-y-1 text-xs text-slate-400">
          <span className="block">Status</span>
          <select
            className={`${controlClass} w-auto`}
            value={status}
            onChange={(e) => {
              setStatus(e.target.value as 'all' | EvidenceStatus);
            }}
            data-testid="evidence-status"
          >
            <option value="all">All statuses</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {EVIDENCE_STATUS_LABEL[s]}
              </option>
            ))}
          </select>
        </label>
        <p className="pb-2 text-xs text-slate-500" role="status">
          {shown.length} of {evidence.length} items
        </p>
      </div>
      <ul
        className="divide-y divide-slate-800 overflow-hidden rounded-xl border border-line bg-surface/80"
        aria-label="Evidence items"
      >
        {shown.map((item) => (
          <li key={item.id} id={item.id} className="scroll-mt-28 space-y-2 px-4 py-4" data-testid="evidence-item">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0 space-y-1">
                <p className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-sm text-accent-300">{item.id}</span>
                  <span className="text-sm font-medium text-white">{item.evidence}</span>
                </p>
                <p className="text-xs text-slate-400">
                  Demonstrates: {item.demonstrates} · Captured as: {item.how}
                </p>
              </div>
              <span className="flex flex-wrap items-center gap-1.5">
                {item.tags.map((tag) => (
                  <Badge key={tag} tone="neutral">
                    {tag}
                  </Badge>
                ))}
                <EvidenceStatusBadge status={item.status} />
              </span>
            </div>
            {item.captions.length === 0 ? null : (
              <ul className="space-y-0.5 text-xs text-slate-400">
                {item.captions.map((caption) => (
                  <li key={caption}>{caption}</li>
                ))}
              </ul>
            )}
            {item.files.length === 0 && item.locations.length === 0 ? null : (
              <p className="flex flex-wrap gap-x-3 gap-y-1 text-xs">
                {item.files.map((file) => (
                  <a
                    key={file.path}
                    href={documentUrl(file.path)}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="inline-flex items-center gap-1 text-accent-300 hover:text-accent-200"
                  >
                    <Icon name="file" className="size-3" />
                    {file.label}
                    <span className="sr-only">(opens GitHub in a new tab)</span>
                  </a>
                ))}
                {item.locations.map((location) => (
                  <span key={location} className="text-slate-400">
                    {location}
                  </span>
                ))}
              </p>
            )}
            {item.status === 'deferred' ? (
              <p className="text-xs text-slate-500">Its phase was deferred by the project owner on 2026-10-13.</p>
            ) : item.status === 'planned' ? (
              <p className="text-xs text-slate-500">Belongs to the cloud, assessment or report workstream.</p>
            ) : item.status === 'pending' ? (
              <p className="text-xs text-rose-300/90">Due in a completed phase but not captured.</p>
            ) : null}
          </li>
        ))}
      </ul>
    </div>
  );
}
