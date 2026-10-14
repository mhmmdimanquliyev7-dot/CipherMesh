'use client';

import { useEffect, useMemo, useState } from 'react';
import { Icon } from '../components/icons';
import { Badge, controlClass, type BadgeTone } from '../components/ui';
import { evidenceItem, isms, risks, type Control, type Risk } from './data';
import { EvidenceChips, LimitationChip } from './ui';

/**
 * The ISMS registers of the Governance & Risk page (Phase 14 + Prompt 16.5, CM-T061), generated
 * from docs/security/isms-control-mapping.md and docs/threat-model/threat-model.md. Filters are
 * local view state only; every status shown is the document's own, and the evidence coverage is
 * counted from the evidence register, so a control without captured evidence says so.
 */

const RATING_TONE: Readonly<Record<string, BadgeTone>> = {
  Low: 'success',
  Medium: 'warning',
  High: 'danger',
  Critical: 'danger',
};
const ratingTone = (rating: string): BadgeTone => RATING_TONE[rating.split(' ')[0] ?? ''] ?? 'neutral';
const LEVEL: Readonly<Record<string, string>> = { L: 'Low', M: 'Medium', H: 'High' };
const level = (value: string): string => LEVEL[value] ?? value;

const STATUS_TONE: Readonly<Record<string, BadgeTone>> = {
  'Implemented by design': 'accent',
  Partial: 'warning',
  Provider: 'info',
  'Provider and team': 'info',
  'Not applicable': 'neutral',
};

function coverage(control: Control): { readonly captured: number; readonly total: number } {
  const items = control.evidence.map((id) => evidenceItem(id));
  return {
    captured: items.filter((item) => item?.status === 'captured' || item?.status === 'partial').length,
    total: items.length,
  };
}

/** Opens the <details> element whose id is in the URL fragment (links from the walkthrough). */
function useOpenFromHash(): void {
  useEffect(() => {
    const id = decodeURIComponent(window.location.hash.slice(1));
    if (id === '') return;
    const target = document.getElementById(id);
    if (target instanceof HTMLDetailsElement) {
      target.open = true;
      target.scrollIntoView({ block: 'start' });
    }
  }, []);
}

export function ControlRegister() {
  const [theme, setTheme] = useState('all');
  const [status, setStatus] = useState('all');
  const themes = useMemo(() => [...new Set(isms.controls.map((c) => c.theme))], []);
  const statuses = useMemo(() => [...new Set(isms.controls.map((c) => c.status))], []);
  const shown = isms.controls.filter(
    (c) => (theme === 'all' || c.theme === theme) && (status === 'all' || c.status === status),
  );
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end gap-3">
        <label className="space-y-1 text-xs text-slate-400">
          <span className="block">Theme</span>
          <select
            className={`${controlClass} w-auto`}
            value={theme}
            onChange={(e) => {
              setTheme(e.target.value);
            }}
          >
            <option value="all">All themes</option>
            {themes.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </label>
        <label className="space-y-1 text-xs text-slate-400">
          <span className="block">Documented status</span>
          <select
            className={`${controlClass} w-auto`}
            value={status}
            onChange={(e) => {
              setStatus(e.target.value);
            }}
          >
            <option value="all">All statuses</option>
            {statuses.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        <p className="pb-2 text-xs text-slate-500" role="status">
          {shown.length} of {isms.controls.length} entries
        </p>
      </div>
      <ul
        className="divide-y divide-slate-800 overflow-hidden rounded-xl border border-line bg-surface/80"
        aria-label="Annex A controls"
      >
        {shown.map((control) => {
          const { captured, total } = coverage(control);
          return (
            <li key={control.control} id={`control-${control.control}`} className="scroll-mt-24">
              <details className="group">
                <summary className="grid gap-2 px-4 py-3 hover:bg-slate-800/30 md:grid-cols-[6rem_minmax(0,1fr)_auto_auto] md:items-center">
                  <span className="font-mono text-sm text-accent-300">{control.control}</span>
                  <span className="flex items-center gap-2 text-sm font-medium text-white">
                    <Icon name="chevronRight" className="disclosure-chevron size-3.5 text-slate-500" />
                    {control.title}
                    <span className="text-xs font-normal text-slate-500">{control.theme}</span>
                  </span>
                  <Badge tone={STATUS_TONE[control.status] ?? 'neutral'}>{control.status}</Badge>
                  <Badge
                    tone={
                      total === 0 ? 'neutral' : captured === total ? 'success' : captured === 0 ? 'danger' : 'warning'
                    }
                  >
                    {total === 0 ? 'No evidence item' : `Evidence ${String(captured)} of ${String(total)} captured`}
                  </Badge>
                </summary>
                <div className="space-y-3 border-t border-slate-800 bg-slate-950/40 px-4 py-4 text-sm">
                  <p className="leading-relaxed text-slate-300">{control.implementation}</p>
                  <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
                    Evidence:{' '}
                    {control.evidence.length > 0 ? (
                      <EvidenceChips ids={control.evidence} />
                    ) : (
                      <span>{control.evidenceText}</span>
                    )}
                  </div>
                </div>
              </details>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function RiskDetail({ risk }: { readonly risk: Risk }) {
  return (
    <div className="space-y-3 border-t border-slate-800 bg-slate-950/40 px-4 py-4 text-sm">
      <dl className="space-y-3">
        {risk.fields.map((field) => (
          <div key={field.label} className="space-y-1">
            <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">{field.label}</dt>
            <dd className="leading-relaxed text-slate-300">
              {field.text === '' ? null : <p>{field.text}</p>}
              {field.items.length === 0 ? null : (
                <ul className="mt-1 list-disc space-y-1 pl-5 marker:text-accent-400">
                  {field.items.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              )}
            </dd>
          </div>
        ))}
      </dl>
      {risk.limitations.length === 0 ? null : (
        <p className="flex flex-wrap items-center gap-1.5 text-xs text-slate-400">
          Related limitations:
          {risk.limitations.map((id) => (
            <LimitationChip key={id} id={id} />
          ))}
        </p>
      )}
    </div>
  );
}

export function RiskRegister() {
  useOpenFromHash();
  const [residual, setResidual] = useState('all');
  const [treatment, setTreatment] = useState('all');
  const shown = risks.filter(
    (r) =>
      (residual === 'all' || r.residual.startsWith(residual)) &&
      (treatment === 'all' || r.treatment.includes(treatment)),
  );
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end gap-3">
        <label className="space-y-1 text-xs text-slate-400">
          <span className="block">Residual risk</span>
          <select
            className={`${controlClass} w-auto`}
            value={residual}
            onChange={(e) => {
              setResidual(e.target.value);
            }}
          >
            <option value="all">All ratings</option>
            {['Low', 'Medium', 'High'].map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </label>
        <label className="space-y-1 text-xs text-slate-400">
          <span className="block">Treatment</span>
          <select
            className={`${controlClass} w-auto`}
            value={treatment}
            onChange={(e) => {
              setTreatment(e.target.value);
            }}
          >
            <option value="all">All treatments</option>
            {['Mitigate', 'Accept', 'Transfer'].map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </label>
        <p className="pb-2 text-xs text-slate-500" role="status">
          {shown.length} of {risks.length} risks
        </p>
      </div>
      <div className="hidden grid-cols-[4.5rem_minmax(0,1fr)_5rem_5rem_6rem_minmax(0,9rem)_6rem] gap-3 px-4 text-xs font-medium uppercase tracking-wide text-slate-500 xl:grid">
        <span>ID</span>
        <span>Threat</span>
        <span>Likelihood</span>
        <span>Impact</span>
        <span>Inherent</span>
        <span>Treatment</span>
        <span>Residual</span>
      </div>
      <ul
        className="divide-y divide-slate-800 overflow-hidden rounded-xl border border-line bg-surface/80"
        aria-label="Risk register"
      >
        {shown.map((risk) => (
          <li key={risk.id}>
            <details id={risk.id} className="group scroll-mt-24" data-testid="risk">
              <summary className="grid gap-2 px-4 py-3 hover:bg-slate-800/30 xl:grid-cols-[4.5rem_minmax(0,1fr)_5rem_5rem_6rem_minmax(0,9rem)_6rem] xl:items-center">
                <span className="font-mono text-sm text-accent-300">{risk.id}</span>
                <span className="flex items-center gap-2 text-sm font-medium text-white">
                  <Icon name="chevronRight" className="disclosure-chevron size-3.5 text-slate-500" />
                  {risk.title}
                </span>
                <span className="text-xs text-slate-300">
                  <span className="xl:hidden">Likelihood </span>
                  {level(risk.likelihood)}
                </span>
                <span className="text-xs text-slate-300">
                  <span className="xl:hidden">Impact </span>
                  {level(risk.impact)}
                </span>
                <span>
                  <Badge tone={ratingTone(risk.inherent)}>Inherent {risk.inherent}</Badge>
                </span>
                <span className="text-xs text-slate-300">{risk.treatment}</span>
                <span>
                  <Badge tone={ratingTone(risk.residual)}>Residual {risk.residual.split(' ')[0]}</Badge>
                </span>
              </summary>
              <RiskDetail risk={risk} />
            </details>
          </li>
        ))}
      </ul>
    </div>
  );
}
