'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { Icon } from '../components/icons';
import { Badge, buttonClass, SecondaryButton } from '../components/ui';
import { EvidenceChips } from './ui';
import { JOURNEYS, type Journey } from './walkthrough';

/**
 * The guided walkthrough (Phase 14 + Prompt 16.5, CM-T061). A presenter steps through one journey
 * at a time; each step links to the real page where the action happens. The journey and step are
 * kept in this component and the URL fragment only: nothing is stored, and the walkthrough has no
 * access of its own, so every action runs with the presenter's normal session, vault and role.
 */
export function WalkthroughView() {
  const [journeyId, setJourneyId] = useState<Journey['id']>('cryptography');
  const [step, setStep] = useState(0);

  useEffect(() => {
    const fromHash = JOURNEYS.find((j) => j.id === window.location.hash.slice(1));
    if (fromHash !== undefined) setJourneyId(fromHash.id);
  }, []);

  const journey = JOURNEYS.find((j) => j.id === journeyId) ?? JOURNEYS[0];
  if (journey === undefined) return null;
  const current = journey.steps[Math.min(step, journey.steps.length - 1)];

  const choose = (id: Journey['id']): void => {
    setJourneyId(id);
    setStep(0);
    window.history.replaceState(null, '', `#${id}`);
  };

  return (
    <div className="space-y-6">
      <div role="tablist" aria-label="Journeys" className="grid gap-3 md:grid-cols-3">
        {JOURNEYS.map((j, index) => (
          <button
            key={j.id}
            type="button"
            role="tab"
            aria-selected={j.id === journey.id}
            onClick={() => {
              choose(j.id);
            }}
            className={`flex items-start gap-3 rounded-xl border p-4 text-left transition-colors ${
              j.id === journey.id
                ? 'border-accent-400/60 bg-accent-500/10'
                : 'border-line bg-surface/80 hover:border-slate-600'
            }`}
          >
            <span className="grid size-10 shrink-0 place-items-center rounded-lg bg-slate-900 text-accent-300">
              <Icon name={j.icon} />
            </span>
            <span className="space-y-1">
              <span className="block text-xs uppercase tracking-wide text-slate-500">
                Journey {String.fromCharCode(65 + index)}
              </span>
              <span className="block font-semibold text-white">{j.title}</span>
              <span className="block text-xs text-slate-400">{j.steps.length} steps</span>
            </span>
          </button>
        ))}
      </div>

      <section className="grid gap-6 lg:grid-cols-[18rem_1fr]" aria-label={journey.title}>
        <div className="space-y-4">
          <div className="space-y-2 rounded-xl border border-line bg-surface/80 p-4 text-sm">
            <p className="text-slate-300">{journey.summary}</p>
            <p className="text-xs text-slate-500">
              <span className="font-medium text-slate-400">Prepare: </span>
              {journey.prepare}
            </p>
          </div>
          <ol className="space-y-1" aria-label="Steps">
            {journey.steps.map((s, index) => (
              <li key={s.title}>
                <button
                  type="button"
                  aria-current={index === step ? 'step' : undefined}
                  onClick={() => {
                    setStep(index);
                  }}
                  className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm transition-colors ${
                    index === step
                      ? 'bg-accent-400/10 text-white ring-1 ring-inset ring-accent-400/30'
                      : 'text-slate-300 hover:bg-slate-800/60'
                  }`}
                >
                  <span
                    className={`grid size-6 shrink-0 place-items-center rounded-full font-mono text-[11px] ${
                      index < step ? 'bg-accent-400 text-accent-950' : 'border border-slate-600 text-slate-300'
                    }`}
                  >
                    {index < step ? <Icon name="check" className="size-3.5" /> : index + 1}
                  </span>
                  {s.title}
                </button>
              </li>
            ))}
          </ol>
        </div>

        {current === undefined ? null : (
          <article
            className="space-y-5 rounded-2xl border border-line bg-surface/90 p-6"
            data-testid="walkthrough-step"
          >
            <div className="flex flex-wrap items-center justify-between gap-3">
              <Badge tone="accent">
                Step {step + 1} of {journey.steps.length}
              </Badge>
              <Link className={buttonClass.secondary} href={current.href}>
                Open the page
                <Icon name="arrowRight" className="size-4" />
              </Link>
            </div>
            <h2 className="text-2xl font-semibold tracking-tight text-white">{current.title}</h2>
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-1.5 rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-slate-400">
                  <Icon name="play" className="size-3.5 text-accent-300" />
                  Do
                </p>
                <p className="leading-relaxed text-slate-200">{current.action}</p>
              </div>
              <div className="space-y-1.5 rounded-xl border border-slate-800 bg-slate-950/50 p-4">
                <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-slate-400">
                  <Icon name="info" className="size-3.5 text-accent-300" />
                  Point out
                </p>
                <p className="leading-relaxed text-slate-200">{current.show}</p>
              </div>
            </div>
            {current.evidence === undefined ? null : (
              <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
                Evidence: <EvidenceChips ids={current.evidence} />
              </div>
            )}
            <div className="flex flex-wrap justify-between gap-3 border-t border-slate-800 pt-4">
              <SecondaryButton
                type="button"
                disabled={step === 0}
                onClick={() => {
                  setStep(step - 1);
                }}
              >
                Previous
              </SecondaryButton>
              <SecondaryButton
                type="button"
                disabled={step >= journey.steps.length - 1}
                onClick={() => {
                  setStep(step + 1);
                }}
              >
                Next step
                <Icon name="arrowRight" className="size-4" />
              </SecondaryButton>
            </div>
          </article>
        )}
      </section>
    </div>
  );
}
