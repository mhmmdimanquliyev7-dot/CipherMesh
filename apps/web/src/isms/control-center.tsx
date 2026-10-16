'use client';

import Link from 'next/link';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { StepUpForm } from '../components/step-up-form';
import { Alert, Badge, Loading } from '../components/ui';
import { publicEnv } from '../config/public-env';
import { ApiError, describeError } from '../lib/api';
import { describeIsmsError, loadState, needsStepUp, type IsmsState, type Write } from './client';
import { IsmsContext, SECTIONS, type IsmsContextValue, type SectionId, type WriteOutcome } from './context';
import { AssetsSection, ContextSection, OverviewSection, PoliciesSection } from './sections-foundation';
import { RisksSection, TreatmentSection } from './sections-risk';
import { AssuranceSection, SoaSection } from './sections-controls';
import { ActionsSection, AuditsSection } from './sections-audit';
import { ImprovementSection, ReviewSection } from './sections-review';

/**
 * The ISMS Control Center (ADR-016, docs/security/isms-operations.md). Platform administrators
 * only: the API answers 404 to everyone else (PA-06 to PA-08), and this page then shows nothing.
 * Every number is computed from the stored records, the documents and the time; every change is a
 * named transition that the server checks. The page fetches on load and after each change.
 */

type View =
  | { readonly kind: 'loading' }
  | { readonly kind: 'signed-out' }
  | { readonly kind: 'forbidden' }
  | { readonly kind: 'failed'; readonly message: string }
  | { readonly kind: 'ready'; readonly state: IsmsState };

interface PendingStepUp {
  readonly write: Write;
  readonly resolve: (outcome: WriteOutcome) => void;
  readonly reject: (error: Error) => void;
}

const ENVIRONMENT: Readonly<Record<string, string>> = {
  'local-docker': 'LOCAL DOCKER DEMONSTRATION',
  development: 'DEVELOPMENT BUILD',
  'cloud-demonstration': 'CLOUD DEMONSTRATION BUILD',
};

function readLocation(): { section: SectionId; item: string | undefined } {
  if (typeof window === 'undefined') return { section: 'overview', item: undefined };
  const params = new URLSearchParams(window.location.search);
  const section = SECTIONS.find((s) => s.id === params.get('section'))?.id ?? 'overview';
  return { section, item: params.get('item') ?? undefined };
}

export function ControlCenter() {
  const [view, setView] = useState<View>({ kind: 'loading' });
  const [section, setSection] = useState<SectionId>('overview');
  const [item, setItem] = useState<string | undefined>();
  const [pending, setPending] = useState<PendingStepUp | undefined>();
  const top = useRef<HTMLDivElement>(null);

  const reload = useCallback(async () => {
    try {
      const state = await loadState();
      setView({ kind: 'ready', state });
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) setView({ kind: 'signed-out' });
      else if (error instanceof ApiError && error.status === 404) setView({ kind: 'forbidden' });
      else setView({ kind: 'failed', message: describeError(error) });
    }
  }, []);

  useEffect(() => {
    const location = readLocation();
    setSection(location.section);
    setItem(location.item);
    void reload();
  }, [reload]);

  // The identity confirmation appears above the sections; bring it into view, or a decision made
  // at the bottom of a long page would seem to do nothing.
  const prompt = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (pending !== undefined) prompt.current?.scrollIntoView({ block: 'start' });
  }, [pending]);

  const go = useCallback((next: SectionId, nextItem?: string) => {
    setSection(next);
    setItem(nextItem);
    const params = new URLSearchParams({ section: next, ...(nextItem === undefined ? {} : { item: nextItem }) });
    window.history.replaceState(null, '', `${window.location.pathname}?${params.toString()}`);
    top.current?.scrollIntoView({ block: 'start' });
  }, []);

  const runWithStepUp = useCallback(
    async (write: Write): Promise<WriteOutcome> => {
      try {
        const result = await write();
        await reload();
        return { code: result.record.code, created: result.created };
      } catch (error) {
        if (needsStepUp(error))
          return new Promise<WriteOutcome>((resolve, reject) => {
            setPending({ write, resolve, reject });
          });
        if (error instanceof ApiError && error.code === 'ISMS_VERSION_CONFLICT') await reload();
        throw new Error(describeIsmsError(error), { cause: error });
      }
    },
    [reload],
  );

  const value = useMemo<IsmsContextValue | undefined>(
    () => (view.kind === 'ready' ? { state: view.state, run: runWithStepUp, go, item } : undefined),
    [view, runWithStepUp, go, item],
  );

  if (view.kind === 'loading') return <Loading label="Loading the ISMS records…" />;
  if (view.kind === 'signed-out') {
    return (
      <Alert kind="info">
        Sign in with a platform administrator account to open the ISMS Control Center.{' '}
        <Link className="font-medium underline" href="/login">
          Sign in
        </Link>
      </Alert>
    );
  }
  if (view.kind === 'forbidden') {
    return (
      <Alert kind="info">
        The ISMS Control Center is available to platform administrators with two-step sign-in only. The server refused
        the request; no ISMS record was sent to this account. The public governance documents are under Governance &amp;
        risk.
      </Alert>
    );
  }
  if (view.kind === 'failed' || value === undefined) {
    return <Alert kind="error">{view.kind === 'failed' ? view.message : 'Unexpected state.'}</Alert>;
  }

  return (
    <IsmsContext.Provider value={value}>
      <div ref={top} className="scroll-mt-24 space-y-6" data-testid="isms-control-center">
        <div className="flex flex-wrap items-center gap-2" data-testid="isms-environment">
          <Badge tone="warning">Environment: {ENVIRONMENT[publicEnv.deploymentEnvironment] ?? 'UNKNOWN'}</Badge>
          <Badge tone="neutral">Oracle Cloud: NOT DEPLOYED / NOT VERIFIED</Badge>
          <Badge tone="neutral">Not certified: academic ISO/IEC 27001:2022-aligned ISMS</Badge>
          <span className="text-xs text-slate-500">State computed {view.state.now.toISOString().slice(0, 19)}Z</span>
        </div>
        {pending === undefined ? null : (
          <div ref={prompt} className="scroll-mt-24">
            <StepUpForm
              mfaEnabled
              reason="This is a decision (PA-08). Confirm your account to record it under your name."
              onDone={() => {
                const current = pending;
                setPending(undefined);
                current
                  .write()
                  .then(async (result) => {
                    await reload();
                    current.resolve({ code: result.record.code, created: result.created });
                  })
                  .catch((error: unknown) => {
                    current.reject(new Error(describeIsmsError(error)));
                  });
              }}
            />
          </div>
        )}
        <nav aria-label="ISMS sections" className="-mx-4 overflow-x-auto px-4 sm:mx-0 sm:px-0">
          <ul className="flex min-w-max flex-wrap gap-1.5">
            {SECTIONS.map((s, index) => (
              <li key={s.id}>
                <button
                  type="button"
                  onClick={() => {
                    go(s.id);
                  }}
                  aria-current={section === s.id ? 'page' : undefined}
                  className={`rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                    section === s.id
                      ? 'border-accent-400/60 bg-accent-500/15 text-white'
                      : 'border-slate-800 text-slate-400 hover:border-slate-600 hover:text-slate-200'
                  }`}
                >
                  <span className="mr-1 font-mono text-[10px] text-slate-500">
                    {String(index + 1).padStart(2, '0')}
                  </span>
                  {s.label}
                </button>
              </li>
            ))}
          </ul>
        </nav>
        {section === 'overview' ? <OverviewSection /> : null}
        {section === 'context' ? <ContextSection /> : null}
        {section === 'assets' ? <AssetsSection /> : null}
        {section === 'risks' ? <RisksSection /> : null}
        {section === 'treatment' ? <TreatmentSection /> : null}
        {section === 'soa' ? <SoaSection /> : null}
        {section === 'policies' ? <PoliciesSection /> : null}
        {section === 'assurance' ? <AssuranceSection /> : null}
        {section === 'audits' ? <AuditsSection /> : null}
        {section === 'actions' ? <ActionsSection /> : null}
        {section === 'review' ? <ReviewSection /> : null}
        {section === 'improvement' ? <ImprovementSection /> : null}
      </div>
    </IsmsContext.Provider>
  );
}
