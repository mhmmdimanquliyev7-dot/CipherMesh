import Link from 'next/link';
import { Icon, type IconName } from '../../components/icons';
import { Badge, buttonClass, PageHeader } from '../../components/ui';
import { CLAIMS, NOT_IMPLEMENTED } from '../../trust/claims';
import { MECHANISMS } from '../../trust/cryptography';
import {
  evidenceFor,
  evidenceSummary,
  isms,
  parameters,
  risks,
  SUBJECT_LABEL,
  type SubjectTag,
} from '../../trust/data';
import { CLOUD_CONTROLS } from '../../trust/infrastructure';
import { EvidenceChips, LimitationChip } from '../../trust/ui';

/**
 * Trust Center summary (Phase 14 + Prompt 16.5, CM-T061). Every figure is counted from the
 * generated document data or the curated registers at build time; no score is computed.
 */

function coverage(tag: SubjectTag): string {
  const summary = evidenceSummary(evidenceFor(tag));
  const due = summary.captured + summary.partial + summary.pending;
  return `${String(summary.captured + summary.partial)} of ${String(due)} due items captured`;
}

const configured = CLOUD_CONTROLS.filter((c) => c.configuration.state === 'configured').length;
const verified = CLOUD_CONTROLS.filter((c) => c.verification.state === 'verified').length;
const highResidual = risks.filter((risk) => /^(High|Critical)/.test(risk.residual)).length;

const PILLARS: readonly {
  readonly href: string;
  readonly icon: IconName;
  readonly subject: SubjectTag;
  readonly title: string;
  readonly question: string;
  readonly status: { readonly tone: 'success' | 'warning' | 'info'; readonly text: string };
  readonly facts: readonly string[];
}[] = [
  {
    href: '/trust/cryptography',
    icon: 'key',
    subject: 'CRY',
    title: 'Data protection & key management',
    question: 'How is my data protected cryptographically?',
    status: { tone: 'success', text: 'Implemented and tested' },
    facts: [
      `${String(MECHANISMS.length)} mechanisms explained with their limits`,
      `${String(parameters.length)} rows of the parameter register, shown verbatim`,
      `Evidence: ${coverage('CRY')}`,
    ],
  },
  {
    href: '/trust/infrastructure',
    icon: 'cloud',
    subject: 'CLD',
    title: 'Deployment & infrastructure',
    question: 'How is the system deployed and secured in the cloud?',
    status: { tone: 'warning', text: 'Designed · cloud deployment not connected' },
    facts: [
      `${String(CLOUD_CONTROLS.length)} cloud-security controls, each designed`,
      `${String(configured)} configured and ${String(verified)} verified locally or in CI; none in the cloud yet`,
      `Evidence: ${coverage('CLD')}`,
    ],
  },
  {
    href: '/trust/governance',
    icon: 'governance',
    subject: 'ISMS',
    title: 'Governance & risk',
    question: 'How are information-security risks and controls managed?',
    status: { tone: 'info', text: 'Documented ISMS, learning-oriented, not certified' },
    facts: [
      `${String(risks.length)} risks rated, ${String(highResidual)} with a High residual rating`,
      `${String(isms.controls.length)} Annex A control entries and ${String(isms.clauses.length)} management clauses mapped`,
      `Evidence: ${coverage('ISMS')}`,
    ],
  },
];

const SUBJECT_ICON: Readonly<Record<SubjectTag, IconName>> = {
  CRY: 'key',
  CLD: 'cloud',
  ISMS: 'governance',
  APP: 'browser',
};

export default function TrustSummaryPage() {
  return (
    <div className="space-y-12">
      <PageHeader
        title="Security & Trust Center"
        description="How CipherMesh protects data, how it is designed to be deployed, and how its risks are managed. Every claim links to its mechanism, its verification, the evidence captured so far and its limits."
        actions={
          <Link className={buttonClass.primary} href="/trust/walkthrough">
            <Icon name="play" className="size-4" />
            Guided walkthrough
          </Link>
        }
      />

      <section aria-label="The three subjects" className="grid gap-4 lg:grid-cols-3">
        {PILLARS.map((pillar) => (
          <Link
            key={pillar.href}
            href={pillar.href}
            className="group flex flex-col gap-4 rounded-2xl border border-line bg-surface/90 p-6 transition-colors hover:border-accent-500/40"
          >
            <div className="flex items-start justify-between gap-3">
              <span className="grid size-11 place-items-center rounded-xl border border-accent-500/30 bg-accent-500/10 text-accent-300">
                <Icon name={pillar.icon} className="size-6" />
              </span>
              <Badge tone={pillar.status.tone}>{pillar.status.text}</Badge>
            </div>
            <div className="space-y-1">
              <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                {SUBJECT_LABEL[pillar.subject]}
              </p>
              <h2 className="text-lg font-semibold text-white group-hover:text-accent-100">{pillar.title}</h2>
              <p className="text-sm text-slate-400">{pillar.question}</p>
            </div>
            <ul className="mt-auto space-y-1.5 border-t border-slate-800 pt-4 text-sm text-slate-300">
              {pillar.facts.map((fact) => (
                <li key={fact} className="flex gap-2">
                  <Icon name="check" className="mt-0.5 size-4 text-accent-400" />
                  {fact}
                </li>
              ))}
            </ul>
          </Link>
        ))}
      </section>

      <section aria-labelledby="claims-heading" className="space-y-4">
        <div className="space-y-1.5">
          <h2 id="claims-heading" className="text-xl font-semibold tracking-tight text-white">
            Security claims and their proof
          </h2>
          <p className="max-w-3xl text-sm text-slate-400">
            Each claim is read left to right: what CipherMesh does, how, how it is verified, the evidence, and the limit
            that remains.
          </p>
        </div>
        <ul className="space-y-3">
          {CLAIMS.map((claim) => (
            <li key={claim.id} className="rounded-xl border border-line bg-surface/90 p-5" data-testid="trust-claim">
              <div className="flex flex-wrap items-start gap-3">
                <span className="grid size-9 place-items-center rounded-lg bg-slate-800/80 text-accent-300">
                  <Icon name={SUBJECT_ICON[claim.subject]} className="size-4" />
                </span>
                <div className="min-w-0 flex-1 space-y-1">
                  <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                    Claim · {SUBJECT_LABEL[claim.subject]}
                  </p>
                  <h3 className="font-semibold text-white">{claim.claim}</h3>
                </div>
              </div>
              <dl className="mt-4 grid gap-4 text-sm md:grid-cols-2 xl:grid-cols-4">
                <div className="space-y-1">
                  <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">Mechanism</dt>
                  <dd className="text-slate-300">{claim.mechanism}</dd>
                </div>
                <div className="space-y-1">
                  <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">Verification</dt>
                  <dd className="text-slate-300">{claim.verification}</dd>
                </div>
                <div className="space-y-1.5">
                  <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">Evidence</dt>
                  <dd>
                    <EvidenceChips ids={claim.evidence} />
                  </dd>
                </div>
                <div className="space-y-1.5">
                  <dt className="text-xs font-medium uppercase tracking-wide text-amber-300/80">Limitation</dt>
                  <dd className="space-y-1.5 text-slate-300">
                    <p>{claim.limitation}</p>
                    <p className="flex flex-wrap gap-1">
                      {claim.limitations.map((id) => (
                        <LimitationChip key={id} id={id} />
                      ))}
                    </p>
                  </dd>
                </div>
              </dl>
            </li>
          ))}
        </ul>
      </section>

      <section
        aria-labelledby="not-implemented-heading"
        className="space-y-4 rounded-2xl border border-amber-500/25 bg-amber-500/5 p-6"
      >
        <div className="flex items-center gap-2">
          <Icon name="alert" className="size-5 text-amber-300" />
          <h2 id="not-implemented-heading" className="text-lg font-semibold text-white">
            Not implemented or not connected
          </h2>
        </div>
        <ul className="grid gap-3 md:grid-cols-2">
          {NOT_IMPLEMENTED.map((item) => (
            <li key={item.name} className="space-y-1 rounded-lg border border-slate-800 bg-slate-950/50 p-4">
              <p className="flex items-center gap-2 font-medium text-white">
                <Badge tone="warning">Not implemented</Badge>
                {item.name}
              </p>
              <p className="text-sm text-slate-400">{item.text}</p>
            </li>
          ))}
        </ul>
      </section>

      <section className="grid gap-4 md:grid-cols-2">
        <Link
          href="/trust/evidence"
          className="flex items-start gap-4 rounded-xl border border-line bg-surface/90 p-5 hover:border-accent-500/40"
        >
          <Icon name="evidence" className="size-6 text-accent-300" />
          <span className="space-y-1">
            <span className="block font-semibold text-white">Evidence register</span>
            <span className="block text-sm text-slate-400">
              Every planned evidence item with its subject, status and committed files, including what is missing.
            </span>
          </span>
        </Link>
        <Link
          href="/trust/dashboard"
          className="flex items-start gap-4 rounded-xl border border-line bg-surface/90 p-5 hover:border-accent-500/40"
        >
          <Icon name="overview" className="size-6 text-accent-300" />
          <span className="space-y-1">
            <span className="block font-semibold text-white">Platform security dashboard</span>
            <span className="block text-sm text-slate-400">
              Aggregate metrics computed from the database, for platform administrators only.
            </span>
          </span>
        </Link>
      </section>
    </div>
  );
}
