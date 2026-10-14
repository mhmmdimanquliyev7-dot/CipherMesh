import type { Metadata } from 'next';
import { Icon } from '../../../components/icons';
import { Badge, PageHeader } from '../../../components/ui';
import { isms, limitations, risks } from '../../../trust/data';
import { GOVERNANCE_GAPS, POLICIES } from '../../../trust/governance';
import { ControlRegister, RiskRegister } from '../../../trust/registers';
import { DocumentLink, SectionHeading } from '../../../trust/ui';

export const metadata: Metadata = { title: 'Governance & risk' };

/**
 * Governance & Risk (Phase 14 + Prompt 16.5, CM-T061): the ISMS as the project documents it.
 * Scope, clauses, Annex A controls, risks and limitations are generated from the documents; the
 * page adds no approval, role, audit result or certification that the documents do not state.
 */

const LEVELS = ['H', 'M', 'L'] as const;
const IMPACTS = ['L', 'M', 'H'] as const;
const LEVEL_NAME = { L: 'Low', M: 'Medium', H: 'High' } as const;
// ISO/IEC 27005-style matrix from the threat model, section 1.
const RATING: Readonly<Record<string, string>> = {
  HL: 'Medium',
  HM: 'High',
  HH: 'Critical',
  ML: 'Low',
  MM: 'Medium',
  MH: 'High',
  LL: 'Low',
  LM: 'Low',
  LH: 'Medium',
};
const CELL_TONE: Readonly<Record<string, string>> = {
  Low: 'bg-emerald-500/10 border-emerald-500/25',
  Medium: 'bg-amber-500/10 border-amber-500/25',
  High: 'bg-rose-500/10 border-rose-500/25',
  Critical: 'bg-rose-500/20 border-rose-500/40',
};

export default function GovernancePage() {
  const accepted = risks.filter((r) => r.treatment.includes('Accept'));
  const highResidual = risks.filter((r) => /^(High|Critical)/.test(r.residual));
  return (
    <div className="space-y-14">
      <PageHeader
        eyebrow="Information security management"
        title="Governance & risk"
        description="How the project manages information-security risk: its scope, the management-system clauses, the risk register, the ISO/IEC 27001:2022 Annex A controls it applies, its limitations and its evidence. A learning-oriented mapping in the style of a Statement of Applicability, not a certified ISMS."
      />

      <section className="grid gap-4 lg:grid-cols-[1.4fr_1fr]">
        <div className="space-y-3 rounded-2xl border border-line bg-surface/90 p-6">
          <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-slate-400">
            <Icon name="governance" className="size-4 text-accent-300" />
            ISMS scope
          </p>
          <p className="text-sm leading-relaxed text-slate-300">{isms.scope}</p>
          <p className="text-xs text-slate-500">
            Source: <DocumentLink path="docs/security/isms-control-mapping.md">isms-control-mapping.md</DocumentLink>
          </p>
        </div>
        <div className="grid grid-cols-2 gap-3">
          {(
            [
              ['Risks rated', String(risks.length)],
              ['Residual High', String(highResidual.length)],
              ['Accept decisions', String(accepted.length)],
              ['Annex A entries', String(isms.controls.length)],
            ] as const
          ).map(([label, value]) => (
            <div key={label} className="space-y-1 rounded-xl border border-line bg-surface/90 p-4">
              <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
              <p className="tabular text-2xl font-semibold text-white">{value}</p>
            </div>
          ))}
          <p className="col-span-2 text-xs text-slate-500">
            Residual High risks and every Accept decision need the project owner&apos;s acknowledgement before the final
            report (threat model, section 5).
          </p>
        </div>
      </section>

      <section className="space-y-5">
        <SectionHeading id="clauses" eyebrow="Management system" title="ISO/IEC 27001:2022 clauses">
          How each clause is met by a project document or practice.
        </SectionHeading>
        <div className="overflow-x-auto rounded-xl border border-line">
          <table className="w-full min-w-[40rem] text-left text-sm">
            <caption className="sr-only">Management-system clauses</caption>
            <thead className="bg-slate-900/80 text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Clause
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  Requirement
                </th>
                <th scope="col" className="px-4 py-2.5 font-medium">
                  CipherMesh implementation
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {isms.clauses.map((clause) => (
                <tr key={clause.clause}>
                  <th scope="row" className="px-4 py-2.5 font-mono text-xs text-accent-300">
                    {clause.clause}
                  </th>
                  <td className="px-4 py-2.5 text-white">{clause.requirement}</td>
                  <td className="px-4 py-2.5 text-slate-300">{clause.implementation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-5">
        <SectionHeading id="risks" eyebrow="Risk management" title="Risk register">
          Qualitative ratings (likelihood and impact Low, Medium or High) with treatment and residual risk, from the
          threat model. Open a risk for its scenario, controls, testing strategy and limitations.
        </SectionHeading>
        <div className="grid gap-6 xl:grid-cols-[18rem_1fr]">
          <figure className="space-y-2" aria-label="Inherent risk matrix">
            <div className="grid grid-cols-[auto_repeat(3,1fr)] gap-1.5 text-center text-xs">
              <span />
              {IMPACTS.map((impact) => (
                <span key={impact} className="pb-1 text-slate-500">
                  {LEVEL_NAME[impact]}
                </span>
              ))}
              {LEVELS.map((likelihood) => (
                <div key={likelihood} className="contents">
                  <span className="flex items-center pr-1 text-slate-500">{LEVEL_NAME[likelihood]}</span>
                  {IMPACTS.map((impact) => {
                    const rating = RATING[`${likelihood}${impact}`] ?? 'Low';
                    const count = risks.filter((r) => r.likelihood === likelihood && r.impact === impact).length;
                    return (
                      <span
                        key={impact}
                        className={`grid aspect-square place-items-center rounded-lg border ${CELL_TONE[rating] ?? ''}`}
                        title={`Likelihood ${LEVEL_NAME[likelihood]}, impact ${LEVEL_NAME[impact]}: ${rating}`}
                      >
                        <span className="tabular text-lg font-semibold text-white">{count}</span>
                        <span className="sr-only">
                          risks with likelihood {LEVEL_NAME[likelihood]} and impact {LEVEL_NAME[impact]} ({rating})
                        </span>
                      </span>
                    );
                  })}
                </div>
              ))}
            </div>
            <figcaption className="text-xs text-slate-500">
              Number of risks per likelihood (rows) and impact (columns), before treatment. Colours repeat the rating of
              the threat model&apos;s matrix.
            </figcaption>
          </figure>
          <RiskRegister />
        </div>
      </section>

      <section className="space-y-5">
        <SectionHeading id="controls" eyebrow="Annex A" title="Control register">
          Applicability and status as the mapping documents them. “Implemented by design” means designed in Phase 0 and
          built in the listed phase; the evidence column shows how much of the cited evidence is captured.
        </SectionHeading>
        <p className="max-w-3xl text-xs text-slate-500">{isms.statusLegend}</p>
        <ControlRegister />
      </section>

      <section className="space-y-5">
        <SectionHeading id="limitations" eyebrow="Accepted limits" title="Limitations register">
          Limits of the security model, documented rather than hidden. Many are accepted risks of the register.
        </SectionHeading>
        <ul className="grid gap-2 lg:grid-cols-2" aria-label="Limitations">
          {limitations.map((item) => (
            <li key={item.id}>
              <details id={item.id} className="group scroll-mt-24 rounded-lg border border-line bg-surface/80">
                <summary className="flex items-start gap-3 px-3 py-2.5 text-sm hover:bg-slate-800/30">
                  <span className="font-mono text-xs text-amber-300">{item.id}</span>
                  <span className="flex-1 text-slate-200">{item.limitation}</span>
                  <Icon name="chevronRight" className="disclosure-chevron mt-0.5 size-3.5 text-slate-500" />
                </summary>
                <dl className="space-y-2 border-t border-slate-800 px-3 py-3 text-xs">
                  <div>
                    <dt className="font-medium uppercase tracking-wide text-slate-500">Why it exists</dt>
                    <dd className="text-slate-300">{item.why}</dd>
                  </div>
                  <div>
                    <dt className="font-medium uppercase tracking-wide text-slate-500">What CipherMesh does</dt>
                    <dd className="text-slate-300">{item.response}</dd>
                  </div>
                  {item.demonstration === '' ? null : (
                    <div>
                      <dt className="font-medium uppercase tracking-wide text-slate-500">How to demonstrate it</dt>
                      <dd className="text-slate-300">{item.demonstration}</dd>
                    </div>
                  )}
                </dl>
              </details>
            </li>
          ))}
        </ul>
      </section>

      <section className="grid gap-8 xl:grid-cols-[1.5fr_1fr]">
        <div className="space-y-5">
          <SectionHeading id="policies" eyebrow="Policies" title="Governing documents">
            The documents that set the rules, as they exist in the repository.
          </SectionHeading>
          <ul className="grid gap-2 md:grid-cols-2">
            {POLICIES.map((policy) => (
              <li key={policy.path} className="space-y-1.5 rounded-xl border border-line bg-surface/80 p-4">
                <p className="flex items-center gap-2 text-xs uppercase tracking-wide text-slate-500">
                  <Icon name={policy.icon} className="size-3.5 text-accent-300" />
                  {policy.area}
                </p>
                <p className="text-sm font-medium text-white">
                  <DocumentLink path={policy.path}>{policy.title}</DocumentLink>
                </p>
                <p className="text-xs text-slate-400">{policy.governs}</p>
              </li>
            ))}
          </ul>
        </div>
        <div className="space-y-5">
          <SectionHeading id="gaps" eyebrow="Improvement" title="Known gaps">
            Documentation the final ISMS workstream still has to add.
          </SectionHeading>
          <ul className="space-y-2">
            {GOVERNANCE_GAPS.map((gap) => (
              <li
                key={gap}
                className="flex gap-2 rounded-lg border border-amber-500/25 bg-amber-500/5 p-3 text-sm text-slate-300"
              >
                <Badge tone="warning">Open</Badge>
                {gap}
              </li>
            ))}
          </ul>
        </div>
      </section>
    </div>
  );
}
