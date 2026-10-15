import { describe, expect, it } from 'vitest';
import {
  annexNumbersOf,
  computeMetrics,
  controlAssurance,
  controlById,
  evidenceFreshness,
  ISMS_CATALOGUE,
  isOverdue,
  levelOf,
  notAssessedAnnexNumbers,
  policyState,
  ratingOf,
  riskMatrix,
  riskRating,
  riskView,
  scopeState,
  type IsmsRecord,
  type IsmsRecordOf,
} from './isms';
import {
  applyTransition,
  attachmentProblem,
  availableTransitions,
  createRecord,
  creationAuthority,
  transitionSpec,
  utf8Length,
  type WorkflowContext,
} from './isms-workflow';

// Operational ISMS logic (ADR-016) with a fixed clock, against the generated catalogue: the risk
// method of the threat model, the freshness rule, every assurance and lifecycle state, metrics and
// the workflow table. The API enforces exactly these functions (tests/isms covers it end to end).

const NOW = new Date('2026-10-15T12:00:00.000Z');
const ADMIN = { userId: '11111111-1111-4111-8111-111111111111', name: 'Security Officer' };

function record<K extends IsmsRecord['kind']>(
  kind: K,
  ref: string,
  status: string,
  data: IsmsRecordOf<K>['data'],
  overrides: Partial<IsmsRecordOf<K>> = {},
): IsmsRecord {
  return {
    id: '22222222-2222-4222-8222-222222222222',
    kind,
    code: `X-${ref}`,
    ref,
    status,
    data,
    version: 1,
    exercise: false,
    createdAt: NOW.toISOString(),
    createdBy: ADMIN,
    updatedAt: NOW.toISOString(),
    updatedBy: ADMIN,
    ...overrides,
  } as IsmsRecord;
}

const pass = (control: string, validUntil: string, result: 'PASS' | 'FAIL' = 'PASS', at = NOW.toISOString()) =>
  record(
    'CONTROL_VERIFICATION',
    control,
    'RECORDED',
    {
      method: 'AUTOMATED_TEST',
      procedure: 'suite',
      environment: 'CI',
      result,
      limitations: 'none',
      relatedRisks: [],
      evidence: [],
      ciRun: null,
      attachment: null,
      freshnessClass: 'TECHNICAL',
      verifiedAt: at,
      validUntil,
    },
    { code: `CV-${control}`, createdAt: at },
  );

const ctx = (records: readonly IsmsRecord[] = [], now = NOW): WorkflowContext => ({
  now,
  actor: ADMIN,
  records,
  catalogue: ISMS_CATALOGUE,
  people: new Map([[ADMIN.userId, ADMIN.name]]),
});

const control = (id: string) => {
  const found = controlById(id);
  if (found === undefined) throw new Error(id);
  return found;
};

describe('risk method (threat model section 1)', () => {
  it('rates likelihood and impact with the documented 3x3 matrix', () => {
    expect(riskRating('High', 'High')).toBe('Critical');
    expect(riskRating('High', 'Low')).toBe('Medium');
    expect(riskRating('Medium', 'High')).toBe('High');
    expect(riskRating('Low', 'Medium')).toBe('Low');
    expect(riskRating('Low', 'High')).toBe('Medium');
  });

  it('reads the register notation', () => {
    expect(levelOf('M')).toBe('Medium');
    expect(levelOf('H')).toBe('High');
    expect(levelOf('?')).toBeUndefined();
    expect(ratingOf('Low (for an attacker limited to the server)')).toBe('Low');
    expect(ratingOf('Medium (Level 1)')).toBe('Medium');
  });

  it('agrees with every documented inherent rating of the register', () => {
    for (const risk of ISMS_CATALOGUE.risks) {
      const view = riskView(risk, []);
      expect(view.source).toBe('REGISTER');
      expect(riskRating(view.likelihood, view.impact), risk.id).toBe(view.inherent);
    }
    const matrix = riskMatrix(ISMS_CATALOGUE.risks.map((r) => riskView(r, [])));
    const total = Object.values(matrix).reduce((sum, row) => sum + row.Low + row.Medium + row.High, 0);
    expect(total).toBe(ISMS_CATALOGUE.risks.length);
  });

  it('uses a dated re-assessment as the current view', () => {
    const risk = ISMS_CATALOGUE.risks.find((r) => r.id === 'T-06');
    if (risk === undefined) throw new Error('T-06');
    const assessed = record('RISK_ASSESSMENT', 'T-06', 'ASSESSED', {
      assets: ['A-01'],
      threat: 't',
      vulnerability: 'v',
      consequences: 'c',
      owner: 'ROLE-01',
      likelihood: 'Medium',
      impact: 'High',
      inherent: 'High',
      rationale: 'r',
    });
    const view = riskView(risk, [assessed]);
    expect(view).toMatchObject({ source: 'RECORD', inherent: 'High', residualSource: 'REGISTER', status: 'ASSESSED' });
  });
});

describe('evidence freshness (section 7)', () => {
  it('applies the class validity from the capture date', () => {
    expect(evidenceFreshness('EV-01-07', NOW)).toMatchObject({
      state: 'STALE',
      freshnessClass: 'VULNERABILITY',
      captured: '2026-10-02',
      expires: '2026-10-09T23:59:59.999Z',
    });
    expect(evidenceFreshness('EV-01-07', new Date('2026-10-05T00:00:00Z')).state).toBe('CURRENT');
    expect(evidenceFreshness('EV-99-99', NOW).state).toBe('UNKNOWN');
    const planned = ISMS_CATALOGUE.evidence.find((e) => e.status === 'planned');
    expect(evidenceFreshness(planned?.id ?? '', NOW).state).toBe('NOT_CAPTURED');
  });

  it('dates every captured item, so nothing captured is undated', () => {
    const undated = ISMS_CATALOGUE.evidence.filter(
      (e) => (e.status === 'captured' || e.status === 'partial') && e.captured === null,
    );
    expect(undated.map((e) => e.id)).toEqual([]);
  });
});

describe('Statement of Applicability and control assurance (sections 7 and 8)', () => {
  it('expands ranges and lists the Annex A numbers that no row covers', () => {
    expect(annexNumbersOf('5.19 to 5.22')).toEqual(['5.19', '5.20', '5.21', '5.22']);
    expect(annexNumbersOf('8.5')).toEqual(['8.5']);
    const notAssessed = notAssessedAnnexNumbers();
    expect(notAssessed).toContain('5.4');
    expect(notAssessed).not.toContain('8.8');
  });

  it('computes every assurance state', () => {
    expect(controlAssurance(control('8.8'), [], NOW).state).toBe('EVIDENCE_STALE');
    expect(controlAssurance(control('6.1 to 6.8'), [], NOW).state).toBe('NOT_APPLICABLE');
    expect(controlAssurance(control('7.1 to 7.14'), [], NOW).state).toBe('PROVIDER');
    expect(controlAssurance(control('8.31'), [], NOW).state).toBe('NO_EVIDENCE');
    const later = '2026-11-01T00:00:00.000Z';
    expect(controlAssurance(control('8.8'), [pass('8.8', later)], NOW).state).toBe('VERIFIED');
    expect(controlAssurance(control('8.8'), [pass('8.8', later)], new Date('2026-11-02T00:00:00Z')).state).toBe(
      'VERIFICATION_DUE',
    );
    expect(controlAssurance(control('8.8'), [pass('8.8', later, 'FAIL')], NOW).state).toBe('FAILED');
    // A withdrawn verification does not count.
    const withdrawn = { ...pass('8.8', later), status: 'WITHDRAWN' } as IsmsRecord;
    expect(controlAssurance(control('8.8'), [withdrawn], NOW).state).toBe('EVIDENCE_STALE');
    expect(controlAssurance(control('8.8'), [], NOW).risks).toEqual(expect.arrayContaining(['T-19', 'T-27']));
  });
});

describe('policies, scope and findings', () => {
  const policy = ISMS_CATALOGUE.policies.find((p) => p.id === 'POL-03');
  if (policy === undefined) throw new Error('POL-03');
  const review = (decision: string, fingerprint = policy.fingerprint, nextReviewDate = '2026-12-31') =>
    record('POLICY_REVIEW', 'POL-03', 'RECORDED', {
      documentFingerprint: fingerprint,
      decision: decision as 'ADOPTED',
      effectiveFrom: '2026-10-15',
      nextReviewDate,
      note: 'n',
    });

  it('derives the policy lifecycle from reviews and the document fingerprint', () => {
    expect(policyState(policy, [], NOW).state).toBe('DOCUMENTED');
    expect(policyState(policy, [review('ADOPTED')], NOW).state).toBe('EFFECTIVE');
    expect(policyState(policy, [review('ADOPTED', 'other')], NOW).state).toBe('CHANGED_SINCE_APPROVAL');
    expect(policyState(policy, [review('ADOPTED', policy.fingerprint, '2026-10-14')], NOW).state).toBe('REVIEW_DUE');
    expect(policyState(policy, [review('CHANGES_REQUIRED')], NOW).state).toBe('UNDER_REVISION');
    expect(policyState(policy, [review('RETIRED')], NOW).state).toBe('RETIRED');
  });

  it('derives the scope state', () => {
    const scope = (fingerprint: string, decision: 'CONFIRMED' | 'CHANGES_REQUIRED', next = '2027-01-01') =>
      record('SCOPE_REVIEW', 'scope-r2', 'RECORDED', {
        scopeRevision: 2,
        scopeFingerprint: fingerprint,
        decision,
        reason: 'r',
        nextReviewDate: next,
      });
    const current = ISMS_CATALOGUE.scope.fingerprint;
    expect(scopeState([], NOW).state).toBe('NOT_REVIEWED');
    expect(scopeState([scope(current, 'CONFIRMED')], NOW).state).toBe('CONFIRMED');
    expect(scopeState([scope('old', 'CONFIRMED')], NOW).state).toBe('CHANGED_SINCE_REVIEW');
    expect(scopeState([scope(current, 'CHANGES_REQUIRED')], NOW).state).toBe('CHANGES_REQUIRED');
    expect(scopeState([scope(current, 'CONFIRMED', '2026-10-01')], NOW).state).toBe('REVIEW_DUE');
  });

  it('marks a finding overdue only past its due date and before effectiveness', () => {
    const finding = (status: string, dueDate: string) =>
      record('FINDING', '8.8', status, {
        source: { type: 'EVIDENCE_FRESHNESS', ref: '8.8' },
        classification: 'OBSERVATION',
        criterion: '8.8',
        observation: 'o',
        evidence: [],
        responsible: 'ROLE-01',
        relatedRisks: [],
        relatedControls: ['8.8'],
        action: { description: 'a', owner: 'ROLE-01', dueDate, plannedAt: NOW.toISOString(), by: ADMIN },
        effectivenessChecks: [],
      }) as IsmsRecordOf<'FINDING'>;
    expect(isOverdue(finding('ACTION_PLANNED', '2026-10-14'), NOW)).toBe(true);
    expect(isOverdue(finding('ACTION_PLANNED', '2026-10-15'), NOW)).toBe(false);
    expect(isOverdue(finding('AWAITING_EFFECTIVENESS', '2026-10-14'), NOW)).toBe(false);
    const metrics = computeMetrics([finding('ACTION_PLANNED', '2026-10-14')], NOW);
    expect(metrics.find((m) => m.id === 'M-03')?.value).toBe(1);
    expect(metrics.find((m) => m.id === 'M-07')?.display).toBe('No management review recorded');
    expect(metrics.find((m) => m.id === 'M-02')).toMatchObject({
      numerator: 0,
      denominator: ISMS_CATALOGUE.risks.length,
    });
  });
});

describe('workflow (sections 6 to 13)', () => {
  it('refuses secret material and oversized attachments', () => {
    expect(attachmentProblem('Tests 12 passed')).toBeUndefined();
    expect(attachmentProblem('-----BEGIN EC PRIVATE KEY-----')).toBe('SECRET_MATERIAL');
    expect(attachmentProblem('Cookie: __Host-cm_session=abc')).toBe('SECRET_MATERIAL');
    expect(attachmentProblem('https://files.localhost:8443/x?X-Amz-Signature=abc')).toBe('SECRET_MATERIAL');
    expect(attachmentProblem('x'.repeat(32 * 1024 + 1))).toBe('TOO_LARGE');
    expect(utf8Length('é€😀')).toBe(2 + 3 + 4);
  });

  it('declares which transitions are decisions', () => {
    expect(transitionSpec('RISK_ASSESSMENT', 'accept_residual')?.authority).toBe('decide');
    expect(transitionSpec('FINDING', 'effectiveness_check')?.authority).toBe('decide');
    expect(transitionSpec('FINDING', 'analyze')?.authority).toBe('record');
    expect(transitionSpec('AUDIT', 'accept_residual')).toBeUndefined();
    expect(creationAuthority('POLICY_REVIEW')).toBe('decide');
    expect(creationAuthority('FINDING')).toBe('record');
  });

  it('offers withdrawal for exercises only and nothing after a final status', () => {
    const real = pass('8.8', '2026-11-01T00:00:00.000Z');
    expect(availableTransitions(real).map((t) => t.name)).toEqual([]);
    expect(availableTransitions({ ...real, exercise: true }).map((t) => t.name)).toEqual(['withdraw']);
    const refused = applyTransition(real, 'withdraw', { reason: 'x' }, ctx());
    expect(refused).toMatchObject({ ok: false, conditions: ['EXERCISE_ONLY'] });
  });

  it('accepts no Critical residual and needs a limitation for High', () => {
    const verified = (risk: string, rating: 'Critical' | 'High') =>
      record('RISK_ASSESSMENT', risk, 'TREATMENT_VERIFIED', {
        assets: [],
        threat: 't',
        vulnerability: 'v',
        consequences: 'c',
        owner: 'ROLE-01',
        likelihood: 'High',
        impact: 'High',
        inherent: 'Critical',
        rationale: 'r',
        residual: {
          likelihood: 'High',
          impact: rating === 'Critical' ? 'High' : 'Medium',
          rating,
          rationale: 'r',
          verifications: [],
          verifiedAt: NOW.toISOString(),
          verifiedBy: ADMIN,
        },
      });
    expect(applyTransition(verified('T-06', 'Critical'), 'accept_residual', { note: 'n' }, ctx())).toMatchObject({
      ok: false,
      conditions: ['CRITICAL_NOT_ACCEPTABLE'],
    });
    // T-14 has no limitation in the register; T-23 names L-01.
    expect(applyTransition(verified('T-14', 'High'), 'accept_residual', { note: 'n' }, ctx())).toMatchObject({
      ok: false,
      conditions: ['LIMITATION_REQUIRED'],
    });
    expect(applyTransition(verified('T-23', 'High'), 'accept_residual', { note: 'n' }, ctx())).toMatchObject({
      ok: true,
      status: 'RESIDUAL_ACCEPTED',
    });
  });

  it('computes a verification validity no later than its cited evidence', () => {
    const current = ISMS_CATALOGUE.evidence.find((e) => e.id === 'EV-17-09');
    expect(current?.captured).toBe('2026-10-15');
    const result = createRecord(
      'CONTROL_VERIFICATION',
      '8.22',
      {
        method: 'LOCAL_VERIFICATION',
        procedure: 'pnpm demo:verify',
        environment: 'LOCAL_DOCKER',
        result: 'PASS',
        limitations: 'Local Docker, not the cloud',
        relatedRisks: ['T-42'],
        evidence: ['EV-17-09'],
        ciRun: null,
        attachment: null,
        freshnessClass: 'DESIGN',
      },
      ctx(),
    );
    expect(result).toMatchObject({ ok: true, status: 'RECORDED' });
    // DESIGN would allow 180 days; the cited TECHNICAL evidence expires after 30.
    if (result.ok) expect(result.data.validUntil).toBe('2026-11-14T23:59:59.999Z');
  });
});
