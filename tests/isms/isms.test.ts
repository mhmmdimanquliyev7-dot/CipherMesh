import { computeMetrics, ISMS_CATALOGUE, type IsmsRecord } from '@ciphermesh/shared';
import {
  ismsRecordDetailResponseSchema,
  ismsStateResponseSchema,
  ismsWriteResponseSchema,
  type IsmsStateResponse,
} from '@ciphermesh/validation';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import type { Database } from '../../apps/api/src/db/client';
import { Browser, startAuthApi, type AuthTestApi } from '../helpers/auth';
import { sqlState, testDatabase } from '../helpers/database';
import { apiDatabase, errorOf, person, platformAdministrator, stepUp, type Person } from '../helpers/rooms';

// Operational ISMS (ADR-016, CM-T088; docs/security/isms-operations.md). Every workflow through
// the real HTTP API, with real accounts: the platform administrator gate (404 for others), the
// step-up of decisions, the documented conditions of each transition, optimistic concurrency,
// malformed input, attachments with secret material, and the database guards as the runtime role.
// This project has its own freshly migrated database and runs one file at a time.

let api: AuthTestApi;
let db: pg.Client;
let database: Database;
let admin: Person & { readonly secret: string };
let other: Person;

const STALE_EVIDENCE = 'EV-01-07'; // dependency audit, 7-day class, captured 2026-10-02 (always stale from now on)
const VULNERABILITY_ATTACHMENT = 'pnpm audit --audit-level high\nNo known vulnerabilities found\n';

type Body = Record<string, unknown>;

async function post(who: Person, path: string, body: Body, status = 200) {
  const response = await who.browser.request('POST', path, body);
  expect(response.status, JSON.stringify(response.body)).toBe(status);
  return response;
}

async function create(who: Person, body: Body) {
  return ismsWriteResponseSchema.parse((await post(who, '/isms/records', body, 201)).body);
}

async function transition(who: Person, id: string, version: number, name: string, input: Body = {}) {
  return ismsWriteResponseSchema.parse(
    (await post(who, `/isms/records/${id}/transitions`, { transition: name, expectedVersion: version, input })).body,
  );
}

async function decide(who: Person & { secret?: string }, id: string, version: number, name: string, input: Body = {}) {
  await stepUp(api, who, (who as { secret?: string }).secret);
  return ismsWriteResponseSchema.parse(
    (await post(who, `/isms/records/${id}/decisions`, { transition: name, expectedVersion: version, input })).body,
  );
}

async function state(who: Person): Promise<IsmsStateResponse> {
  const response = await who.browser.request('GET', '/isms/state');
  expect(response.status).toBe(200);
  return ismsStateResponseSchema.parse(response.body);
}

const verification = (control: string, extra: Body = {}): Body => ({
  kind: 'CONTROL_VERIFICATION',
  ref: control,
  exercise: false,
  input: {
    method: 'AUTOMATED_TEST',
    procedure: 'pnpm test:authz (the BOLA and IDOR suite)',
    environment: 'DEVELOPMENT',
    result: 'PASS',
    limitations: 'Covers the routes in the route inventory only',
    relatedRisks: ['T-06'],
    evidence: [],
    ciRun: null,
    attachment: { label: 'Test output', text: ' Test Files  1 passed (1)\n      Tests  42 passed (42)\n' },
    freshnessClass: 'TECHNICAL',
    ...extra,
  },
});

const conditionOf = (response: { body: Record<string, unknown> }): string[] =>
  (((response.body['error'] as { issues?: { code: string }[] } | undefined)?.issues ?? []) as { code: string }[]).map(
    (i) => i.code,
  );

beforeAll(async () => {
  api = await startAuthApi();
  db = await testDatabase(inject('databaseName')).connect('api');
  database = apiDatabase();
  admin = await platformAdministrator(api, database);
  other = await person(api);
});
afterAll(async () => {
  await db.end();
  await database.close();
  await api.close();
});

describe('authorization (PA-06 to PA-08)', () => {
  const routes: readonly [string, string, Body | undefined][] = [
    ['GET', '/isms/state', undefined],
    ['GET', '/isms/records/2f1b1c4e-8a7d-4c9e-9b1a-1d2e3f4a5b6c', undefined],
    ['POST', '/isms/records', verification('8.3')],
    [
      'POST',
      '/isms/records/2f1b1c4e-8a7d-4c9e-9b1a-1d2e3f4a5b6c/transitions',
      { transition: 'start', expectedVersion: 1, input: {} },
    ],
    [
      'POST',
      '/isms/decisions',
      {
        kind: 'SCOPE_REVIEW',
        exercise: false,
        input: { decision: 'CONFIRMED', reason: 'x', nextReviewDate: '2027-01-01' },
      },
    ],
    [
      'POST',
      '/isms/records/2f1b1c4e-8a7d-4c9e-9b1a-1d2e3f4a5b6c/decisions',
      { transition: 'record_review', expectedVersion: 1, input: {} },
    ],
  ];

  it('answers the generic 404 to an account that is not a platform administrator, and 401 without a session', async () => {
    for (const [method, path, body] of routes) {
      const response = await other.browser.request(method as 'GET' | 'POST', path, body);
      expect(response.status, `${method} ${path}`).toBe(404);
      expect(errorOf(response).code).toBe('NOT_FOUND');
      const anonymous = await new Browser(api).request(method as 'GET' | 'POST', path, body);
      expect(anonymous.status, `${method} ${path}`).toBe(401);
    }
    // Nothing was written by the refused requests.
    expect((await state(admin)).records).toEqual([]);
  });

  it('requires a fresh step-up for every decision route', async () => {
    api.clock.advance(16 * 60_000); // past the 15-minute step-up window
    const response = await admin.browser.request('POST', '/isms/decisions', {
      kind: 'SCOPE_REVIEW',
      exercise: false,
      input: { decision: 'CONFIRMED', reason: 'Reviewed', nextReviewDate: '2099-01-01' },
    });
    expect(response.status).toBe(401);
    expect(errorOf(response).code).toBe('STEP_UP_REQUIRED');
  });

  it('refuses unknown fields, a status field, malformed identifiers and unknown references', async () => {
    const extra = await admin.browser.request('POST', '/isms/records', { ...verification('8.3'), status: 'VERIFIED' });
    expect(extra.status).toBe(400);
    const badId = await admin.browser.request('GET', '/isms/records/not-a-uuid');
    expect(badId.status).toBe(404);
    const unknownControl = await admin.browser.request('POST', '/isms/records', verification('8.99'));
    expect(unknownControl.status).toBe(400);
    expect(errorOf(unknownControl).code).toBe('ISMS_REFERENCE_UNKNOWN');
    const unknownRisk = await admin.browser.request(
      'POST',
      '/isms/records',
      verification('8.3', { relatedRisks: ['T-99'] }),
    );
    expect(conditionOf(unknownRisk)).toContain('RISK_UNKNOWN');
  });
});

describe('control verification and evidence freshness (section 7)', () => {
  it('records a PASS with an attached output, stores its digest, and lists it without the text', async () => {
    const created = await create(admin, verification('8.3'));
    expect(created.record.code).toBe('CV-001');
    const attachment = created.record.data['attachment'] as Record<string, unknown>;
    expect(attachment['sha256']).toMatch(/^[0-9a-f]{64}$/);
    expect(attachment['text']).toBeUndefined();
    const listed = (await state(admin)).records.find((r) => r.code === 'CV-001');
    expect((listed?.data['attachment'] as Record<string, unknown>)['text']).toBeUndefined();
    const detail = ismsRecordDetailResponseSchema.parse(
      (await admin.browser.request('GET', `/isms/records/${created.record.id}`)).body,
    );
    expect((detail.record.data['attachment'] as Record<string, unknown>)['text']).toContain('42 passed');
    expect(detail.history.map((h) => h.action)).toEqual(['create']);
    // The history keeps the digest, never the attached text.
    expect(JSON.stringify(detail.history[0]?.snapshot)).not.toContain('42 passed');
  });

  it('refuses a PASS that cites stale evidence, and a PASS without any support', async () => {
    const stale = await admin.browser.request(
      'POST',
      '/isms/records',
      verification('8.8', { evidence: [STALE_EVIDENCE], attachment: null, freshnessClass: 'VULNERABILITY' }),
    );
    expect(stale.status).toBe(409);
    expect(conditionOf(stale)).toEqual(['EVIDENCE_NOT_CURRENT']);
    const unsupported = await admin.browser.request('POST', '/isms/records', verification('8.8', { attachment: null }));
    expect(conditionOf(unsupported)).toEqual(['SUPPORT_REQUIRED']);
  });

  it('refuses attached output that contains secret material, without echoing it', async () => {
    for (const secret of [
      'AGE-SECRET-KEY-1QQQQ',
      'postgresql://cm_api:hunter2hunter2@db/ciphermesh',
      'password = hunter2hunter2',
    ]) {
      const response = await admin.browser.request(
        'POST',
        '/isms/records',
        verification('8.8', { attachment: { label: 'Output', text: `ok\n${secret}\n` } }),
      );
      expect(response.status).toBe(400);
      expect(errorOf(response).code).toBe('ISMS_ATTACHMENT_REJECTED');
      expect(JSON.stringify(response.body)).not.toContain('hunter2');
      expect(JSON.stringify(response.body)).not.toContain('AGE-SECRET-KEY');
    }
  });

  it('refuses a verification of an excluded control and a link that is not a CI run of this repository', async () => {
    const excluded = await admin.browser.request('POST', '/isms/records', verification('6.1 to 6.8'));
    expect(conditionOf(excluded)).toEqual(['CONTROL_NOT_APPLICABLE']);
    const link = await admin.browser.request(
      'POST',
      '/isms/records',
      verification('8.8', { ciRun: 'https://evil.example/actions/runs/1' }),
    );
    expect(conditionOf(link)).toEqual(['CI_RUN_INVALID']);
  });
});

describe('risk assessment and treatment (section 6)', () => {
  it('runs the treatment workflow with its conditions, and the acceptance only with a step-up', async () => {
    const assessed = await create(admin, {
      kind: 'RISK_ASSESSMENT',
      ref: 'T-05',
      exercise: false,
      input: {
        assets: ['A-01', 'A-02'],
        threat: 'An authenticated non-member tries to read a room',
        vulnerability: 'A route that forgets the membership check',
        consequences: 'Disclosure of ciphertext metadata and room membership',
        owner: 'ROLE-01',
        likelihood: 'Medium',
        impact: 'High',
        rationale: 'Re-assessed after the authorization suite was extended',
      },
    });
    expect(assessed.record.status).toBe('ASSESSED');
    expect(assessed.record.data['inherent']).toBe('High');
    // A second open assessment of the same risk is refused; the inherent rating is computed, never sent.
    const { inherent: _inherent, ...input } = assessed.record.data;
    expect(_inherent).toBe('High');
    const duplicate = await admin.browser.request('POST', '/isms/records', {
      kind: 'RISK_ASSESSMENT',
      ref: 'T-05',
      exercise: false,
      input,
    });
    expect(duplicate.status).toBe(409);
    expect(conditionOf(duplicate)).toEqual(['ASSESSMENT_OPEN']);
    const sentRating = await admin.browser.request('POST', '/isms/records', {
      kind: 'RISK_ASSESSMENT',
      ref: 'T-07',
      exercise: false,
      input: assessed.record.data,
    });
    expect(sentRating.status).toBe(400);
    const id = assessed.record.id;
    const noControls = await admin.browser.request('POST', `/isms/records/${id}/transitions`, {
      transition: 'plan_treatment',
      expectedVersion: 1,
      input: {
        option: 'MITIGATE',
        responsible: 'ROLE-02',
        controls: [],
        activity: 'x',
        targetDate: null,
        requiredEvidence: [],
      },
    });
    expect(conditionOf(noControls)).toEqual(['CONTROLS_REQUIRED']);
    const planned = await transition(admin, id, 1, 'plan_treatment', {
      option: 'MITIGATE',
      responsible: 'ROLE-02',
      controls: ['5.15'],
      activity: 'Central room authorization on every room route; BOLA suite in CI',
      targetDate: null,
      requiredEvidence: [],
    });
    expect(planned.record.status).toBe('TREATMENT_PLANNED');
    // 5.15 has no verification record yet: the treatment cannot be verified.
    const early = await admin.browser.request('POST', `/isms/records/${id}/transitions`, {
      transition: 'verify_treatment',
      expectedVersion: 2,
      input: { likelihood: 'Low', impact: 'High', rationale: 'x' },
    });
    expect(conditionOf(early)).toEqual(['CONTROL_NOT_VERIFIED']);
    await create(admin, verification('5.15'));
    const above = await admin.browser.request('POST', `/isms/records/${id}/transitions`, {
      transition: 'verify_treatment',
      expectedVersion: 2,
      input: { likelihood: 'High', impact: 'High', rationale: 'x' },
    });
    expect(conditionOf(above)).toEqual(['RESIDUAL_ABOVE_INHERENT']);
    const verified = await transition(admin, id, 2, 'verify_treatment', {
      likelihood: 'Low',
      impact: 'High',
      rationale: 'The suite proves 404 for non-members on every room route',
    });
    expect(verified.record.status).toBe('TREATMENT_VERIFIED');
    expect((verified.record.data['residual'] as Record<string, unknown>)['rating']).toBe('Medium');
    // A decision cannot be sent through the record route.
    const wrongRoute = await admin.browser.request('POST', `/isms/records/${id}/transitions`, {
      transition: 'accept_residual',
      expectedVersion: 3,
      input: { note: 'x' },
    });
    expect(wrongRoute.status).toBe(400);
    const accepted = await decide(admin, id, 3, 'accept_residual', { note: 'Residual Medium is within the criteria' });
    expect(accepted.record.status).toBe('RESIDUAL_ACCEPTED');
    expect((accepted.record.data['acceptance'] as { by: { userId: string } }).by.userId).toBe(admin.userId);
    // A final record does not change; a new assessment of the risk is now possible.
    const again = await admin.browser.request('POST', `/isms/records/${id}/transitions`, {
      transition: 'plan_treatment',
      expectedVersion: 4,
      input: {
        option: 'ACCEPT',
        responsible: 'ROLE-01',
        controls: [],
        activity: 'x',
        targetDate: null,
        requiredEvidence: [],
      },
    });
    expect(again.status).toBe(409);
    expect(errorOf(again).code).toBe('ISMS_TRANSITION_NOT_ALLOWED');
  });

  it('refuses a stale version (optimistic concurrency) and records every change in the history', async () => {
    const assessed = await create(admin, {
      kind: 'RISK_ASSESSMENT',
      ref: 'T-13',
      exercise: false,
      input: {
        assets: ['A-06'],
        threat: 'Cross-site request forgery',
        vulnerability: 'A state-changing route without the same-origin gate',
        consequences: 'Actions in a victim session',
        owner: 'ROLE-01',
        likelihood: 'Medium',
        impact: 'Medium',
        rationale: 'Baseline confirmed',
      },
    });
    const id = assessed.record.id;
    await transition(admin, id, 1, 'plan_treatment', {
      option: 'MITIGATE',
      responsible: 'ROLE-02',
      controls: ['8.26'],
      activity: 'Same-origin verification on every state-changing request (INV-19)',
      targetDate: null,
      requiredEvidence: [],
    });
    const stale = await admin.browser.request('POST', `/isms/records/${id}/transitions`, {
      transition: 'plan_treatment',
      expectedVersion: 1,
      input: {
        option: 'MITIGATE',
        responsible: 'ROLE-02',
        controls: ['8.26'],
        activity: 'y',
        targetDate: null,
        requiredEvidence: [],
      },
    });
    expect(stale.status).toBe(409);
    expect(errorOf(stale).code).toBe('ISMS_VERSION_CONFLICT');
    const detail = ismsRecordDetailResponseSchema.parse(
      (await admin.browser.request('GET', `/isms/records/${id}`)).body,
    );
    expect(detail.history.map((h) => [h.action, h.fromStatus, h.toStatus])).toEqual([
      ['create', null, 'ASSESSED'],
      ['plan_treatment', 'ASSESSED', 'TREATMENT_PLANNED'],
    ]);
    expect(detail.history.every((h) => h.actor.userId === admin.userId)).toBe(true);
  });
});

describe('internal audit, findings and corrective action (sections 9 and 10)', () => {
  it('refuses an "internal audit" by its own planner', async () => {
    const response = await admin.browser.request('POST', '/isms/records', {
      kind: 'AUDIT',
      exercise: true,
      input: {
        title: 'Access control audit',
        scope: 'Room authorization',
        objective: 'Check 5.15 and 8.3',
        criteria: ['5.15'],
        scheduledFor: '2026-10-16',
        independence: 'INTERNAL_AUDIT',
        auditorUserId: admin.userId,
      },
    });
    expect(conditionOf(response)).toEqual(['INDEPENDENCE_NOT_MET']);
  });

  it('turns a nonconformity into a finding, and closes it only with eligible evidence and a verified control', async () => {
    const audit = await create(admin, {
      kind: 'AUDIT',
      exercise: true,
      input: {
        title: 'Self-assessment of vulnerability management',
        scope: 'Control 8.8 and its evidence',
        objective: 'Check that vulnerability evidence is current',
        criteria: ['8.8', '9.1'],
        scheduledFor: '2026-10-16',
        independence: 'SELF_ASSESSMENT',
        auditorUserId: admin.userId,
      },
    });
    const auditId = audit.record.id;
    await transition(admin, auditId, 1, 'start');
    const outOfScope = await admin.browser.request('POST', `/isms/records/${auditId}/transitions`, {
      transition: 'record_check',
      expectedVersion: 2,
      input: { criterion: '5.15', result: 'CONFORMITY', note: 'x', evidence: [] },
    });
    expect(conditionOf(outOfScope)).toEqual(['CRITERION_NOT_IN_SCOPE']);
    const conformity = await transition(admin, auditId, 2, 'record_check', {
      criterion: '9.1',
      result: 'CONFORMITY',
      note: 'Metrics are computed from records',
      evidence: [],
    });
    expect(conformity.created).toEqual([]);
    const check = await transition(admin, auditId, 3, 'record_check', {
      criterion: '8.8',
      result: 'MINOR_NONCONFORMITY',
      note: 'The dependency audit evidence is past its 7-day freshness',
      evidence: [STALE_EVIDENCE],
    });
    expect(check.created).toHaveLength(1);
    const findingCode = check.created[0] ?? '';
    const checks = check.record.data['checks'] as { finding: string | null }[];
    expect(checks[1]?.finding).toBe(findingCode);
    const completed = await transition(admin, auditId, 4, 'complete', { conclusion: 'One minor nonconformity' });
    expect(completed.record.status).toBe('COMPLETED');

    const finding = (await state(admin)).records.find((r) => r.code === findingCode);
    expect(finding?.status).toBe('OPEN');
    expect(finding?.exercise).toBe(true);
    const id = finding?.id ?? '';
    await transition(admin, id, 1, 'analyze', {
      rootCause: 'The audit runs in CI, but its result was not captured as ISMS evidence',
      correction: '',
    });
    const past = await admin.browser.request('POST', `/isms/records/${id}/transitions`, {
      transition: 'plan_action',
      expectedVersion: 2,
      input: { description: 'x', owner: 'ROLE-01', dueDate: '2020-01-01' },
    });
    expect(conditionOf(past)).toEqual(['DATE_IN_PAST']);
    // A verification recorded before the plan cannot close the action.
    const before = await create(
      admin,
      verification('8.8', {
        procedure: 'pnpm audit:deps',
        attachment: { label: 'Audit', text: VULNERABILITY_ATTACHMENT },
        freshnessClass: 'VULNERABILITY',
      }),
    );
    api.clock.advance(1000);
    await transition(admin, id, 2, 'plan_action', {
      description: 'Run pnpm audit:deps and record the verification',
      owner: 'ROLE-01',
      dueDate: '2099-12-31',
    });
    await transition(admin, id, 3, 'implement_action', { note: 'Audit run on the workstation' });
    const ineligible = await admin.browser.request('POST', `/isms/records/${id}/transitions`, {
      transition: 'submit_closure_evidence',
      expectedVersion: 4,
      input: { verifications: [before.record.code], evidence: [] },
    });
    expect(conditionOf(ineligible)).toEqual(['VERIFICATION_NOT_ELIGIBLE']);
    api.clock.advance(1000);
    const after = await create(
      admin,
      verification('8.8', {
        procedure: 'pnpm audit:deps',
        attachment: { label: 'Audit', text: VULNERABILITY_ATTACHMENT },
        freshnessClass: 'VULNERABILITY',
      }),
    );
    await transition(admin, id, 4, 'submit_closure_evidence', { verifications: [after.record.code], evidence: [] });
    const notEffective = await decide(admin, id, 5, 'effectiveness_check', {
      result: 'NOT_EFFECTIVE',
      note: 'Re-check later',
    });
    expect(notEffective.record.status).toBe('ACTION_PLANNED');
    await transition(admin, id, 6, 'implement_action', { note: 'Audit capture added to the checklist' });
    await transition(admin, id, 7, 'submit_closure_evidence', { verifications: [after.record.code], evidence: [] });
    const closed = await decide(admin, id, 8, 'effectiveness_check', {
      result: 'EFFECTIVE',
      note: '8.8 verified with a current audit',
    });
    expect(closed.record.status).toBe('CLOSED');
    const checksDone = closed.record.data['effectivenessChecks'] as { independentOfImplementer: boolean }[];
    // The same person implemented and checked: recorded as self-verification, never as independent.
    expect(checksDone.map((c) => c.independentOfImplementer)).toEqual([false, false]);
  });

  it('withdraws exercises only, and keeps their history', async () => {
    const real = await create(admin, {
      kind: 'FINDING',
      exercise: false,
      input: {
        source: { type: 'SELF_ASSESSMENT', ref: null },
        classification: 'OBSERVATION',
        criterion: '5.9',
        observation: 'The asset inventory had no operational assets before revision A-14 to A-18',
        evidence: [],
        responsible: 'ROLE-01',
        relatedRisks: [],
        relatedControls: ['5.9'],
      },
    });
    const refused = await admin.browser.request('POST', `/isms/records/${real.record.id}/transitions`, {
      transition: 'withdraw',
      expectedVersion: 1,
      input: { reason: 'cleanup' },
    });
    expect(conditionOf(refused)).toEqual(['EXERCISE_ONLY']);
    const exercise = await create(admin, {
      kind: 'INCIDENT',
      exercise: true,
      input: {
        title: 'Tabletop: lost operator laptop',
        detection: 'Exercise scenario',
        classification: 'SECURITY_EVENT',
        impact: 'None: exercise',
        owner: 'ROLE-03',
        relatedRisks: ['T-43'],
        relatedControls: ['8.13'],
      },
    });
    const withdrawn = await transition(admin, exercise.record.id, 1, 'withdraw', { reason: 'Exercise finished' });
    expect(withdrawn.record.status).toBe('WITHDRAWN');
    // Audit findings come only from audit checks, so each names its audit and check.
    const manualAudit = await admin.browser.request('POST', '/isms/records', {
      kind: 'FINDING',
      exercise: true,
      input: {
        source: { type: 'AUDIT', ref: null },
        classification: 'OBSERVATION',
        criterion: '9.2',
        observation: 'x',
        evidence: [],
        responsible: 'ROLE-01',
        relatedRisks: [],
        relatedControls: [],
      },
    });
    expect(conditionOf(manualAudit)).toEqual(['AUDIT_FINDINGS_FROM_CHECKS']);
  });
});

describe('management review, scope and policy decisions (section 11)', () => {
  it('computes the inputs, records the review with a step-up and tracks its actions as findings', async () => {
    const draft = await create(admin, {
      kind: 'MANAGEMENT_REVIEW',
      exercise: false,
      input: {
        title: 'Project review',
        reviewDate: new Date(api.clock.now()).toISOString().slice(0, 10),
        format: 'ONE_PERSON_PROJECT_REVIEW',
        participants: [],
        inputNotes: '',
        decisions: [],
        actions: [],
      },
    });
    const inputs = draft.record.data['inputs'] as { metrics: { id: string }[]; openFindings: unknown[] };
    expect(inputs.metrics.map((m) => m.id)).toEqual(['M-01', 'M-02', 'M-03', 'M-04', 'M-05', 'M-06', 'M-07']);
    const empty = await (async () => {
      await stepUp(api, admin, admin.secret);
      return admin.browser.request('POST', `/isms/records/${draft.record.id}/decisions`, {
        transition: 'record_review',
        expectedVersion: 1,
        input: {},
      });
    })();
    expect(conditionOf(empty)).toEqual(['PARTICIPANTS_REQUIRED', 'DECISIONS_REQUIRED']);
    await transition(admin, draft.record.id, 1, 'update_draft', {
      participants: ['Project owner'],
      inputNotes: 'Inputs as computed',
      decisions: ['Keep the 7-day freshness rule for vulnerability evidence'],
      actions: [{ description: 'Capture the dependency audit every week', owner: 'ROLE-01', dueDate: '2099-01-01' }],
    });
    const recorded = await decide(admin, draft.record.id, 2, 'record_review');
    expect(recorded.record.status).toBe('RECORDED');
    expect(recorded.created).toHaveLength(1);
    const actions = recorded.record.data['actions'] as { finding: string }[];
    expect(actions[0]?.finding).toBe(recorded.created[0]);
  });

  it('records scope and policy decisions with the reviewed fingerprint', async () => {
    await stepUp(api, admin, admin.secret);
    const scope = ismsWriteResponseSchema.parse(
      (
        await post(
          admin,
          '/isms/decisions',
          {
            kind: 'SCOPE_REVIEW',
            exercise: false,
            input: {
              decision: 'CONFIRMED',
              reason: 'Scope revision 2 matches the system',
              nextReviewDate: '2099-01-01',
            },
          },
          201,
        )
      ).body,
    );
    expect(scope.record.data['scopeFingerprint']).toBe(ISMS_CATALOGUE.scope.fingerprint);
    const policy = ismsWriteResponseSchema.parse(
      (
        await post(
          admin,
          '/isms/decisions',
          {
            kind: 'POLICY_REVIEW',
            ref: 'POL-03',
            exercise: false,
            input: { decision: 'ADOPTED', effectiveFrom: '2026-10-15', nextReviewDate: '2099-01-01', note: 'Adopted' },
          },
          201,
        )
      ).body,
    );
    expect(policy.record.data['documentFingerprint']).toBe(
      ISMS_CATALOGUE.policies.find((p) => p.id === 'POL-03')?.fingerprint,
    );
    // A decision cannot be created through the record route.
    const viaRecord = await admin.browser.request('POST', '/isms/records', {
      kind: 'POLICY_REVIEW',
      ref: 'POL-03',
      exercise: false,
      input: { decision: 'ADOPTED', effectiveFrom: '2026-10-15', nextReviewDate: '2099-01-01', note: 'x' },
    });
    expect(viaRecord.status).toBe(400);
  });

  it('computes the metrics from the stored records', async () => {
    const records = (await state(admin)).records as unknown as IsmsRecord[];
    const metrics = computeMetrics(records, api.clock.now());
    const m06 = metrics.find((m) => m.id === 'M-06');
    expect(m06?.numerator).toBe(1); // POL-03 adopted
    const m07 = metrics.find((m) => m.id === 'M-07');
    expect(m07?.value).toBe(0);
  });
});

describe('database guards as the runtime role', () => {
  it('refuses to change or delete the activity history, delete records, or skip a version', async () => {
    const { rows } = await db.query<{ id: string; version: number }>(`SELECT id, version FROM isms_records LIMIT 1`);
    const row = rows[0];
    expect(row).toBeDefined();
    expect(await sqlState(db.query(`UPDATE isms_activity SET rationale = 'rewritten'`))).not.toBe('none');
    expect(await sqlState(db.query(`DELETE FROM isms_activity`))).not.toBe('none');
    expect(await sqlState(db.query(`DELETE FROM isms_records`))).not.toBe('none');
    expect(await sqlState(db.query(`UPDATE isms_records SET status = status WHERE id = $1`, [row?.id]))).not.toBe(
      'none',
    );
    expect(
      await sqlState(
        db.query(`UPDATE isms_records SET created_by_id = $2, version = version + 1 WHERE id = $1`, [
          row?.id,
          other.userId,
        ]),
      ),
    ).not.toBe('none');
    const closed = await db.query<{ id: string }>(`SELECT id FROM isms_records WHERE status = 'CLOSED' LIMIT 1`);
    expect(
      await sqlState(
        db.query(`UPDATE isms_records SET status = 'OPEN', version = version + 1 WHERE id = $1`, [closed.rows[0]?.id]),
      ),
    ).not.toBe('none');
    expect(
      await sqlState(
        db.query(`UPDATE isms_records SET status = 'VERIFIED', version = version + 1 WHERE id = $1`, [row?.id]),
      ),
    ).not.toBe('none');
  });
});
