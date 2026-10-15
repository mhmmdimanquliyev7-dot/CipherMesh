import { expect, test, type Locator, type Page } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { login, newUser, register, type TestUser } from '../e2e/helpers';
import { enrollMfa, totp } from '../e2e/room-helpers';
import { authSlots } from './pace';

// Screenshots of the operational ISMS in the running local Docker demonstration (EV-22-04 to
// EV-22-15, CM-T092). Runs on demand: CM_ISMS_EVIDENCE_DIR names the output directory. A synthetic
// platform administrator (granted with cm-platform-admin, as an operator would) walks the ISMS
// lifecycle, and EVERY record it creates is marked EXERCISE: a script is not the project owner, so
// it makes no real decision. The support it cites is real: committed evidence EV-05-02 (the BOLA
// suite, still current) and the output of a dependency audit run now. With
// CM_ISMS_AFTER_RESTART=1 the second test signs in again after a restart and shows the records.

const out = process.env['CM_ISMS_EVIDENCE_DIR'];
const root = fileURLToPath(new URL('../../', import.meta.url));
const ACCOUNT = (): string => join(out ?? '', 'account.json');
test.skip(out === undefined || out === '', 'evidence capture on demand (CM_ISMS_EVIDENCE_DIR)');
test.use({ viewport: { width: 1440, height: 900 }, actionTimeout: 30_000 });

/** Distinguishes this run's records from earlier runs' in lists (texts carry it). */
const RUN = new Date().toISOString().slice(11, 19).replace(/:/g, '');

// Scrolled to the top first, so the sticky header and sidebar sit where they belong.
const shot = async (page: Page, name: string): Promise<void> => {
  await page.evaluate(() => {
    window.scrollTo(0, 0);
  });
  await page.screenshot({ path: join(out ?? '', name), fullPage: true, animations: 'disabled', caret: 'initial' });
};

async function signInWithCode(page: Page, user: TestUser, secret: string): Promise<void> {
  await authSlots(2);
  await page.goto('/login');
  await page.getByLabel('Email address').fill(user.email);
  await page.getByLabel('Account password').fill(user.password);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Authentication code').fill(await totp(secret));
  await page.getByRole('button', { name: 'Verify' }).click();
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
}

async function confirm(page: Page, user: TestUser, secret: string, outcome: Locator, capture?: string): Promise<void> {
  const prompt = page.getByRole('heading', { name: 'Confirm your account' });
  await expect(prompt.or(outcome)).toBeVisible({ timeout: 20_000 });
  if (await prompt.isVisible()) {
    if (capture !== undefined) {
      await prompt.scrollIntoViewIfNeeded();
      await page.screenshot({ path: join(out ?? '', capture), animations: 'disabled', caret: 'initial' });
    }
    await authSlots(1);
    await page.getByLabel('Account password').fill(user.password);
    await page.getByLabel('Authentication code').fill(await totp(secret));
    await page.getByRole('button', { name: 'Confirm account' }).click();
  }
  await expect(outcome).toBeVisible({ timeout: 20_000 });
}

async function step(page: Page, code: string, button: string, fields: Record<string, string>, submit: string) {
  const panel = page.getByTestId(`transitions-${code}`);
  await panel.getByRole('button', { name: button }).click();
  const form = panel.locator('form');
  for (const [label, value] of Object.entries(fields)) {
    const field = form.getByLabel(label, { exact: true });
    if ((await field.evaluate((el) => el.tagName)) === 'SELECT') await field.selectOption(value);
    else await field.fill(value);
  }
  await form.getByRole('button', { name: submit }).click();
  // The form closes when the server has accepted the change. A decision may first ask for an
  // identity confirmation, which the caller answers, so it is not waited for here.
  if (!button.endsWith('(decision)')) await expect(form).toHaveCount(0);
}

async function codeOf(page: Page, prefix: string, text: string): Promise<string> {
  const item = page.locator(`[data-testid^="${prefix}"]`).filter({ hasText: text }).first();
  await expect(item).toBeVisible();
  return ((await item.getAttribute('data-testid')) ?? '').replace(/^[a-z]+-/, '');
}

test('capture the operational ISMS screenshots (exercise records)', async ({ page, browser }) => {
  test.skip(process.env['CM_ISMS_AFTER_RESTART'] === '1', 'the restart check runs alone');
  test.setTimeout(15 * 60_000);
  mkdirSync(out ?? '', { recursive: true });

  const admin = { ...newUser(), name: 'Security Officer (synthetic)' };
  await authSlots(1);
  await register(page, admin);
  await authSlots(1);
  await login(page, admin);
  await authSlots(3);
  const secret = await enrollMfa(page, admin);
  const granted = spawnSync(process.execPath, ['scripts/demo.mjs', 'admin', admin.email], {
    cwd: root,
    encoding: 'utf8',
  });
  expect(granted.status, granted.stderr).toBe(0);
  await signInWithCode(page, admin, secret);
  writeFileSync(ACCOUNT(), JSON.stringify({ ...admin, secret }), { mode: 0o600 });

  // Exercise records of earlier captures are withdrawn through the documented workflow, so only
  // this run's labelled set is active (withdrawn records stay in the history, out of the views
  // and metrics). Real records cannot be withdrawn: the API refuses it (EXERCISE_ONLY).
  await page.goto('/trust/isms?section=improvement');
  await expect(page.getByTestId('isms-activity').or(page.getByText('No activity yet.'))).toBeVisible();
  const unfinished = page
    .getByTestId('isms-improvement')
    .locator('li')
    .filter({ has: page.getByRole('button', { name: 'Withdraw this exercise record' }) });
  while ((await unfinished.count()) > 0) {
    const item = unfinished.first();
    await item.getByRole('button', { name: 'Withdraw this exercise record' }).click();
    await item
      .locator('form')
      .getByLabel('Reason for withdrawing this exercise')
      .fill('Superseded by a later evidence capture');
    await item.locator('form').getByRole('button', { name: 'Withdraw this exercise record' }).click();
    await expect(item.locator('form')).toHaveCount(0);
  }

  // EV-22-04 and EV-22-06: the foundation.
  await page.goto('/trust/isms');
  await expect(page.getByTestId('isms-overview')).toBeVisible();
  await shot(page, '01_isms-overview.png');
  await page.goto('/trust/isms?section=assets');
  await expect(page.getByTestId('isms-assets')).toBeVisible();
  await shot(page, '03_asset-inventory.png');

  // EV-22-05: a scope review (exercise).
  await page.goto('/trust/isms?section=context');
  await page.getByRole('button', { name: 'Record a scope review (decision)' }).click();
  const scope = page.getByTestId('form-scope-review');
  await scope.getByLabel('Next review date').fill('2027-01-15');
  await scope
    .getByLabel('Reason')
    .fill(`Demonstration ${RUN}: revision 2 matches the local Docker demonstration and the deferred Oracle VM`);
  await scope.getByLabel('This is a demonstration exercise').check();
  await scope.getByRole('button', { name: 'Record the scope review' }).click();
  await confirm(
    page,
    admin,
    secret,
    page.getByTestId('isms-context').getByText(RUN),
    '14_identity-confirmation-before-a-decision.png',
  );
  await shot(page, '02_scope-and-context.png');

  // EV-22-13: a policy decision (exercise).
  await page.goto('/trust/isms?section=policies&item=POL-08');
  const policy = page.getByTestId('form-policy-review');
  await policy.getByLabel('Next review date').fill('2027-01-15');
  await policy.getByLabel('Note').fill(`Demonstration ${RUN}: the testing plan names the ISMS suites`);
  await policy.getByLabel('This is a demonstration exercise').check();
  await policy.getByRole('button', { name: 'Record the policy decision' }).click();
  await confirm(page, admin, secret, page.getByTestId('policy-POL-08').getByText(RUN));
  await shot(page, '12_policy-register.png');

  // EV-22-07: T-06 re-assessed, treated with 8.3, the control verified with EV-05-02, residual decided.
  await page.goto('/trust/isms?section=risks&item=T-06');
  const detail = page.getByTestId('risk-detail-T-06');
  await detail.getByRole('button', { name: 'Record a re-assessment of T-06' }).click();
  const assess = page.getByTestId('form-risk-assessment');
  await assess.getByLabel('Vulnerability or exposure').fill('A new room route that skips the central authorization');
  await assess.getByLabel('Potential consequences').fill('Objects of another room read or changed');
  await assess.getByLabel('Likelihood').selectOption('High');
  await assess.getByLabel('Impact').selectOption('High');
  await assess.getByLabel('Assessment rationale').fill(`Demonstration ${RUN}: the register rating confirmed`);
  await assess.getByLabel('This is a demonstration exercise').check();
  await assess.getByRole('button', { name: 'Record the assessment' }).click();
  const ra = await codeOf(page, 'assessment-RA-', `Demonstration ${RUN}: the register rating confirmed`);
  await step(
    page,
    ra,
    'Plan the treatment',
    {
      'Linked controls (Statement of Applicability rows)': '8.3',
      'Implementation activity': 'Central room authorization and the BOLA and IDOR suite on every pull request',
    },
    'Plan the treatment',
  );
  await page.goto('/trust/isms?section=assurance&item=8.3');
  await page.getByTestId('control-detail-8.3').getByRole('button', { name: 'Record a verification of 8.3' }).click();
  const verify = page.getByTestId('form-verification');
  await verify
    .getByLabel('Verification procedure')
    .fill('BOLA and IDOR suite (tests/authz), committed result EV-05-02');
  await verify.getByLabel('Environment').selectOption('DEVELOPMENT');
  await verify
    .getByLabel('Limitations of this verification')
    .fill('Covers the room routes of the route inventory; demonstration record');
  await verify.getByLabel('This is a demonstration exercise').check();
  await verify.getByRole('button', { name: 'Record the verification' }).click();
  await expect(page.getByTestId('isms-assurance')).toContainText('Verified (current)');
  await page.goto('/trust/isms?section=risks&item=T-06');
  await step(
    page,
    ra,
    'Verify the treatment and reassess the residual risk',
    {
      'Residual likelihood': 'Low',
      'Residual impact': 'High',
      'Residual risk rationale': 'The control is verified; new routes are caught by the route inventory',
    },
    'Verify the treatment and reassess the residual risk',
  );
  await step(
    page,
    ra,
    'Accept the residual risk (decision)',
    { 'Decision note': 'Demonstration of the decision step' },
    'Accept the residual risk',
  );
  await confirm(page, admin, secret, page.getByTestId(`assessment-${ra}`).getByText('Residual accepted'));
  await shot(page, '04_risk-assessment-and-treatment.png');

  // EV-22-10 and EV-22-09: stale evidence of 8.8, a finding and its corrective action.
  await page.goto('/trust/isms?section=assurance&item=8.8');
  await expect(page.getByTestId('freshness-EV-01-07')).toContainText('stale');
  await page.getByTestId('control-detail-8.8').getByRole('button', { name: 'Raise a finding on 8.8' }).click();
  const raise = page.getByTestId('form-finding');
  await raise.getByLabel('This is a demonstration exercise').check();
  await raise.getByRole('button', { name: 'Raise the finding' }).click();
  const findingDetail = page.locator('[data-testid^="finding-detail-FND-"]');
  await expect(findingDetail).toBeVisible();
  const fnd = ((await findingDetail.getAttribute('data-testid')) ?? '').replace('finding-detail-', '');
  await step(
    page,
    fnd,
    'Record the root-cause analysis',
    {
      'Root cause':
        'The dependency audit runs in CI on every pull request, but its result was not captured as ISMS evidence within the 7-day rule',
    },
    'Record the root-cause analysis',
  );
  await step(
    page,
    fnd,
    'Plan the corrective action',
    {
      'Corrective action': 'Run pnpm audit:deps and record the verification of 8.8 with its output',
      'Due date': '2026-10-18',
    },
    'Plan the corrective action',
  );
  const audit = spawnSync('pnpm', ['audit:deps'], { cwd: root, encoding: 'utf8', shell: true });
  const output = `${audit.stdout}${audit.stderr}`.trim();
  expect(output).toContain('No known vulnerabilities found');
  await step(
    page,
    fnd,
    'Record the implementation',
    { 'Implementation note': 'pnpm audit:deps run on the workstation' },
    'Record the implementation',
  );
  await page.goto('/trust/isms?section=assurance&item=8.8');
  await page.getByTestId('control-detail-8.8').getByRole('button', { name: 'Record a verification of 8.8' }).click();
  await verify.getByLabel('Method').selectOption('LOCAL_VERIFICATION');
  await verify.getByLabel('Environment').selectOption('DEVELOPMENT');
  await verify.getByLabel('Verification procedure').fill(`pnpm audit:deps (pnpm audit --audit-level high), run ${RUN}`);
  await verify.getByLabel('Freshness class').selectOption('VULNERABILITY');
  await verify.getByLabel('Attached output label').fill('pnpm audit:deps output');
  await verify.getByLabel('Attached output (command output, at most 32 KiB)').fill(output);
  await verify
    .getByLabel('Limitations of this verification')
    .fill('Known advisories of the npm registry on this day only; demonstration record');
  await verify.getByLabel('This is a demonstration exercise').check();
  await verify.getByRole('button', { name: 'Record the verification' }).click();
  const cv = await codeOf(page, 'verification-CV-', `run ${RUN}`);
  await page
    .getByTestId(`verification-${cv}`)
    .getByRole('button', { name: /Show attached output/ })
    .click();
  await expect(page.getByTestId(`verification-${cv}`)).toContainText('No known vulnerabilities found');
  await shot(page, '06_control-verification-and-evidence.png');
  await page.goto(`/trust/isms?section=actions&item=${fnd}`);
  await step(page, fnd, 'Submit closure evidence', { 'Verification records (CV-xxx)': cv }, 'Submit closure evidence');
  await step(
    page,
    fnd,
    'Check effectiveness and decide closure (decision)',
    { Effectiveness: 'EFFECTIVE', 'Effectiveness note': '8.8 is verified with a current audit' },
    'Check effectiveness and decide closure',
  );
  await confirm(page, admin, secret, page.getByTestId(`finding-detail-${fnd}`).getByText(/self-verified/));
  await shot(page, '07_finding-and-corrective-action.png');

  // EV-22-11: a self-assessment with a genuine observation.
  await page.goto('/trust/isms?section=audits');
  await page.getByRole('button', { name: 'Plan an audit' }).click();
  const plan = page.getByTestId('form-audit');
  await plan.getByLabel('Audit title').fill(`Self-assessment of the Statement of Applicability (${RUN})`);
  await plan.getByLabel('Audit scope').fill('Clause 6.1.3 and the measurement of clause 9.1');
  await plan
    .getByLabel('Objective')
    .fill('Check that the SoA covers Annex A and that the metrics are computed from records');
  await plan.getByLabel('Criteria (clauses or controls, for example 8.8 or 9.1)').fill('6.1.3\n9.1');
  await plan.getByLabel('This is a demonstration exercise').check();
  await plan.getByRole('button', { name: 'Plan the audit' }).click();
  const aud = await codeOf(page, 'audit-AUD-', `Self-assessment of the Statement of Applicability (${RUN})`);
  await step(page, aud, 'Start the audit', {}, 'Start the audit');
  await step(
    page,
    aud,
    'Record a check',
    { Criterion: '9.1', Result: 'CONFORMITY', Observation: 'M-01 to M-07 are computed from the records on every view' },
    'Record a check',
  );
  await step(
    page,
    aud,
    'Record a check',
    {
      Criterion: '6.1.3',
      Result: 'OBSERVATION',
      Observation:
        '19 Annex A control numbers are covered by no Statement of Applicability row; they are shown as not assessed',
    },
    'Record a check',
  );
  await step(
    page,
    aud,
    'Complete the audit',
    { 'Audit conclusion': 'One observation; no nonconformity. A self-assessment, not independent.' },
    'Complete the audit',
  );
  await expect(page.getByTestId(`audit-${aud}`)).toContainText('Completed');
  await shot(page, '08_internal-audit-self-assessment.png');

  // EV-22-08: the Statement of Applicability with the computed assurance.
  await page.goto('/trust/isms?section=soa');
  await expect(page.getByTestId('soa-table')).toBeVisible();
  await shot(page, '05_statement-of-applicability.png');

  // EV-22-12: a management review (exercise) fed by the records.
  await page.goto('/trust/isms?section=review');
  await page.getByRole('button', { name: 'Prepare a management review' }).click();
  const review = page.getByTestId('form-management-review');
  await review.getByLabel('Review title').fill(`ISMS management review (demonstration ${RUN})`);
  await review.getByLabel('Participants actually present').fill('Security Officer (synthetic account, demonstration)');
  await review
    .getByLabel('Decisions (one per line)')
    .fill('Keep the 7-day freshness rule for vulnerability evidence\nAssess the 19 Annex A numbers that no row covers');
  await review.getByLabel('Follow-up actions').fill('Assess the uncovered Annex A numbers | ROLE-01 | 2026-11-15');
  await review.getByLabel('This is a demonstration exercise').check();
  await review.getByRole('button', { name: 'Create the draft with computed inputs' }).click();
  const mr = await codeOf(page, 'review-MR-', `ISMS management review (demonstration ${RUN})`);
  await page
    .getByTestId(`transitions-${mr}`)
    .getByRole('button', { name: 'Record the management review (decision)' })
    .click();
  await page
    .getByTestId(`transitions-${mr}`)
    .locator('form')
    .getByRole('button', { name: 'Record the management review' })
    .click();
  await confirm(page, admin, secret, page.getByTestId(`review-${mr}`).getByText('Recorded by'));
  await shot(page, '09_management-review.png');

  // EV-22-14: the activity history.
  await page.goto('/trust/isms?section=improvement');
  await expect(page.getByTestId('isms-activity')).toContainText(fnd);
  await shot(page, '10_activity-and-improvement.png');
  await page.goto('/trust/isms');
  await expect(page.getByTestId('isms-overview')).toBeVisible();
  await shot(page, '11_isms-overview-after-the-walkthrough.png');

  // EV-22-15: an account without the role gets nothing.
  const visitorContext = await browser.newContext({
    ignoreHTTPSErrors: test.info().project.use.ignoreHTTPSErrors ?? false,
    viewport: { width: 1440, height: 900 },
  });
  const visitor = await visitorContext.newPage();
  const user = { ...newUser(), name: 'Ordinary member (synthetic)' };
  await authSlots(1);
  await register(visitor, user);
  await authSlots(1);
  await login(visitor, user);
  await visitor.goto('/trust/isms');
  await expect(visitor.getByText('available to platform administrators with two-step sign-in only')).toBeVisible();
  await visitor.screenshot({
    path: join(out ?? '', '13_refused-to-a-non-administrator.png'),
    animations: 'disabled',
    caret: 'initial',
  });
  await visitorContext.close();
});

test('after a restart, the ISMS records are still there', async ({ page }) => {
  test.skip(process.env['CM_ISMS_AFTER_RESTART'] !== '1', 'runs after pnpm demo:down and pnpm demo:up');
  const account = JSON.parse(readFileSync(ACCOUNT(), 'utf8')) as TestUser & { secret: string };
  await signInWithCode(page, account, account.secret);
  await page.goto('/trust/isms?section=improvement');
  await expect(page.getByTestId('isms-activity')).toContainText('FND-');
  await shot(page, '15_records-after-restart.png');
});
