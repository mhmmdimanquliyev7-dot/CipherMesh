import { expect, test, type Locator, type Page } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { collectCspViolations, login, newUser, register, useDistinctClientAddress, type TestUser } from './helpers';
import { enrollMfa, totp } from './room-helpers';

// Operational ISMS (ADR-016, CM-T089): the full lifecycle in the ISMS Control Center, in three
// engines, through the real UI and API. A platform administrator (granted with the server-side CLI,
// as an operator would) re-assesses a real risk, plans a treatment, verifies a real control,
// accepts the residual risk with a step-up, raises a finding on a control whose evidence is stale,
// takes the corrective action to closure, records a management review and finds everything again
// after a reload. Records are marked EXERCISE. A non-administrator gets nothing. Each engine works
// on its own risk, so the engines can run in parallel against one database.

const root = fileURLToPath(new URL('../../', import.meta.url));

// A missing control fails fast instead of waiting for the whole test timeout.
test.use({ actionTimeout: 20_000 });

/** The code of the record whose list item carries a unique token (engines run in parallel). */
async function codeOf(page: Page, prefix: string, token: string): Promise<string> {
  const item = page.locator(`[data-testid^="${prefix}"]`).filter({ hasText: token });
  await expect(item).toHaveCount(1);
  return ((await item.getAttribute('data-testid')) ?? '').replace(/^[a-z]+-/, '');
}

const RISK_OF: Readonly<Record<string, { readonly risk: string; readonly control: string }>> = {
  chromium: { risk: 'T-06', control: '8.3' },
  firefox: { risk: 'T-05', control: '5.15' },
  webkit: { risk: 'T-08', control: '8.5' },
};

/**
 * Grants the platform administrator role with the server-side CLI, as an operator would (there is
 * no API for it). The CLI needs a full server configuration; this is the environment the E2E
 * server gives the API, built from the test process's own settings (the database and storage of
 * the job), so it works the same locally and in CI, where no .env file exists.
 */
function grantPlatformAdmin(email: string): void {
  // Locally the settings live in .env (the E2E server loads it itself); in CI they are exported.
  const envFile = join(root, '.env');
  if (process.env['DATABASE_URL'] === undefined && existsSync(envFile)) process.loadEnvFile(envFile);
  const required = ['DATABASE_URL', 'STORAGE_ENDPOINT', 'STORAGE_ACCESS_KEY_ID', 'STORAGE_SECRET_ACCESS_KEY'] as const;
  for (const name of required) expect(process.env[name], `${name} is needed to grant the role`).toBeTruthy();
  const result = spawnSync(
    process.execPath,
    ['--import', 'tsx', 'apps/api/src/cli/platform-admin.ts', 'grant', email],
    {
      cwd: root,
      encoding: 'utf8',
      env: {
        PATH: process.env['PATH'] ?? '',
        SystemRoot: process.env['SystemRoot'] ?? '',
        NODE_ENV: 'development',
        APP_ORIGIN: 'https://127.0.0.1:4173',
        API_HOST: '127.0.0.1',
        API_PORT: '4199',
        LOG_LEVEL: 'warn',
        DATABASE_URL: process.env['DATABASE_URL'] ?? '',
        TOTP_ENCRYPTION_KEY: randomBytes(32).toString('base64url'),
        TOTP_ENCRYPTION_KEY_ID: 'e2e',
        IDENTIFIER_HMAC_KEY: randomBytes(32).toString('base64url'),
        TRUST_PROXY_HOPS: '1',
        STORAGE_ENDPOINT: process.env['STORAGE_ENDPOINT'] ?? '',
        STORAGE_PUBLIC_ENDPOINT: 'https://localhost:4174',
        STORAGE_BUCKET: process.env['STORAGE_BUCKET'] ?? 'cm-files',
        STORAGE_REGION: process.env['STORAGE_REGION'] ?? 'us-east-1',
        STORAGE_ACCESS_KEY_ID: process.env['STORAGE_ACCESS_KEY_ID'] ?? '',
        STORAGE_SECRET_ACCESS_KEY: process.env['STORAGE_SECRET_ACCESS_KEY'] ?? '',
      },
    },
  );
  expect(result.status, result.stderr).toBe(0);
}

async function signInWithCode(page: Page, user: TestUser, secret: string): Promise<void> {
  await page.goto('/login');
  await page.getByLabel('Email address').fill(user.email);
  await page.getByLabel('Account password').fill(user.password);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Authentication code').fill(await totp(secret));
  await page.getByRole('button', { name: 'Verify' }).click();
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
}

/**
 * Decisions (PA-08) need a step-up within 15 minutes: waits for either the prompt or the outcome,
 * and answers the prompt with the account password and a fresh authentication code.
 */
async function confirmIfAsked(page: Page, user: TestUser, secret: string, outcome: Locator): Promise<void> {
  const prompt = page.getByRole('heading', { name: 'Confirm your account' });
  await expect(prompt.or(outcome)).toBeVisible({ timeout: 15_000 });
  if (await prompt.isVisible()) {
    await page.getByLabel('Account password').fill(user.password);
    await page.getByLabel('Authentication code').fill(await totp(secret));
    await page.getByRole('button', { name: 'Confirm account' }).click();
  }
  await expect(outcome).toBeVisible({ timeout: 15_000 });
}

async function transition(page: Page, code: string, button: string, fields: Record<string, string>, submit: string) {
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

test('the ISMS lifecycle: assess, treat, verify, accept, correct, review, and find it all again', async ({
  page,
  browserName,
}) => {
  test.setTimeout(8 * 60_000);
  const { risk, control } = RISK_OF[browserName] ?? { risk: 'T-06', control: '8.3' };
  const token = `${browserName}-${randomBytes(3).toString('hex')}`;
  const violations = await collectCspViolations(page);
  const admin = { ...newUser(), name: `ISMS Manager (synthetic ${browserName})` };
  await useDistinctClientAddress(page);
  await register(page, admin);
  await login(page, admin);
  const secret = await enrollMfa(page, admin);
  grantPlatformAdmin(admin.email);
  await signInWithCode(page, admin, secret);

  // Scenario A: the foundation.
  await page.goto('/trust/isms');
  await expect(page.getByRole('heading', { level: 1, name: 'ISMS Control Center' })).toBeVisible();
  await expect(page.getByTestId('isms-environment')).toContainText('Oracle Cloud: NOT DEPLOYED / NOT VERIFIED');
  await expect(page.getByTestId('isms-metrics')).toContainText('M-01');
  await page.getByRole('button', { name: /Scope & context/ }).click();
  await expect(page.getByTestId('isms-context')).toContainText('revision 2');
  await page.getByRole('button', { name: /Assets/ }).click();
  await expect(page.getByTestId('isms-assets')).toContainText('A-18');

  // Scenario B: a real risk, re-assessed and treated (exercise records).
  await page.goto(`/trust/isms?section=risks&item=${risk}`);
  const detail = page.getByTestId(`risk-detail-${risk}`);
  await expect(detail).toBeVisible();
  // A leftover open exercise assessment from an interrupted run is withdrawn first.
  const leftover = detail.getByRole('button', { name: 'Withdraw this exercise record' });
  if (
    await leftover
      .first()
      .isVisible()
      .catch(() => false)
  ) {
    await leftover.first().click();
    await detail.locator('form').getByLabel('Reason for withdrawing this exercise').fill('Interrupted earlier run');
    await detail.locator('form').getByRole('button', { name: 'Withdraw this exercise record' }).click();
  }
  await detail.getByRole('button', { name: `Record a re-assessment of ${risk}` }).click();
  const assess = page.getByTestId('form-risk-assessment');
  await assess.getByLabel('Vulnerability or exposure').fill('A route added without the central room authorization');
  await assess.getByLabel('Potential consequences').fill('Disclosure of room metadata to a non-member');
  await assess.getByLabel('Likelihood').selectOption('Medium');
  await assess.getByLabel('Impact').selectOption('High');
  await assess.getByLabel('Assessment rationale').fill(`E2E exercise of the documented method (${token})`);
  await assess.getByLabel('This is a demonstration exercise').check();
  await assess.getByRole('button', { name: 'Record the assessment' }).click();
  const raCode = await codeOf(page, 'assessment-RA-', token);
  const assessment = page.getByTestId(`assessment-${raCode}`);
  await transition(
    page,
    raCode,
    'Plan the treatment',
    {
      'Linked controls (Statement of Applicability rows)': control,
      'Implementation activity': 'Keep the control and its regression suite',
    },
    'Plan the treatment',
  );
  await expect(assessment).toContainText('Treatment planned');

  // Scenario C: the control is verified with real procedure output before the treatment counts.
  await page.goto(`/trust/isms?section=assurance&item=${encodeURIComponent(control)}`);
  const controlDetail = page.getByTestId(`control-detail-${control}`);
  await controlDetail.getByRole('button', { name: `Record a verification of ${control}` }).click();
  const verify = page.getByTestId('form-verification');
  await verify.getByLabel('Verification procedure').fill('pnpm test:authz and the route inventory suite');
  await verify.getByLabel('Attached output label').fill('Vitest summary');
  await verify
    .getByLabel('Attached output (command output, at most 32 KiB)')
    .fill('Test Files  9 passed (9)\nTests  412 passed (412)');
  await verify.getByLabel('Limitations of this verification').fill('E2E exercise; the output is a sample summary');
  await verify.getByLabel('This is a demonstration exercise').check();
  await verify.getByRole('button', { name: 'Record the verification' }).click();
  await expect(controlDetail).toContainText('Verification records');
  await expect(page.getByTestId('isms-assurance')).toContainText('Verified (current)');

  await page.goto(`/trust/isms?section=risks&item=${risk}`);
  await transition(
    page,
    raCode,
    'Verify the treatment and reassess the residual risk',
    { 'Residual likelihood': 'Low', 'Residual impact': 'High', 'Residual risk rationale': 'The control is verified' },
    'Verify the treatment and reassess the residual risk',
  );
  await expect(page.getByTestId(`assessment-${raCode}`)).toContainText('Treatment verified');
  await transition(
    page,
    raCode,
    'Accept the residual risk (decision)',
    { 'Decision note': 'Within the criteria' },
    'Accept the residual risk',
  );
  await confirmIfAsked(page, admin, secret, page.getByTestId(`assessment-${raCode}`).getByText('Residual accepted'));
  await expect(page.getByTestId(`assessment-${raCode}`)).toContainText(
    'project owner decision, no independent approver',
  );

  // Scenario D: stale evidence leads to a finding and a corrective action, closed with new evidence.
  await page.goto('/trust/isms?section=assurance&item=8.8');
  const vulnerability = page.getByTestId('control-detail-8.8');
  await expect(vulnerability.getByTestId('freshness-EV-01-07')).toContainText('stale');
  await vulnerability.getByRole('button', { name: 'Raise a finding on 8.8' }).click();
  const raise = page.getByTestId('form-finding');
  await raise.getByLabel('This is a demonstration exercise').check();
  await raise.getByRole('button', { name: 'Raise the finding' }).click();
  const finding = page.locator('[data-testid^="finding-detail-FND-"]');
  await expect(finding).toBeVisible();
  const fnd = ((await finding.getAttribute('data-testid')) ?? '').replace('finding-detail-', '');
  await transition(
    page,
    fnd,
    'Record the root-cause analysis',
    { 'Root cause': 'The audit result was not captured' },
    'Record the root-cause analysis',
  );
  await transition(
    page,
    fnd,
    'Plan the corrective action',
    { 'Corrective action': 'Run pnpm audit:deps and record the verification', 'Due date': '2099-12-31' },
    'Plan the corrective action',
  );
  await transition(
    page,
    fnd,
    'Record the implementation',
    { 'Implementation note': 'Audit run' },
    'Record the implementation',
  );
  await page.goto('/trust/isms?section=assurance&item=8.8');
  await vulnerability.getByRole('button', { name: 'Record a verification of 8.8' }).click();
  await verify.getByLabel('Verification procedure').fill(`pnpm audit:deps (${token})`);
  await verify.getByLabel('Freshness class').selectOption('VULNERABILITY');
  await verify.getByLabel('Attached output label').fill('Dependency audit');
  await verify.getByLabel('Attached output (command output, at most 32 KiB)').fill('No known vulnerabilities found');
  await verify.getByLabel('Limitations of this verification').fill('E2E exercise output');
  await verify.getByLabel('This is a demonstration exercise').check();
  await verify.getByRole('button', { name: 'Record the verification' }).click();
  const cvCode = await codeOf(page, 'verification-CV-', token);
  await page.goto(`/trust/isms?section=actions&item=${fnd}`);
  await transition(
    page,
    fnd,
    'Submit closure evidence',
    { 'Verification records (CV-xxx)': cvCode },
    'Submit closure evidence',
  );
  await transition(
    page,
    fnd,
    'Check effectiveness and decide closure (decision)',
    { Effectiveness: 'EFFECTIVE', 'Effectiveness note': '8.8 verified with a current audit' },
    'Check effectiveness and decide closure',
  );
  await confirmIfAsked(page, admin, secret, page.getByTestId(`finding-detail-${fnd}`).getByText(/self-verified/));
  await expect(page.getByTestId(`finding-detail-${fnd}`).getByLabel('Corrective action lifecycle')).toContainText(
    'Closed',
  );

  // Scenario E: a management review fed by the records.
  await page.goto('/trust/isms?section=review');
  await page.getByRole('button', { name: 'Prepare a management review' }).click();
  const review = page.getByTestId('form-management-review');
  await review.getByLabel('Review title').fill(`ISMS management review (${token})`);
  await review.getByLabel('Participants actually present').fill('Project owner (E2E exercise)');
  await review.getByLabel('Decisions (one per line)').fill('Keep the 7-day freshness rule for vulnerability evidence');
  await review.getByLabel('Follow-up actions').fill('Capture the dependency audit weekly | ROLE-01 | 2099-01-01');
  await review.getByLabel('This is a demonstration exercise').check();
  await review.getByRole('button', { name: 'Create the draft with computed inputs' }).click();
  const mrCode = await codeOf(page, 'review-MR-', token);
  const draft = page.getByTestId(`review-${mrCode}`);
  await expect(draft).toContainText('One-person project review');
  await page
    .getByTestId(`transitions-${mrCode}`)
    .getByRole('button', { name: 'Record the management review (decision)' })
    .click();
  await page
    .getByTestId(`transitions-${mrCode}`)
    .locator('form')
    .getByRole('button', { name: 'Record the management review' })
    .click();
  await confirmIfAsked(page, admin, secret, page.getByTestId(`review-${mrCode}`).getByText('Recorded by'));

  // Scenario F: everything is stored and linked; a reload finds it again.
  await page.reload();
  await expect(page.getByTestId(`review-${mrCode}`)).toContainText('Recorded');
  await page.goto(`/trust/isms?section=actions&item=${fnd}`);
  await expect(page.getByTestId(`finding-detail-${fnd}`)).toContainText('Closed');
  await page.goto('/trust/isms?section=improvement');
  await expect(page.getByTestId('isms-activity')).toContainText(fnd);
  await expect(page.getByTestId('isms-activity')).toContainText('effectiveness check');
  expect(await violations()).toEqual([]);
});

test('the ISMS Control Center refuses non-administrators, in the page and at the API', async ({ page }) => {
  await page.goto('/trust/isms');
  await expect(page.getByText('Sign in with a platform administrator account')).toBeVisible();
  const user = newUser();
  await useDistinctClientAddress(page);
  await register(page, user);
  await login(page, user);
  await page.goto('/trust/isms');
  await expect(page.getByText('available to platform administrators with two-step sign-in only')).toBeVisible();
  await expect(page.getByTestId('isms-control-center')).toHaveCount(0);
  const status = await page.evaluate(async () => {
    const response = await fetch('/api/isms/records', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-ciphermesh-request': '1' },
      // A valid body: the refusal must come from the administrator gate, not from validation.
      body: JSON.stringify({
        kind: 'FINDING',
        exercise: true,
        input: {
          source: { type: 'SELF_ASSESSMENT', ref: null },
          classification: 'OBSERVATION',
          criterion: '9.2',
          observation: 'A non-administrator tries to write',
          evidence: [],
          responsible: 'ROLE-01',
          relatedRisks: [],
          relatedControls: [],
        },
      }),
    });
    return response.status;
  });
  expect(status).toBe(404);
});
