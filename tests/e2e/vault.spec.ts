import { expect, firefox, test, webkit, type Page } from '@playwright/test';
import { createHash } from 'node:crypto';
import {
  captureRequests,
  collectCspViolations,
  login,
  newUser,
  newVaultPassphrase,
  readableStorage,
  register,
  useDistinctClientAddress,
  type TestUser,
} from './helpers';

// Vault in the browser (Phase 4, CM-T025 to CM-T028) in Chromium, Firefox and WebKit, against the
// built static export under the production CSP and the real API:
// - the Vault Passphrase, the derived keys and the private keys never leave the browser;
// - nothing secret is persisted in cookies, localStorage, sessionStorage, IndexedDB or Cache Storage;
// - the Argon2id worker and its WebAssembly run under the CSP with no violation;
// - lock, unlock, auto-lock, logout and session loss behave as designed (CP-22);
// - a vault created in one engine opens in the others with the same fingerprint.

const PASSPHRASE_FIELD = 'Vault Passphrase (not your account password)';
// PKCS#8 private keys always contain these OIDs (rsaEncryption, id-ecPublicKey).
const PKCS8_MARKERS = ['2a864886f70d010101', '2a8648ce3d0201'];

/** Every encoding a passphrase could take in a request: as is, URL-encoded, base64, base64url, hex. */
const encodingsOf = (secret: string): string[] => {
  const bytes = Buffer.from(secret, 'utf8');
  return [
    secret,
    encodeURIComponent(secret),
    bytes.toString('base64'),
    bytes.toString('base64url'),
    bytes.toString('hex'),
  ];
};

async function stepUp(page: Page, user: TestUser): Promise<void> {
  await expect(page.getByRole('heading', { name: 'Confirm your account' })).toBeVisible();
  await page.getByLabel('Account password').fill(user.password);
  await page.getByRole('button', { name: 'Confirm account' }).click();
}

/** Registers, signs in and creates a vault through the UI; returns the user, passphrase and setup body. */
async function userWithVault(page: Page) {
  const user = newUser();
  const passphrase = newVaultPassphrase();
  await useDistinctClientAddress(page);
  await register(page, user);
  await login(page, user);
  await page.getByRole('link', { name: 'Vault', exact: true }).click();
  await stepUp(page, user);
  await page.getByLabel(PASSPHRASE_FIELD).fill(passphrase);
  await page.getByLabel('Repeat the Vault Passphrase').fill(passphrase);
  await page.getByLabel('I understand that CipherMesh cannot recover a lost Vault Passphrase.').check();
  const posted = page.waitForRequest((r) => r.url().endsWith('/api/vault') && r.method() === 'POST');
  await page.getByRole('button', { name: 'Create vault' }).click();
  const setupBody = JSON.parse((await posted).postData() ?? '{}') as {
    identity: { encryptionPublicKey: string; signingPublicKey: string; fingerprint: string };
    wrappedEncryptionKey: { ciphertext: string };
    wrappedSigningKey: { ciphertext: string };
  };
  await expect(page.getByRole('heading', { name: 'Vault unlocked' })).toBeVisible({ timeout: 60_000 });
  return { user, passphrase, setupBody };
}

async function unlock(page: Page, passphrase: string): Promise<void> {
  await page.getByLabel(PASSPHRASE_FIELD).fill(passphrase);
  await page.getByRole('button', { name: 'Unlock', exact: true }).click();
}

const lockNow = (page: Page) => page.getByRole('main').getByRole('button', { name: 'Lock now' }).click();
const shownFingerprint = async (page: Page): Promise<string> =>
  (await page.getByTestId('own-fingerprint').innerText()).replace(/\s+/g, '');

test('setup, lock, unlock and passphrase change keep every secret in the browser', async ({ page }) => {
  test.setTimeout(180_000);
  const violations = await collectCspViolations(page);
  const requests = captureRequests(page);
  const { user, passphrase, setupBody } = await userWithVault(page);

  // The upload holds public keys, KDF metadata and ciphertext only (DF-03, EV-04-01).
  expect(Object.keys(setupBody).sort()).toEqual(
    ['identity', 'kdf', 'vaultVersion', 'wrappedEncryptionKey', 'wrappedSigningKey'].sort(),
  );
  for (const wrapped of [setupBody.wrappedEncryptionKey, setupBody.wrappedSigningKey]) {
    const hex = Buffer.from(wrapped.ciphertext, 'base64url').toString('hex');
    for (const marker of PKCS8_MARKERS) expect(hex).not.toContain(marker);
  }

  // The fingerprint on screen equals one computed here, independently, from the uploaded public keys.
  const statement =
    `{"ctx":"cm.identity.fingerprint","encryptionKeySpki":"${setupBody.identity.encryptionPublicKey}",` +
    `"signingKeySpki":"${setupBody.identity.signingPublicKey}","suite":"CM1","v":1}`;
  const expectedFingerprint = createHash('sha256').update(statement, 'utf8').digest('hex');
  expect(setupBody.identity.fingerprint).toBe(expectedFingerprint);
  expect(await shownFingerprint(page)).toBe(expectedFingerprint);

  // Lock, a wrong passphrase (generic failure), the right passphrase.
  await lockNow(page);
  await expect(page.getByRole('heading', { name: 'Unlock your vault' })).toBeVisible();
  await unlock(page, `${passphrase}!`);
  await expect(page.getByText('The vault could not be opened.')).toBeVisible({ timeout: 60_000 });
  await unlock(page, passphrase);
  await expect(page.getByRole('heading', { name: 'Vault unlocked' })).toBeVisible({ timeout: 60_000 });

  // Passphrase change: same fingerprint, new passphrase works, old one no longer does.
  const next = newVaultPassphrase();
  await page.getByLabel('Current Vault Passphrase', { exact: true }).fill(passphrase);
  await page.getByLabel('New Vault Passphrase', { exact: true }).fill(next);
  await page.getByLabel('Repeat the new Vault Passphrase', { exact: true }).fill(next);
  await page.getByRole('button', { name: 'Change Vault Passphrase' }).click();
  await expect(page.getByText('The Vault Passphrase was changed.')).toBeVisible({ timeout: 90_000 });
  expect(await shownFingerprint(page)).toBe(expectedFingerprint);
  await lockNow(page);
  await unlock(page, passphrase);
  await expect(page.getByText('The vault could not be opened.')).toBeVisible({ timeout: 60_000 });
  await unlock(page, next);
  await expect(page.getByRole('heading', { name: 'Vault unlocked' })).toBeVisible({ timeout: 60_000 });

  // No request carried a passphrase in any encoding, or a plaintext PKCS#8 key (EV-04-01).
  expect(requests.length).toBeGreaterThan(5);
  for (const request of requests) {
    for (const secret of [passphrase, next]) {
      for (const encoded of encodingsOf(secret)) {
        expect(request.body).not.toContain(encoded);
        expect(request.url).not.toContain(encoded);
      }
    }
    for (const marker of PKCS8_MARKERS) expect(Buffer.from(request.body).toString('hex')).not.toContain(marker);
  }
  // The re-wrap request was signed, and carried no passphrase field.
  const rewrap = requests.find((r) => r.url.endsWith('/api/vault/rewrap'));
  expect(Object.keys(JSON.parse(rewrap?.body ?? '{}') as object).sort()).toEqual(
    ['kdf', 'keyId', 'previousKdfSalt', 'signature', 'wrappedEncryptionKey', 'wrappedSigningKey'].sort(),
  );

  // Nothing secret was persisted, after setup, unlock, use, lock and passphrase change (EV-04-04).
  const storage = await readableStorage(page);
  for (const secret of [passphrase, next, user.password]) expect(storage).not.toContain(secret);
  expect(
    await page.evaluate(async () => ({
      local: localStorage.length,
      session: sessionStorage.length,
      databases: 'databases' in indexedDB ? (await indexedDB.databases()).length : 0,
      caches: 'caches' in globalThis ? (await caches.keys()).length : 0,
    })),
  ).toEqual({ local: 0, session: 0, databases: 0, caches: 0 });
  expect(await violations()).toEqual([]);
});

test('a vault created in Chromium opens in Firefox and WebKit with the same fingerprint', async ({
  page,
  browserName,
  baseURL,
}) => {
  test.skip(browserName !== 'chromium', 'Runs once from Chromium and opens the other two engines itself');
  test.setTimeout(240_000);
  const { user, passphrase, setupBody } = await userWithVault(page);
  for (const engine of [firefox, webkit]) {
    const browser = await engine.launch();
    try {
      const context = await browser.newContext({ ignoreHTTPSErrors: true, ...(baseURL ? { baseURL } : {}) });
      const other = await context.newPage();
      await useDistinctClientAddress(other);
      await login(other, user);
      await other.goto('/vault');
      await unlock(other, passphrase);
      await expect(other.getByRole('heading', { name: 'Vault unlocked' })).toBeVisible({ timeout: 90_000 });
      expect(await shownFingerprint(other)).toBe(setupBody.identity.fingerprint);
    } finally {
      await browser.close();
    }
  }
});

test('a modified vault record from the server is refused and nothing is decrypted', async ({ page }) => {
  test.setTimeout(180_000);
  const { passphrase } = await userWithVault(page);
  await lockNow(page);
  // Flip one character of the wrapped encryption key in every GET /api/vault answer.
  await page.route('**/api/vault', async (route) => {
    if (route.request().method() !== 'GET') return route.continue();
    const response = await route.fetch();
    const json = (await response.json()) as { vault: { wrappedEncryptionKey: { ciphertext: string } } };
    const ct = json.vault.wrappedEncryptionKey.ciphertext;
    json.vault.wrappedEncryptionKey.ciphertext = `${ct.slice(0, 50)}${ct.charAt(50) === 'A' ? 'B' : 'A'}${ct.slice(51)}`;
    return route.fulfill({ response, json });
  });
  await unlock(page, passphrase);
  await expect(page.getByText('The vault could not be opened.')).toBeVisible({ timeout: 60_000 });
  await expect(page.getByRole('heading', { name: 'Vault unlocked' })).toHaveCount(0);

  // A substituted public key fails the identity check before any passphrase is used.
  await page.unroute('**/api/vault');
  await page.route('**/api/vault', async (route) => {
    if (route.request().method() !== 'GET') return route.continue();
    const response = await route.fetch();
    const json = (await response.json()) as { vault: { identity: { signingPublicKey: string } } };
    const key = json.vault.identity.signingPublicKey;
    json.vault.identity.signingPublicKey = `${key.slice(0, 60)}${key.charAt(60) === 'A' ? 'B' : 'A'}${key.slice(61)}`;
    return route.fulfill({ response, json });
  });
  await page.reload();
  await expect(page.getByText('failed its integrity checks in this browser')).toBeVisible({ timeout: 30_000 });
});

test('the vault locks after 15 minutes without user input; script-made events do not keep it open', async ({
  page,
}) => {
  test.setTimeout(180_000);
  await page.clock.install();
  await userWithVault(page);
  // Synthetic events dispatched by a script are not user activity (isTrusted is false).
  await page.evaluate(() => {
    for (let i = 0; i < 20; i++) {
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'a' }));
      document.dispatchEvent(new PointerEvent('pointerdown'));
    }
  });
  await page.clock.fastForward('14:00');
  await expect(page.getByRole('heading', { name: 'Vault unlocked' })).toBeVisible();
  await page.clock.fastForward('01:30');
  await expect(page.getByRole('heading', { name: 'Unlock your vault' })).toBeVisible();
  await expect(page.getByText('The vault locked itself after 15 minutes without activity.')).toBeVisible();
});

// Review finding R-04-01: a background refresh that failed (network, rate limit) used to replace the
// unlocked view by an error view while the private keys stayed in memory, outside the auto-lock,
// and the next successful refresh then locked with a false "different identity" message.
test('a failed background refresh keeps the vault under the auto-lock and reports no identity change', async ({
  page,
}) => {
  test.setTimeout(180_000);
  await page.clock.install();
  await userWithVault(page);
  // The next GET /api/vault fails as on a broken network; later ones work again.
  let failures = 0;
  await page.route('**/api/vault', (route) => {
    if (route.request().method() === 'GET' && failures === 0) {
      failures += 1;
      return route.abort('failed');
    }
    return route.continue();
  });
  // Client-side navigation refreshes the vault state.
  await page.getByRole('link', { name: 'Account', exact: true }).click();
  await expect.poll(() => failures).toBe(1);
  const reloaded = page.waitForResponse(
    (response) => response.url().endsWith('/api/vault') && response.request().method() === 'GET' && response.ok(),
  );
  await page.getByRole('link', { name: 'Vault', exact: true }).click();
  await reloaded;
  await expect(page.getByRole('heading', { name: 'Vault unlocked' })).toBeVisible();
  await expect(page.getByText('a different identity was found on the server')).toHaveCount(0);
  // The keys are still under the inactivity lock.
  await page.clock.fastForward('15:30');
  await expect(page.getByRole('heading', { name: 'Unlock your vault' })).toBeVisible();
  await expect(page.getByText('The vault locked itself after 15 minutes without activity.')).toBeVisible();
});

test('signing out locks the vault, and a session ended elsewhere locks it too', async ({ page, browser }) => {
  test.setTimeout(180_000);
  const { user, passphrase } = await userWithVault(page);
  // Sign out (client-side navigation keeps the same page runtime, so state would survive otherwise).
  await page.getByRole('link', { name: 'Account', exact: true }).click();
  await page.getByRole('button', { name: 'Sign out' }).first().click();
  await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel('Email address').fill(user.email);
  await page.getByLabel('Account password').fill(user.password);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('heading', { name: 'Account', exact: true })).toBeVisible();
  await page.getByRole('link', { name: 'Vault', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Unlock your vault' })).toBeVisible();

  // Unlock again, then end this session from another device.
  await unlock(page, passphrase);
  await expect(page.getByRole('heading', { name: 'Vault unlocked' })).toBeVisible({ timeout: 60_000 });
  const otherContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const other = await otherContext.newPage();
  await useDistinctClientAddress(other);
  await login(other, user);
  const revoked = other.waitForResponse((r) => r.url().endsWith('/api/auth/sessions/revoke-others'));
  await other.getByRole('button', { name: 'Sign out all other sessions' }).click();
  expect((await revoked).status()).toBe(200);
  await otherContext.close();
  // The next API answer for this tab is 401: the vault locks and the tab is signed out.
  await page.getByRole('link', { name: 'Account', exact: true }).click();
  await expect(page).toHaveURL(/\/login$/);
  await page.getByRole('link', { name: 'Vault', exact: true }).click();
  await expect(page.getByText('Sign in first.')).toBeVisible();
});

test('negative control: the leak checks detect a passphrase that was stored or sent', async ({ page }) => {
  const secret = newVaultPassphrase();
  await page.goto('/');
  const requests = captureRequests(page);
  await page.evaluate((value) => {
    localStorage.setItem('leak', value);
    void fetch('/api/does-not-exist', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-ciphermesh-request': '1' },
      body: JSON.stringify({ note: value }),
    });
  }, secret);
  await expect.poll(() => requests.length).toBeGreaterThan(0);
  expect(await readableStorage(page)).toContain(secret);
  expect(requests.some((r) => encodingsOf(secret).some((e) => r.body.includes(e)))).toBe(true);
  await page.evaluate(() => {
    localStorage.clear();
  });
});
