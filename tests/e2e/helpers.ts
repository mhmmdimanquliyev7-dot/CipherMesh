import { expect, type Page, type Request } from '@playwright/test';
import { randomBytes } from 'node:crypto';

// Shared helpers for browser tests: synthetic accounts, sign-in, browser storage inspection and
// request capture. Every value is random and synthetic.

export interface TestUser {
  readonly email: string;
  readonly password: string;
  readonly name: string;
}

export const newUser = (): TestUser => ({
  email: `e2e-${randomBytes(6).toString('hex')}@example.test`,
  password: `${randomBytes(15).toString('base64url')}!`,
  name: 'Synthetic E2E User',
});

/** A random Vault Passphrase that meets the policy, different from any account password. */
export const newVaultPassphrase = (): string => `vault ${randomBytes(9).toString('base64url')} sentence`;

/**
 * Gives the page's browser context its own client address (IPv6 documentation range), honoured
 * only by the E2E proxy, so per-address rate limits of one test cannot affect another.
 */
export async function useDistinctClientAddress(page: Page): Promise<void> {
  const group = (): string => randomBytes(2).toString('hex');
  await page.context().setExtraHTTPHeaders({ 'x-e2e-client-address': `2001:db8::${group()}:${group()}` });
}

export async function register(page: Page, user: TestUser): Promise<void> {
  await page.goto('/register');
  await page.getByLabel('Email address').fill(user.email);
  await page.getByLabel('Display name').fill(user.name);
  await page.getByLabel('Account password').fill(user.password);
  await page.getByLabel('Repeat the password').fill(user.password);
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.getByText('Your account exists')).toBeVisible();
}

export async function login(page: Page, user: TestUser): Promise<void> {
  await page.goto('/login');
  await page.getByLabel('Email address').fill(user.email);
  await page.getByLabel('Account password').fill(user.password);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('heading', { name: 'Account', exact: true })).toBeVisible();
}

/**
 * Everything a script in the page can read from browser storage, as one string: cookies,
 * localStorage, sessionStorage, the names and contents of every IndexedDB database, and every
 * Cache Storage entry.
 */
export async function readableStorage(page: Page): Promise<string> {
  return page.evaluate(async () => {
    const dump = (storage: Storage) => JSON.stringify(Object.keys(storage).map((key) => [key, storage.getItem(key)]));
    const parts = [document.cookie, dump(localStorage), dump(sessionStorage)];
    if ('databases' in indexedDB) {
      for (const info of await indexedDB.databases()) {
        parts.push(JSON.stringify(info));
        if (info.name === undefined) continue;
        const name = info.name;
        const db = await new Promise<IDBDatabase>((resolve, reject) => {
          const request = indexedDB.open(name);
          request.onsuccess = () => {
            resolve(request.result);
          };
          request.onerror = () => {
            reject(new Error('open failed'));
          };
        });
        for (const store of Array.from(db.objectStoreNames)) {
          const all = await new Promise<unknown[]>((resolve) => {
            const request = db.transaction(store, 'readonly').objectStore(store).getAll();
            request.onsuccess = () => {
              resolve(request.result as unknown[]);
            };
            request.onerror = () => {
              resolve([]);
            };
          });
          parts.push(JSON.stringify(all));
        }
        db.close();
      }
    }
    if ('caches' in globalThis) {
      for (const cacheName of await caches.keys()) {
        parts.push(cacheName);
        const cache = await caches.open(cacheName);
        for (const request of await cache.keys()) {
          parts.push(request.url);
          const response = await cache.match(request);
          if (response !== undefined) parts.push(await response.text());
        }
      }
    }
    return parts.join('\n');
  });
}

/** Captures every request with its method, URL and body, for leak checks. */
export function captureRequests(page: Page): { url: string; method: string; body: string }[] {
  const captured: { url: string; method: string; body: string }[] = [];
  page.on('request', (request: Request) => {
    captured.push({ url: request.url(), method: request.method(), body: request.postData() ?? '' });
  });
  return captured;
}

/** Collects Content-Security-Policy violations of the page (and reports from its console). */
export async function collectCspViolations(page: Page): Promise<() => Promise<string[]>> {
  const fromConsole: string[] = [];
  page.on('console', (message) => {
    if (/content.security.policy/i.test(message.text())) fromConsole.push(message.text());
  });
  await page.addInitScript(() => {
    const store = ((window as unknown as { __cmCsp: string[] }).__cmCsp = [] as string[]);
    document.addEventListener('securitypolicyviolation', (event) => {
      store.push(`${event.violatedDirective} ${event.blockedURI}`);
    });
  });
  return async () => [
    ...fromConsole,
    ...(await page.evaluate(() => (window as unknown as { __cmCsp?: string[] }).__cmCsp ?? [])),
  ];
}
