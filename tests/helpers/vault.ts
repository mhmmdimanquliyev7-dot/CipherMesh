import {
  createVault,
  vaultRecordFromWire,
  vaultRecordToWire,
  type VaultRecord,
  type VaultSetup,
  type VaultWire,
} from '@ciphermesh/crypto';
import { randomBytes } from 'node:crypto';
import { createInProcessRunner } from '../../packages/crypto/src/kdf/runner';
import { signedInUser, type AuthTestApi, type Browser } from './auth';

// Helpers for the vault suites (tests/vault). Vault records are produced by the real browser code
// of packages/crypto with the production Argon2id parameters; only the runner differs (in-process
// instead of a Web Worker, because Node.js has no page to keep responsive). Passphrases are random
// per user and synthetic.

export const runner = createInProcessRunner();

/** A random, synthetic Vault Passphrase that passes the policy. */
export const newPassphrase = (): string => `vault ${randomBytes(12).toString('base64url')} phrase`;

export interface VaultTestUser {
  readonly identity: { email: string; password: string; displayName: string };
  readonly browser: Browser;
  readonly userId: string;
  readonly account: { email: string; displayName: string };
}

/** A signed-in user with a fresh step-up, ready to set up a vault. */
export async function vaultUser(api: AuthTestApi): Promise<VaultTestUser> {
  const { identity, browser } = await signedInUser(api);
  const session = await browser.request('GET', '/auth/session');
  const userId = (session.body['user'] as { id: string }).id;
  const stepUp = await browser.request('POST', '/auth/step-up', { password: identity.password });
  if (stepUp.status !== 200) throw new Error(`step-up failed: ${String(stepUp.status)}`);
  return { identity, browser, userId, account: { email: identity.email, displayName: identity.displayName } };
}

export function prepareVault(user: VaultTestUser, passphrase: string): Promise<VaultSetup> {
  return createVault({ userId: user.userId, passphrase, account: user.account, runner });
}

/** The JSON a browser sends for a setup (what crosses the network). */
export const setupBody = (setup: VaultSetup): VaultWire => vaultRecordToWire(setup.record);

/** A user with an uploaded vault, and the passphrase that unlocks it. */
export async function userWithVault(api: AuthTestApi) {
  const user = await vaultUser(api);
  const passphrase = newPassphrase();
  const setup = await prepareVault(user, passphrase);
  const created = await user.browser.request('POST', '/vault', setupBody(setup));
  if (created.status !== 201) throw new Error(`vault setup failed: ${String(created.status)}`);
  return { ...user, passphrase, setup };
}

/** The caller's stored vault as the browser decodes it. */
export async function fetchStoredVault(user: VaultTestUser): Promise<VaultRecord> {
  const response = await user.browser.request('GET', '/vault');
  if (response.status !== 200) throw new Error(`GET /vault failed: ${String(response.status)}`);
  return vaultRecordFromWire(response.body['vault'] as VaultWire, user.userId);
}
