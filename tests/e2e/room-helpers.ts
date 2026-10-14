import { expect, type Page } from '@playwright/test';
import { Secret, TOTP } from 'otpauth';
import { login, newUser, newVaultPassphrase, register, useDistinctClientAddress, type TestUser } from './helpers';

// Browser helpers for the room suites (Phases 5 and 6). Everything goes through the real UI:
// accounts, vaults, rooms, invitations. Values are random and synthetic.

export const PASSPHRASE_FIELD = 'Vault Passphrase (not your account password)';

export async function confirmAccount(page: Page, user: TestUser): Promise<void> {
  await expect(page.getByRole('heading', { name: 'Confirm your account' })).toBeVisible();
  await page.getByLabel('Account password').fill(user.password);
  await page.getByRole('button', { name: 'Confirm account' }).click();
}

/** Registers, signs in and creates a vault through the UI; the vault is unlocked afterwards. */
export async function signedInWithVault(
  page: Page,
  name = 'Synthetic E2E User',
): Promise<TestUser & { readonly passphrase: string }> {
  const user = { ...newUser(), name };
  await useDistinctClientAddress(page);
  await register(page, user);
  await login(page, user);
  await page.getByRole('link', { name: 'Vault', exact: true }).click();
  await confirmAccount(page, user);
  const passphrase = newVaultPassphrase();
  await page.getByLabel(PASSPHRASE_FIELD).fill(passphrase);
  await page.getByLabel('Repeat the Vault Passphrase').fill(passphrase);
  await page.getByLabel('I understand that CipherMesh cannot recover a lost Vault Passphrase.').check();
  await page.getByRole('button', { name: 'Create vault' }).click();
  await expect(page.getByRole('heading', { name: 'Vault unlocked' })).toBeVisible({ timeout: 90_000 });
  return { ...user, passphrase };
}

/** Unlocks the vault on the Vault page. */
export async function unlockVault(page: Page, passphrase: string): Promise<void> {
  await page.getByRole('link', { name: 'Vault', exact: true }).click();
  await page.getByLabel(PASSPHRASE_FIELD).fill(passphrase);
  await page.getByRole('button', { name: 'Unlock', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Vault unlocked' })).toBeVisible({ timeout: 90_000 });
}

/** Creates a room on the Rooms page (key version 1 is made in this browser); returns its ID. */
export async function createRoomThroughUi(page: Page, name: string, profile = 'STANDARD'): Promise<string> {
  await page.getByRole('link', { name: 'Rooms', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Rooms', exact: true })).toBeVisible();
  await expect(page.getByText('Room names are not encrypted')).toBeVisible();
  await page.getByLabel('Room name').fill(name);
  await page.getByLabel('Security profile').selectOption(profile);
  await page.getByRole('button', { name: 'Create room' }).click();
  await expect(page).toHaveURL(/\/rooms\/room\?id=[0-9a-f-]{36}$/, { timeout: 60_000 });
  await expect(page.getByRole('heading', { name })).toBeVisible();
  return new URL(page.url()).searchParams.get('id') ?? '';
}

/**
 * Opens a room by navigating inside the app. A full page load (page.goto, reload) starts a new
 * document, which by design holds no unlocked vault (keys are memory-only, CP-22).
 */
export async function openRoomThroughUi(page: Page, roomName: string): Promise<void> {
  await page.getByRole('link', { name: 'Rooms', exact: true }).click();
  await page.getByRole('list', { name: 'Your rooms' }).getByRole('link', { name: roomName }).click();
  await expect(page.getByRole('heading', { name: roomName })).toBeVisible();
}

/** Waits for the room key to be verified on this device and returns its Safety Code words. */
export async function verifiedSafetyCode(page: Page): Promise<string> {
  await expect(page.getByTestId('room-key-status')).toContainText('verified on this device', { timeout: 60_000 });
  const words = page.getByTestId('safety-code-words');
  await expect(words).toBeVisible();
  return (await words.innerText()).replace(/\s+/g, ' ').trim();
}

/** Looks the invitee up on the room page and invites them; optionally confirms the fingerprint. */
export async function inviteThroughUi(
  page: Page,
  invitee: TestUser,
  role: 'Admin' | 'Member' | 'Viewer',
  confirmFingerprint: boolean,
): Promise<string> {
  await page.getByLabel('Email address of the person to invite').fill(invitee.email);
  await page.getByRole('button', { name: 'Look up' }).click();
  const candidate = page.getByTestId('invite-candidate');
  await expect(candidate).toContainText(invitee.name);
  await expect(candidate).toContainText('email address not verified');
  const fingerprint = (await page.getByTestId('invitee-fingerprint').innerText()).trim();
  if (confirmFingerprint) {
    await candidate.getByLabel(`I compared this fingerprint with ${invitee.name} over a channel I trust`).check();
  }
  await candidate.getByLabel('Role').selectOption({ label: role });
  await candidate.getByRole('button', { name: 'Invite' }).click();
  await expect(page.getByText(`${invitee.name} was invited.`)).toBeVisible({ timeout: 60_000 });
  return fingerprint;
}

/** Accepts the invitation to the named room on the Invitations page; ends on the room page. */
export async function acceptThroughUi(page: Page, roomName: string): Promise<void> {
  await page.getByRole('link', { name: 'Invitations', exact: true }).click();
  const item = page.getByRole('list', { name: 'Your invitations' }).getByRole('listitem').filter({ hasText: roomName });
  await expect(item).toBeVisible();
  await item.getByRole('button', { name: 'Accept' }).click();
  await expect(page).toHaveURL(/\/rooms\/room\?id=/);
  await expect(page.getByRole('heading', { name: roomName })).toBeVisible();
}

/** The fingerprint shown on the user's own Vault page (what they read to an inviter). */
export async function ownFingerprint(page: Page): Promise<string> {
  await page.getByRole('link', { name: 'Vault', exact: true }).click();
  return (await page.getByTestId('own-fingerprint').innerText()).trim();
}

// ------------------------------------------------ MFA (moved from room-keys.spec.ts in Phase 10)

/** Turns on TOTP in Account; returns the secret. */
export async function enrollMfa(page: Page, user: TestUser): Promise<string> {
  await page.getByRole('link', { name: 'Account', exact: true }).click();
  await page.getByRole('button', { name: 'Set up an authenticator app' }).click();
  // The vault setup's step-up may still be fresh; otherwise the server asks for the password first.
  const qr = page.getByRole('img', { name: 'QR code for the authenticator app' });
  const confirm = page.getByText('Confirm your identity to continue');
  await expect(qr.or(confirm)).toBeVisible();
  if (await confirm.isVisible()) {
    await page.getByLabel('Account password').first().fill(user.password);
    await page.getByRole('button', { name: 'Confirm' }).click();
    await expect(confirm).toHaveCount(0);
    await page.getByRole('button', { name: 'Set up an authenticator app' }).click();
  }
  await expect(qr).toBeVisible();
  const secret = (await page.locator('p.font-mono').innerText()).trim();
  await page.getByLabel('Code from the app').fill(await totp(secret));
  await page.getByRole('button', { name: 'Turn on' }).click();
  await page.getByRole('button', { name: 'I have stored them' }).click();
  return secret;
}
/**
 * A code for a time step this secret has not used yet: the API refuses a replayed step (CP-09), so
 * each enrollment, sign-in and step-up takes the next unused step, waiting for real time to reach
 * it when it is more than one step ahead (the accepted drift).
 */
const usedSteps = new Map<string, number>();
export async function totp(secret: string): Promise<string> {
  const now = (): number => Math.floor(Date.now() / 30_000);
  const target = Math.max(now(), (usedSteps.get(secret) ?? -1) + 1);
  while (target > now() + 1) await new Promise((resolve) => setTimeout(resolve, 1000));
  usedSteps.set(secret, target);
  return TOTP.generate({ secret: Secret.fromBase32(secret), digits: 6, period: 30, timestamp: target * 30_000 });
}

/** Signs in again with the second factor, which gives the session the MFA verification of PC-01. */
export async function loginWithMfa(page: Page, user: TestUser, secret: string): Promise<void> {
  await page.getByRole('button', { name: 'Sign out' }).first().click();
  await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel('Email address').fill(user.email);
  await page.getByLabel('Account password').fill(user.password);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Authentication code').fill(await totp(secret));
  await page.getByRole('button', { name: 'Verify' }).click();
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
}
