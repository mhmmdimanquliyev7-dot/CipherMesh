import { expect, test } from '@playwright/test';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { collectCspViolations, login } from '../e2e/helpers';
import { openRoomThroughUi, unlockVault } from '../e2e/room-helpers';
import { authSlots } from './pace';

// Browser-level restore check (ADR-014, EV-19-07): after cm-restore rebuilt the stack from an
// encrypted backup onto empty volumes, the synthetic account recorded by cloud-smoke.spec.ts signs
// in again, unlocks its vault (the wrapped private keys came back from the backup), opens the room
// (its key envelope came back), and decrypts the note and the file it stored before the backup.
// Runs only when CM_SMOKE_RESTORED_ACCOUNTS names the directory of recorded accounts.

const directory = process.env['CM_SMOKE_RESTORED_ACCOUNTS'];

interface Recorded {
  readonly email: string;
  readonly password: string;
  readonly name: string;
  readonly passphrase: string;
  readonly roomName: string;
  readonly noteSecret: string;
  readonly file: string;
}

test('after a restore, the recorded account decrypts its note and file again', async ({ page, browserName }) => {
  test.skip(directory === undefined || directory === '', 'runs only after a restore (CM_SMOKE_RESTORED_ACCOUNTS)');
  test.setTimeout(300_000);
  const file = join(directory ?? '', `${browserName}.json`);
  expect(existsSync(file), `recorded account for ${browserName}`).toBe(true);
  const recorded = JSON.parse(readFileSync(file, 'utf8')) as Recorded;
  const violations = await collectCspViolations(page);

  await authSlots(1);
  await login(page, recorded);
  await unlockVault(page, recorded.passphrase);
  await openRoomThroughUi(page, recorded.roomName);

  const note = page.getByTestId('note-row').filter({ hasText: 'Cloud smoke note' });
  await expect(note).toBeVisible({ timeout: 60_000 });
  if ((await note.getByTestId('note-view').count()) === 0) await note.getByTestId('note-open').click();
  await expect(note.getByTestId('note-view')).toContainText(recorded.noteSecret);

  const row = page.getByTestId('file-row').first();
  await expect(row).toBeVisible({ timeout: 60_000 });
  const pending = page.waitForEvent('download');
  await row.getByRole('button', { name: /^Download/ }).click();
  const downloaded = readFileSync(await (await pending).path());
  expect(downloaded.equals(Buffer.from(recorded.file, 'base64')), 'restored file decrypts to the original').toBe(true);
  expect(await violations()).toEqual([]);
});
