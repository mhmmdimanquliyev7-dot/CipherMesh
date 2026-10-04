import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { checkSchema } from '../../scripts/db/check-schema.mjs';

// Negative controls for the forbidden-field checker (CM-T013, EV-02-01). Each case adds one
// field from the data-model "must never exist" list to a copy of the real schema and expects the
// checker to fail. A checker that always passes would fail these tests.
const root = fileURLToPath(new URL('../..', import.meta.url));
const schema = readFileSync(join(root, 'prisma/schema.prisma'), 'utf8');

/** Adds lines to the end of a model block of the real schema. */
function withField(model: string, ...lines: string[]): string {
  const start = schema.indexOf(`model ${model} {`);
  if (start < 0) throw new Error(`model ${model} not found`);
  const end = schema.indexOf('\n}', start);
  return `${schema.slice(0, end)}\n${lines.join('\n')}${schema.slice(end)}`;
}

const classified = (cls: string, field: string): string[] => [`  /// class: ${cls}`, `  ${field}`];

describe('forbidden-field checker', () => {
  it('passes the real schema', () => {
    expect(checkSchema(schema)).toEqual([]);
  });

  it.each([
    ['plaintext password', 'User', classified('META', 'password String')],
    ['reversibly encrypted password', 'User', classified('CT', 'passwordEncrypted Bytes')],
    ['Vault Passphrase verifier', 'User', classified('DIG', 'vaultPassphraseHash Bytes')],
    ['plaintext private key', 'UserKeyPair', classified('META', 'privateKey Bytes')],
    ['private-key wrapping key', 'UserKeyPair', classified('META', 'pkwk Bytes')],
    ['room key column', 'Room', classified('META', 'roomKey Bytes')],
    ['room key material', 'RoomKeyVersion', classified('META', 'rkm Bytes')],
    ['room wrapping key', 'RoomKeyVersion', classified('META', 'wrappingKey Bytes')],
    ['plaintext DEK', 'EncryptedFile', classified('META', 'dek Bytes')],
    ['plaintext SEK', 'Secret', classified('META', 'sek Bytes')],
    ['plaintext filename', 'EncryptedFile', classified('META', 'fileName String')],
    ['plaintext MIME type', 'EncryptedFile', classified('META', 'mimeType String')],
    ['plaintext file hash', 'EncryptedFile', classified('INT', 'plaintextSha256 Bytes')],
    ['note title', 'EncryptedNote', classified('META', 'title String')],
    ['note body', 'EncryptedNote', classified('META', 'body String')],
    ['secret plaintext', 'Secret', classified('META', 'secretValue String')],
    ['raw session token', 'Session', classified('META', 'token String')],
    ['raw recovery code', 'RecoveryCode', classified('META', 'code String')],
    ['plaintext TOTP secret', 'User', classified('META', 'totpSecret String')],
    ['invitation bearer token', 'Invitation', classified('META', 'inviteToken String')],
    ['key escrow', 'Room', classified('WK', 'escrowKey Bytes')],
    ['master key', 'Room', classified('WK', 'masterKey Bytes')],
    ['Room Safety Code', 'RoomKeyVersion', classified('META', 'safetyCode String')],
    ['presigned URL', 'EncryptedFile', classified('META', 'presignedUrl String')],
    ['IP address in audit events', 'AuditEvent', classified('PII', 'ipAddress String')],
    ['an unreviewed key field', 'Session', classified('META', 'sessionKey Bytes')],
    ['an unclassified field', 'Room', ['  description String']],
    ['an unknown classification', 'Room', classified('SECRET', 'notes Int')],
    ['ciphertext stored as text', 'EncryptedNote', classified('CT', 'ciphertextBase64 String')],
    ['a wrapped key stored as text', 'KeyEnvelope', classified('WK', 'wrappedKeyHex String')],
    ['a mapped column with a forbidden name', 'Room', classified('META', 'label String @map("room_key")')],
  ])('fails on a %s', (_label, model, lines) => {
    const problems = checkSchema(withField(model, ...lines));
    // The finding must name the injected field, so the case cannot pass for an unrelated reason.
    const field = String(lines.at(-1)).trim().split(/\s+/)[0];
    expect(problems.map((p) => p.message)).toEqual(
      expect.arrayContaining([expect.stringContaining(`${model}.${String(field)}:`)]),
    );
  });

  it.each([
    ['a mutable security policy table', 'model SecurityPolicy {\n  /// class: ID\n  id String @id\n}'],
    ['a key escrow table', 'model KeyEscrow {\n  /// class: ID\n  id String @id\n}'],
  ])('fails on %s', (_label, model) => {
    expect(checkSchema(`${schema}\n${model}\n`).length).toBeGreaterThan(0);
  });

  it('fails closed on an empty or unreadable schema', () => {
    expect(checkSchema('')).not.toEqual([]);
    expect(checkSchema('this is not a prisma schema')).not.toEqual([]);
  });

  it('exits 1 from the command line on a bad schema and 0 on the real one', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cm-schema-'));
    try {
      const bad = join(dir, 'schema.prisma');
      writeFileSync(bad, withField('User', ...classified('META', 'password String')));
      const failing = spawnSync(process.execPath, ['scripts/db/check-schema.mjs', bad], {
        cwd: root,
        encoding: 'utf8',
      });
      expect(failing.status).toBe(1);
      expect(failing.stderr).toContain('User.password');
      const passing = spawnSync(process.execPath, ['scripts/db/check-schema.mjs'], { cwd: root, encoding: 'utf8' });
      expect(passing.status, passing.stderr).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
