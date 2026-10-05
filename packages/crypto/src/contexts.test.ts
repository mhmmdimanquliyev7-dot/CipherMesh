import { describe, expect, it } from 'vitest';
import { CONTEXT_NAMES, contextBytes, type ContextFields, type ContextName } from './contexts';
import { CryptoErrorCode, isCryptoError } from './errors';

const ROOM = '1d6b4f0e-2c3a-4b5d-8e9f-0a1b2c3d4e5f';
const FILE = '7a8b9c0d-1e2f-4a3b-9c4d-5e6f7a8b9c0d';
const USER = '4b0c0b7e-6a5c-4d0e-9f3a-2b1c8d7e6f5a';
const KEY_ID = '8f14e45f-ceea-467a-a5ad-6c1f0d9a2b3c';
const B64 = (bytes: number): string => Buffer.alloc(bytes, 7).toString('base64url');

// One valid field set per context, so every context in the table is exercised.
const SAMPLES: { readonly [N in ContextName]: ContextFields<N> } = {
  'cm.vault.pk-wrap': { userId: USER, keyId: KEY_ID, purpose: 'encryption' },
  'cm.vault.private-key': {
    userId: USER,
    keyId: KEY_ID,
    purpose: 'signing',
    fingerprint: 'a'.repeat(64),
    suite: 'CM1',
    vaultVersion: 1,
  },
  'cm.vault.pair-check': { userId: USER, keyId: KEY_ID, suite: 'CM1' },
  'cm.vault.signing-check': { userId: USER, keyId: KEY_ID, challenge: B64(32) },
  'cm.vault.rewrap': {
    userId: USER,
    keyId: KEY_ID,
    suite: 'CM1',
    vaultVersion: 1,
    previousKdfSalt: B64(16),
    kdfAlgorithm: 'argon2id',
    kdfMemoryKiB: 65536,
    kdfIterations: 3,
    kdfParallelism: 1,
    kdfSalt: B64(16),
    encryptionKeyIv: B64(12),
    encryptionKeyCiphertext: B64(1809),
    signingKeyIv: B64(12),
    signingKeyCiphertext: B64(154),
  },
  'cm.identity.binding': {
    userId: USER,
    keyId: KEY_ID,
    suite: 'CM1',
    encryptionKeySpki: B64(422),
    signingKeySpki: B64(91),
  },
  'cm.identity.fingerprint': { suite: 'CM1', encryptionKeySpki: B64(422), signingKeySpki: B64(91) },
  'cm.room.envelope': { roomId: ROOM, keyVersion: 1, recipientUserId: USER, recipientKeyId: KEY_ID, suite: 'CM1' },
  'cm.room.dek-wrap-key': { roomId: ROOM, keyVersion: 1 },
  'cm.room.commitment': { roomId: ROOM, keyVersion: 1 },
  'cm.room.safety-code': { roomId: ROOM, keyVersion: 1 },
  'cm.dek.wrap': { roomId: ROOM, keyVersion: 2, itemType: 'file', itemId: FILE, revision: 0 },
  'cm.file.content': { roomId: ROOM, fileId: FILE },
  'cm.file.manifest': { roomId: ROOM, fileId: FILE },
  'cm.note.content': { roomId: ROOM, noteId: FILE, revision: 3 },
  'cm.secret.sek-wrap': { roomId: ROOM, secretId: FILE, recipientUserId: USER, recipientKeyId: KEY_ID, suite: 'CM1' },
  'cm.secret.payload': { roomId: ROOM, secretId: FILE },
  'cm.srv.totp': { userId: USER, keyId: 'server-key-1' },
};

const text = (bytes: Uint8Array): string => Buffer.from(bytes).toString('utf8');

const invalid = (fn: () => unknown): void => {
  let caught: unknown;
  try {
    fn();
  } catch (error) {
    caught = error;
  }
  expect(isCryptoError(caught, CryptoErrorCode.INVALID_INPUT)).toBe(true);
};

describe('canonical contexts (CP-15, cryptographic-architecture section 8)', () => {
  it('matches the documented example byte for byte', () => {
    // cryptographic-architecture.md section 8: the AAD for file content.
    expect(text(contextBytes('cm.file.content', { roomId: ROOM, fileId: FILE }))).toBe(
      `{"ctx":"cm.file.content","fileId":"${FILE}","roomId":"${ROOM}","v":1}`,
    );
  });

  it('builds every context in the table with ctx and v first in canonical order', () => {
    expect([...CONTEXT_NAMES].sort()).toEqual(Object.keys(SAMPLES).sort());
    for (const name of CONTEXT_NAMES) {
      const parsed = JSON.parse(text(contextBytes(name, SAMPLES[name] as never))) as Record<string, unknown>;
      expect(parsed['ctx']).toBe(name);
      expect(parsed['v']).toBe(1);
    }
  });

  it('gives every context distinct bytes, even for the same field values (domain separation)', () => {
    const outputs = CONTEXT_NAMES.map((name) => text(contextBytes(name, SAMPLES[name] as never)));
    expect(new Set(outputs).size).toBe(outputs.length);
    const commitment = text(contextBytes('cm.room.commitment', { roomId: ROOM, keyVersion: 1 }));
    const wrapKey = text(contextBytes('cm.room.dek-wrap-key', { roomId: ROOM, keyVersion: 1 }));
    const safetyCode = text(contextBytes('cm.room.safety-code', { roomId: ROOM, keyVersion: 1 }));
    expect(new Set([commitment, wrapKey, safetyCode]).size).toBe(3);
  });

  it('changes when any single field changes', () => {
    const base = text(contextBytes('cm.vault.private-key', SAMPLES['cm.vault.private-key']));
    const variants: ContextFields<'cm.vault.private-key'>[] = [
      { ...SAMPLES['cm.vault.private-key'], purpose: 'encryption' },
      { ...SAMPLES['cm.vault.private-key'], userId: ROOM },
      { ...SAMPLES['cm.vault.private-key'], keyId: FILE },
      { ...SAMPLES['cm.vault.private-key'], fingerprint: 'b'.repeat(64) },
    ];
    for (const variant of variants) expect(text(contextBytes('cm.vault.private-key', variant))).not.toBe(base);
  });

  it('refuses missing, extra and malformed fields and unknown contexts', () => {
    invalid(() => contextBytes('cm.file.content', { roomId: ROOM } as never));
    invalid(() => contextBytes('cm.file.content', { roomId: ROOM, fileId: FILE, extra: 'x' } as never));
    invalid(() => contextBytes('cm.file.content', { roomId: ROOM.toUpperCase(), fileId: FILE }));
    invalid(() => contextBytes('cm.file.content', { roomId: 'not-a-uuid', fileId: FILE }));
    invalid(() => contextBytes('cm.room.commitment', { roomId: ROOM, keyVersion: 0 }));
    invalid(() => contextBytes('cm.room.commitment', { roomId: ROOM, keyVersion: 1.5 }));
    invalid(() => contextBytes('cm.vault.pk-wrap', { userId: USER, keyId: KEY_ID, purpose: 'other' as never }));
    invalid(() =>
      contextBytes('cm.vault.private-key', { ...SAMPLES['cm.vault.private-key'], fingerprint: 'A'.repeat(64) }),
    );
    invalid(() =>
      contextBytes('cm.identity.fingerprint', { suite: 'CM1', encryptionKeySpki: B64(421), signingKeySpki: B64(91) }),
    );
    invalid(() => contextBytes('cm.srv.totp', { userId: USER, keyId: 'Bad Key' }));
    invalid(() => contextBytes('cm.unknown' as ContextName, {} as never));
    invalid(() => contextBytes('cm.file.content', { roomId: ROOM, fileId: undefined } as never));
    invalid(() => contextBytes('cm.file.content', { roomId: 42, fileId: FILE } as never));
    invalid(() => contextBytes('cm.vault.signing-check', { userId: USER, keyId: KEY_ID, challenge: 42 } as never));
    invalid(() => contextBytes('cm.vault.signing-check', { userId: USER, keyId: KEY_ID, challenge: 'A' }));
    invalid(() =>
      contextBytes('cm.dek.wrap', {
        roomId: ROOM,
        keyVersion: 1,
        itemType: 'secret' as never,
        itemId: FILE,
        revision: 0,
      }),
    );
    expect(() =>
      contextBytes('cm.dek.wrap', { roomId: ROOM, keyVersion: 1, itemType: 'note', itemId: FILE, revision: 3 }),
    ).not.toThrow();
  });

  it('a UUID that is not version 4 is refused (identifiers in contexts are UUIDv4, CD-08)', () => {
    invalid(() => contextBytes('cm.file.content', { roomId: '1d6b4f0e-2c3a-1b5d-8e9f-0a1b2c3d4e5f', fileId: FILE }));
  });
});
