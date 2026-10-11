import { describe, expect, it } from 'vitest';
import {
  formatListCursor,
  listQuerySchema,
  invitationCreateRequestSchema,
  keyReportRequestSchema,
  memberRoleChangeRequestSchema,
  ownershipTransferRequestSchema,
  parseListCursor,
  roomCreateRequestSchema,
  roomNameSchema,
  roomRenameRequestSchema,
  safetyCodeRecordRequestSchema,
} from './index';

// Room schemas (CM-T030, CM-T031): strict objects, normalized names, keyset cursors.
const ROOM = '0b2f6c1e-8d3a-4f5b-9c7d-2e1f0a9b8c7d';
// Base64url text of the length of `bytes` bytes (filler; the schema checks alphabet and size).
const b64 = (bytes: number): string => 'A'.repeat(Math.ceil((bytes * 4) / 3));
// Synthetic filler of the right sizes: never a key, never derived from one.
const KEYS = {
  creatorKeyId: ROOM,
  commitment: b64(32),
  envelope: b64(384),
  genesisSignature: b64(64),
  keyVersionSignature: b64(64),
};
const GRANT = { subjectKeyId: ROOM, signature: b64(64) };

describe('room names', () => {
  it('are NFKC-normalized and trimmed', () => {
    expect(roomNameSchema.parse('  Ｐｒｏｊｅｃｔ  plan \n')).toBe('Project  plan');
    expect(roomNameSchema.parse('x'.repeat(100))).toHaveLength(100);
  });

  it.each([
    ['empty after trimming', '   '],
    ['longer than 100 characters', 'x'.repeat(101)],
    ['a control character', 'a\u0000b'],
    ['a C1 control character', 'a\u0085b'],
    ['a right-to-left override', 'report‮fdp.exe'],
    ['a first-strong isolate', 'a⁨b'],
  ])('refuses %s', (_label, value) => {
    expect(roomNameSchema.safeParse(value).success).toBe(false);
  });
});

describe('room requests are strict', () => {
  it('accept exactly the declared fields', () => {
    const room = { roomId: ROOM, name: 'A', securityProfile: 'RESTRICTED', keys: KEYS };
    expect(roomCreateRequestSchema.safeParse(room).success).toBe(true);
    for (const extra of [{ role: 'OWNER' }, { createdById: ROOM }, { keyState: 'ACTIVE' }, { envelope: 'AA' }]) {
      expect(roomCreateRequestSchema.safeParse({ ...room, ...extra }).success).toBe(false);
    }
    expect(roomRenameRequestSchema.safeParse({ name: 'B', roomId: ROOM }).success).toBe(false);
  });

  it('never accept OWNER or an unknown role in a role change', () => {
    for (const role of ['MEMBER', 'VIEWER'])
      expect(memberRoleChangeRequestSchema.safeParse({ role }).success).toBe(true);
    expect(memberRoleChangeRequestSchema.safeParse({ role: 'ADMIN', grant: GRANT }).success).toBe(true);
    for (const role of ['OWNER', 'admin', 'PLATFORM_ADMIN', '', null]) {
      expect(memberRoleChangeRequestSchema.safeParse({ role }).success).toBe(false);
    }
  });

  it('require a signed grant exactly for the ADMIN role and for an ownership transfer (ADR-015)', () => {
    expect(memberRoleChangeRequestSchema.safeParse({ role: 'ADMIN' }).success).toBe(false);
    expect(memberRoleChangeRequestSchema.safeParse({ role: 'MEMBER', grant: GRANT }).success).toBe(false);
    expect(ownershipTransferRequestSchema.safeParse({ grant: GRANT }).success).toBe(true);
    expect(ownershipTransferRequestSchema.safeParse({}).success).toBe(false);
    expect(ownershipTransferRequestSchema.safeParse({ grant: { ...GRANT, role: 'OWNER' } }).success).toBe(false);
    expect(ownershipTransferRequestSchema.safeParse({ grant: { ...GRANT, signature: b64(63) } }).success).toBe(false);
  });
});

describe('room key requests cannot carry key material (INV-01, INV-04, INV-18)', () => {
  const room = { roomId: ROOM, name: 'A', securityProfile: 'STANDARD', keys: KEYS };

  it('refuses a room without key version 1, and any raw-key field in the key package', () => {
    const { keys: _keys, ...keyless } = room;
    expect(roomCreateRequestSchema.safeParse(keyless).success).toBe(false);
    for (const field of ['rkm', 'roomKey', 'roomKeyMaterial', 'rwk', 'wrappingKey', 'privateKey', 'safetyCode']) {
      expect(roomCreateRequestSchema.safeParse({ ...room, keys: { ...KEYS, [field]: b64(32) } }).success, field).toBe(
        false,
      );
    }
    // Sizes are exact: a 32-byte value in the envelope field is not an envelope.
    expect(roomCreateRequestSchema.safeParse({ ...room, keys: { ...KEYS, envelope: b64(32) } }).success).toBe(false);
    expect(roomCreateRequestSchema.safeParse({ ...room, keys: { ...KEYS, commitment: b64(33) } }).success).toBe(false);
    expect(roomCreateRequestSchema.safeParse({ ...room, keys: { ...KEYS, commitment: '+'.repeat(43) } }).success).toBe(
      false,
    );
  });

  it('accepts invitations with envelopes and a grant only, and no OWNER role or caller identity', () => {
    const invitation = {
      inviteeUserId: ROOM,
      inviteeKeyId: ROOM,
      role: 'MEMBER',
      confirmedFingerprint: null,
      grantSignature: b64(64),
      envelopes: [{ keyVersion: 1, wrappedKey: b64(384) }],
    };
    expect(invitationCreateRequestSchema.safeParse(invitation).success).toBe(true);
    expect(
      invitationCreateRequestSchema.safeParse({ ...invitation, confirmedFingerprint: 'a'.repeat(64) }).success,
    ).toBe(true);
    for (const variant of [
      { ...invitation, role: 'OWNER' },
      { ...invitation, envelopes: [] },
      { ...invitation, envelopes: [{ keyVersion: 0, wrappedKey: b64(384) }] },
      { ...invitation, envelopes: [{ keyVersion: 1, wrappedKey: b64(384), rkm: b64(32) }] },
      { ...invitation, expiresAt: '2030-01-01T00:00:00.000Z' },
      { ...invitation, invitedById: ROOM },
      { ...invitation, confirmedFingerprint: 'A'.repeat(64) },
    ]) {
      expect(invitationCreateRequestSchema.safeParse(variant).success).toBe(false);
    }
  });

  it('records a Safety Code comparison or a key report with the key version only', () => {
    expect(safetyCodeRecordRequestSchema.safeParse({ keyVersion: 1, result: 'MATCH' }).success).toBe(true);
    expect(safetyCodeRecordRequestSchema.safeParse({ keyVersion: 1, result: 'MISMATCH' }).success).toBe(true);
    for (const field of ['code', 'words', 'digits', 'safetyCode']) {
      expect(
        safetyCodeRecordRequestSchema.safeParse({ keyVersion: 1, result: 'MATCH', [field]: 'orbit velvet' }).success,
      ).toBe(false);
    }
    expect(keyReportRequestSchema.safeParse({ keyVersion: 2, problem: 'COMMITMENT_MISMATCH' }).success).toBe(true);
    expect(
      keyReportRequestSchema.safeParse({ keyVersion: 2, problem: 'COMMITMENT_MISMATCH', commitment: b64(32) }).success,
    ).toBe(false);
  });
});

describe('list cursors (OL-08)', () => {
  it('round-trip the sort key of the last item', () => {
    const at = new Date('2026-10-06T05:10:11.123Z');
    const cursor = formatListCursor(at, ROOM);
    expect(cursor).toBe(`2026-10-06T05:10:11.123Z_${ROOM}`);
    expect(parseListCursor(cursor)).toEqual({ at, id: ROOM });
    expect(listQuerySchema.safeParse({ cursor }).success).toBe(true);
    expect(listQuerySchema.safeParse({}).success).toBe(true);
  });

  it.each([
    ['no separator', 'abc'],
    ['an invalid date', `2026-02-30T00:00:00.000Z_${ROOM}`],
    ['a non-canonical date', `2026-10-06T05:10:11Z_${ROOM}`],
    ['an uppercase ID', `2026-10-06T05:10:11.123Z_${ROOM.toUpperCase()}`],
    ['a trailing extra', `2026-10-06T05:10:11.123Z_${ROOM}x`],
  ])('refuse %s', (_label, cursor) => {
    expect(parseListCursor(cursor)).toBeUndefined();
    expect(listQuerySchema.safeParse({ cursor }).success).toBe(false);
  });

  it('refuse unknown query parameters', () => {
    expect(listQuerySchema.safeParse({ limit: '1000' }).success).toBe(false);
  });
});
