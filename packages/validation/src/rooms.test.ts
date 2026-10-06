import { describe, expect, it } from 'vitest';
import {
  formatListCursor,
  listQuerySchema,
  memberRoleChangeRequestSchema,
  parseListCursor,
  roomCreateRequestSchema,
  roomNameSchema,
  roomRenameRequestSchema,
} from './index';

// Room schemas (CM-T030, CM-T031): strict objects, normalized names, keyset cursors.
const ROOM = '0b2f6c1e-8d3a-4f5b-9c7d-2e1f0a9b8c7d';

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
    expect(roomCreateRequestSchema.safeParse({ roomId: ROOM, name: 'A', securityProfile: 'RESTRICTED' }).success).toBe(
      true,
    );
    for (const extra of [{ role: 'OWNER' }, { createdById: ROOM }, { keyState: 'ACTIVE' }, { envelope: 'AA' }]) {
      expect(
        roomCreateRequestSchema.safeParse({ roomId: ROOM, name: 'A', securityProfile: 'STANDARD', ...extra }).success,
      ).toBe(false);
    }
    expect(roomRenameRequestSchema.safeParse({ name: 'B', roomId: ROOM }).success).toBe(false);
  });

  it('never accept OWNER or an unknown role in a role change', () => {
    for (const role of ['ADMIN', 'MEMBER', 'VIEWER'])
      expect(memberRoleChangeRequestSchema.safeParse({ role }).success).toBe(true);
    for (const role of ['OWNER', 'admin', 'PLATFORM_ADMIN', '', null]) {
      expect(memberRoleChangeRequestSchema.safeParse({ role }).success).toBe(false);
    }
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
