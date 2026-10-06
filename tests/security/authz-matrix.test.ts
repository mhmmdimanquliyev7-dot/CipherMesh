import {
  ACCOUNT_ACTIONS,
  ROOM_ACTION_IDS,
  ROOM_ACTIONS,
  ROOM_ROLES,
  type AccountActionId,
  type RoomActionId,
  type RoomRole,
  type RoomRule,
} from '@ciphermesh/shared';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

// `authz-matrix` suite (security testing plan section 3, CM-T029). The normative matrix is the
// table in docs/security/authorization-model.md; the enforced matrix is the catalogue in
// packages/shared. This suite parses the document and compares every cell, so a changed cell on
// either side fails CI until both say the same. The decision function itself is tested
// exhaustively in packages/shared/src/authorization.test.ts and end to end in tests/authz.
const MODEL = readFileSync(new URL('../../docs/security/authorization-model.md', import.meta.url), 'utf8');

/** The table rows of one section, split into trimmed cells. */
function tableRows(heading: string, prefix: RegExp): string[][] {
  const start = MODEL.indexOf(`\n## ${heading}`);
  expect(start, `section "${heading}" in the authorization model`).toBeGreaterThan(0);
  const end = MODEL.indexOf('\n## ', start + 1);
  return MODEL.slice(start, end === -1 ? undefined : end)
    .split('\n')
    .filter((line) => prefix.test(line))
    .map((line) =>
      line
        .split('|')
        .slice(1, -1)
        .map((cell) => cell.trim()),
    );
}

/** One cell of section 3 in the notation of the document. Anything unknown fails the suite. */
function parseCell(cell: string): RoomRule {
  if (cell === 'Same as read access to the item') return { kind: 'inherited' };
  if (cell === 'Recipient') return { kind: 'recipient' };
  if (/^own\b/.test(cell)) return { kind: 'own' };
  if (/^N\b/.test(cell)) return { kind: 'deny' };
  const yes = /^Y(?: \((.*)\))?$/.exec(cell);
  if (yes === null) throw new Error(`Unrecognized matrix cell: "${cell}"`);
  const named: readonly string[] = (yes[1] ?? '').match(/\b(?:OWNER|ADMIN|MEMBER|VIEWER)\b/g) ?? [];
  // "Y (any)" and plain "Y" allow; "Y (ADMIN, MEMBER, VIEWER)" is a ceiling on the roles touched.
  return named.length === 0
    ? { kind: 'allow' }
    : { kind: 'targetRoles', roles: ROOM_ROLES.filter((r) => named.includes(r)) };
}

/**
 * Reviewed cells whose restriction is written in the action title instead of the cell. AZ-05 says
 * "Y" for the OWNER, and the action is "Transfer ownership to an ADMIN": only a current ADMIN can
 * become the new owner.
 */
const TITLE_RESTRICTIONS: Partial<
  Record<RoomActionId, { readonly title: RegExp; readonly cells: Partial<Record<RoomRole, RoomRule>> }>
> = {
  'AZ-05': { title: /to an ADMIN$/, cells: { OWNER: { kind: 'targetRoles', roles: ['ADMIN'] } } },
};

const roomRows = tableRows('3. Room authorization matrix', /^\| AZ-\d{2} \|/);
const accountRows = tableRows('4. Platform and self-service actions', /^\| (?:PA|SS)-\d{2} \|/);

describe('authz-matrix: the enforced room matrix equals the normative table', () => {
  it('has exactly the actions of section 3, in order', () => {
    expect(roomRows.map((row) => row[0])).toEqual([...ROOM_ACTION_IDS]);
  });

  it.each(roomRows.map((row) => [row[0] ?? '', row] as const))('%s matches its row', (id, row) => {
    const [, title = '', owner = '', admin = '', member = '', viewer = '', notes = ''] = row;
    const action = ROOM_ACTIONS[id as RoomActionId];
    expect(action.title).toBe(title);
    // AZ-27 writes one statement across all four role columns.
    const cells =
      owner === 'Same as read access to the item' ? [owner, owner, owner, owner] : [owner, admin, member, viewer];
    const exception = TITLE_RESTRICTIONS[id as RoomActionId];
    if (exception !== undefined) expect(title).toMatch(exception.title);
    ROOM_ROLES.forEach((role, column) => {
      const expected = exception?.cells[role] ?? parseCell(cells[column] ?? '');
      expect(action.rules[role], `${id} for ${role}`).toEqual(expected);
    });
    // Step-ups the matrix demands in every profile are part of the catalogue, so the route
    // registry can refuse a route that forgets them. Profile-dependent step-ups (PC-03) are not.
    expect(action.stepUp === 'always', `${id} step-up`).toBe(notes.includes('Step-up in every profile'));
  });
});

describe('authz-matrix: the platform and self-service actions equal section 4', () => {
  it('has exactly the actions of section 4, in order', () => {
    expect(accountRows.map((row) => row[0])).toEqual(Object.keys(ACCOUNT_ACTIONS));
  });

  it.each(accountRows.map((row) => [row[0] ?? '', row] as const))('%s matches its row', (id, row) => {
    const [, title = '', who = '', notes = ''] = row;
    const action = ACCOUNT_ACTIONS[id as AccountActionId];
    expect(action.title).toBe(title);
    const scope = id.startsWith('SS-')
      ? 'self'
      : who === 'PLATFORM_ADMIN'
        ? 'platform'
        : who === 'Nobody outside the room'
          ? 'none'
          : 'unknown';
    expect(action.scope).toBe(scope);
    // PA-03 and PA-04 need a step-up every time; self-service step-ups depend on the operation.
    expect(action.stepUp === 'always', `${id} step-up`).toBe(id.startsWith('PA-') && /step-up/i.test(notes));
  });
});

describe('authz-matrix: invariants of the role model (section 2)', () => {
  it('never lets an ADMIN create, remove or demote an ADMIN, or anyone grant OWNER outside AZ-05', () => {
    for (const id of ['AZ-06', 'AZ-09', 'AZ-10'] as const) {
      const adminCell = ROOM_ACTIONS[id].rules.ADMIN;
      const ownerCell = ROOM_ACTIONS[id].rules.OWNER;
      expect(adminCell.kind === 'targetRoles' && !adminCell.roles.includes('ADMIN')).toBe(true);
      expect(ownerCell.kind === 'targetRoles' && !ownerCell.roles.includes('OWNER')).toBe(true);
    }
  });

  it('gives no role anything beyond its own column: lower roles never exceed higher ones', () => {
    const rank = (rule: RoomRule): number =>
      ({ deny: 0, inherited: 0, own: 1, recipient: 1, targetRoles: 1, allow: 2 })[rule.kind];
    for (const id of ROOM_ACTION_IDS) {
      const { OWNER, ADMIN, MEMBER, VIEWER } = ROOM_ACTIONS[id].rules;
      // AZ-11 is the one exception by design: every role except the OWNER may leave.
      if (id === 'AZ-11') continue;
      expect(rank(VIEWER) <= rank(MEMBER) && rank(MEMBER) <= rank(ADMIN) && rank(ADMIN) <= rank(OWNER), id).toBe(true);
    }
  });
});
