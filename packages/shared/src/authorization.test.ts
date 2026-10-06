import { describe, expect, it } from 'vitest';
import {
  ACCOUNT_ACTIONS,
  decideRoomAction,
  describeMatrixAction,
  isRoomActionId,
  isRoomRole,
  MEMBERSHIP_STATUSES,
  ROOM_ACTION_IDS,
  ROOM_ACTIONS,
  ROOM_ROLES,
  ROOM_STATUSES,
  roomRuleFor,
  type RoomActionId,
  type RoomDecision,
  type RoomDenyReason,
  type RoomMembershipFacts,
  type RoomResourceFacts,
  type RoomRole,
} from './index';

// CM-T029: exhaustive tests of the central room decision. The cell values themselves are compared
// with the normative table in tests/security/authz-matrix.test.ts; here every action and role is
// run through every kind of fact, and the security-critical cells are asserted independently.
const ROOM_A = '0b2f6c1e-8d3a-4f5b-9c7d-2e1f0a9b8c7d';
const ROOM_B = '1c3a7d2f-9e4b-4a6c-8d8e-3f2a1b0c9d8e';
const ACTOR = '2d4b8e3a-0f5c-4b7d-9e9f-4a3b2c1d0e9f';
const OTHER_USER = '3e5c9f4b-1a6d-4c8e-8f0a-5b4c3d2e1f0a';

const member = (role: RoomRole, overrides: Partial<RoomMembershipFacts> = {}): RoomMembershipFacts => ({
  roomId: ROOM_A,
  userId: ACTOR,
  role,
  status: 'ACTIVE',
  roomStatus: 'ACTIVE',
  ...overrides,
});

const decide = (
  action: RoomActionId,
  membership: RoomMembershipFacts | null,
  resource?: RoomResourceFacts,
): RoomDecision =>
  decideRoomAction({ actorUserId: ACTOR, roomId: ROOM_A, membership, action, ...(resource ? { resource } : {}) });

const allowed = (role: RoomRole): RoomDecision => ({ allowed: true, role });
const denied = (reason: RoomDenyReason): RoomDecision => ({ allowed: false, reason });

/** Facts that would satisfy every kind of cell: they must never turn a denial into an allow. */
const EVERYTHING: RoomResourceFacts = {
  roomId: ROOM_A,
  createdById: ACTOR,
  recipientUserId: ACTOR,
  roles: ['MEMBER'],
};

const ALL_CASES = ROOM_ACTION_IDS.flatMap((action) => ROOM_ROLES.map((role) => [action, role] as const));

/** Actions whose cell for the role is anything but deny or inherited. */
const permittedFor = (role: RoomRole): RoomActionId[] =>
  ROOM_ACTION_IDS.filter((action) => !['deny', 'inherited'].includes(ROOM_ACTIONS[action].rules[role].kind));

describe('room matrix catalogue', () => {
  it('lists AZ-01 to AZ-30 with a cell for exactly the four room roles', () => {
    expect(ROOM_ACTION_IDS).toEqual(Array.from({ length: 30 }, (_, i) => `AZ-${String(i + 1).padStart(2, '0')}`));
    for (const action of ROOM_ACTION_IDS) {
      expect(Object.keys(ROOM_ACTIONS[action].rules).sort()).toEqual([...ROOM_ROLES].sort());
    }
    expect(ROOM_ROLES).toEqual(['OWNER', 'ADMIN', 'MEMBER', 'VIEWER']);
    expect(MEMBERSHIP_STATUSES).toEqual(['ACTIVE', 'SUSPENDED', 'REMOVED', 'LEFT']);
    expect(ROOM_STATUSES).toEqual(['ACTIVE', 'DELETING', 'DELETED']);
  });

  it('lists the platform and self-service actions of section 4', () => {
    expect(Object.keys(ACCOUNT_ACTIONS)).toEqual([
      'PA-01',
      'PA-02',
      'PA-03',
      'PA-04',
      'PA-05',
      'SS-01',
      'SS-02',
      'SS-03',
      'SS-04',
      'SS-05',
      'SS-06',
    ]);
    expect(describeMatrixAction('SS-06')).toEqual({
      id: 'SS-06',
      scope: 'self',
      stepUpAlways: false,
      needsResource: false,
      inherited: false,
    });
  });

  it('is deeply frozen, so no code path can widen a permission at runtime', () => {
    const rules = ROOM_ACTIONS['AZ-04'].rules as Record<string, unknown>;
    expect(() => {
      rules['ADMIN'] = { kind: 'allow' };
    }).toThrow(TypeError);
    const ceiling = ROOM_ACTIONS['AZ-10'].rules.ADMIN;
    expect(ceiling.kind === 'targetRoles' && Object.isFrozen(ceiling.roles)).toBe(true);
    expect(() => {
      (ACCOUNT_ACTIONS['PA-05'] as { scope: string }).scope = 'platform';
    }).toThrow(TypeError);
    expect(roomRuleFor('AZ-04', 'ADMIN')).toEqual({ kind: 'deny' });
  });
});

describe('decideRoomAction: every action and role through every kind of fact', () => {
  it.each(ALL_CASES)('%s for %s', (action, role) => {
    const rule = ROOM_ACTIONS[action].rules[role];
    const as = member(role);
    switch (rule.kind) {
      case 'allow':
        expect(decide(action, as)).toEqual(allowed(role));
        expect(decide(action, as, { roomId: ROOM_A })).toEqual(allowed(role));
        expect(decide(action, as, { roomId: ROOM_B })).toEqual(denied('RESOURCE_OUTSIDE_ROOM'));
        break;
      case 'deny':
        expect(decide(action, as)).toEqual(denied('ROLE_NOT_PERMITTED'));
        expect(decide(action, as, EVERYTHING)).toEqual(denied('ROLE_NOT_PERMITTED'));
        break;
      case 'inherited':
        expect(decide(action, as)).toEqual(denied('INHERITED_ACTION'));
        expect(decide(action, as, EVERYTHING)).toEqual(denied('INHERITED_ACTION'));
        break;
      case 'own':
        expect(decide(action, as)).toEqual(denied('RESOURCE_REQUIRED'));
        expect(decide(action, as, { roomId: ROOM_A, createdById: ACTOR })).toEqual(allowed(role));
        expect(decide(action, as, { roomId: ROOM_A, createdById: OTHER_USER })).toEqual(denied('NOT_OWN_ITEM'));
        expect(decide(action, as, { roomId: ROOM_A, recipientUserId: ACTOR })).toEqual(denied('NOT_OWN_ITEM'));
        expect(decide(action, as, { roomId: ROOM_B, createdById: ACTOR })).toEqual(denied('RESOURCE_OUTSIDE_ROOM'));
        break;
      case 'recipient':
        expect(decide(action, as)).toEqual(denied('RESOURCE_REQUIRED'));
        expect(decide(action, as, { roomId: ROOM_A, recipientUserId: ACTOR })).toEqual(allowed(role));
        expect(decide(action, as, { roomId: ROOM_A, recipientUserId: OTHER_USER })).toEqual(denied('NOT_RECIPIENT'));
        expect(decide(action, as, { roomId: ROOM_A, createdById: ACTOR })).toEqual(denied('NOT_RECIPIENT'));
        expect(decide(action, as, { roomId: ROOM_B, recipientUserId: ACTOR })).toEqual(denied('RESOURCE_OUTSIDE_ROOM'));
        break;
      case 'targetRoles': {
        expect(decide(action, as)).toEqual(denied('RESOURCE_REQUIRED'));
        expect(decide(action, as, { roomId: ROOM_A, roles: rule.roles })).toEqual(allowed(role));
        for (const target of ROOM_ROLES) {
          const expected = rule.roles.includes(target) ? allowed(role) : denied('TARGET_ROLE_NOT_PERMITTED');
          expect(decide(action, as, { roomId: ROOM_A, roles: [target] })).toEqual(expected);
          // One role outside the ceiling is enough to deny, wherever it appears.
          if (!rule.roles.includes(target)) {
            expect(decide(action, as, { roomId: ROOM_A, roles: [...rule.roles, target] })).toEqual(
              denied('TARGET_ROLE_NOT_PERMITTED'),
            );
          }
        }
        expect(decide(action, as, { roomId: ROOM_A, roles: [] })).toEqual(denied('TARGET_ROLE_NOT_PERMITTED'));
        expect(decide(action, as, { roomId: ROOM_A })).toEqual(denied('TARGET_ROLE_NOT_PERMITTED'));
        expect(decide(action, as, { roomId: ROOM_A, roles: ['SUPERADMIN' as RoomRole] })).toEqual(
          denied('TARGET_ROLE_NOT_PERMITTED'),
        );
        expect(decide(action, as, { roomId: ROOM_B, roles: rule.roles })).toEqual(denied('RESOURCE_OUTSIDE_ROOM'));
        break;
      }
    }
  });
});

describe('decideRoomAction: membership is required, current and for this room (OL-01, T-05, T-06)', () => {
  it.each(ROOM_ACTION_IDS)('%s: no membership is a denial, whatever the facts', (action) => {
    expect(decide(action, null)).toEqual(denied('NOT_A_MEMBER'));
    expect(decide(action, null, EVERYTHING)).toEqual(denied('NOT_A_MEMBER'));
  });

  it.each(ALL_CASES)('%s: a %s membership of room B never authorizes room A', (action, role) => {
    expect(decide(action, member(role, { roomId: ROOM_B }))).toEqual(denied('MEMBERSHIP_MISMATCH'));
    expect(decide(action, member(role, { roomId: ROOM_B }), EVERYTHING)).toEqual(denied('MEMBERSHIP_MISMATCH'));
    // The same membership does authorize its own room for the same role and action.
    const own = decideRoomAction({
      actorUserId: ACTOR,
      roomId: ROOM_B,
      membership: member(role, { roomId: ROOM_B }),
      action,
    });
    expect(own.allowed || !['NOT_A_MEMBER', 'MEMBERSHIP_MISMATCH'].includes(own.reason)).toBe(true);
  });

  it.each(ALL_CASES)("%s: another user's %s membership never authorizes the caller", (action, role) => {
    expect(decide(action, member(role, { userId: OTHER_USER }), EVERYTHING)).toEqual(denied('MEMBERSHIP_MISMATCH'));
  });

  it.each(['SUSPENDED', 'REMOVED', 'LEFT', 'PENDING', ''])(
    'a %s membership grants nothing, even an OWNER one',
    (status) => {
      for (const action of ROOM_ACTION_IDS) {
        const as = member('OWNER', { status: status as RoomMembershipFacts['status'] });
        expect(decide(action, as)).toEqual(denied('MEMBERSHIP_NOT_ACTIVE'));
        expect(decide(action, as, EVERYTHING)).toEqual(denied('MEMBERSHIP_NOT_ACTIVE'));
      }
    },
  );

  it.each(['DELETING', 'DELETED', 'ARCHIVED', ''])('a %s room refuses every action, even to its OWNER', (status) => {
    for (const action of ROOM_ACTION_IDS) {
      const as = member('OWNER', { roomStatus: status as RoomMembershipFacts['roomStatus'] });
      expect(decide(action, as, EVERYTHING)).toEqual(denied('ROOM_NOT_ACTIVE'));
    }
  });

  it.each(['PLATFORM_ADMIN', 'SUPERADMIN', 'owner', 'ADMIN ', '', 'constructor'])(
    'an unknown room role %j grants nothing',
    (role) => {
      for (const action of ROOM_ACTION_IDS) {
        expect(decide(action, member(role as RoomRole), EVERYTHING)).toEqual(denied('UNKNOWN_ROLE'));
      }
    },
  );

  it.each(['AZ-31', 'AZ-00', 'AZ-1', 'PA-01', 'SS-04', '__proto__', 'constructor', 'toString', 'hasOwnProperty', ''])(
    'an undefined action %j is denied, even to the OWNER',
    (action) => {
      expect(decide(action as RoomActionId, member('OWNER'), EVERYTHING)).toEqual(denied('UNKNOWN_ACTION'));
      expect(roomRuleFor(action, 'OWNER')).toEqual({ kind: 'deny' });
    },
  );

  it('ignores the platform role: a PLATFORM_ADMIN without a membership is an outsider (PA-05)', () => {
    for (const action of ROOM_ACTION_IDS) {
      const input = { actorUserId: ACTOR, roomId: ROOM_A, membership: null, action, platformRole: 'PLATFORM_ADMIN' };
      expect(decideRoomAction(input)).toEqual(denied('NOT_A_MEMBER'));
    }
  });
});

describe('decideRoomAction: security-critical cells, asserted independently of the catalogue', () => {
  it('keeps OWNER-only actions OWNER-only: profile, deletion, ownership transfer, ADMIN invitation approval', () => {
    const ownerOnly = ROOM_ACTION_IDS.filter(
      (action) =>
        ROOM_ACTIONS[action].rules.OWNER.kind !== 'deny' &&
        (['ADMIN', 'MEMBER', 'VIEWER'] as const).every((role) => ROOM_ACTIONS[action].rules[role].kind === 'deny'),
    );
    expect(ownerOnly).toEqual(['AZ-03', 'AZ-04', 'AZ-05', 'AZ-07']);
    for (const action of ownerOnly) {
      for (const role of ['ADMIN', 'MEMBER', 'VIEWER'] as const) {
        expect(decide(action, member(role), { ...EVERYTHING, roles: ['ADMIN'] })).toEqual(denied('ROLE_NOT_PERMITTED'));
      }
    }
  });

  it('gives VIEWER and MEMBER exactly the actions of their columns', () => {
    expect(permittedFor('VIEWER')).toEqual([
      'AZ-01',
      'AZ-11',
      'AZ-12',
      'AZ-15',
      'AZ-17',
      'AZ-20',
      'AZ-24',
      'AZ-29',
      'AZ-30',
    ]);
    expect(permittedFor('MEMBER')).toEqual([
      'AZ-01',
      'AZ-11',
      'AZ-12',
      'AZ-15',
      'AZ-16',
      'AZ-17',
      'AZ-18',
      'AZ-19',
      'AZ-20',
      'AZ-21',
      'AZ-22',
      'AZ-23',
      'AZ-24',
      'AZ-25',
      'AZ-26',
      'AZ-29',
      'AZ-30',
    ]);
    expect(ROOM_ACTION_IDS.filter((a) => !permittedFor('ADMIN').includes(a))).toEqual([
      'AZ-03',
      'AZ-04',
      'AZ-05',
      'AZ-07',
      'AZ-27',
    ]);
    expect(ROOM_ACTION_IDS.filter((a) => !permittedFor('OWNER').includes(a))).toEqual(['AZ-11', 'AZ-27']);
  });

  it('lets a MEMBER change or delete only their own items (OL-04)', () => {
    for (const action of ['AZ-18', 'AZ-21', 'AZ-22', 'AZ-25'] as const) {
      expect(decide(action, member('MEMBER'), { roomId: ROOM_A, createdById: ACTOR })).toEqual(allowed('MEMBER'));
      expect(decide(action, member('MEMBER'), { roomId: ROOM_A, createdById: OTHER_USER })).toEqual(
        denied('NOT_OWN_ITEM'),
      );
      expect(decide(action, member('ADMIN'), { roomId: ROOM_A, createdById: OTHER_USER })).toEqual(allowed('ADMIN'));
    }
  });

  it('lets only the recipient reveal a secret, whatever their role (AZ-24, OL-06)', () => {
    for (const role of ROOM_ROLES) {
      expect(decide('AZ-24', member(role), { roomId: ROOM_A, recipientUserId: ACTOR })).toEqual(allowed(role));
      expect(decide('AZ-24', member(role), { roomId: ROOM_A, recipientUserId: OTHER_USER })).toEqual(
        denied('NOT_RECIPIENT'),
      );
    }
  });

  it('never lets an ADMIN create, promote to, remove or demote an ADMIN, or touch the OWNER (T-04)', () => {
    const admin = member('ADMIN');
    const touching = (...roles: RoomRole[]) => ({ roomId: ROOM_A, roles });
    expect(decide('AZ-06', admin, touching('ADMIN'))).toEqual(denied('TARGET_ROLE_NOT_PERMITTED'));
    expect(decide('AZ-10', admin, touching('MEMBER', 'ADMIN'))).toEqual(denied('TARGET_ROLE_NOT_PERMITTED'));
    expect(decide('AZ-10', admin, touching('ADMIN', 'MEMBER'))).toEqual(denied('TARGET_ROLE_NOT_PERMITTED'));
    expect(decide('AZ-10', admin, touching('OWNER', 'MEMBER'))).toEqual(denied('TARGET_ROLE_NOT_PERMITTED'));
    expect(decide('AZ-09', admin, touching('ADMIN'))).toEqual(denied('TARGET_ROLE_NOT_PERMITTED'));
    expect(decide('AZ-09', admin, touching('OWNER'))).toEqual(denied('TARGET_ROLE_NOT_PERMITTED'));
    expect(decide('AZ-10', admin, touching('MEMBER', 'VIEWER'))).toEqual(allowed('ADMIN'));
    expect(decide('AZ-10', admin, touching('VIEWER', 'MEMBER'))).toEqual(allowed('ADMIN'));
    expect(decide('AZ-09', admin, touching('VIEWER'))).toEqual(allowed('ADMIN'));
  });

  it('grants OWNER only through a transfer to a current ADMIN, never by role change or invitation (AZ-05)', () => {
    const owner = member('OWNER');
    const touching = (...roles: RoomRole[]) => ({ roomId: ROOM_A, roles });
    expect(decide('AZ-05', owner, touching('ADMIN'))).toEqual(allowed('OWNER'));
    for (const target of ['MEMBER', 'VIEWER', 'OWNER'] as const) {
      expect(decide('AZ-05', owner, touching(target))).toEqual(denied('TARGET_ROLE_NOT_PERMITTED'));
    }
    expect(decide('AZ-10', owner, touching('ADMIN', 'OWNER'))).toEqual(denied('TARGET_ROLE_NOT_PERMITTED'));
    expect(decide('AZ-06', owner, touching('OWNER'))).toEqual(denied('TARGET_ROLE_NOT_PERMITTED'));
    // The OWNER cannot remove or demote themselves either: their own role is OWNER.
    expect(decide('AZ-09', owner, touching('OWNER'))).toEqual(denied('TARGET_ROLE_NOT_PERMITTED'));
    expect(decide('AZ-10', owner, touching('OWNER', 'ADMIN'))).toEqual(denied('TARGET_ROLE_NOT_PERMITTED'));
    expect(decide('AZ-11', owner)).toEqual(denied('ROLE_NOT_PERMITTED'));
    expect(decide('AZ-10', owner, touching('ADMIN', 'MEMBER'))).toEqual(allowed('OWNER'));
  });
});

describe('matrix helpers', () => {
  it('recognises only the four room roles and the thirty room actions', () => {
    expect(ROOM_ROLES.every(isRoomRole)).toBe(true);
    for (const value of ['PLATFORM_ADMIN', 'USER', 'owner', '', undefined, 1, null])
      expect(isRoomRole(value)).toBe(false);
    expect(ROOM_ACTION_IDS.every(isRoomActionId)).toBe(true);
    for (const value of ['AZ-31', 'PA-03', '__proto__', 'constructor', undefined, 7]) {
      expect(isRoomActionId(value)).toBe(false);
    }
  });

  it('returns the cell, or deny for anything unknown', () => {
    expect(roomRuleFor('AZ-02', 'ADMIN')).toEqual({ kind: 'allow' });
    expect(roomRuleFor('AZ-02', 'MEMBER')).toEqual({ kind: 'deny' });
    expect(roomRuleFor('AZ-02', 'PLATFORM_ADMIN')).toEqual({ kind: 'deny' });
    expect(roomRuleFor('AZ-99', 'OWNER')).toEqual({ kind: 'deny' });
  });

  it('describes what a route must declare for each action', () => {
    const info = (id: string) => describeMatrixAction(id);
    expect(info('AZ-01')).toEqual({
      id: 'AZ-01',
      scope: 'room',
      stepUpAlways: false,
      needsResource: false,
      inherited: false,
    });
    expect(info('AZ-04')).toMatchObject({ scope: 'room', stepUpAlways: true, needsResource: false });
    expect(info('AZ-05')).toMatchObject({ scope: 'room', stepUpAlways: true, needsResource: true });
    expect(info('AZ-08')).toMatchObject({ needsResource: true });
    expect(info('AZ-10')).toMatchObject({ needsResource: true, stepUpAlways: false });
    expect(info('AZ-24')).toMatchObject({ needsResource: true });
    expect(info('AZ-27')).toMatchObject({ inherited: true, needsResource: false });
    expect(info('PA-03')).toEqual({
      id: 'PA-03',
      scope: 'platform',
      stepUpAlways: true,
      needsResource: false,
      inherited: false,
    });
    expect(info('PA-01')).toMatchObject({ scope: 'platform', stepUpAlways: false });
    expect(info('PA-05')).toMatchObject({ scope: 'none' });
    expect(info('SS-04')).toMatchObject({ scope: 'self', stepUpAlways: false });
    for (const unknown of ['AZ-31', 'PA-06', 'SS-00', 'XX-01', '__proto__', 'toString', '']) {
      expect(info(unknown)).toBeUndefined();
    }
  });
});
