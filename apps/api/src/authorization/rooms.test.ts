import { MEMBERSHIP_STATUSES, ROOM_ROLES, ROOM_STATUSES } from '@ciphermesh/shared';
import { describe, expect, it } from 'vitest';
import { MembershipStatus, RoomRole, RoomStatus } from '../generated/prisma/enums';
import { roomDenialError, type RoomDenial } from './rooms';

// Error semantics of room denials (authorization model section 7, OL-01, OL-02, OL-06). The
// record type forces a decision for every reason: anything that could reveal a room or object to
// someone outside it is the generic 404; an active member without the permission gets 403.
const EXPECTED: Record<RoomDenial, 403 | 404> = {
  NOT_A_MEMBER: 404,
  MEMBERSHIP_MISMATCH: 404,
  MEMBERSHIP_NOT_ACTIVE: 404,
  ROOM_NOT_ACTIVE: 404,
  UNKNOWN_ROLE: 404,
  RESOURCE_OUTSIDE_ROOM: 404,
  RESOURCE_NOT_FOUND: 404,
  NOT_RECIPIENT: 404,
  UNKNOWN_ACTION: 403,
  ROLE_NOT_PERMITTED: 403,
  INHERITED_ACTION: 403,
  RESOURCE_REQUIRED: 403,
  NOT_OWN_ITEM: 403,
  TARGET_ROLE_NOT_PERMITTED: 403,
};

describe('room denial responses', () => {
  it.each(Object.entries(EXPECTED) as [RoomDenial, 403 | 404][])('%s answers %i', (reason, status) => {
    const error = roomDenialError(reason);
    expect(error.status).toBe(status);
    expect([error.code, error.message]).toEqual(
      status === 404
        ? ['NOT_FOUND', 'Resource not found']
        : ['FORBIDDEN', 'You do not have permission for this action'],
    );
    // The reason never reaches the client: no issues, no headers, no reason in the message.
    expect(error.issues).toBeUndefined();
    expect(error.headers).toEqual({});
    expect(error.message).not.toContain(reason);
  });

  it('uses the same room roles and states as the database enums', () => {
    expect(Object.values(RoomRole)).toEqual([...ROOM_ROLES]);
    expect(Object.values(MembershipStatus)).toEqual([...MEMBERSHIP_STATUSES]);
    expect(Object.values(RoomStatus)).toEqual([...ROOM_STATUSES]);
  });
});
