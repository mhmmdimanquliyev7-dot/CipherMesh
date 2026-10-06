import {
  ASSIGNABLE_ROOM_ROLES,
  roomRuleFor,
  type AssignableRoomRole,
  type RoomActionId,
  type RoomRole,
} from '@ciphermesh/shared';

/**
 * Which controls to show, read from the shared matrix (packages/shared/src/authorization.ts).
 * UX only: the API decides every request against the membership stored in the database, and a
 * hidden or shown button changes nothing about that (INV-05).
 */
export function mayAttempt(action: RoomActionId, role: RoomRole, touched: readonly RoomRole[] = []): boolean {
  const rule = roomRuleFor(action, role);
  if (rule.kind === 'allow') return true;
  if (rule.kind === 'targetRoles') return touched.length > 0 && touched.every((r) => rule.roles.includes(r));
  return false;
}

/** The roles `role` may give a member who currently has `targetRole` (AZ-10). */
export function assignableRoles(role: RoomRole, targetRole: RoomRole): AssignableRoomRole[] {
  return ASSIGNABLE_ROOM_ROLES.filter((to) => to !== targetRole && mayAttempt('AZ-10', role, [targetRole, to]));
}

export const ROLE_LABEL: Readonly<Record<RoomRole, string>> = {
  OWNER: 'Owner',
  ADMIN: 'Admin',
  MEMBER: 'Member',
  VIEWER: 'Viewer',
};

export const PROFILE_DESCRIPTION: Readonly<Record<string, string>> = {
  STANDARD: 'Internal material of moderate sensitivity.',
  CONFIDENTIAL: 'Sensitive material. Needs a session verified with an authentication code, signed in within 4 hours.',
  RESTRICTED:
    'Highly sensitive material. Needs a session verified with an authentication code, signed in within 1 hour.',
};
