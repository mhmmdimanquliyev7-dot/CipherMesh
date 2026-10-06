import { randomUUID } from 'node:crypto';
import type { Browser } from './auth';
import type { Person } from './rooms';

/**
 * CM-T032: the reviewed inventory of every production route that takes a room or user identifier
 * or lists rooms, with the attack classes that tests/authz/bola.test.ts runs against it. The
 * suite iterates over THIS table, and tests/security/bola-inventory.test.ts fails when it differs
 * from the registry in either direction, so a new room route cannot ship without a case here and
 * a removed route cannot leave a stale one.
 *
 * Attack classes (prompt 07C section 4):
 *   A  a member of room A addresses the existing room B
 *   B  the same request answers identically for a nonexistent room (non-disclosure)
 *   C  addressed room A, target member of room B (cross-room target)
 *   D  role variants: OWNER, ADMIN, MEMBER, VIEWER, outsider, PLATFORM_ADMIN, and people who are
 *      members of two rooms with different roles
 *   E  membership states: SUSPENDED, REMOVED, LEFT
 *   F  room states: DELETING, DELETED, REKEY_REQUIRED
 *   G  every denied mutation leaves rooms and memberships byte-for-byte unchanged
 *   H  client-supplied identity (body, query, headers) never changes the outcome
 */
export type Response = Awaited<ReturnType<Browser['request']>>;

export type AttackClass = 'A' | 'B' | 'C' | 'D' | 'E' | 'F' | 'G' | 'H';

export interface RoomRef {
  readonly roomId: string;
  /** The user ID in the path, for routes that name a member. */
  readonly userId?: string;
}

export interface Extras {
  /** Extra body fields (POST), or extra query parameters (GET). */
  readonly fields?: Readonly<Record<string, string>>;
  readonly headers?: Readonly<Record<string, string>>;
}

export interface BolaCase {
  /** `METHOD path` exactly as the registry lists it. */
  readonly key: string;
  readonly kind: 'room' | 'collection';
  readonly mutates: boolean;
  /** The path names a member (`:userId`); the target may belong to another room. */
  readonly targetsMember: boolean;
  /** The route requires a recent step-up, so attackers confirm their account first. */
  readonly stepUp: boolean;
  /** For targeted routes: which member of room B is the target. */
  readonly target?: 'MEMBER' | 'ADMIN';
  readonly classes: readonly AttackClass[];
  readonly send: (who: Person, ref: RoomRef, extras?: Extras) => Promise<Response>;
}

const query = (fields: Readonly<Record<string, string>> | undefined): string =>
  fields === undefined || Object.keys(fields).length === 0 ? '' : `?${new URLSearchParams(fields).toString()}`;

const get =
  (path: (ref: RoomRef) => string): BolaCase['send'] =>
  (who, ref, extras) =>
    who.browser.request('GET', `${path(ref)}${query(extras?.fields)}`, undefined, { ...extras?.headers });

const post =
  (path: (ref: RoomRef) => string, body: Readonly<Record<string, unknown>>): BolaCase['send'] =>
  (who, ref, extras) =>
    who.browser.request('POST', path(ref), { ...body, ...extras?.fields }, { ...extras?.headers });

const member = (ref: RoomRef): string => ref.userId ?? randomUUID();

export const BOLA_CASES: readonly BolaCase[] = [
  {
    key: 'GET /rooms/:roomId',
    kind: 'room',
    mutates: false,
    targetsMember: false,
    stepUp: false,
    classes: ['A', 'B', 'D', 'E', 'F', 'H'],
    send: get((ref) => `/rooms/${ref.roomId}`),
  },
  {
    key: 'GET /rooms/:roomId/members',
    kind: 'room',
    mutates: false,
    targetsMember: false,
    stepUp: false,
    classes: ['A', 'B', 'D', 'E', 'F', 'H'],
    send: get((ref) => `/rooms/${ref.roomId}/members`),
  },
  {
    key: 'POST /rooms/:roomId/rename',
    kind: 'room',
    mutates: true,
    targetsMember: false,
    stepUp: false,
    classes: ['A', 'B', 'D', 'E', 'F', 'G', 'H'],
    send: post((ref) => `/rooms/${ref.roomId}/rename`, { name: 'Hijacked name' }),
  },
  {
    key: 'POST /rooms/:roomId/delete',
    kind: 'room',
    mutates: true,
    targetsMember: false,
    stepUp: true,
    classes: ['A', 'B', 'D', 'E', 'F', 'G', 'H'],
    send: post((ref) => `/rooms/${ref.roomId}/delete`, {}),
  },
  {
    key: 'POST /rooms/:roomId/members/:userId/role',
    kind: 'room',
    mutates: true,
    targetsMember: true,
    stepUp: false,
    target: 'MEMBER',
    classes: ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'],
    send: post((ref) => `/rooms/${ref.roomId}/members/${member(ref)}/role`, { role: 'VIEWER' }),
  },
  {
    key: 'POST /rooms/:roomId/members/:userId/remove',
    kind: 'room',
    mutates: true,
    targetsMember: true,
    stepUp: false,
    target: 'MEMBER',
    classes: ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'],
    send: post((ref) => `/rooms/${ref.roomId}/members/${member(ref)}/remove`, {}),
  },
  {
    key: 'POST /rooms/:roomId/members/:userId/transfer-ownership',
    kind: 'room',
    mutates: true,
    targetsMember: true,
    stepUp: true,
    target: 'ADMIN',
    classes: ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'],
    send: post((ref) => `/rooms/${ref.roomId}/members/${member(ref)}/transfer-ownership`, {}),
  },
  // Self-service routes name no room. They are covered for caller-controlled identity (H) only:
  // the rooms they return or create belong to the session user, never to a request field.
  {
    key: 'GET /rooms',
    kind: 'collection',
    mutates: false,
    targetsMember: false,
    stepUp: false,
    classes: ['H'],
    send: get(() => '/rooms'),
  },
  {
    key: 'POST /rooms',
    kind: 'collection',
    mutates: true,
    targetsMember: false,
    stepUp: false,
    classes: ['H'],
    send: (who, ref, extras) =>
      who.browser.request(
        'POST',
        '/rooms',
        { roomId: ref.roomId, name: 'Hijack attempt', securityProfile: 'STANDARD', ...extras?.fields },
        { ...extras?.headers },
      ),
  },
];

export const ROOM_CASES: readonly BolaCase[] = BOLA_CASES.filter((c) => c.kind === 'room');
