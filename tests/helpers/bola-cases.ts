import type { RoomActionId } from '@ciphermesh/shared';
import { randomBytes, randomUUID } from 'node:crypto';
import type { Browser } from './auth';
import type { Person } from './rooms';

/**
 * CM-T032: the reviewed inventory of every production route that takes a room or user identifier
 * or lists rooms, with the attack classes that tests/authz/bola.test.ts runs against it. The
 * suite iterates over THIS table, and tests/security/bola-inventory.test.ts fails when it differs
 * from the registry in either direction, so a new room route cannot ship without a case here and
 * a removed route cannot leave a stale one. Phase 6 added the key-material, invitation, key-report
 * and Safety Code routes (CM-T033 to CM-T036, CM-T085).
 *
 * Attack classes (prompt 07C section 4):
 *   A  a member of room A addresses the existing room B
 *   B  the same request answers identically for a nonexistent room (non-disclosure)
 *   C  addressed room A, target object of room B (a member or an invitation; cross-room target)
 *   D  role variants: OWNER, ADMIN, MEMBER, VIEWER, outsider, PLATFORM_ADMIN, and people who are
 *      members of two rooms with different roles
 *   E  membership states: SUSPENDED, REMOVED, LEFT
 *   F  room states: DELETING, DELETED, REKEY_REQUIRED
 *   G  every denied mutation leaves rooms, memberships, invitations, key versions and envelopes
 *      byte-for-byte unchanged
 *   H  client-supplied identity (body, query, headers) never changes the outcome
 */
export type Response = Awaited<ReturnType<Browser['request']>>;

export type AttackClass = 'A' | 'B' | 'C' | 'D' | 'E' | 'F' | 'G' | 'H';

export interface RoomRef {
  readonly roomId: string;
  /** The user ID in the path, for routes that name a member. */
  readonly userId?: string;
  /** The invitation ID in the path, for routes that name an invitation. */
  readonly invitationId?: string;
}

export interface Extras {
  /** Extra body fields (POST), or extra query parameters (GET). */
  readonly fields?: Readonly<Record<string, string>>;
  readonly headers?: Readonly<Record<string, string>>;
}

export interface BolaCase {
  /** `METHOD path` exactly as the registry lists it. */
  readonly key: string;
  /** The matrix action the route declares (AZ-xx), from which the expected denials follow. */
  readonly action?: RoomActionId;
  readonly kind: 'room' | 'collection';
  readonly mutates: boolean;
  /** The path names a member (`:userId`); the target may belong to another room. */
  readonly targetsMember: boolean;
  /** The path names an invitation (`:invitationId`); it may belong to another room. */
  readonly targetsInvitation: boolean;
  /** The route requires a recent step-up, so attackers confirm their account first. */
  readonly stepUp: boolean;
  /** For targeted routes: which object of the room is the target. */
  readonly target?: 'MEMBER' | 'ADMIN' | 'INVITATION';
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
  (path: (ref: RoomRef) => string, body: () => Readonly<Record<string, unknown>>): BolaCase['send'] =>
  (who, ref, extras) =>
    who.browser.request('POST', path(ref), { ...body(), ...extras?.fields }, { ...extras?.headers });

const member = (ref: RoomRef): string => ref.userId ?? randomUUID();
const invitation = (ref: RoomRef): string => ref.invitationId ?? randomUUID();
const b64 = (bytes: number): string => randomBytes(bytes).toString('base64url');

/** Well-formed bodies that nobody signed: authorization must refuse them before anything else. */
const fillerGrant = () => ({ subjectKeyId: randomUUID(), signature: b64(64) });
const fillerInvitation = () => ({
  inviteeUserId: randomUUID(),
  inviteeKeyId: randomUUID(),
  role: 'MEMBER',
  confirmedFingerprint: null,
  grantSignature: b64(64),
  envelopes: [{ keyVersion: 1, wrappedKey: b64(384) }],
});
const fillerKeys = () => ({
  creatorKeyId: randomUUID(),
  commitment: b64(32),
  envelope: b64(384),
  genesisSignature: b64(64),
  keyVersionSignature: b64(64),
});

const room = { kind: 'room', targetsMember: false, targetsInvitation: false, stepUp: false } as const;
const READ: readonly AttackClass[] = ['A', 'B', 'D', 'E', 'F', 'H'];
const WRITE: readonly AttackClass[] = ['A', 'B', 'D', 'E', 'F', 'G', 'H'];
const TARGETED_WRITE: readonly AttackClass[] = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'];

export const BOLA_CASES: readonly BolaCase[] = [
  {
    ...room,
    key: 'GET /rooms/:roomId',
    action: 'AZ-01',
    mutates: false,
    classes: READ,
    send: get((ref) => `/rooms/${ref.roomId}`),
  },
  {
    ...room,
    key: 'GET /rooms/:roomId/members',
    action: 'AZ-01',
    mutates: false,
    classes: READ,
    send: get((ref) => `/rooms/${ref.roomId}/members`),
  },
  {
    ...room,
    key: 'POST /rooms/:roomId/rename',
    action: 'AZ-02',
    mutates: true,
    classes: WRITE,
    send: post(
      (ref) => `/rooms/${ref.roomId}/rename`,
      () => ({ name: 'Hijacked name' }),
    ),
  },
  {
    ...room,
    key: 'POST /rooms/:roomId/delete',
    action: 'AZ-04',
    mutates: true,
    stepUp: true,
    classes: WRITE,
    send: post(
      (ref) => `/rooms/${ref.roomId}/delete`,
      () => ({}),
    ),
  },
  {
    ...room,
    key: 'POST /rooms/:roomId/members/:userId/role',
    action: 'AZ-10',
    mutates: true,
    targetsMember: true,
    target: 'MEMBER',
    classes: TARGETED_WRITE,
    send: post(
      (ref) => `/rooms/${ref.roomId}/members/${member(ref)}/role`,
      () => ({ role: 'VIEWER' }),
    ),
  },
  {
    ...room,
    key: 'POST /rooms/:roomId/members/:userId/remove',
    action: 'AZ-09',
    mutates: true,
    targetsMember: true,
    target: 'MEMBER',
    classes: TARGETED_WRITE,
    send: post(
      (ref) => `/rooms/${ref.roomId}/members/${member(ref)}/remove`,
      () => ({}),
    ),
  },
  {
    ...room,
    key: 'POST /rooms/:roomId/members/:userId/transfer-ownership',
    action: 'AZ-05',
    mutates: true,
    targetsMember: true,
    stepUp: true,
    target: 'ADMIN',
    classes: TARGETED_WRITE,
    send: post(
      (ref) => `/rooms/${ref.roomId}/members/${member(ref)}/transfer-ownership`,
      () => ({ grant: fillerGrant() }),
    ),
  },
  // ------------------------------------------------------------------- Phase 6: room keys
  {
    ...room,
    key: 'GET /rooms/:roomId/key-versions',
    action: 'AZ-15',
    mutates: false,
    classes: READ,
    send: get((ref) => `/rooms/${ref.roomId}/key-versions`),
  },
  {
    ...room,
    key: 'GET /rooms/:roomId/envelopes',
    action: 'AZ-12',
    mutates: false,
    classes: READ,
    send: get((ref) => `/rooms/${ref.roomId}/envelopes`),
  },
  {
    ...room,
    key: 'GET /rooms/:roomId/members/:userId/identity',
    action: 'AZ-01',
    mutates: false,
    targetsMember: true,
    target: 'MEMBER',
    classes: ['A', 'B', 'C', 'D', 'E', 'F', 'H'],
    send: get((ref) => `/rooms/${ref.roomId}/members/${member(ref)}/identity`),
  },
  {
    ...room,
    key: 'POST /rooms/:roomId/key-reports',
    action: 'AZ-29',
    mutates: true,
    classes: WRITE,
    send: post(
      (ref) => `/rooms/${ref.roomId}/key-reports`,
      () => ({ keyVersion: 1, problem: 'AUTHENTICATION_FAILED' }),
    ),
  },
  {
    ...room,
    key: 'POST /rooms/:roomId/safety-code',
    action: 'AZ-30',
    mutates: true,
    classes: WRITE,
    send: post(
      (ref) => `/rooms/${ref.roomId}/safety-code`,
      () => ({ keyVersion: 1, result: 'MATCH' }),
    ),
  },
  // ------------------------------------------------------------------ Phase 6: invitations
  {
    ...room,
    key: 'GET /rooms/:roomId/invitations',
    action: 'AZ-31',
    mutates: false,
    classes: READ,
    send: get((ref) => `/rooms/${ref.roomId}/invitations`),
  },
  {
    ...room,
    key: 'POST /rooms/:roomId/invitations',
    action: 'AZ-06',
    mutates: true,
    classes: WRITE,
    send: post((ref) => `/rooms/${ref.roomId}/invitations`, fillerInvitation),
  },
  {
    ...room,
    key: 'POST /rooms/:roomId/invitations/:invitationId/approve',
    action: 'AZ-07',
    mutates: true,
    targetsInvitation: true,
    target: 'INVITATION',
    classes: TARGETED_WRITE,
    send: post(
      (ref) => `/rooms/${ref.roomId}/invitations/${invitation(ref)}/approve`,
      () => ({}),
    ),
  },
  {
    ...room,
    key: 'POST /rooms/:roomId/invitations/:invitationId/revoke',
    action: 'AZ-08',
    mutates: true,
    targetsInvitation: true,
    target: 'INVITATION',
    classes: TARGETED_WRITE,
    send: post(
      (ref) => `/rooms/${ref.roomId}/invitations/${invitation(ref)}/revoke`,
      () => ({}),
    ),
  },
  // Self-service routes name no room. They are covered for caller-controlled identity (H) only:
  // the rooms they return or create belong to the session user, never to a request field.
  {
    key: 'GET /rooms',
    kind: 'collection',
    mutates: false,
    targetsMember: false,
    targetsInvitation: false,
    stepUp: false,
    classes: ['H'],
    send: get(() => '/rooms'),
  },
  {
    key: 'POST /rooms',
    kind: 'collection',
    mutates: true,
    targetsMember: false,
    targetsInvitation: false,
    stepUp: false,
    classes: ['H'],
    send: (who, ref, extras) =>
      who.browser.request(
        'POST',
        '/rooms',
        {
          roomId: ref.roomId,
          name: 'Hijack attempt',
          securityProfile: 'STANDARD',
          keys: fillerKeys(),
          ...extras?.fields,
        },
        { ...extras?.headers },
      ),
  },
];

export const ROOM_CASES: readonly BolaCase[] = BOLA_CASES.filter((c) => c.kind === 'room');
