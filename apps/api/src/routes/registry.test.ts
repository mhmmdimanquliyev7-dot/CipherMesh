import { emptyQuerySchema, healthResponseSchema, uuidV4Schema, z } from '@ciphermesh/validation';
import { describe, expect, it } from 'vitest';
import type { RoomAuthorizer } from '../authorization/rooms';
import { createLifecycle } from '../lifecycle';
import {
  buildRouter,
  defineRoute,
  RouteRegistrationError,
  type AnyRoute,
  type Authenticator,
  type PublicRouteEntry,
} from './registry';
import { PUBLIC_ROUTE_ALLOWLIST, systemRoutes } from './system';

const route = (overrides: Partial<AnyRoute> = {}): AnyRoute => ({
  ...defineRoute({
    method: 'GET',
    path: '/probe',
    action: 'TEST-PROBE',
    access: { kind: 'public', justification: 'test' },
    query: emptyQuerySchema,
    body: undefined,
    response: healthResponseSchema,
    handler: () => ({ status: 200, body: { status: 'ok' as const } }),
  }),
  ...overrides,
});

const allow: PublicRouteEntry[] = [
  { method: 'GET', path: '/probe' },
  { method: 'POST', path: '/probe' },
];

const authenticator: Authenticator = {
  authenticate: () => Promise.resolve({ failure: 'missing' as const }),
  now: () => new Date(),
};

// Registration never calls the room authorizer; requests are tested against the real one
// (tests/authz/room-access.test.ts).
const rooms: RoomAuthorizer = {
  authorize: () => Promise.reject(new Error('not used during registration')),
};

const roomParams = z.strictObject({ roomId: uuidV4Schema });
const memberParams = z.strictObject({ roomId: uuidV4Schema, userId: uuidV4Schema });
const loadNothing = () => Promise.resolve(null);

/** A valid room route (AZ-01), changed by the overrides. */
const roomRoute = (overrides: Partial<AnyRoute> = {}): AnyRoute =>
  route({ path: '/rooms/:roomId', action: 'AZ-01-PROBE', access: { kind: 'room' }, params: roomParams, ...overrides });

const register = (routes: AnyRoute[]) => buildRouter(routes, allow, authenticator, rooms);

describe('route registry', () => {
  it('registers the system routes as the only public routes', () => {
    const { registered } = buildRouter(
      systemRoutes(createLifecycle(), { ping: () => Promise.resolve(true) }),
      PUBLIC_ROUTE_ALLOWLIST,
    );
    expect(registered).toEqual([
      { method: 'GET', path: '/health', action: 'SYS-HEALTH', access: 'public' },
      { method: 'GET', path: '/ready', action: 'SYS-READY', access: 'public' },
    ]);
  });

  it.each([
    [
      'authenticated routes without an authenticator (fail closed)',
      route({ access: { kind: 'authenticated' } }),
      /without an authenticator/,
    ],
    ['public routes missing from the allowlist', route({ path: '/other' }), /allowlist/],
    [
      'public routes without a justification',
      route({ access: { kind: 'public', justification: ' ' } }),
      /justification/,
    ],
    ['routes without a valid action ID', route({ action: 'probe' }), /action ID/],
    ['POST routes without a body schema', route({ method: 'POST' }), /body schema/],
    ['GET routes with a body schema', route({ body: z.strictObject({}) }), /body schema/],
  ])('refuses %s', (_label, bad, message) => {
    expect(() => buildRouter([bad], allow)).toThrow(RouteRegistrationError);
    expect(() => buildRouter([bad], allow)).toThrow(message);
  });

  it('refuses duplicate registrations', () => {
    expect(() => buildRouter([route(), route()], allow)).toThrow(/registered twice/);
  });

  it('refuses an authenticated route that is also on the public allowlist', () => {
    const authenticated = { action: 'SS-01-PROBE', access: { kind: 'authenticated' } } as const;
    expect(() => buildRouter([route(authenticated)], allow, authenticator)).toThrow(/on the public allowlist/);
    expect(() => buildRouter([route({ ...authenticated, path: '/private' })], allow, authenticator)).not.toThrow();
  });
});

describe('route registry: authorization declarations (CM-T029)', () => {
  const authenticated = (overrides: Partial<AnyRoute>) =>
    route({ path: '/private', access: { kind: 'authenticated' }, ...overrides });

  it('accepts self-service and platform actions with the declarations the matrix requires', () => {
    expect(() =>
      register([
        authenticated({ action: 'SS-01-SESSION' }),
        authenticated({ path: '/vault', action: 'SS-02-VAULT-READ' }),
        authenticated({
          method: 'POST',
          path: '/admin/users/disable',
          action: 'PA-03-DISABLE',
          body: z.strictObject({}),
          access: { kind: 'authenticated', requires: { platformAdmin: true, stepUp: 'standard' } },
        }),
      ]),
    ).not.toThrow();
  });

  it.each([
    ['a public route that declares a matrix action', route({ action: 'SS-01-PROBE' }), /public route cannot/],
    ['an authenticated route without a matrix action', authenticated({ action: 'TEST-PROBE' }), /must declare/],
    ['an unknown room action', roomRoute({ action: 'AZ-31-PROBE' }), /AZ-31 is not in the authorization matrix/],
    ['an unknown self-service action', authenticated({ action: 'SS-06-PROBE' }), /SS-06 is not in/],
    ['an unknown platform action', authenticated({ action: 'PA-00-PROBE' }), /PA-00 is not in/],
    ['a room action on an authenticated route', authenticated({ action: 'AZ-01-PROBE' }), /not a self-service/],
    ['the explicit deny PA-05 as an action', authenticated({ action: 'PA-05-PROBE' }), /not a self-service/],
    ['a platform action without the administrator gate', authenticated({ action: 'PA-01-DASHBOARD' }), /platform/],
    [
      'a self-service action behind the administrator gate',
      authenticated({ action: 'SS-01-PROBE', access: { kind: 'authenticated', requires: { platformAdmin: true } } }),
      /platform actions, and only they/,
    ],
    [
      'PA-03 without a step-up',
      authenticated({ action: 'PA-03-DISABLE', access: { kind: 'authenticated', requires: { platformAdmin: true } } }),
      /PA-03 requires a step-up/,
    ],
  ])('refuses %s', (_label, bad, message) => {
    expect(() => register([bad])).toThrow(RouteRegistrationError);
    expect(() => register([bad])).toThrow(message);
  });
});

describe('route registry: room routes (CM-T029, OL-01)', () => {
  const roleChange = (overrides: Partial<AnyRoute> = {}) =>
    roomRoute({
      method: 'POST',
      path: '/rooms/:roomId/members/:userId/role',
      action: 'AZ-10-ROLE-CHANGE',
      params: memberParams,
      body: z.strictObject({ role: z.enum(['ADMIN', 'MEMBER', 'VIEWER']) }),
      access: { kind: 'room', resource: loadNothing },
      ...overrides,
    });

  it('accepts room routes that declare a room action, the room path, a loader and step-ups as required', () => {
    const { registered } = register([
      roomRoute(),
      roleChange(),
      roomRoute({
        method: 'POST',
        path: '/rooms/:roomId/delete',
        action: 'AZ-04-ROOM-DELETE',
        body: z.strictObject({}),
        access: { kind: 'room', requires: { stepUp: 'standard' } },
      }),
    ]);
    expect(registered.map((r) => `${r.method} ${r.path} ${r.action} ${r.access}`)).toEqual([
      'GET /rooms/:roomId AZ-01-PROBE room',
      'POST /rooms/:roomId/members/:userId/role AZ-10-ROLE-CHANGE room',
      'POST /rooms/:roomId/delete AZ-04-ROOM-DELETE room',
    ]);
  });

  it.each([
    ['a self-service action on a room route', roomRoute({ action: 'SS-01-PROBE' }), /must declare a room action/],
    ['a non-matrix action on a room route', roomRoute({ action: 'TEST-PROBE' }), /must declare a matrix action/],
    ['the inherited action AZ-27', roomRoute({ action: 'AZ-27-INSPECT' }), /no permission of its own/],
    [
      'a room route whose path does not start with the room ID',
      roomRoute({ path: '/members/:roomId', params: roomParams }),
      /starts with \/rooms\/:roomId/,
    ],
    [
      'a room route keyed by another parameter name',
      roomRoute({ path: '/rooms/:id', params: z.strictObject({ id: uuidV4Schema }) }),
      /starts with \/rooms\/:roomId/,
    ],
    [
      'AZ-04 without a step-up',
      roomRoute({ method: 'POST', action: 'AZ-04-ROOM-DELETE', body: z.strictObject({}) }),
      /AZ-04 requires a step-up/,
    ],
    [
      'AZ-05 without a step-up',
      roleChange({ action: 'AZ-05-TRANSFER', access: { kind: 'room', resource: loadNothing } }),
      /AZ-05 requires a step-up/,
    ],
    ['a target-dependent action without a loader', roleChange({ access: { kind: 'room' } }), /needs a resource/],
    [
      'a loader on an action that does not depend on the target',
      roomRoute({ access: { kind: 'room', resource: loadNothing } }),
      /takes no resource loader/,
    ],
    [
      'the platform administrator gate on a room route',
      roomRoute({ access: { kind: 'room', requires: { platformAdmin: true } as never } }),
      /PLATFORM_ADMIN has no room access/,
    ],
    ['a room route on the public allowlist', roomRoute({ path: '/probe' }), /on the public allowlist/],
    [
      'an authenticated route below /rooms/:roomId, which would skip the membership check',
      roomRoute({ action: 'SS-04-PROBE', access: { kind: 'authenticated' } }),
      /a path that names a room must be a room route/,
    ],
    [
      'an authenticated route below /rooms/ with another parameter name',
      roomRoute({
        path: '/rooms/:id',
        params: z.strictObject({ id: uuidV4Schema }),
        action: 'SS-04-PROBE',
        access: { kind: 'authenticated' },
      }),
      /a path that names a room must be a room route/,
    ],
    [
      'an authenticated route with a :roomId parameter elsewhere in the path',
      roomRoute({ path: '/invitations/:roomId', action: 'SS-03-PROBE', access: { kind: 'authenticated' } }),
      /a path that names a room must be a room route/,
    ],
  ])('refuses %s', (_label, bad, message) => {
    expect(() => register([bad])).toThrow(RouteRegistrationError);
    expect(() => register([bad])).toThrow(message);
  });

  it('refuses a public route that names a room', () => {
    const publicRoom = roomRoute({ access: { kind: 'public', justification: 'test' }, action: 'TEST-PROBE' });
    expect(() => buildRouter([publicRoom], [{ method: 'GET', path: '/rooms/:roomId' }], authenticator, rooms)).toThrow(
      /a path that names a room must be a room route/,
    );
  });

  it('still allows the room collection path, which names no room (SS-04, create a room)', () => {
    const create = route({
      method: 'POST',
      path: '/rooms',
      action: 'SS-04-ROOM-CREATE',
      body: z.strictObject({}),
      access: { kind: 'authenticated' },
    });
    expect(() => register([create])).not.toThrow();
  });

  it('refuses room routes without an authenticator or without a room authorizer (fail closed)', () => {
    expect(() => buildRouter([roomRoute()], allow)).toThrow(/room route registered without an authenticator/);
    expect(() => buildRouter([roomRoute()], allow, authenticator)).toThrow(/without a room authorizer/);
  });
});

describe('route registry: path parameters', () => {
  const authenticatedAt = (path: string) => route({ path, action: 'SS-01-PROBE', access: { kind: 'authenticated' } });

  it.each([
    ['a parameterized path without a params schema', roomRoute({ params: undefined }), /exactly the path parameters/],
    ['a params schema on a path without parameters', route({ params: roomParams }), /no parameters/],
    [
      'a params schema with an extra key',
      roomRoute({ params: z.strictObject({ roomId: uuidV4Schema, other: uuidV4Schema }) }),
      /exactly the path parameters/,
    ],
    [
      'a params schema with a different key',
      roomRoute({ params: z.strictObject({ room: uuidV4Schema }) }),
      /exactly the path parameters/,
    ],
    ['a params schema that is not an object', roomRoute({ params: uuidV4Schema }), /exactly the path parameters/],
    ['a repeated parameter', roomRoute({ path: '/rooms/:roomId/copy/:roomId' }), /repeats/],
    ['a wildcard segment', roomRoute({ path: '/rooms/:roomId/*rest' }), /lowercase static segments/],
    ['an optional segment', roomRoute({ path: '/rooms/:roomId{/extra}' }), /lowercase static segments/],
    ['an uppercase segment', authenticatedAt('/Private'), /lowercase static segments/],
    ['a trailing slash', authenticatedAt('/private/'), /lowercase static segments/],
    ['an empty segment', authenticatedAt('/private//probe'), /lowercase static segments/],
  ])('refuses %s', (_label, bad, message) => {
    expect(() => register([bad])).toThrow(RouteRegistrationError);
    expect(() => register([bad])).toThrow(message);
  });
});
