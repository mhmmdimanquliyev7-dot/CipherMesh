import { emptyQuerySchema, healthResponseSchema, z } from '@ciphermesh/validation';
import { describe, expect, it } from 'vitest';
import { createLifecycle } from '../lifecycle';
import { buildRouter, defineRoute, RouteRegistrationError, type AnyRoute, type PublicRouteEntry } from './registry';
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
      'authenticated routes before authentication exists',
      route({ access: { kind: 'authenticated' } }),
      /authentication pipeline/,
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
});
