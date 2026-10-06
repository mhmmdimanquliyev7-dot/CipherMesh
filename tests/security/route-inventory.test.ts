import { describeMatrixAction } from '@ciphermesh/shared';
import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createApp } from '../../apps/api/src/app';
import { loadConfig } from '../../apps/api/src/config/env';
import { createDatabase } from '../../apps/api/src/db/client';
import { createLifecycle } from '../../apps/api/src/lifecycle';
import { createLogger } from '../../apps/api/src/logging/logger';
import { AUTH_PUBLIC_ROUTES } from '../../apps/api/src/routes/auth';
import { PUBLIC_ROUTE_ALLOWLIST } from '../../apps/api/src/routes/system';

// Route inventory (security testing plan, `route-inventory` suite): the production application
// exposes exactly the reviewed public routes; every other route requires a session.
const logger = createLogger({ level: 'fatal', sink: { write: () => undefined } });
const PRODUCTION_ENV = {
  NODE_ENV: 'production',
  APP_ORIGIN: 'https://ciphermesh.example',
  // Never connected to: route registration needs no database.
  DATABASE_URL: 'postgresql://cm_api:unused-test-value@db.ciphermesh.example/ciphermesh?sslmode=verify-full',
  TOTP_ENCRYPTION_KEY: randomBytes(32).toString('base64url'),
  TOTP_ENCRYPTION_KEY_ID: 'inventory-test',
  IDENTIFIER_HMAC_KEY: randomBytes(32).toString('base64url'),
};

function productionApp(testing?: Parameters<typeof createApp>[0]['testing']) {
  const config = loadConfig(PRODUCTION_ENV);
  const database = createDatabase({ url: config.database.url, logger });
  return createApp({ config, logger, lifecycle: createLifecycle(), database, ...(testing ? { testing } : {}) });
}

/** The reviewed public surface. Changing it needs a security review and an update here. */
const EXPECTED_PUBLIC = [
  'GET /health',
  'GET /ready',
  'POST /auth/register',
  'POST /auth/login',
  'POST /auth/mfa/verify',
  'POST /auth/mfa/recovery',
];

describe('route inventory', () => {
  it('exposes exactly the reviewed public routes; everything else requires a session', () => {
    const { routes } = productionApp();
    const publicRoutes = routes.filter((r) => r.access === 'public').map((r) => `${r.method} ${r.path}`);
    expect(publicRoutes).toEqual(EXPECTED_PUBLIC);
    const others = routes.filter((r) => r.access !== 'public');
    expect(others.length).toBeGreaterThan(10);
    expect(others.every((r) => r.access === 'authenticated' || r.access === 'room')).toBe(true);
    expect(routes.every((r) => /^[A-Z]/.test(r.action))).toBe(true);
  });

  it('declares a matrix action for every route behind authentication, consistent with its access (CM-T029)', () => {
    const { routes } = productionApp();
    for (const route of routes) {
      const declared = describeMatrixAction(/^(?:AZ|PA|SS)-\d{2}/.exec(route.action)?.[0] ?? '');
      const label = `${route.method} ${route.path} ${route.action}`;
      if (route.access === 'public') expect(declared, label).toBeUndefined();
      else if (route.access === 'room') expect(declared?.scope, label).toBe('room');
      else expect(['self', 'platform'], label).toContain(declared?.scope);
    }
  });

  it('room routes exist only as reviewed (CM-T030, CM-T031; every one gets BOLA coverage in CM-T032)', () => {
    const { routes } = productionApp();
    const room = routes.filter((r) => r.access === 'room').map((r) => `${r.method} ${r.path} ${r.action}`);
    expect(room).toEqual([
      'GET /rooms/:roomId AZ-01-ROOM-READ',
      'GET /rooms/:roomId/members AZ-01-MEMBER-LIST',
      'POST /rooms/:roomId/rename AZ-02-ROOM-RENAME',
      'POST /rooms/:roomId/delete AZ-04-ROOM-DELETE',
      'POST /rooms/:roomId/members/:userId/role AZ-10-MEMBER-ROLE',
      'POST /rooms/:roomId/members/:userId/remove AZ-09-MEMBER-REMOVE',
      'POST /rooms/:roomId/members/:userId/transfer-ownership AZ-05-OWNERSHIP-TRANSFER',
    ]);
  });

  it('the allowlists contain exactly the reviewed public routes', () => {
    expect([...PUBLIC_ROUTE_ALLOWLIST, ...AUTH_PUBLIC_ROUTES].map((r) => `${r.method} ${r.path}`)).toEqual(
      EXPECTED_PUBLIC,
    );
  });

  it('mounts no route outside the registry', () => {
    const { app } = productionApp();
    // Express keeps app-level layers on app.router.stack; a layer with `route` is a handler
    // mounted directly (app.get, app.post, ...), which would bypass the registry's checks.
    const stack = (app as unknown as { router: { stack: { route?: unknown }[] } }).router.stack;
    expect(stack.length).toBeGreaterThan(0);
    expect(stack.filter((layer) => layer.route !== undefined)).toEqual([]);
  });

  it('refuses test seams in production, so the public surface and the clock cannot be changed', () => {
    expect(() => productionApp({ routes: [], publicAllowlist: [] })).toThrow(/production/);
    expect(() => productionApp({ clock: () => new Date(0) })).toThrow(/production/);
  });

  it('no GET route is an authentication action that changes state', () => {
    const { routes } = productionApp();
    const gets = routes.filter((r) => r.method === 'GET').map((r) => r.path);
    expect(gets).toEqual([
      '/health',
      '/ready',
      '/auth/session',
      '/auth/sessions',
      '/vault',
      // Phase 5: reads only (SS-06, AZ-01); every room change is a POST through the CSRF gate.
      '/rooms',
      '/rooms/:roomId',
      '/rooms/:roomId/members',
    ]);
  });

  it('the room self-service routes exist only as reviewed (CM-T030)', () => {
    const { routes } = productionApp();
    const own = routes.filter((r) => r.path === '/rooms').map((r) => `${r.method} ${r.path} ${r.action} ${r.access}`);
    expect(own).toEqual(['POST /rooms SS-04-ROOM-CREATE authenticated', 'GET /rooms SS-06-ROOM-LIST authenticated']);
  });

  it('the vault and directory routes exist only as reviewed, all authenticated (Phase 4)', () => {
    const { routes } = productionApp();
    const vault = routes
      .filter((r) => r.path.startsWith('/vault') || r.path.startsWith('/directory'))
      .map((r) => `${r.method} ${r.path} ${r.action} ${r.access}`);
    expect(vault).toEqual([
      'GET /vault SS-02-VAULT-READ authenticated',
      'POST /vault SS-02-VAULT-CREATE authenticated',
      'POST /vault/rewrap SS-02-VAULT-REWRAP authenticated',
      'POST /vault/reset SS-02-VAULT-RESET authenticated',
      'POST /directory/lookup SS-05-DIRECTORY-LOOKUP authenticated',
    ]);
  });
});
