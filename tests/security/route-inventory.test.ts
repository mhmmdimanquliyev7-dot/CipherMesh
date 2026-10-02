import { describe, expect, it } from 'vitest';
import { createApp } from '../../apps/api/src/app';
import { loadConfig } from '../../apps/api/src/config/env';
import { createLifecycle } from '../../apps/api/src/lifecycle';
import { createLogger } from '../../apps/api/src/logging/logger';
import { PUBLIC_ROUTE_ALLOWLIST } from '../../apps/api/src/routes/system';

// Route inventory (security testing plan, `route-inventory` suite): the production
// application exposes exactly the allowlisted public routes and nothing else.
const logger = createLogger({ level: 'fatal', sink: { write: () => undefined } });

describe('route inventory', () => {
  it('registers only allowlisted public routes, each with an action ID', () => {
    const config = loadConfig({ NODE_ENV: 'production', APP_ORIGIN: 'https://ciphermesh.example' });
    const { routes } = createApp({ config, logger, lifecycle: createLifecycle() });
    expect(routes.map(({ method, path }) => ({ method, path }))).toEqual([...PUBLIC_ROUTE_ALLOWLIST]);
    expect(routes.every((route) => route.access === 'public' && /^[A-Z]/.test(route.action))).toBe(true);
  });

  it('mounts no route outside the registry', () => {
    const config = loadConfig({ NODE_ENV: 'production', APP_ORIGIN: 'https://ciphermesh.example' });
    const { app } = createApp({ config, logger, lifecycle: createLifecycle() });
    // Express keeps app-level layers on app.router.stack; a layer with `route` is a handler
    // mounted directly (app.get, app.post, ...), which would bypass the registry's checks.
    const stack = (app as unknown as { router: { stack: { route?: unknown }[] } }).router.stack;
    expect(stack.length).toBeGreaterThan(0);
    expect(stack.filter((layer) => layer.route !== undefined)).toEqual([]);
  });

  it('refuses test routes in production, so the public surface cannot be widened', () => {
    const config = loadConfig({ NODE_ENV: 'production', APP_ORIGIN: 'https://ciphermesh.example' });
    expect(() =>
      createApp({ config, logger, lifecycle: createLifecycle(), testing: { routes: [], publicAllowlist: [] } }),
    ).toThrow(/production/);
  });

  it('allowlists only the health and readiness probes in Phase 1', () => {
    expect(PUBLIC_ROUTE_ALLOWLIST).toEqual([
      { method: 'GET', path: '/health' },
      { method: 'GET', path: '/ready' },
    ]);
  });
});
