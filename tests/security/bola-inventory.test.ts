import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createApp } from '../../apps/api/src/app';
import { loadConfig } from '../../apps/api/src/config/env';
import { createDatabase } from '../../apps/api/src/db/client';
import { createLifecycle } from '../../apps/api/src/lifecycle';
import { createLogger } from '../../apps/api/src/logging/logger';
import { BOLA_CASES, ROOM_CASES } from '../helpers/bola-cases';

// CM-T032 (`bola` suite, security testing plan section 3): the BOLA and IDOR attack suite
// (tests/authz/bola.test.ts) iterates over the table in tests/helpers/bola-cases.ts. This test
// ties that table to the production registry, so a route that takes a room or user identifier
// cannot be added without a reviewed case, and a case cannot outlive its route. It needs no
// database: route registration connects to nothing.
const logger = createLogger({ level: 'fatal', sink: { write: () => undefined } });
const config = loadConfig({
  NODE_ENV: 'production',
  APP_ORIGIN: 'https://ciphermesh.example',
  DATABASE_URL: 'postgresql://cm_api:unused-test-value@db.ciphermesh.example/ciphermesh?sslmode=verify-full',
  TOTP_ENCRYPTION_KEY: randomBytes(32).toString('base64url'),
  TOTP_ENCRYPTION_KEY_ID: 'bola-inventory-test',
  IDENTIFIER_HMAC_KEY: randomBytes(32).toString('base64url'),
});
const { routes } = createApp({
  config,
  logger,
  lifecycle: createLifecycle(),
  database: createDatabase({ url: config.database.url, logger }),
});

/** Routes that take a room or user identifier in the path, or that list or create rooms. */
const roomRelated = routes
  .filter((r) => r.access === 'room' || r.path === '/rooms' || r.path.startsWith('/rooms/'))
  .map((r) => `${r.method} ${r.path}`);

describe('bola inventory', () => {
  it('covers every production room route, and only those', () => {
    expect([...BOLA_CASES.map((c) => c.key)].sort()).toEqual([...roomRelated].sort());
  });

  it('declares every route once, with no duplicate case', () => {
    const keys = BOLA_CASES.map((c) => c.key);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('agrees with the registry about which routes are room routes', () => {
    const registryRoom = routes.filter((r) => r.access === 'room').map((r) => `${r.method} ${r.path}`);
    expect(ROOM_CASES.map((c) => c.key).sort()).toEqual([...registryRoom].sort());
    for (const c of BOLA_CASES) {
      const route = routes.find((r) => `${r.method} ${r.path}` === c.key);
      expect(route, c.key).toBeDefined();
      expect(c.kind === 'room', c.key).toBe(route?.access === 'room');
      expect(c.mutates, c.key).toBe(route?.method !== 'GET');
      expect(c.targetsMember, c.key).toBe(c.key.includes(':userId'));
    }
  });

  it('gives every room route the object-level classes, and every mutation the unchanged-state class', () => {
    for (const c of ROOM_CASES) {
      for (const required of ['A', 'B', 'D', 'E', 'F', 'H'] as const) expect(c.classes, c.key).toContain(required);
      if (c.mutates) expect(c.classes, c.key).toContain('G');
      if (c.targetsMember) {
        expect(c.classes, c.key).toContain('C');
        expect(c.target, c.key).toBeDefined();
      }
    }
    for (const c of BOLA_CASES.filter((x) => x.kind === 'collection')) expect(c.classes, c.key).toContain('H');
  });

  it('marks the routes the matrix protects with a step-up, so attackers are confirmed before they attack', () => {
    const stepUpRoutes = routes.filter((r) => r.access === 'room' && /\/(delete|transfer-ownership)$/.test(r.path));
    expect(
      BOLA_CASES.filter((c) => c.stepUp)
        .map((c) => c.key)
        .sort(),
    ).toEqual(stepUpRoutes.map((r) => `${r.method} ${r.path}`).sort());
  });
});
