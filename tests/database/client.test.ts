import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { createApp } from '../../apps/api/src/app';
import { loadConfig } from '../../apps/api/src/config/env';
import { SecretValue } from '../../apps/api/src/config/secret';
import { createDatabase, type Database } from '../../apps/api/src/db/client';
import { createLifecycle } from '../../apps/api/src/lifecycle';
import { createLogger } from '../../apps/api/src/logging/logger';
import { defineRoute } from '../../apps/api/src/routes/registry';
import { emptyQuerySchema, z } from '@ciphermesh/validation';
import { PLACEHOLDER_PHC } from '../helpers/db-fixtures';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';

// The API database module (CM-T013): lazy connection, readiness, shutdown, no query logging and
// no leakage of the connection string or row values through errors and logs.
loadDatabaseTestEnv();
const db = testDatabase(inject('databaseName'));
const lines: string[] = [];
const logger = createLogger({ level: 'debug', sink: { write: (line) => lines.push(line) } });
let database: Database;

beforeAll(() => {
  database = createDatabase({ url: new SecretValue(db.url('api')), logger, poolMax: 2 });
});
afterAll(async () => {
  await database.close();
});

class Rollback extends Error {}

describe('database client', () => {
  it('connects lazily as the API role and answers the readiness ping', async () => {
    expect(await database.ping()).toBe(true);
    const rows = await database.prisma.$queryRaw<{ role: string }[]>`SELECT current_user AS role`;
    expect(rows).toEqual([{ role: 'cm_api' }]);
  });

  it('writes and reads typed rows through Prisma inside a rolled-back transaction', async () => {
    const email = `synthetic-${randomUUID()}@example.test`;
    await expect(
      database.prisma.$transaction(async (tx) => {
        const user = await tx.user.create({
          data: { email, displayName: 'Synthetic', passwordHash: PLACEHOLDER_PHC, passwordChangedAt: new Date() },
          select: { id: true, status: true },
        });
        expect(user.status).toBe('ACTIVE');
        throw new Rollback();
      }),
    ).rejects.toBeInstanceOf(Rollback);
    expect(await database.prisma.user.count({ where: { email } })).toBe(0);
  });

  it('never logs queries, and database errors do not carry row values', async () => {
    const canary = `canary-${randomUUID()}@example.test`;
    const before = lines.length;
    let caught: unknown;
    await database.prisma
      .$transaction(async (tx) => {
        const data = {
          email: canary,
          displayName: 'Synthetic',
          passwordHash: PLACEHOLDER_PHC,
          passwordChangedAt: new Date(),
        };
        await tx.user.create({ data });
        await tx.user.create({ data });
      })
      .catch((error: unknown) => {
        caught = error;
      });
    expect(caught).toBeInstanceOf(Error);
    const error = caught as Error & { code?: string };
    expect(error.code).toBe('P2002');
    expect(`${error.message} ${JSON.stringify(error)}`).not.toContain(canary);
    expect(lines.slice(before).join('')).toBe('');
  });

  it('reports an unreachable database as not ready within the timeout, without the URL or password', async () => {
    const password = 'canary-unreachable-password';
    const unreachable = createDatabase({
      url: new SecretValue(`postgresql://cm_api:${password}@127.0.0.1:1/ciphermesh`),
      logger,
      poolMax: 1,
    });
    const started = Date.now();
    expect(await unreachable.ping()).toBe(false);
    expect(Date.now() - started).toBeLessThan(6_000);
    await unreachable.close();
    const logged = lines.join('');
    expect(logged).toContain('database not reachable');
    expect(logged).not.toContain(password);
    expect(logged).not.toContain('127.0.0.1:1');
  });

  it('closes its pool and can be closed twice', async () => {
    const short = createDatabase({ url: new SecretValue(db.url('api')), logger, poolMax: 1 });
    expect(await short.ping()).toBe(true);
    await short.close();
    await short.close();
  });
});

describe('readiness probe with the real database', () => {
  it.each([
    ['reachable', true, 200, { status: 'ready' }],
    ['unreachable', false, 503, { status: 'not-ready' }],
  ])('answers for a %s database with a status word only', async (_label, reachable, status, body) => {
    const url = reachable ? db.url('api') : 'postgresql://cm_api:canary-pw-123456@127.0.0.1:1/ciphermesh';
    const config = loadConfig({ NODE_ENV: 'test', APP_ORIGIN: 'https://ciphermesh.test', DATABASE_URL: url });
    const probeDb = createDatabase({ url: config.database.url, logger, poolMax: 1 });
    const lifecycle = createLifecycle();
    const { app } = createApp({ config, logger, lifecycle, database: probeDb });
    const server = createServer(app).listen(0, '127.0.0.1');
    await once(server, 'listening');
    lifecycle.markReady();
    try {
      const { port } = server.address() as AddressInfo;
      const response = await fetch(`http://127.0.0.1:${String(port)}/api/ready`);
      expect(response.status).toBe(status);
      expect(await response.json()).toEqual(body);
    } finally {
      server.closeAllConnections();
      server.close();
      await probeDb.close();
    }
  });
});

describe('unhandled database errors in the API', () => {
  it('are logged by class and code only, because Prisma messages can quote query values (INV-10)', async () => {
    const canary = `canary-${randomUUID()}@example.test`;
    let rawMessage = '';
    const route = defineRoute({
      method: 'GET',
      path: '/test/database-error',
      action: 'TEST-DB-ERROR',
      access: { kind: 'public', justification: 'database test' },
      query: emptyQuerySchema,
      body: undefined,
      response: z.strictObject({}),
      handler: async () => {
        try {
          // Missing required fields: Prisma rejects the call and quotes the arguments.
          await database.prisma.user.create({ data: { email: canary } as never });
        } catch (error) {
          rawMessage = error instanceof Error ? error.message : '';
          throw error;
        }
        return { status: 200, body: {} };
      },
    });
    const captured: string[] = [];
    const config = loadConfig({ NODE_ENV: 'test', APP_ORIGIN: 'https://ciphermesh.test', DATABASE_URL: db.url('api') });
    const { app } = createApp({
      config,
      logger: createLogger({ level: 'debug', sink: { write: (line) => captured.push(line) } }),
      lifecycle: createLifecycle(),
      database,
      testing: { routes: [route], publicAllowlist: [{ method: 'GET', path: '/test/database-error' }] },
    });
    const server = createServer(app).listen(0, '127.0.0.1');
    await once(server, 'listening');
    try {
      const { port } = server.address() as AddressInfo;
      const response = await fetch(`http://127.0.0.1:${String(port)}/api/test/database-error`);
      expect(response.status).toBe(500);
      expect(await response.text()).not.toContain(canary);
    } finally {
      server.closeAllConnections();
      server.close();
    }
    // The control: the raw error really does contain the value, so the redaction is what protects it.
    expect(rawMessage).toContain(canary);
    const log = captured.join('');
    expect(log).toContain('PrismaClientValidationError');
    expect(log).not.toContain(canary);
  });
});
