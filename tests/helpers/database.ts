import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import {
  adminConnection,
  dropTestDatabase,
  ensureDatabase,
  ensureRoles,
  loadLocalEnv,
  roleUrlFor,
  ROLES,
} from '../../scripts/db/lib.mjs';

// Throwaway databases for tests/database (CM-T013, CM-T014). Each database is created by the
// local container administrator, owned by cm_migrator, migrated with `prisma migrate deploy`
// through the allowlisted CLI wrapper, and dropped afterwards. Tests then connect as the real
// least-privilege roles: nothing is mocked and no grant is widened for testing.

export type RoleKey = keyof typeof ROLES;

const root = fileURLToPath(new URL('../..', import.meta.url));

export interface TestDatabase {
  readonly name: string;
  readonly url: (role: RoleKey) => string;
  /** A connected client for the role; the caller ends it. */
  readonly connect: (role: RoleKey) => Promise<pg.Client>;
}

export function loadDatabaseTestEnv(): void {
  loadLocalEnv();
}

export async function withAdmin<T>(fn: (admin: pg.Client) => Promise<T>): Promise<T> {
  const admin = new pg.Client(adminConnection());
  await admin.connect();
  try {
    return await fn(admin);
  } finally {
    await admin.end();
  }
}

/** Runs `prisma migrate deploy` (or another allowlisted command) against one database. */
export function runPrisma(database: string, args: readonly string[]): { status: number | null; output: string } {
  const result = spawnSync(process.execPath, ['scripts/db/prisma.mjs', ...args], {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, MIGRATION_DATABASE_URL: roleUrlFor('migrator', database) },
  });
  return { status: result.status, output: `${result.stdout}${result.stderr}` };
}

/** Runs the drift check against one database. */
export function runDriftCheck(database: string): { status: number | null; output: string } {
  const result = spawnSync(process.execPath, ['scripts/db/check-drift.mjs'], {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, MIGRATION_DATABASE_URL: roleUrlFor('migrator', database) },
  });
  return { status: result.status, output: `${result.stdout}${result.stderr}` };
}

export function testDatabase(name: string): TestDatabase {
  return {
    name,
    url: (role) => roleUrlFor(role, name),
    connect: async (role) => {
      const client = new pg.Client({ connectionString: roleUrlFor(role, name) });
      await client.connect();
      return client;
    },
  };
}

/** Creates an empty, provisioned database. With `migrate`, applies all migrations. */
export async function createTestDatabase(options: { migrate: boolean }): Promise<TestDatabase> {
  loadLocalEnv();
  const name = `cm_test_${randomBytes(8).toString('hex')}`;
  await withAdmin(async (admin) => {
    await ensureRoles(admin);
    await ensureDatabase(admin, name);
  });
  if (options.migrate) {
    const result = runPrisma(name, ['migrate', 'deploy']);
    if (result.status !== 0) throw new Error(`migrate deploy failed:\n${result.output}`);
  }
  return testDatabase(name);
}

export async function dropDatabase(name: string): Promise<void> {
  await withAdmin((admin) => dropTestDatabase(admin, name));
}

/**
 * Runs `fn` inside a transaction that is always rolled back, so tests sharing one database
 * stay independent.
 */
export async function inRolledBackTransaction<T>(client: pg.Client, fn: () => Promise<T>): Promise<T> {
  await client.query('BEGIN');
  try {
    return await fn();
  } finally {
    await client.query('ROLLBACK');
  }
}

/** The PostgreSQL error code (SQLSTATE) of a failed query, or 'none' when it succeeded. */
export async function sqlState(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
    return 'none';
  } catch (error) {
    return typeof error === 'object' && error !== null && 'code' in error ? String(error.code) : 'unknown';
  }
}

/** Like sqlState, inside a savepoint, so the surrounding transaction stays usable. */
export async function sqlStateInSavepoint(client: pg.Client, sql: string, values: unknown[] = []): Promise<string> {
  await client.query('SAVEPOINT probe');
  const state = await sqlState(client.query(sql, values));
  await client.query(state === 'none' ? 'RELEASE SAVEPOINT probe' : 'ROLLBACK TO SAVEPOINT probe');
  return state;
}

export const SQLSTATE = {
  checkViolation: '23514',
  uniqueViolation: '23505',
  foreignKeyViolation: '23503',
  notNullViolation: '23502',
  insufficientPrivilege: '42501',
  integrityConstraintViolation: '23000',
  invalidTextRepresentation: '22P02',
} as const;
