import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { loadDatabaseTestEnv, sqlState, SQLSTATE, testDatabase, type RoleKey } from '../helpers/database';

// Least privilege for the database roles (CM-T014, TB-05, EV-02-03).
// EXPECTED is an independent copy of the grant matrix in the grant migration and in
// docs/security/database-security.md. Any extra or missing privilege fails this test, so a
// grant change cannot reach main without a reviewed update of this file.
loadDatabaseTestEnv();
const db = testDatabase(inject('databaseName'));

type Privilege = 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE' | 'TRUNCATE' | 'REFERENCES' | 'TRIGGER';
const PRIVILEGES: readonly Privilege[] = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'];
const S = 'SELECT',
  I = 'INSERT',
  U = 'UPDATE',
  D = 'DELETE';

const EXPECTED: Record<'cm_api' | 'cm_worker' | 'cm_verifier', Record<string, readonly Privilege[]>> = {
  cm_api: {
    users: [S, I, U],
    recovery_codes: [S, I, U, D],
    sessions: [S, I, U],
    login_attempts: [S, I],
    user_key_pairs: [S, I, U],
    rooms: [S, I, U],
    room_members: [S, I, U],
    invitations: [S, I, U],
    room_key_versions: [S, I, U],
    rekey_operations: [S, I, U],
    key_envelopes: [S, I, U, D],
    encrypted_files: [S, I, U],
    encrypted_notes: [S, I, U],
    secrets: [S, I, U],
    audit_events: [S, I],
  },
  cm_worker: {
    sessions: [S, D],
    login_attempts: [S, D],
    rooms: [S, U],
    room_members: [S],
    invitations: [S, U],
    room_key_versions: [S, U],
    rekey_operations: [S, U, D],
    key_envelopes: [S, D],
    encrypted_files: [S, U],
    encrypted_notes: [S, U],
    secrets: [S, U],
    audit_events: [S, I],
  },
  cm_verifier: {
    audit_events: [S],
  },
};

let migrator: pg.Client;
const clients = new Map<RoleKey, pg.Client>();
const as = (role: RoleKey): pg.Client => {
  const client = clients.get(role);
  if (client === undefined) throw new Error(`no client for ${role}`);
  return client;
};

beforeAll(async () => {
  migrator = await db.connect('migrator');
  for (const role of ['api', 'worker', 'verifier'] as const) clients.set(role, await db.connect(role));
});
afterAll(async () => {
  await migrator.end();
  for (const client of clients.values()) await client.end();
});

describe('role attributes', () => {
  it('no CipherMesh role is a superuser or can create databases, roles or replication', async () => {
    const { rows } = await migrator.query<{ rolname: string; flags: boolean[] }>(
      `SELECT rolname, ARRAY[rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolinherit] AS flags
         FROM pg_roles WHERE rolname LIKE 'cm\\_%' ORDER BY rolname`,
    );
    expect(rows.map((r) => r.rolname)).toEqual(['cm_api', 'cm_migrator', 'cm_verifier', 'cm_worker']);
    for (const row of rows) expect(row.flags, row.rolname).toEqual([false, false, false, false, false, false]);
  });

  it('no CipherMesh role is a member of another role, including predefined roles such as pg_write_all_data', async () => {
    const { rows } = await migrator.query(
      `SELECT m.rolname AS member, r.rolname AS role FROM pg_auth_members a
         JOIN pg_roles m ON m.oid = a.member JOIN pg_roles r ON r.oid = a.roleid
        WHERE m.rolname LIKE 'cm\\_%'`,
    );
    expect(rows).toEqual([]);
  });

  it('runtime roles carry statement and idle-transaction timeouts (T-26)', async () => {
    for (const role of ['api', 'worker', 'verifier'] as const) {
      const { rows } = await as(role).query<{ statement_timeout: string; idle: string }>(
        `SELECT current_setting('statement_timeout') AS statement_timeout,
                current_setting('idle_in_transaction_session_timeout') AS idle`,
      );
      expect(rows[0], role).toEqual({ statement_timeout: '15s', idle: '30s' });
    }
  });
});

describe('ownership', () => {
  it('the migration role owns the database, the schema and every object; runtime roles own nothing', async () => {
    const owners = await migrator.query<{ kind: string; owner: string }>(
      `SELECT 'database' AS kind, pg_get_userbyid(datdba) AS owner FROM pg_database WHERE datname = current_database()
       UNION ALL SELECT 'schema', pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'public'
       UNION ALL SELECT 'relation ' || relname, pg_get_userbyid(relowner) FROM pg_class
                  WHERE relnamespace = 'public'::regnamespace
       UNION ALL SELECT 'function ' || proname, pg_get_userbyid(proowner) FROM pg_proc
                  WHERE pronamespace = 'public'::regnamespace AND proname LIKE 'cm\\_%'
       UNION ALL SELECT 'type ' || typname, pg_get_userbyid(typowner) FROM pg_type
                  WHERE typnamespace = 'public'::regnamespace AND typtype = 'e'`,
    );
    expect(owners.rows.length).toBeGreaterThan(30);
    for (const { kind, owner } of owners.rows) expect(owner, kind).toBe('cm_migrator');
  });
});

describe('grant matrix', () => {
  it('runtime roles hold exactly the reviewed table privileges and nothing else', async () => {
    const tables = (
      await migrator.query<{ tablename: string }>(
        `SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY 1`,
      )
    ).rows.map((r) => r.tablename);
    expect(tables).toContain('_prisma_migrations');
    for (const [role, expected] of Object.entries(EXPECTED)) {
      for (const table of tables) {
        const actual: Privilege[] = [];
        for (const privilege of PRIVILEGES) {
          const { rows } = await migrator.query<{ granted: boolean }>(
            `SELECT has_table_privilege($1, format('public.%I', $2::text), $3) AS granted`,
            [role, table, privilege],
          );
          if (rows[0]?.granted === true) actual.push(privilege);
        }
        expect(actual, `${role} on ${table}`).toEqual(expected[table] ?? []);
      }
    }
  });

  it('grants no column-level privileges that the table matrix would not show', async () => {
    const { rows } = await migrator.query(
      `SELECT attrelid::regclass::text AS relation, attname FROM pg_attribute
        WHERE attacl IS NOT NULL AND attrelid IN (SELECT oid FROM pg_class WHERE relnamespace = 'public'::regnamespace)`,
    );
    expect(rows).toEqual([]);
  });

  it('PUBLIC holds no privilege on the database, the schema or any table', async () => {
    const database = await migrator.query(
      `SELECT a.privilege_type FROM pg_database d, aclexplode(d.datacl) a
        WHERE d.datname = current_database() AND a.grantee = 0`,
    );
    expect(database.rows).toEqual([]);
    const schema = await migrator.query(
      `SELECT a.privilege_type FROM pg_namespace n, aclexplode(n.nspacl) a WHERE n.nspname = 'public' AND a.grantee = 0`,
    );
    expect(schema.rows).toEqual([]);
    const tables = await migrator.query(
      `SELECT c.relname FROM pg_class c, aclexplode(c.relacl) a
        WHERE c.relnamespace = 'public'::regnamespace AND a.grantee = 0`,
    );
    expect(tables.rows).toEqual([]);
  });

  it('runtime roles may use the schema but not create objects in it', async () => {
    for (const role of ['cm_api', 'cm_worker', 'cm_verifier']) {
      const { rows } = await migrator.query<{ usage: boolean; create: boolean }>(
        `SELECT has_schema_privilege($1, 'public', 'USAGE') AS usage, has_schema_privilege($1, 'public', 'CREATE') AS create`,
        [role],
      );
      expect(rows[0], role).toEqual({ usage: true, create: false });
    }
  });
});

describe('what the API role cannot do', () => {
  it.each([
    ['create a table', 'CREATE TABLE public.attacker (id int)'],
    ['create a temporary table', 'CREATE TEMP TABLE attacker (id int)'],
    ['create a function', 'CREATE FUNCTION public.attacker() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$'],
    ['add a column', 'ALTER TABLE users ADD COLUMN password text'],
    ['drop a table', 'DROP TABLE sessions'],
    ['disable the audit trigger', 'ALTER TABLE audit_events DISABLE TRIGGER audit_events_reject_update_delete'],
    ['truncate a table', 'TRUNCATE sessions'],
    ['delete users (tombstones only)', 'DELETE FROM users'],
    ['delete rooms (tombstones only)', 'DELETE FROM rooms'],
    ['delete encrypted content (tombstones only)', 'DELETE FROM encrypted_files'],
    ['read the migration history', 'SELECT * FROM _prisma_migrations'],
    ['create a role', `CREATE ROLE attacker LOGIN PASSWORD 'x'`],
    ['create a database', 'CREATE DATABASE attacker'],
    ['become the migration role', 'SET ROLE cm_migrator'],
    ['make itself a superuser', 'ALTER ROLE cm_api SUPERUSER'],
    ['read server files', `SELECT pg_read_file('postgresql.conf')`],
  ])('cannot %s', async (_label, sql) => {
    const state = await sqlState(as('api').query(sql));
    expect(['42501', '42P01', '42883']).toContain(state); // insufficient privilege (or no access to the object)
    expect(state).not.toBe('none');
  });
});

describe('privilege escalation through GRANT', () => {
  it('a GRANT by the API role has no effect: it holds no grant option', async () => {
    // PostgreSQL answers a GRANT without grant option with a warning, not an error, so the
    // test checks the resulting privilege instead of the statement outcome.
    await as('api').query('GRANT DELETE ON users TO cm_api');
    const { rows } = await migrator.query<{ granted: boolean }>(
      `SELECT has_table_privilege('cm_api', 'public.users', 'DELETE') AS granted`,
    );
    expect(rows[0]).toEqual({ granted: false });
  });
});

describe('worker and verifier roles', () => {
  it('the worker cannot delete users, change audit rows or read password hashes and private keys', async () => {
    expect(await sqlState(as('worker').query('DELETE FROM users'))).toBe(SQLSTATE.insufficientPrivilege);
    expect(await sqlState(as('worker').query('UPDATE audit_events SET hash_version = 2'))).toBe(
      SQLSTATE.insufficientPrivilege,
    );
    expect(await sqlState(as('worker').query('SELECT password_hash FROM users'))).toBe(SQLSTATE.insufficientPrivilege);
    expect(await sqlState(as('worker').query('SELECT encrypted_private_key FROM user_key_pairs'))).toBe(
      SQLSTATE.insufficientPrivilege,
    );
  });

  it('the verifier can read audit events and nothing else, and cannot write them', async () => {
    expect(await sqlState(as('verifier').query('SELECT count(*) FROM audit_events'))).toBe('none');
    expect(await sqlState(as('verifier').query('SELECT count(*) FROM users'))).toBe(SQLSTATE.insufficientPrivilege);
    expect(
      await sqlState(
        as('verifier').query(
          `INSERT INTO audit_events (seq, occurred_at, actor_type, action, outcome, prev_hash, event_hash, hash_version)
           VALUES (999999, now(), 'SYSTEM', 'VERIFIER_WRITE', 'SUCCESS', '\\x00', '\\x00', 1)`,
        ),
      ),
    ).toBe(SQLSTATE.insufficientPrivilege);
  });
});
