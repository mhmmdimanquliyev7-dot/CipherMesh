import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { auditRow, insert } from '../helpers/db-fixtures';
import {
  createTestDatabase,
  dropDatabase,
  loadDatabaseTestEnv,
  sqlState,
  SQLSTATE,
  testDatabase,
  type TestDatabase,
} from '../helpers/database';

// Append-only audit table (CM-T014, INV-09, T-20, EV-02-02). Two independent layers:
// 1. grants: runtime roles hold only SELECT and INSERT;
// 2. triggers: UPDATE, DELETE and TRUNCATE are rejected for every role, including the owner.
// The hash chain is Phase 12 work (ADR-009) and is not tested here.
loadDatabaseTestEnv();
const shared = testDatabase(inject('databaseName'));
let api: pg.Client;
let migrator: pg.Client;
const SEQ = 1_000_000 + Math.floor(Date.now() % 1_000_000);

beforeAll(async () => {
  api = await shared.connect('api');
  migrator = await shared.connect('migrator');
  await insert(api, 'audit_events', auditRow(SEQ));
});
afterAll(async () => {
  await api.end();
  await migrator.end();
});

const errorOf = async (promise: Promise<unknown>): Promise<{ code: string; message: string }> => {
  try {
    await promise;
    return { code: 'none', message: '' };
  } catch (error) {
    const e = error as { code?: string; message?: string };
    return { code: e.code ?? 'unknown', message: e.message ?? '' };
  }
};

describe('audit_events as the API role', () => {
  it('can append and read events', async () => {
    const { rows } = await api.query('SELECT action FROM audit_events WHERE seq = $1', [SEQ]);
    expect(rows).toEqual([{ action: 'SYNTHETIC_TEST_EVENT' }]);
  });

  it.each([
    ['UPDATE', `UPDATE audit_events SET outcome = 'FAILURE' WHERE seq = ${String(SEQ)}`],
    ['DELETE', `DELETE FROM audit_events WHERE seq = ${String(SEQ)}`],
    ['TRUNCATE', 'TRUNCATE audit_events'],
  ])('is refused %s by its grants', async (_label, sql) => {
    const error = await errorOf(api.query(sql));
    expect(error.code).toBe(SQLSTATE.insufficientPrivilege);
    expect(error.message).toMatch(/permission denied/);
  });
});

describe('audit_events as the table owner (the trigger layer)', () => {
  it.each([
    ['UPDATE', `UPDATE audit_events SET outcome = 'FAILURE' WHERE seq = ${String(SEQ)}`],
    ['DELETE', `DELETE FROM audit_events WHERE seq = ${String(SEQ)}`],
    ['TRUNCATE', 'TRUNCATE audit_events'],
  ])('is refused %s even though the owner holds every privilege', async (operation, sql) => {
    const error = await errorOf(migrator.query(sql));
    expect(error.code).toBe(SQLSTATE.insufficientPrivilege);
    expect(error.message).toBe(`audit_events is append-only: ${operation} is not allowed`);
    const { rows } = await migrator.query('SELECT outcome FROM audit_events WHERE seq = $1', [SEQ]);
    expect(rows).toEqual([{ outcome: 'SUCCESS' }]);
  });
});

describe('audit_events with misconfigured grants', () => {
  let isolated: TestDatabase;
  beforeAll(async () => {
    // A separate database, so the deliberately wrong grant never affects other tests.
    isolated = await createTestDatabase({ migrate: true });
  }, 120_000);
  afterAll(async () => {
    await dropDatabase(isolated.name);
  });

  it('still rejects UPDATE, DELETE and TRUNCATE when the API role is wrongly granted them', async () => {
    const owner = await isolated.connect('migrator');
    const role = await isolated.connect('api');
    try {
      await insert(role, 'audit_events', auditRow(1));
      await owner.query('GRANT UPDATE, DELETE, TRUNCATE ON audit_events TO cm_api');
      for (const sql of [
        `UPDATE audit_events SET outcome = 'FAILURE'`,
        'DELETE FROM audit_events',
        'TRUNCATE audit_events',
      ]) {
        const error = await errorOf(role.query(sql));
        expect(error.message, sql).toMatch(/^audit_events is append-only/);
      }
      expect((await role.query('SELECT count(*)::int AS n FROM audit_events')).rows).toEqual([{ n: 1 }]);
    } finally {
      await owner.end();
      await role.end();
    }
  });

  it('documents the limit: the owner can disable the trigger, which is why ADR-009 adds a hash chain and checkpoints', async () => {
    const owner = await isolated.connect('migrator');
    try {
      await owner.query('BEGIN');
      expect(
        await sqlState(owner.query('ALTER TABLE audit_events DISABLE TRIGGER audit_events_reject_update_delete')),
      ).toBe('none');
      expect(await sqlState(owner.query(`UPDATE audit_events SET outcome = 'FAILURE'`))).toBe('none');
    } finally {
      await owner.query('ROLLBACK');
      await owner.end();
    }
  });
});
