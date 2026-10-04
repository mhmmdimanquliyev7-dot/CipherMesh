import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parseSchema } from '../../scripts/db/check-schema.mjs';
import { createTestDatabase, dropDatabase, runDriftCheck, runPrisma, type TestDatabase } from '../helpers/database';

// Migrations from an empty database (CM-T013 acceptance criterion), repeatability, drift
// detection with a negative control, and a live check that every column is declared and
// classified in prisma/schema.prisma.
const root = fileURLToPath(new URL('../..', import.meta.url));
const migrationDirs = readdirSync(`${root}prisma/migrations`, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort();

let fresh: TestDatabase;
let migrator: pg.Client;

beforeAll(async () => {
  fresh = await createTestDatabase({ migrate: false });
  migrator = await fresh.connect('migrator');
}, 120_000);
afterAll(async () => {
  await migrator.end();
  await dropDatabase(fresh.name);
});

describe('migrations', () => {
  it('start from an empty database: no tables before deploy', async () => {
    const { rows } = await migrator.query(`SELECT tablename FROM pg_tables WHERE schemaname = 'public'`);
    expect(rows).toEqual([]);
  });

  it('apply cleanly from zero as the migration role', () => {
    const result = runPrisma(fresh.name, ['migrate', 'deploy']);
    expect(result.status, result.output).toBe(0);
    expect(result.output).toContain('All migrations have been successfully applied.');
  });

  it('record every migration directory as finished, none rolled back', async () => {
    const { rows } = await migrator.query<{ migration_name: string }>(
      `SELECT migration_name FROM _prisma_migrations
        WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL ORDER BY migration_name`,
    );
    expect(rows.map((r) => r.migration_name)).toEqual(migrationDirs);
  });

  it('are idempotent: a second deploy applies nothing', () => {
    const result = runPrisma(fresh.name, ['migrate', 'deploy']);
    expect(result.status, result.output).toBe(0);
    expect(result.output).toContain('No pending migrations to apply.');
    const status = runPrisma(fresh.name, ['migrate', 'status']);
    expect(status.output).toContain('Database schema is up to date!');
  });

  it('leave no drift between the database and prisma/schema.prisma', () => {
    const result = runDriftCheck(fresh.name);
    expect(result.status, result.output).toBe(0);
    expect(result.output).toContain('PASS');
  });

  it('every live column is declared and classified in the schema, and nothing else exists', async () => {
    const { fields, models } = parseSchema(readFileSync(`${root}prisma/schema.prisma`, 'utf8'));
    const tableOf = new Map(models.map((m) => [m.name, m.table]));
    const declared = fields
      .filter((f) => f.classification !== undefined)
      .map((f) => `${String(tableOf.get(f.model))}.${f.column}`)
      .sort();
    const { rows } = await migrator.query<{ col: string }>(
      `SELECT table_name || '.' || column_name AS col FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name <> '_prisma_migrations' ORDER BY 1`,
    );
    expect(rows.map((r) => r.col).sort()).toEqual(declared);
  });

  it('the generated migration SQL contains no plaintext content columns or file bytes', () => {
    const sql = migrationDirs
      .map((dir) => readFileSync(`${root}prisma/migrations/${dir}/migration.sql`, 'utf8'))
      .join('\n');
    expect(sql).not.toMatch(
      /"(password|passphrase|private_key|room_key|filename|mime_type|title|body|plaintext|file_bytes|content)"\s/i,
    );
    expect(sql).not.toMatch(/\b(DROP TABLE|DROP COLUMN|DELETE FROM|UPDATE\s+"?\w+"?\s+SET)\b/i);
  });
});

describe('drift detection negative control', () => {
  it('fails when the database differs from the schema (an index removed outside migrations)', async () => {
    await migrator.query('DROP INDEX room_members_one_active_owner');
    const result = runDriftCheck(fresh.name);
    expect(result.status).toBe(1);
    expect(result.output).toContain('FAIL');
  });
});
