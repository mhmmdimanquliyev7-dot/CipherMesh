import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, expect, inject, it } from 'vitest';
import { PLACEHOLDER_PHC, SYNTHETIC_USERS } from '../../scripts/db/synthetic';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';

// Synthetic seed (CM-T011): idempotent, fake data only, runs as the API role, refuses
// production and remote databases.
loadDatabaseTestEnv();
const db = testDatabase(inject('databaseName'));
const root = fileURLToPath(new URL('../..', import.meta.url));

function seed(env: Record<string, string>): { status: number | null; output: string } {
  const result = spawnSync(process.execPath, ['--import', 'tsx', 'scripts/db/seed.ts'], {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, NODE_ENV: 'development', APP_ORIGIN: 'https://localhost:8443', ...env },
  });
  return { status: result.status, output: `${result.stdout}${result.stderr}` };
}

describe('db:seed', () => {
  it('inserts only the synthetic, disabled accounts, and is idempotent', async () => {
    for (let run = 0; run < 2; run += 1) {
      const result = seed({ DATABASE_URL: db.url('api') });
      expect(result.status, result.output).toBe(0);
    }
    const client = await db.connect('api');
    try {
      const { rows } = await client.query<{ email: string; status: string; password_hash: string }>(
        `SELECT email, status, password_hash FROM users WHERE email LIKE 'seed-user-%@example.test' ORDER BY email`,
      );
      expect(rows).toEqual(
        SYNTHETIC_USERS.map((u) => ({ email: u.email, status: 'DISABLED', password_hash: PLACEHOLDER_PHC })),
      );
      const keys = await client.query(
        `SELECT count(*)::int AS n FROM user_key_pairs k JOIN users u ON u.id = k.user_id WHERE u.email LIKE 'seed-user-%'`,
      );
      expect(keys.rows).toEqual([{ n: 0 }]);
    } finally {
      await client.end();
    }
  });

  it('every synthetic address uses the reserved .test domain', () => {
    for (const user of SYNTHETIC_USERS) expect(user.email).toMatch(/@example\.test$/);
  });

  it('refuses production and databases outside the loopback interface', () => {
    const production = seed({
      NODE_ENV: 'production',
      APP_ORIGIN: 'https://ciphermesh.example',
      DATABASE_URL: 'postgresql://cm_api:canary-seed-password@db.ciphermesh.example/ciphermesh?sslmode=verify-full',
    });
    expect(production.status).toBe(1);
    expect(production.output).toContain('production');
    const remote = seed({
      DATABASE_URL: 'postgresql://cm_api:canary-seed-password@db.ciphermesh.example/ciphermesh?sslmode=verify-full',
    });
    expect(remote.status).toBe(1);
    expect(remote.output).toContain('loopback');
    expect(`${production.output}${remote.output}`).not.toContain('canary-seed-password');
  });

  it('refuses to run as any role other than the API role', () => {
    const result = seed({ DATABASE_URL: db.url('migrator') });
    expect(result.status).toBe(1);
    expect(result.output).toContain('DATABASE_URL');
  });
});
