// `pnpm db:drift`: proves that the migrated database (MIGRATION_DATABASE_URL) matches
// prisma/schema.prisma exactly, so no table, column or index exists outside reviewed migrations.
//
// The Prisma CLI can exit 0 with empty output when the schema engine fails to start (for example
// without a datasource). This script therefore requires the explicit "No difference detected."
// message as well as exit code 0, and fails on anything else.
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';

const cli = createRequire(import.meta.url).resolve('prisma/build/index.js');
const result = spawnSync(
  process.execPath,
  [cli, 'migrate', 'diff', '--from-config-datasource', '--to-schema', 'prisma/schema.prisma', '--exit-code'],
  { encoding: 'utf8', env: { ...process.env, CHECKPOINT_DISABLE: '1', PRISMA_HIDE_UPDATE_MESSAGE: '1' } },
);
const output = `${result.stdout}${result.stderr}`;

if (result.status === 0 && output.includes('No difference detected.')) {
  console.log('PASS database schema matches prisma/schema.prisma (no drift)');
} else {
  console.error(`FAIL schema drift check (exit ${String(result.status)})`);
  console.error(output.trim() || '(no output from prisma migrate diff)');
  process.exitCode = 1;
}
