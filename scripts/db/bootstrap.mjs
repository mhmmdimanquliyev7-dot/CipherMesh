// `pnpm db:bootstrap`: creates the CipherMesh database roles and the application database on the
// local development container (CM-T014). Idempotent: rerunning it resets the role attributes and
// passwords to the values in .env. Exits non-zero on any failure.
import pg from 'pg';
import { adminConnection, ensureDatabase, ensureRoles, loadLocalEnv, roleUrl, ROLES } from './lib.mjs';

loadLocalEnv();

try {
  const databases = new Set(Object.keys(ROLES).map((key) => roleUrl(/** @type {keyof typeof ROLES} */ (key)).database));
  if (databases.size !== 1) throw new Error('All role URLs must name the same database');
  const [database] = /** @type {[string]} */ ([...databases]);
  if (database === adminConnection().database) throw new Error('The application database must differ from POSTGRES_DB');

  const admin = new pg.Client(adminConnection());
  await admin.connect();
  try {
    await ensureRoles(admin);
    const created = await ensureDatabase(admin, database);
    console.log(
      `roles ready: ${Object.values(ROLES)
        .map((r) => r.name)
        .join(', ')}`,
    );
    console.log(`database ${database} ${created ? 'created' : 'already existed'}; next: pnpm db:migrate`);
  } finally {
    await admin.end();
  }
} catch (error) {
  // pg errors carry no credentials; messages from lib.mjs name variables, never values.
  console.error(`db:bootstrap failed: ${error instanceof Error ? error.message : 'unknown error'}`);
  process.exitCode = 1;
}
