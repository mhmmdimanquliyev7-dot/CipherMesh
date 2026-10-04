// Local database provisioning helpers (CM-T014). Used by `pnpm db:bootstrap`, the seed script
// and the database tests. Never imported by the API: the API reads only DATABASE_URL, through
// apps/api/src/config/env.ts.
//
// Scope: the local development container and CI service container, where POSTGRES_USER is the
// container's superuser. A managed cloud database is provisioned by the deployment runbook
// (CM-T067) with the same role names and attributes; local roles are not cloud IAM.
import { existsSync } from 'node:fs';
import pg from 'pg';

/** Fixed role names: the grant migration refers to them. */
export const ROLES = Object.freeze({
  migrator: Object.freeze({ name: 'cm_migrator', urlVariable: 'MIGRATION_DATABASE_URL', connectionLimit: 5 }),
  api: Object.freeze({ name: 'cm_api', urlVariable: 'DATABASE_URL', connectionLimit: 40 }),
  worker: Object.freeze({ name: 'cm_worker', urlVariable: 'WORKER_DATABASE_URL', connectionLimit: 10 }),
  verifier: Object.freeze({ name: 'cm_verifier', urlVariable: 'VERIFIER_DATABASE_URL', connectionLimit: 5 }),
});

/** @typedef {keyof typeof ROLES} RoleKey */

const RUNTIME_ROLES = /** @type {const} */ (['api', 'worker', 'verifier']);
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]']);
const TEST_DATABASE_PATTERN = /^cm_test_[0-9a-f]{16}$/;

/** Loads the local .env file without overriding variables that are already set. */
export function loadLocalEnv() {
  if (existsSync('.env')) process.loadEnvFile('.env');
}

/**
 * @param {string} variable
 * @returns {string}
 */
function required(variable) {
  const value = process.env[variable];
  // The value is never echoed: it may be a credential.
  if (value === undefined || value === '') throw new Error(`${variable} is not set (see .env.example)`);
  return value;
}

/**
 * Connection settings for the local container administrator (POSTGRES_*). Loopback only.
 * @param {string} [database]
 * @returns {pg.ClientConfig}
 */
export function adminConnection(database) {
  return {
    host: '127.0.0.1',
    port: Number(required('POSTGRES_PORT')),
    user: required('POSTGRES_USER'),
    password: required('POSTGRES_PASSWORD'),
    database: database ?? required('POSTGRES_DB'),
  };
}

/**
 * Reads and checks one role URL. The user name must be the fixed role name and the host must be
 * a loopback address, because these helpers provision local databases only.
 * @param {RoleKey} key
 * @returns {{ role: string, password: string, url: URL, database: string }}
 */
export function roleUrl(key) {
  const { name, urlVariable } = ROLES[key];
  /** @type {URL} */
  let url;
  try {
    url = new URL(required(urlVariable));
  } catch (error) {
    if (error instanceof Error && error.message.includes('is not set')) throw error;
    // No `cause`: Node's URL error carries the input, which contains the password.
    // eslint-disable-next-line preserve-caught-error
    throw new Error(`${urlVariable} is not a valid URL`);
  }
  if (url.protocol !== 'postgresql:' && url.protocol !== 'postgres:')
    throw new Error(`${urlVariable} must be a postgresql:// URL`);
  if (decodeURIComponent(url.username) !== name) throw new Error(`${urlVariable} must connect as ${name}`);
  if (!LOOPBACK_HOSTS.has(url.hostname))
    throw new Error(`${urlVariable} must point to a loopback host for local provisioning`);
  const password = decodeURIComponent(url.password);
  if (password.length < 16) throw new Error(`${urlVariable} needs a password of at least 16 characters`);
  const database = decodeURIComponent(url.pathname.slice(1));
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(database))
    throw new Error(`${urlVariable} needs a simple lower-case database name`);
  return { role: name, password, url, database };
}

/**
 * The same role URL, pointing at another database (used for per-run test databases).
 * @param {RoleKey} key
 * @param {string} database
 * @returns {string}
 */
export function roleUrlFor(key, database) {
  const { url } = roleUrl(key);
  const copy = new URL(url);
  copy.pathname = `/${database}`;
  return copy.toString();
}

/**
 * Creates or updates a role with fixed, minimal attributes. Identifiers and the password are
 * quoted by the server (format %I and %L), never concatenated in JavaScript.
 * @param {pg.Client} admin
 * @param {RoleKey} key
 * @param {string} password
 */
async function ensureRole(admin, key, password) {
  const { name, connectionLimit } = ROLES[key];
  const exists = (await admin.query('SELECT 1 FROM pg_roles WHERE rolname = $1', [name])).rowCount === 1;
  const attributes =
    'LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT %s PASSWORD %L';
  const { rows } = await admin.query(`SELECT format($1, $2::text, $3::int, $4::text) AS sql`, [
    `${exists ? 'ALTER' : 'CREATE'} ROLE %I WITH ${attributes}`,
    name,
    connectionLimit,
    password,
  ]);
  await admin.query(/** @type {{ sql: string }} */ (rows[0]).sql);
  if (key !== 'migrator') {
    // Bound runaway statements and abandoned transactions of the runtime roles (T-26).
    for (const [setting, value] of [
      ['statement_timeout', '15s'],
      ['idle_in_transaction_session_timeout', '30s'],
    ]) {
      const set = await admin.query(`SELECT format('ALTER ROLE %I SET %s = %L', $1::text, $2::text, $3::text) AS sql`, [
        name,
        setting,
        value,
      ]);
      await admin.query(/** @type {{ sql: string }} */ (set.rows[0]).sql);
    }
  }
}

/**
 * Creates the four roles. Role passwords must not reach the server log: statement logging and
 * failed-statement logging are switched off for this session (the local administrator is a
 * superuser).
 * @param {pg.Client} admin
 */
export async function ensureRoles(admin) {
  await admin.query(`SET log_statement = 'none'`);
  // A failed statement is otherwise logged with its text, which would include the password.
  await admin.query(`SET log_min_error_statement = 'panic'`);
  for (const key of /** @type {RoleKey[]} */ (Object.keys(ROLES))) {
    await ensureRole(admin, key, roleUrl(key).password);
  }
}

/**
 * Creates a database owned by the migration role, closed to PUBLIC, with CONNECT for the
 * runtime roles, and hands the public schema to the migration role.
 * @param {pg.Client} admin
 * @param {string} database
 * @returns {Promise<boolean>} true when the database was created
 */
export async function ensureDatabase(admin, database) {
  const exists = (await admin.query('SELECT 1 FROM pg_database WHERE datname = $1', [database])).rowCount === 1;
  /** @param {string} template @param {...string} args */
  const run = async (template, ...args) => {
    const placeholders = args.map((_, i) => `$${i + 2}::text`).join(', ');
    const { rows } = await admin.query(`SELECT format($1${placeholders ? `, ${placeholders}` : ''}) AS sql`, [
      template,
      ...args,
    ]);
    await admin.query(/** @type {{ sql: string }} */ (rows[0]).sql);
  };
  if (!exists)
    await run(`CREATE DATABASE %I OWNER %I ENCODING 'UTF8' TEMPLATE template0`, database, ROLES.migrator.name);
  await run('REVOKE ALL ON DATABASE %I FROM PUBLIC', database);
  for (const key of RUNTIME_ROLES) await run('GRANT CONNECT ON DATABASE %I TO %I', database, ROLES[key].name);

  const inDatabase = new pg.Client(adminConnection(database));
  await inDatabase.connect();
  try {
    await inDatabase.query(
      (
        await inDatabase.query(`SELECT format('ALTER SCHEMA public OWNER TO %I', $1::text) AS sql`, [
          ROLES.migrator.name,
        ])
      ).rows[0].sql,
    );
  } finally {
    await inDatabase.end();
  }
  return !exists;
}

/**
 * Drops a per-run test database. Refuses any name outside the test pattern.
 * @param {pg.Client} admin
 * @param {string} database
 */
export async function dropTestDatabase(admin, database) {
  if (!TEST_DATABASE_PATTERN.test(database)) throw new Error('Refusing to drop a database that is not a test database');
  const { rows } = await admin.query(`SELECT format('DROP DATABASE IF EXISTS %I WITH (FORCE)', $1::text) AS sql`, [
    database,
  ]);
  await admin.query(/** @type {{ sql: string }} */ (rows[0]).sql);
}

export { TEST_DATABASE_PATTERN };
