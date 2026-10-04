// Starts the built API bundle (apps/api/dist/server.js) as a real process and probes it.
// Used by CI after `pnpm build` and to capture evidence. Exits non-zero on any failure.
//
// Run 1 (production mode): the database is unreachable and TLS-only. The API must start, stay
//   alive, and report not-ready: readiness fails closed without revealing why.
// Run 2 (development mode): the real database from DATABASE_URL (the local container, or the CI
//   service). Readiness must succeed. This run is required, not skipped: start the database
//   first (`pnpm services:up && pnpm db:bootstrap && pnpm db:migrate`).
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';

const apiDir = fileURLToPath(new URL('../apps/api/', import.meta.url));
if (existsSync('.env')) process.loadEnvFile('.env');

/** @returns {Promise<number>} */
const freePort = () =>
  new Promise((resolve) => {
    const probe = createServer().listen(0, '127.0.0.1', () => {
      const address = probe.address();
      probe.close(() => resolve(typeof address === 'object' && address ? address.port : 0));
    });
  });

/** @type {string[]} */
const failures = [];

/** Random authentication keys for this run only (Phase 3 configuration). Never printed. */
const AUTH_KEYS = {
  TOTP_ENCRYPTION_KEY: randomBytes(32).toString('base64url'),
  TOTP_ENCRYPTION_KEY_ID: 'smoke',
  IDENTIFIER_HMAC_KEY: randomBytes(32).toString('base64url'),
};

/**
 * @param {string} label
 * @param {Record<string, string>} env
 * @param {[string, number, string | null][]} probes path, expected status, expected exact body
 */
async function smoke(label, env, probes) {
  console.log(`--- ${label}`);
  const port = await freePort();
  const child = spawn(process.execPath, ['dist/server.js'], {
    cwd: apiDir,
    // A minimal environment: nothing else from the developer's shell reaches the process.
    env: { PATH: process.env.PATH ?? '', SystemRoot: process.env.SystemRoot ?? '', API_PORT: String(port), ...env },
    stdio: ['ignore', 'pipe', 'inherit'],
  });

  let output = '';
  const listening = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('API did not start within 15 seconds')), 15_000);
    child.stdout.on('data', (chunk) => {
      output += String(chunk);
      if (output.includes('"api listening"')) {
        clearTimeout(timer);
        resolve(undefined);
      }
    });
    child.on('exit', (code) => reject(new Error(`API exited early with code ${code}`)));
  });

  try {
    await listening;
    for (const [path, status, body] of probes) {
      const response = await fetch(`http://127.0.0.1:${port}${path}`);
      const text = await response.text();
      const ok =
        response.status === status && (body === null || text === body) && !response.headers.has('x-powered-by');
      console.log(`${ok ? 'PASS' : 'FAIL'} GET ${path} -> ${response.status} ${text}`);
      if (!ok) failures.push(`${label} ${path}`);
    }
  } finally {
    if (process.platform === 'win32') {
      // Windows has no SIGTERM delivery to child processes; graceful shutdown is verified in CI (Linux).
      child.kill();
      console.log('SKIP graceful shutdown check: not observable on Windows');
    } else {
      const exited = new Promise((resolve) => child.once('exit', (code) => resolve(code)));
      child.kill('SIGTERM');
      const code = await exited;
      const graceful = code === 0 && output.includes('"shutdown complete"');
      console.log(`${graceful ? 'PASS' : 'FAIL'} SIGTERM -> exit code ${code} (database pool closed)`);
      if (!graceful) failures.push(`${label} graceful shutdown`);
    }
  }
  // The connection string must never reach the log, whatever happened above.
  const password = (() => {
    try {
      return decodeURIComponent(new URL(env.DATABASE_URL ?? '').password);
    } catch {
      return '';
    }
  })();
  if (password !== '' && output.includes(password)) {
    console.log('FAIL the database password appeared in the API log');
    failures.push(`${label} log redaction`);
  } else {
    console.log('PASS the API log contains no database password');
  }
}

try {
  await smoke(
    'production mode, database unreachable (TLS required)',
    {
      NODE_ENV: 'production',
      APP_ORIGIN: 'https://ciphermesh.example',
      DATABASE_URL: 'postgresql://cm_api:smoke-placeholder-value@127.0.0.1:1/ciphermesh?sslmode=verify-full',
      ...AUTH_KEYS,
    },
    [
      ['/api/health', 200, '{"status":"ok"}'],
      ['/api/ready', 503, '{"status":"not-ready"}'],
      ['/api/nothing-here', 404, null],
    ],
  );

  const databaseUrl = process.env.DATABASE_URL;
  if (databaseUrl === undefined || databaseUrl === '') {
    throw new Error('DATABASE_URL is required for the database run (see .env.example)');
  }
  await smoke(
    'development mode, real database as cm_api',
    { NODE_ENV: 'development', APP_ORIGIN: 'https://localhost:8443', DATABASE_URL: databaseUrl, ...AUTH_KEYS },
    [
      ['/api/health', 200, '{"status":"ok"}'],
      ['/api/ready', 200, '{"status":"ready"}'],
      ['/api/nothing-here', 404, null],
    ],
  );
} catch (error) {
  console.log(`FAIL ${error instanceof Error ? error.message : 'smoke test error'}`);
  failures.push('startup');
}

if (failures.length > 0) {
  console.log(`Smoke test failed: ${failures.join(', ')}`);
  process.exit(1);
}
console.log('Smoke test passed against the built API bundle.');
