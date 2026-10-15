// Integrity check of stored ciphertext (backup restore drill and operator check, ADR-014).
// Runs inside the worker container (the API image), as cm_worker, which may read encrypted_files:
//
//   docker compose run --rm --no-deps -T -v <this file>:/opt/cm/verify-objects.mjs:ro worker /opt/cm/verify-objects.mjs
//
// For every AVAILABLE file it fetches the object from storage with the runtime credential and
// compares its size and SHA-256 with ciphertext_size and ciphertext_sha256 recorded at upload.
// It never decrypts anything and holds no key: identical ciphertext under identical wrapped keys
// is what the members' browsers decrypt. Output: counts only (no object keys, no URLs; INV-10).
// Exit code 0 only when every object matched and at least one file was checked or none exist.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

// Dependencies come from the API image's node_modules, not from this file's directory.
const require = createRequire('/app/package.json');
const pg = require('pg');
const { AwsClient } = await import(require.resolve('aws4fetch'));

// Secret values may come as files (<NAME>_FILE), as in the worker container (CM-T071).
const env = { ...process.env };
for (const name of ['WORKER_DATABASE_URL', 'STORAGE_SECRET_ACCESS_KEY']) {
  const file = env[`${name}_FILE`];
  if (!env[name] && file) env[name] = readFileSync(file, 'utf8').trim();
}
for (const name of [
  'WORKER_DATABASE_URL',
  'STORAGE_ENDPOINT',
  'STORAGE_BUCKET',
  'STORAGE_ACCESS_KEY_ID',
  'STORAGE_SECRET_ACCESS_KEY',
]) {
  if (!env[name]) {
    console.error(`verify-objects: ${name} is not set`);
    process.exit(2);
  }
}

const db = new pg.Client({ connectionString: env.WORKER_DATABASE_URL, application_name: 'ciphermesh-verify-objects' });
const s3 = new AwsClient({
  accessKeyId: env.STORAGE_ACCESS_KEY_ID,
  secretAccessKey: env.STORAGE_SECRET_ACCESS_KEY,
  service: 's3',
  region: env.STORAGE_REGION || 'us-east-1',
  retries: 0,
});

const result = { checked: 0, matched: 0, missing: 0, sizeMismatch: 0, digestMismatch: 0, errors: 0, retries: 0 };
// Status codes of the retried attempts (counts only), so a drill report shows why it waited.
const transient = {};

// A freshly started SeaweedFS answers its S3 port before its filer and volumes serve objects, so a
// failed fetch is retried for up to a minute. Only the fetch is retried: a missing object (404), a
// size or digest mismatch, or a failure that persists is reported as before.
const ATTEMPTS = 20;
const RETRY_MS = 3000;
async function fetchObject(url) {
  for (let attempt = 1; ; attempt += 1) {
    let reason;
    try {
      const response = await s3.fetch(url, { method: 'GET', redirect: 'error', signal: AbortSignal.timeout(30_000) });
      if (response.ok || response.status === 404 || attempt === ATTEMPTS) return response;
      reason = String(response.status);
      await response.body?.cancel();
    } catch (error) {
      if (attempt === ATTEMPTS) throw error;
      reason = 'network';
    }
    result.retries += 1;
    transient[reason] = (transient[reason] ?? 0) + 1;
    await new Promise((resolve) => setTimeout(resolve, RETRY_MS));
  }
}
await db.connect();
try {
  const { rows } = await db.query(
    `SELECT object_key, ciphertext_size::text AS size, ciphertext_sha256 FROM encrypted_files WHERE status = 'AVAILABLE' ORDER BY created_at`,
  );
  for (const row of rows) {
    result.checked += 1;
    try {
      const response = await fetchObject(`${env.STORAGE_ENDPOINT}/${env.STORAGE_BUCKET}/${row.object_key}`);
      if (response.status === 404) {
        result.missing += 1;
        await response.body?.cancel();
        continue;
      }
      if (!response.ok || response.body === null) {
        result.errors += 1;
        await response.body?.cancel();
        continue;
      }
      const hash = createHash('sha256');
      let size = 0n;
      for await (const chunk of response.body) {
        hash.update(chunk);
        size += BigInt(chunk.length);
      }
      if (size.toString() !== row.size) result.sizeMismatch += 1;
      else if (!hash.digest().equals(row.ciphertext_sha256)) result.digestMismatch += 1;
      else result.matched += 1;
    } catch {
      result.errors += 1;
    }
  }
} finally {
  await db.end();
}
console.log(
  JSON.stringify({ check: 'stored-ciphertext-integrity', at: new Date().toISOString(), ...result, transient }),
);
process.exit(result.checked === result.matched ? 0 : 1);
