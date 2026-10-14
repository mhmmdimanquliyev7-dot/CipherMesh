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
import { createRequire } from 'node:module';

// Dependencies come from the API image's node_modules, not from this file's directory.
const require = createRequire('/app/package.json');
const pg = require('pg');
const { AwsClient } = await import(require.resolve('aws4fetch'));

const env = process.env;
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

const result = { checked: 0, matched: 0, missing: 0, sizeMismatch: 0, digestMismatch: 0, errors: 0 };
await db.connect();
try {
  const { rows } = await db.query(
    `SELECT object_key, ciphertext_size::text AS size, ciphertext_sha256 FROM encrypted_files WHERE status = 'AVAILABLE' ORDER BY created_at`,
  );
  for (const row of rows) {
    result.checked += 1;
    try {
      const response = await s3.fetch(`${env.STORAGE_ENDPOINT}/${env.STORAGE_BUCKET}/${row.object_key}`, {
        method: 'GET',
        redirect: 'error',
        signal: AbortSignal.timeout(30_000),
      });
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
console.log(JSON.stringify({ check: 'stored-ciphertext-integrity', at: new Date().toISOString(), ...result }));
process.exit(result.checked === result.matched ? 0 : 1);
