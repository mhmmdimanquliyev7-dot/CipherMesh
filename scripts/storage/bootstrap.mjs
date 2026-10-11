// `pnpm storage:bootstrap` (Phase 7, CM-T037): prepares the local object-storage emulator and
// proves the runtime credential's scope. Development and CI only; production buckets are created
// by the provider configuration (Phase 19).
//
//   1. The administrator identity (S3_*) creates the content bucket, if it does not exist.
//   2. The runtime identity (STORAGE_*, used by the API and the worker) must be able to write,
//      read, inspect and delete an object in that bucket, and must NOT be able to list its
//      objects, create a bucket or delete the bucket. Anonymous requests must be refused.
// Any deviation fails the script, so a misconfigured emulator never passes silently.
import { randomBytes } from 'node:crypto';
import { loadLocalEnv, storageClient, storageTarget } from './lib.mjs';

loadLocalEnv();
const { endpoint, bucket } = storageTarget();
const admin = storageClient('admin');
const runtime = storageClient('runtime');
const base = `${endpoint}/${bucket}`;
let failed = false;

/**
 * @param {string} label
 * @param {Promise<Response>} request
 * @param {(status: number) => boolean} expected
 */
async function check(label, request, expected) {
  let status;
  try {
    status = (await request).status;
  } catch {
    status = 0;
  }
  const ok = expected(status);
  if (!ok) failed = true;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${label} (HTTP ${String(status)})`);
}

const created = await admin.fetch(base, { method: 'PUT' }).catch(() => undefined);
if (created === undefined) {
  console.error(`FAIL object storage at ${endpoint} is not reachable (pnpm services:up)`);
  process.exit(1);
}
// 200 created; 409 BucketAlreadyOwnedByYou or BucketAlreadyExists when it was there before.
const bucketOk = created.status === 200 || created.status === 409;
if (!bucketOk) failed = true;
console.log(`${bucketOk ? 'PASS' : 'FAIL'} bucket ${bucket} exists (HTTP ${String(created.status)})`);

const probe = `${base}/f/${randomBytes(32).toString('base64url')}`;
const ok = (/** @type {number} */ s) => s >= 200 && s < 300;
const denied = (/** @type {number} */ s) => s === 403;
await check('runtime identity writes an object', runtime.fetch(probe, { method: 'PUT', body: 'probe' }), ok);
await check('runtime identity reads an object', runtime.fetch(probe), ok);
await check('runtime identity inspects an object (HEAD)', runtime.fetch(probe, { method: 'HEAD' }), ok);
await check('anonymous read is refused', fetch(probe), denied);
await check('anonymous listing is refused', fetch(`${base}?list-type=2`), denied);
await check('runtime identity cannot list objects', runtime.fetch(`${base}?list-type=2`), denied);
await check(
  'runtime identity cannot create a bucket',
  runtime.fetch(`${endpoint}/cm-bootstrap-${randomBytes(4).toString('hex')}`, { method: 'PUT' }),
  denied,
);
await check('runtime identity cannot delete the bucket', runtime.fetch(base, { method: 'DELETE' }), denied);
await check('runtime identity deletes an object', runtime.fetch(probe, { method: 'DELETE' }), ok);

if (failed) {
  console.error('FAIL object storage is not configured as infrastructure/docker/compose.dev.yml requires');
  process.exitCode = 1;
}
