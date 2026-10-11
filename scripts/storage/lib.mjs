// Shared helpers for the object-storage scripts and tests (Phase 7, CM-T037). Development and CI
// only: they talk to the local S3-compatible emulator (infrastructure/docker/compose.dev.yml).
// Credentials come from the environment (.env locally, masked random values in CI) and are never
// printed; errors name the variable only.
import { AwsClient } from 'aws4fetch';
import { existsSync } from 'node:fs';

export function loadLocalEnv() {
  if (existsSync('.env')) process.loadEnvFile('.env');
}

/**
 * @param {string} variable
 * @returns {string}
 */
function required(variable) {
  const value = process.env[variable];
  if (value === undefined || value === '') throw new Error(`${variable} is not set (see .env.example)`);
  return value;
}

/** The S3 endpoint and bucket the API uses. */
export function storageTarget() {
  return {
    endpoint: required('STORAGE_ENDPOINT'),
    bucket: process.env.STORAGE_BUCKET || 'cm-files',
    region: process.env.STORAGE_REGION || 'us-east-1',
  };
}

/**
 * @param {'admin' | 'runtime'} who
 * @returns {AwsClient}
 */
export function storageClient(who) {
  const [id, secret] =
    who === 'admin'
      ? ['S3_ACCESS_KEY_ID', 'S3_SECRET_ACCESS_KEY']
      : ['STORAGE_ACCESS_KEY_ID', 'STORAGE_SECRET_ACCESS_KEY'];
  return new AwsClient({
    accessKeyId: required(id),
    secretAccessKey: required(secret),
    service: 's3',
    region: storageTarget().region,
    retries: 0,
  });
}
