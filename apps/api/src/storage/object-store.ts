import { FILE_LIMITS } from '@ciphermesh/shared';
import { AwsClient } from 'aws4fetch';
import { randomBytes } from 'node:crypto';
import type { StorageConfig } from '../config/env';

/**
 * Object storage for encrypted file content (Phase 7, CM-T037; ADR-006, OL-07, CP-20). The only
 * module that talks to the S3-compatible API (ESLint enforces this). It stores and serves
 * ciphertext it cannot read: the browser encrypts before upload and decrypts after download.
 *
 * - Object keys are generated here: "f/" plus 32 random bytes in base64url. They never contain a
 *   room ID, a user ID or anything derived from a file name or a request (T-11, INV-16), and the
 *   database refuses any other form.
 * - Browsers never receive credentials. They receive presigned URLs (AWS Signature Version 4,
 *   signed by LIB-09) for one object, one method and a short time: an upload URL for exactly the
 *   announced ciphertext size (the signed content-length) valid 5 minutes, a download URL valid
 *   60 seconds that forces an attachment of type application/octet-stream (CP-20).
 * - The API itself only checks an object's size (HEAD) and deletes objects. Its credential is
 *   scoped to the content bucket for reading and writing objects; it cannot list objects, create
 *   or delete buckets, or reach other buckets (infrastructure/docker, deployment-architecture).
 * - Presigned URLs are bearer capabilities: they are never logged, stored or put in errors
 *   (INV-10); StorageError carries a fixed message and the status code only.
 */
export interface StorageCapability {
  readonly url: string;
  readonly expiresAt: Date;
}

export interface ObjectStore {
  /** Whether storage is configured. When false, every operation throws StorageError. */
  readonly available: boolean;
  /** A presigned PUT for exactly `size` bytes to `objectKey`, valid for CP-20's 5 minutes. */
  presignUpload(objectKey: string, size: number, now: Date): Promise<StorageCapability>;
  /** A presigned GET of `objectKey` as an octet-stream attachment, valid for CP-20's 60 seconds. */
  presignDownload(objectKey: string, now: Date): Promise<StorageCapability>;
  /** The stored size of an object, or null when it does not exist. */
  head(objectKey: string): Promise<{ readonly size: number } | null>;
  /** Deletes an object; deleting an object that does not exist succeeds. */
  delete(objectKey: string): Promise<void>;
}

/** Storage was not configured, did not answer in time, or answered unexpectedly. */
export class StorageError extends Error {
  constructor(readonly status?: number) {
    super('Object storage request failed');
    this.name = 'StorageError';
  }
}

const OBJECT_KEY = /^f\/[A-Za-z0-9_-]{43}$/;

/** A new random object key (256 bits from the CSPRNG); never derived from request data. */
export function newObjectKey(): string {
  return `f/${randomBytes(32).toString('base64url')}`;
}

export function isObjectKey(value: string): boolean {
  return OBJECT_KEY.test(value);
}

/** Requests to storage time out instead of holding a request or a worker run open (T-26). */
const REQUEST_TIMEOUT_MS = 10_000;

/** AWS SigV4 date form, YYYYMMDD'T'HHMMSS'Z', of the signing time. */
const amzDate = (now: Date): string => now.toISOString().replace(/[:-]|\.\d{3}/g, '');

function requireKey(objectKey: string): void {
  if (!isObjectKey(objectKey)) throw new StorageError();
}

/** The S3-compatible implementation, path-style URLs, one bucket. */
export function createS3ObjectStore(config: StorageConfig): ObjectStore {
  const client = new AwsClient({
    accessKeyId: config.accessKeyId,
    secretAccessKey: config.secretAccessKey.reveal(),
    service: 's3',
    region: config.region,
    retries: 0,
  });
  const objectUrl = (base: string, objectKey: string): URL => new URL(`${base}/${config.bucket}/${objectKey}`);

  async function presign(
    method: 'PUT' | 'GET',
    objectKey: string,
    seconds: number,
    now: Date,
    headers: Record<string, string>,
    query: Record<string, string>,
  ): Promise<StorageCapability> {
    requireKey(objectKey);
    const url = objectUrl(config.publicEndpoint, objectKey);
    url.searchParams.set('X-Amz-Expires', String(seconds));
    for (const [name, value] of Object.entries(query)) url.searchParams.set(name, value);
    // allHeaders: the content-length of an upload is part of the signature, so storage refuses a
    // body of any other size (checked against the emulator in tests/files).
    const signed = await client.sign(url.toString(), {
      method,
      headers,
      aws: { signQuery: true, allHeaders: true, datetime: amzDate(now) },
    });
    return { url: signed.url, expiresAt: new Date(now.getTime() - (now.getTime() % 1000) + seconds * 1000) };
  }

  async function call(method: 'HEAD' | 'DELETE', objectKey: string): Promise<Response> {
    requireKey(objectKey);
    try {
      return await client.fetch(objectUrl(config.endpoint, objectKey).toString(), {
        method,
        redirect: 'error',
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch {
      throw new StorageError();
    }
  }

  return {
    available: true,
    presignUpload: (objectKey, size, now) => {
      if (!Number.isSafeInteger(size) || size < 0 || size > FILE_LIMITS.maxCiphertextBytes) {
        return Promise.reject(new StorageError());
      }
      return presign('PUT', objectKey, FILE_LIMITS.uploadUrlSeconds, now, { 'content-length': String(size) }, {});
    },
    presignDownload: (objectKey, now) =>
      presign(
        'GET',
        objectKey,
        FILE_LIMITS.downloadUrlSeconds,
        now,
        {},
        {
          // Never rendered by the browser as a page: always a download of opaque bytes (T-11).
          'response-content-disposition': 'attachment',
          'response-content-type': 'application/octet-stream',
          'response-cache-control': 'no-store',
        },
      ),
    async head(objectKey) {
      const response = await call('HEAD', objectKey);
      if (response.status === 404) return null;
      const length = Number(response.headers.get('content-length'));
      if (response.status !== 200 || !Number.isSafeInteger(length) || length < 0) {
        throw new StorageError(response.status);
      }
      return { size: length };
    },
    async delete(objectKey) {
      const response = await call('DELETE', objectKey);
      if (response.status !== 204 && response.status !== 200 && response.status !== 404) {
        throw new StorageError(response.status);
      }
    },
  };
}

/** Storage when none is configured (outside production only): nothing works, nothing is faked. */
export const unavailableObjectStore: ObjectStore = Object.freeze({
  available: false,
  presignUpload: () => Promise.reject(new StorageError()),
  presignDownload: () => Promise.reject(new StorageError()),
  head: () => Promise.reject(new StorageError()),
  delete: () => Promise.reject(new StorageError()),
});

export function createObjectStore(config: StorageConfig | null): ObjectStore {
  return config === null ? unavailableObjectStore : createS3ObjectStore(config);
}
