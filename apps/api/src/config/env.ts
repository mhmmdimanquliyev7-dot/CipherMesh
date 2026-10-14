import { z } from 'zod';
import { SecretValue } from './secret';

/**
 * The only module allowed to read process.env (ESLint enforces this).
 * Configuration is validated once at startup and the process refuses to start
 * when it is invalid (principle 10, fail securely).
 */
export const LOG_LEVELS = ['fatal', 'error', 'warn', 'info', 'debug'] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

export interface AppConfig {
  readonly nodeEnv: 'development' | 'test' | 'production';
  readonly isProduction: boolean;
  readonly api: { readonly host: string; readonly port: number };
  readonly logLevel: LogLevel;
  /** The single origin allowed to send state-changing requests (INV-19). */
  readonly appOrigin: string;
  /** Maximum JSON body size. Files never pass through the API (CP-19, CP-25). */
  readonly bodyLimitBytes: number;
  /** Connection to PostgreSQL as the least-privilege API role (CM-T014, TB-05). */
  readonly database: { readonly url: SecretValue };
  /** Server-held authentication keys (Phase 3). Both are 32 random bytes, base64url encoded. */
  readonly auth: {
    /** AES-256-GCM key for TOTP secrets at rest (CP-11) and the ID stored with each ciphertext. */
    readonly totpEncryptionKey: SecretValue;
    readonly totpEncryptionKeyId: string;
    /** HMAC-SHA-256 key for unknown login identifiers (CP-12). */
    readonly identifierHmacKey: SecretValue;
  };
  /**
   * Number of reverse proxies whose X-Forwarded-For entry is trusted for the client address
   * (TB-04). 0 locally; 1 behind the single Nginx hop in production (Phase 17).
   */
  readonly trustProxyHops: 0 | 1;
  /**
   * Object storage for encrypted file content (Phase 7, CM-T037), or null outside production
   * when it is not configured: the file routes then answer STORAGE_UNAVAILABLE.
   */
  readonly storage: StorageConfig | null;
  /**
   * The host status file of the cloud deployment (cm-status-collect, ADR-014), mounted read-only;
   * null when the API does not run on the cloud VM. The dashboard reads it, never writes it.
   */
  readonly platformStatusFile: string | null;
}

/**
 * The S3-compatible object storage the API and the worker use (ADR-006, deployment-architecture).
 * The credential is the runtime one, scoped to the content bucket (read and write objects only);
 * the emulator's administrator credential (S3_*) is used only by `pnpm storage:bootstrap`.
 */
export interface StorageConfig {
  /** Origin the API and the worker call for HEAD and DELETE. */
  readonly endpoint: string;
  /** Origin written into presigned URLs, which browsers reach (the page's CSP connect-src allows it). */
  readonly publicEndpoint: string;
  readonly region: string;
  readonly bucket: string;
  readonly accessKeyId: string;
  readonly secretAccessKey: SecretValue;
}

const BODY_LIMIT_BYTES = 128 * 1024;

/** The API connects only as its runtime role; grants are written for this name (CM-T014). */
export const API_DATABASE_ROLE = 'cm_api';
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]']);

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']),
  API_HOST: z.string().min(1).default('127.0.0.1'),
  API_PORT: z.coerce.number().int().min(1).max(65535).default(4100),
  LOG_LEVEL: z.enum(LOG_LEVELS).default('info'),
  APP_ORIGIN: z.string().refine(isOrigin, { message: 'must be an origin such as https://example.org' }),
  DATABASE_URL: z.string(),
  TOTP_ENCRYPTION_KEY: z.string().refine(isKey32, { message: 'must be 32 random bytes, base64url encoded' }),
  TOTP_ENCRYPTION_KEY_ID: z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/),
  IDENTIFIER_HMAC_KEY: z.string().refine(isKey32, { message: 'must be 32 random bytes, base64url encoded' }),
  TRUST_PROXY_HOPS: z.enum(['0', '1']).default('0'),
  PLATFORM_STATUS_FILE: z
    .string()
    .regex(/^\/[A-Za-z0-9._/-]{1,200}\.json$/, { message: 'must be an absolute path to a .json file' })
    .refine((value) => !value.split('/').includes('..'), { message: 'must not contain ..' })
    .optional(),
  ...storageFields(),
});

/** The storage variables, shared by the API and the worker. Cross-field rules: storageRules(). */
function storageFields() {
  const origin = z.string().refine(isOrigin, { message: 'must be an origin such as https://storage.example' });
  return {
    STORAGE_ENDPOINT: origin.optional(),
    STORAGE_PUBLIC_ENDPOINT: origin.optional(),
    STORAGE_REGION: z
      .string()
      .regex(/^[a-z0-9-]{1,32}$/)
      .default('us-east-1'),
    STORAGE_BUCKET: z
      .string()
      .regex(/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/)
      .optional(),
    STORAGE_ACCESS_KEY_ID: z
      .string()
      .regex(/^[A-Za-z0-9._-]{3,128}$/)
      .optional(),
    STORAGE_SECRET_ACCESS_KEY: z.string().min(16).max(256).optional(),
  };
}

const STORAGE_REQUIRED = ['STORAGE_ENDPOINT', 'STORAGE_BUCKET', 'STORAGE_ACCESS_KEY_ID', 'STORAGE_SECRET_ACCESS_KEY'];

/**
 * Storage is all or nothing, required in production, and reached over TLS except on loopback in
 * development (CP-21). Problems name the variable, never its value.
 */
function storageRules(env: Readonly<Record<string, string>>): { variable: string; problem: string }[] {
  const isProduction = env['NODE_ENV'] === 'production';
  const configured = STORAGE_REQUIRED.some((name) => env[name] !== undefined);
  const problems: { variable: string; problem: string }[] = [];
  if (configured || isProduction || env['STORAGE_PUBLIC_ENDPOINT'] !== undefined) {
    for (const name of STORAGE_REQUIRED) {
      if (env[name] === undefined) problems.push({ variable: name, problem: 'required with object storage' });
    }
  }
  // SF-07-01: browsers send the session cookie by host, not by port, and one tested engine sent it
  // to another port of the application's host even for requests without credentials. Presigned
  // URLs must therefore point to another host, never to the application's own.
  const appOrigin = env['APP_ORIGIN'];
  const publicEndpoint = env['STORAGE_PUBLIC_ENDPOINT'] ?? env['STORAGE_ENDPOINT'];
  if (
    appOrigin !== undefined &&
    publicEndpoint !== undefined &&
    isOrigin(appOrigin) &&
    isOrigin(publicEndpoint) &&
    new URL(appOrigin).hostname === new URL(publicEndpoint).hostname
  ) {
    problems.push({
      variable: env['STORAGE_PUBLIC_ENDPOINT'] === undefined ? 'STORAGE_ENDPOINT' : 'STORAGE_PUBLIC_ENDPOINT',
      problem: 'must not be on the application host (cookies are not isolated by port)',
    });
  }
  for (const name of ['STORAGE_ENDPOINT', 'STORAGE_PUBLIC_ENDPOINT']) {
    const value = env[name];
    if (value === undefined || !isOrigin(value)) continue;
    const url = new URL(value);
    if (url.protocol === 'https:') continue;
    if (isProduction) problems.push({ variable: name, problem: 'must use https in production' });
    else if (!LOOPBACK_HOSTS.has(url.hostname)) {
      problems.push({ variable: name, problem: 'must use https for a non-local host' });
    }
  }
  return problems;
}

interface StorageEnv {
  readonly STORAGE_ENDPOINT?: string | undefined;
  readonly STORAGE_PUBLIC_ENDPOINT?: string | undefined;
  readonly STORAGE_REGION: string;
  readonly STORAGE_BUCKET?: string | undefined;
  readonly STORAGE_ACCESS_KEY_ID?: string | undefined;
  readonly STORAGE_SECRET_ACCESS_KEY?: string | undefined;
}

function storageConfigOf(e: StorageEnv): StorageConfig | null {
  const endpoint = e.STORAGE_ENDPOINT;
  const bucket = e.STORAGE_BUCKET;
  const accessKeyId = e.STORAGE_ACCESS_KEY_ID;
  const secret = e.STORAGE_SECRET_ACCESS_KEY;
  if (endpoint === undefined || bucket === undefined || accessKeyId === undefined || secret === undefined) return null;
  return Object.freeze({
    endpoint,
    publicEndpoint: e.STORAGE_PUBLIC_ENDPOINT ?? endpoint,
    region: e.STORAGE_REGION,
    bucket,
    accessKeyId,
    secretAccessKey: new SecretValue(secret),
  });
}

/** 32 bytes in canonical unpadded base64url (43 characters). */
function isKey32(value: string): boolean {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) return false;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.length === 32 && bytes.toString('base64url') === value;
}

/**
 * Cross-field rules, checked on the raw values so they are reported together with any field
 * errors (zod skips object-level refinements once a field has failed).
 */
function productionRules(env: Readonly<Record<string, string>>): { variable: string; problem: string }[] {
  const origin = env['APP_ORIGIN'];
  const problems: { variable: string; problem: string }[] =
    env['NODE_ENV'] === 'production' && origin !== undefined && !origin.startsWith('https://')
      ? [{ variable: 'APP_ORIGIN', problem: 'must use https in production' }]
      : [];
  const databaseUrl = env['DATABASE_URL'];
  const databaseProblem =
    databaseUrl === undefined ? undefined : checkDatabaseUrl(databaseUrl, env['NODE_ENV'] === 'production');
  if (databaseProblem !== undefined) problems.push({ variable: 'DATABASE_URL', problem: databaseProblem });
  // Key separation: one key per purpose (key-hierarchy.md).
  if (env['TOTP_ENCRYPTION_KEY'] !== undefined && env['TOTP_ENCRYPTION_KEY'] === env['IDENTIFIER_HMAC_KEY']) {
    problems.push({ variable: 'IDENTIFIER_HMAC_KEY', problem: 'must differ from TOTP_ENCRYPTION_KEY' });
  }
  problems.push(...storageRules(env));
  return problems;
}

/**
 * Database connection rules (TB-05, CP-21). Problems are described without the value, which
 * contains a password.
 * - Only the API role may be used: never the migration role or an administrator.
 * - Production requires TLS with certificate and host name verification (sslmode=verify-full).
 *   Weaker modes would allow an attacker on the network path to read or alter traffic.
 * - Outside production, a connection without verify-full is accepted only to a loopback host
 *   (the local development container).
 */
function checkDatabaseUrl(value: string, isProduction: boolean, role: string = API_DATABASE_ROLE): string | undefined {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return 'must be a postgresql:// URL';
  }
  if (url.protocol !== 'postgresql:' && url.protocol !== 'postgres:') return 'must be a postgresql:// URL';
  if (url.hostname === '' || url.pathname.length < 2) return 'must name a host and a database';
  if (decodeURIComponent(url.username) !== role) return `must connect as the ${role} role`;
  if (url.password === '') return 'must include the role password';
  const verifyFull = url.searchParams.get('sslmode') === 'verify-full';
  if (isProduction && !verifyFull) return 'must use sslmode=verify-full in production';
  if (!verifyFull && !LOOPBACK_HOSTS.has(url.hostname)) return 'must use sslmode=verify-full for a non-local host';
  return undefined;
}

function isOrigin(value: string): boolean {
  try {
    const url = new URL(value);
    return (url.protocol === 'https:' || url.protocol === 'http:') && url.origin === value;
  } catch {
    return false;
  }
}

export class ConfigError extends Error {
  readonly problems: readonly { readonly variable: string; readonly problem: string }[];

  constructor(problems: readonly { readonly variable: string; readonly problem: string }[]) {
    // Names and problem types only: values are never echoed, because a misplaced secret
    // in the wrong variable must not end up in startup logs (INV-10).
    super(`Invalid configuration: ${problems.map((p) => `${p.variable} (${p.problem})`).join(', ')}`);
    this.name = 'ConfigError';
    this.problems = problems;
  }
}

export function loadConfig(env: Readonly<Record<string, string | undefined>>): AppConfig {
  // Empty strings count as missing, so `API_PORT=` falls back to the default or fails.
  const present = Object.fromEntries(
    Object.entries(env).filter((entry): entry is [string, string] => entry[1] !== undefined && entry[1] !== ''),
  );
  const result = envSchema.safeParse(present);
  const problems = [
    ...(result.success
      ? []
      : result.error.issues.map((issue) => ({
          variable: issue.path.map(String).join('.') || '(environment)',
          problem: issue.code === 'custom' ? issue.message : issue.code,
        }))),
    ...productionRules(present),
  ].filter((p, i, all) => all.findIndex((q) => q.variable === p.variable && q.problem === p.problem) === i);
  if (!result.success || problems.length > 0) throw new ConfigError(problems);
  const e = result.data;
  return Object.freeze({
    nodeEnv: e.NODE_ENV,
    isProduction: e.NODE_ENV === 'production',
    api: Object.freeze({ host: e.API_HOST, port: e.API_PORT }),
    logLevel: e.LOG_LEVEL,
    appOrigin: e.APP_ORIGIN,
    bodyLimitBytes: BODY_LIMIT_BYTES,
    database: Object.freeze({ url: new SecretValue(e.DATABASE_URL) }),
    auth: Object.freeze({
      totpEncryptionKey: new SecretValue(e.TOTP_ENCRYPTION_KEY),
      totpEncryptionKeyId: e.TOTP_ENCRYPTION_KEY_ID,
      identifierHmacKey: new SecretValue(e.IDENTIFIER_HMAC_KEY),
    }),
    trustProxyHops: e.TRUST_PROXY_HOPS === '1' ? 1 : 0,
    storage: storageConfigOf(e),
    platformStatusFile: e.PLATFORM_STATUS_FILE ?? null,
  });
}

/** Configuration of worker jobs (Phase 3: retention). Only the worker role may be used. */
export interface WorkerConfig {
  readonly isProduction: boolean;
  readonly logLevel: LogLevel;
  readonly database: { readonly url: SecretValue };
  /** Object storage, for deleting the objects of deleted, expired and abandoned files (CM-T040). */
  readonly storage: StorageConfig | null;
}

export const WORKER_DATABASE_ROLE = 'cm_worker';

export function loadWorkerConfig(env: Readonly<Record<string, string | undefined>>): WorkerConfig {
  const present = Object.fromEntries(
    Object.entries(env).filter((entry): entry is [string, string] => entry[1] !== undefined && entry[1] !== ''),
  );
  const result = z
    .object({
      NODE_ENV: z.enum(['development', 'test', 'production']),
      LOG_LEVEL: z.enum(LOG_LEVELS).default('info'),
      WORKER_DATABASE_URL: z.string().min(1),
      ...storageFields(),
    })
    .safeParse(present);
  if (!result.success) {
    throw new ConfigError(
      result.error.issues.map((issue) => ({
        variable: issue.path.map(String).join('.') || '(environment)',
        problem: issue.code,
      })),
    );
  }
  const isProduction = result.data.NODE_ENV === 'production';
  const problem = checkDatabaseUrl(result.data.WORKER_DATABASE_URL, isProduction, WORKER_DATABASE_ROLE);
  const problems = [
    ...(problem === undefined ? [] : [{ variable: 'WORKER_DATABASE_URL', problem }]),
    ...storageRules(present),
  ];
  if (problems.length > 0) throw new ConfigError(problems);
  return Object.freeze({
    isProduction,
    logLevel: result.data.LOG_LEVEL,
    database: Object.freeze({ url: new SecretValue(result.data.WORKER_DATABASE_URL) }),
    storage: storageConfigOf(result.data),
  });
}

export function loadWorkerConfigFromProcessEnv(): WorkerConfig {
  return loadWorkerConfig(process.env);
}

export function loadConfigFromProcessEnv(): AppConfig {
  return loadConfig(process.env);
}
