import { z } from 'zod';

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
}

const BODY_LIMIT_BYTES = 128 * 1024;

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']),
  API_HOST: z.string().min(1).default('127.0.0.1'),
  API_PORT: z.coerce.number().int().min(1).max(65535).default(4100),
  LOG_LEVEL: z.enum(LOG_LEVELS).default('info'),
  APP_ORIGIN: z.string().refine(isOrigin, { message: 'must be an origin such as https://example.org' }),
});

/**
 * Cross-field rule, checked on the raw values so it is reported together with any field
 * errors (zod skips object-level refinements once a field has failed).
 */
function productionRules(env: Readonly<Record<string, string>>): { variable: string; problem: string }[] {
  const origin = env['APP_ORIGIN'];
  return env['NODE_ENV'] === 'production' && origin !== undefined && !origin.startsWith('https://')
    ? [{ variable: 'APP_ORIGIN', problem: 'must use https in production' }]
    : [];
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
  });
}

export function loadConfigFromProcessEnv(): AppConfig {
  return loadConfig(process.env);
}
