import type { LogLevel } from '../config/env';
import { redact as defaultRedact } from './redact';

/**
 * Minimal structured JSON logger. Every field passes through the central redactor
 * before serialisation. There is deliberately no API for logging raw request bodies,
 * query strings or the environment.
 */
export interface LogSink {
  write(line: string): void;
}

export type LogFields = Readonly<Record<string, unknown>>;

export interface Logger {
  fatal(message: string, fields?: LogFields): void;
  error(message: string, fields?: LogFields): void;
  warn(message: string, fields?: LogFields): void;
  info(message: string, fields?: LogFields): void;
  debug(message: string, fields?: LogFields): void;
  child(fields: LogFields): Logger;
}

const SEVERITY: Record<LogLevel, number> = { fatal: 60, error: 50, warn: 40, info: 30, debug: 20 };

export interface LoggerOptions {
  readonly level: LogLevel;
  readonly sink?: LogSink;
  readonly base?: LogFields;
  readonly redact?: (value: unknown) => unknown;
  readonly now?: () => Date;
}

export function createLogger(options: LoggerOptions): Logger {
  const sink: LogSink = options.sink ?? { write: (line) => process.stdout.write(line) };
  const redact = options.redact ?? defaultRedact;
  const now = options.now ?? (() => new Date());
  const threshold = SEVERITY[options.level];

  const make = (base: LogFields): Logger => {
    const emit = (level: LogLevel, message: string, fields?: LogFields): void => {
      if (SEVERITY[level] < threshold) return;
      const record = redact({ ...base, ...fields }) as Record<string, unknown>;
      // Reserved keys are written last so a field cannot overwrite them.
      sink.write(`${JSON.stringify({ ...record, time: now().toISOString(), level, msg: redact(message) })}\n`);
    };
    return {
      fatal: (m, f) => {
        emit('fatal', m, f);
      },
      error: (m, f) => {
        emit('error', m, f);
      },
      warn: (m, f) => {
        emit('warn', m, f);
      },
      info: (m, f) => {
        emit('info', m, f);
      },
      debug: (m, f) => {
        emit('debug', m, f);
      },
      child: (fields) => make({ ...base, ...fields }),
    };
  };
  return make(options.base ?? {});
}
