import { describe, expect, it } from 'vitest';
import { createLogger, type LogSink } from './logger';

function capture(): { sink: LogSink; lines: () => Record<string, unknown>[] } {
  const raw: string[] = [];
  return {
    sink: { write: (line) => raw.push(line) },
    lines: () => raw.map((line) => JSON.parse(line) as Record<string, unknown>),
  };
}

const fixedNow = (): Date => new Date('2026-10-02T10:00:00.000Z');

describe('logger', () => {
  it('writes one JSON object per line with time, level and message', () => {
    const { sink, lines } = capture();
    createLogger({ level: 'info', sink, now: fixedNow }).info('hello', { requestId: 'r-1' });
    expect(lines()).toEqual([{ requestId: 'r-1', time: '2026-10-02T10:00:00.000Z', level: 'info', msg: 'hello' }]);
  });

  it('drops records below the configured level', () => {
    const { sink, lines } = capture();
    const logger = createLogger({ level: 'warn', sink });
    logger.info('ignored');
    logger.debug('ignored');
    logger.error('kept');
    expect(lines().map((l) => l['msg'])).toEqual(['kept']);
  });

  it('redacts sensitive fields, including those inherited by child loggers', () => {
    const { sink, lines } = capture();
    const child = createLogger({ level: 'debug', sink }).child({ sessionToken: 'canary-child' });
    child.info('login attempt', { password: 'canary-password', user: { totpSecret: 'canary-totp' } });
    const text = JSON.stringify(lines());
    expect(text).not.toMatch(/canary-/);
    expect(lines()[0]?.['password']).toBe('[REDACTED]');
  });

  it('redacts sensitive values that appear in the message itself', () => {
    const { sink, lines } = capture();
    createLogger({ level: 'info', sink }).info('upload to https://s.example/o?X-Amz-Signature=abc');
    expect(lines()[0]?.['msg']).toBe('[REDACTED]');
  });

  it('does not let fields overwrite the reserved keys', () => {
    const { sink, lines } = capture();
    createLogger({ level: 'info', sink, now: fixedNow }).info('real', { level: 'fatal', msg: 'forged', time: 'x' });
    expect(lines()[0]).toMatchObject({ level: 'info', msg: 'real', time: '2026-10-02T10:00:00.000Z' });
  });
});
