/**
 * In-process abuse limits (CM-T018, T-09, T-10, T-26). The API runs as one process on one VM, so
 * in-memory state is sufficient; Nginx adds per-IP limits in front (Phase 17). Memory is bounded:
 * each limiter tracks at most `maxKeys` keys and forgets the oldest first.
 */

export class BusyError extends Error {
  constructor() {
    super('Too many concurrent password computations');
    this.name = 'BusyError';
  }
}

/** Runs at most `max` tasks at once with a bounded queue; beyond it, fails fast with BusyError. */
export class ConcurrencyLimiter {
  private active = 0;
  private readonly waiting: (() => void)[] = [];

  constructor(
    private readonly max: number,
    private readonly maxQueue: number,
  ) {}

  async run<T>(task: () => Promise<T>): Promise<T> {
    if (this.active >= this.max) {
      if (this.waiting.length >= this.maxQueue) throw new BusyError();
      await new Promise<void>((resolve) => this.waiting.push(resolve));
    } else {
      this.active += 1;
    }
    try {
      return await task();
    } finally {
      const next = this.waiting.shift();
      if (next)
        next(); // the slot passes directly to the next task
      else this.active -= 1;
    }
  }
}

export interface RateDecision {
  readonly allowed: boolean;
  readonly retryAfterSeconds: number;
}

/** Fixed-window counter per key, for example per client address and route. */
export class FixedWindowLimiter {
  private readonly windows = new Map<string, { start: number; count: number }>();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    private readonly maxKeys = 10_000,
    private readonly now: () => number = Date.now,
  ) {}

  consume(key: string): RateDecision {
    const now = this.now();
    let entry = this.windows.get(key);
    if (entry === undefined || now - entry.start >= this.windowMs) {
      if (entry === undefined && this.windows.size >= this.maxKeys) {
        const oldest = this.windows.keys().next();
        if (oldest.done !== true) this.windows.delete(oldest.value);
      }
      entry = { start: now, count: 0 };
      this.windows.delete(key);
      this.windows.set(key, entry);
    }
    entry.count += 1;
    if (entry.count <= this.limit) return { allowed: true, retryAfterSeconds: 0 };
    return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil((entry.start + this.windowMs - now) / 1000)) };
  }
}

/**
 * Progressive backoff per account or unknown identifier (no permanent lockout, CM-T018): the first
 * five consecutive failures are free, then each further failure blocks attempts for 30 seconds,
 * doubling up to 15 minutes. A correct password after the delay resets the count.
 */
export const BACKOFF = Object.freeze({ freeFailures: 5, baseSeconds: 30, maxSeconds: 900 });

export function backoffSeconds(consecutiveFailures: number): number {
  if (consecutiveFailures < BACKOFF.freeFailures) return 0;
  const exponent = Math.min(consecutiveFailures - BACKOFF.freeFailures, 10);
  return Math.min(BACKOFF.maxSeconds, BACKOFF.baseSeconds * 2 ** exponent);
}
