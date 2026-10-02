/** Readiness state: not ready until the server listens, and not ready again once shutdown starts. */
export interface Lifecycle {
  isReady(): boolean;
  markReady(): void;
  markShuttingDown(): void;
}

export function createLifecycle(): Lifecycle {
  let state: 'starting' | 'ready' | 'shutting-down' = 'starting';
  return {
    isReady: () => state === 'ready',
    markReady: () => {
      if (state === 'starting') state = 'ready';
    },
    markShuttingDown: () => {
      state = 'shutting-down';
    },
  };
}
