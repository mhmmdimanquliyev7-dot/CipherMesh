import type { Response } from 'express';

/** Request-scoped values live in res.locals behind typed accessors. */
export function setRequestId(res: Response, id: string): void {
  res.locals['requestId'] = id;
}

export function getRequestId(res: Response): string {
  const id: unknown = res.locals['requestId'];
  if (typeof id !== 'string') throw new Error('Request ID middleware did not run');
  return id;
}
