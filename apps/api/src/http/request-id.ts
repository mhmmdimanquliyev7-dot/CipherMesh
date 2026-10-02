import { randomUUID } from 'node:crypto';
import { REQUEST_ID_HEADER } from '@ciphermesh/shared';
import type { RequestHandler } from 'express';
import { setRequestId } from './context';

/**
 * Every request gets a server-generated UUIDv4. Client-supplied IDs are ignored, so an
 * attacker cannot inject values into logs or correlate across users. Phase 17 may accept
 * the edge ID from Nginx once the proxy hop is trusted.
 */
export const requestId: RequestHandler = (_req, res, next) => {
  const id = randomUUID();
  setRequestId(res, id);
  res.setHeader(REQUEST_ID_HEADER, id);
  next();
};
