import { CIPHERMESH_REQUEST_HEADER, CIPHERMESH_REQUEST_HEADER_VALUE, ErrorCode } from '@ciphermesh/shared';
import type { Request, RequestHandler } from 'express';
import { sendError } from './errors';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * INV-19: every state-changing request must come from the CipherMesh origin and carry
 * the custom request header. Runs before body parsing, so cross-site payloads are never
 * parsed. SameSite cookies are a separate layer and are not relied on here.
 * Design: docs/security/session-and-csrf.md section 8.
 */
export function isSameOriginRequest(req: Request, appOrigin: string): boolean {
  const fetchSite = req.get('sec-fetch-site');
  if (fetchSite !== undefined) {
    if (fetchSite !== 'same-origin') return false;
  } else {
    const origin = req.get('origin');
    // A missing Origin and the literal `null` are both rejected.
    if (origin === undefined || origin !== appOrigin) return false;
  }
  return req.get(CIPHERMESH_REQUEST_HEADER) === CIPHERMESH_REQUEST_HEADER_VALUE;
}

export function sameOriginGate(appOrigin: string): RequestHandler {
  return (req, res, next) => {
    if (SAFE_METHODS.has(req.method) || isSameOriginRequest(req, appOrigin)) {
      next();
      return;
    }
    sendError(res, 403, ErrorCode.ORIGIN_REJECTED, 'Request origin rejected');
  };
}
