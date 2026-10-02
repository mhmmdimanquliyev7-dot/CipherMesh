import { ErrorCode } from '@ciphermesh/shared';
import type { Request, RequestHandler } from 'express';
import { sendError } from './errors';

function hasBody(req: Request): boolean {
  if (req.headers['transfer-encoding'] !== undefined) return true;
  const length = req.headers['content-length'];
  return length !== undefined && length !== '0';
}

/** The API accepts JSON bodies only. Forms and text/plain are rejected before parsing. */
export const requireJsonBody: RequestHandler = (req, res, next) => {
  if (hasBody(req) && req.is('application/json') === false) {
    sendError(res, 415, ErrorCode.UNSUPPORTED_MEDIA_TYPE, 'Request body must be application/json');
    return;
  }
  next();
};
