import { ErrorCode, type ApiErrorBody, type ValidationIssue } from '@ciphermesh/shared';
import type { ErrorRequestHandler, RequestHandler, Response } from 'express';
import { describeDatabaseError, isDatabaseError } from '../db/errors';
import type { Logger } from '../logging/logger';
import { getRequestId } from './context';

/** An expected error with a safe, generic message. */
export class HttpError extends Error {
  readonly status: number;
  readonly code: ErrorCode;
  readonly issues: readonly ValidationIssue[] | undefined;

  constructor(status: number, code: ErrorCode, message: string, issues?: readonly ValidationIssue[]) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.code = code;
    this.issues = issues;
  }
}

export function sendError(
  res: Response,
  status: number,
  code: ErrorCode,
  message: string,
  issues?: readonly ValidationIssue[],
): void {
  const body: ApiErrorBody = {
    error: { code, message, requestId: getRequestId(res), ...(issues ? { issues } : {}) },
  };
  res.status(status).json(body);
}

export const notFound: RequestHandler = (_req, res) => {
  sendError(res, 404, ErrorCode.NOT_FOUND, 'Resource not found');
};

/** Errors raised by Express's JSON body parser carry a `type` property. */
const BODY_PARSER_ERRORS: Record<string, readonly [number, ErrorCode, string]> = {
  'entity.parse.failed': [400, ErrorCode.INVALID_JSON, 'Request body is not valid JSON'],
  'entity.too.large': [413, ErrorCode.PAYLOAD_TOO_LARGE, 'Request body is too large'],
  'encoding.unsupported': [415, ErrorCode.UNSUPPORTED_MEDIA_TYPE, 'Unsupported content encoding'],
  'charset.unsupported': [415, ErrorCode.UNSUPPORTED_MEDIA_TYPE, 'Unsupported charset'],
  'request.size.invalid': [400, ErrorCode.INVALID_JSON, 'Request body length mismatch'],
};

function bodyParserError(err: unknown): readonly [number, ErrorCode, string] | undefined {
  if (typeof err !== 'object' || err === null || !('type' in err)) return undefined;
  const type = err.type;
  return typeof type === 'string' ? BODY_PARSER_ERRORS[type] : undefined;
}

/**
 * Last middleware. Clients get a stable code, a generic message and the request ID,
 * never a stack trace, SQL, file path or internal message (principle 10).
 */
export function errorHandler(logger: Logger): ErrorRequestHandler {
  return (err: unknown, req, res, _next) => {
    const requestId = getRequestId(res);
    if (err instanceof HttpError) {
      sendError(res, err.status, err.code, err.message, err.issues);
      return;
    }
    const parserError = bodyParserError(err);
    if (parserError) {
      const [status, code, message] = parserError;
      logger.warn('request body rejected', { requestId, method: req.method, path: req.path, code });
      sendError(res, status, code, message);
      return;
    }
    // Database errors are logged by class and code only: Prisma validation errors can quote the
    // query arguments, and driver errors can quote row values (INV-10).
    const detail = isDatabaseError(err) ? describeDatabaseError(err) : { err };
    logger.error('unhandled error', { requestId, method: req.method, path: req.path, ...detail });
    if (res.headersSent) {
      res.end();
      return;
    }
    sendError(res, 500, ErrorCode.INTERNAL_ERROR, 'Internal server error');
  };
}
