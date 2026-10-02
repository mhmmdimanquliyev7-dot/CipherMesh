import type { RequestHandler } from 'express';
import type { Logger } from '../logging/logger';
import { getRequestId } from './context';

/**
 * One line per request: method, path without the query string, status and duration.
 * Bodies, query strings, headers and cookies are never logged.
 */
export function requestLog(logger: Logger): RequestHandler {
  return (req, res, next) => {
    const started = process.hrtime.bigint();
    res.on('finish', () => {
      logger.info('request completed', {
        requestId: getRequestId(res),
        method: req.method,
        path: req.path,
        status: res.statusCode,
        durationMs: Number(process.hrtime.bigint() - started) / 1e6,
      });
    });
    next();
  };
}
