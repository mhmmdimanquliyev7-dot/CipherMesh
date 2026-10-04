import { ErrorCode } from '@ciphermesh/shared';
import { parseWith, type z } from '@ciphermesh/validation';
import { Router, type Request, type Response } from 'express';
import { getRequestId } from '../http/context';
import { HttpError } from '../http/errors';

/**
 * Deny-by-default route registration (CM-T007, authorization model section 6).
 *
 * Every route declares an action ID, its access level, a query schema, a body schema
 * exactly when the method carries a body, and a response schema. Handlers can only
 * answer through the response schema (explicit projection). Routes are mounted only
 * through this registry, so a route cannot silently skip a pipeline step.
 *
 * Request pipeline (app.ts):
 *   request ID -> security headers -> request log -> same-origin gate (state changes)
 *   -> JSON content-type gate -> JSON parsing with size limit
 *   -> [authentication: Phase 3, CM-T016] -> [authorization: Phase 5, CM-T029]
 *   -> input validation -> handler -> response projection -> error handler
 */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export type RouteAccess =
  { readonly kind: 'public'; readonly justification: string } | { readonly kind: 'authenticated' };

export interface RouteContext<Q, B> {
  readonly query: Q;
  readonly body: B;
  readonly requestId: string;
}

export interface RouteResult<R> {
  readonly status: number;
  readonly body: R;
}

export interface RouteDefinition<QS extends z.ZodType, BS extends z.ZodType | undefined, RS extends z.ZodType> {
  readonly method: HttpMethod;
  readonly path: string;
  readonly action: string;
  readonly access: RouteAccess;
  readonly query: QS;
  readonly body: BS;
  readonly response: RS;
  readonly handler: (
    ctx: RouteContext<z.output<QS>, BS extends z.ZodType ? z.output<BS> : undefined>,
  ) => RouteResult<z.input<RS>> | Promise<RouteResult<z.input<RS>>>;
}

/** A route with its types erased, for heterogeneous route lists. */
export interface AnyRoute {
  readonly method: HttpMethod;
  readonly path: string;
  readonly action: string;
  readonly access: RouteAccess;
  readonly query: z.ZodType;
  readonly body: z.ZodType | undefined;
  readonly response: z.ZodType;
  readonly handler: (ctx: RouteContext<unknown, unknown>) => RouteResult<unknown> | Promise<RouteResult<unknown>>;
}

export function defineRoute<QS extends z.ZodType, BS extends z.ZodType | undefined, RS extends z.ZodType>(
  route: RouteDefinition<QS, BS, RS>,
): AnyRoute {
  // The typed definition is checked here; at runtime every input is validated by its schema.
  return route as unknown as AnyRoute;
}

export interface PublicRouteEntry {
  readonly method: HttpMethod;
  readonly path: string;
}

export interface RegisteredRoute {
  readonly method: HttpMethod;
  readonly path: string;
  readonly action: string;
  readonly access: RouteAccess['kind'];
}

const METHODS_WITH_BODY: ReadonlySet<HttpMethod> = new Set(['POST', 'PUT', 'PATCH']);
const ACTION_ID = /^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*$/;

export class RouteRegistrationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RouteRegistrationError';
  }
}

/** Builds the router. Throws at startup, before any request is served, if a rule is broken. */
export function buildRouter(
  routes: readonly AnyRoute[],
  publicAllowlist: readonly PublicRouteEntry[],
): { readonly router: Router; readonly registered: readonly RegisteredRoute[] } {
  const router = Router();
  const seen = new Set<string>();
  const registered: RegisteredRoute[] = [];

  for (const route of routes) {
    const key = `${route.method} ${route.path}`;
    if (!ACTION_ID.test(route.action)) throw new RouteRegistrationError(`${key}: missing or malformed action ID`);
    if (seen.has(key)) throw new RouteRegistrationError(`${key}: registered twice`);
    if (route.access.kind === 'authenticated') {
      // Fail closed: there is no authentication pipeline before CM-T016 (Phase 3).
      throw new RouteRegistrationError(
        `${key}: authenticated routes cannot be registered before the authentication pipeline exists`,
      );
    }
    if (route.access.justification.trim() === '') {
      throw new RouteRegistrationError(`${key}: a public route needs a justification`);
    }
    if (!publicAllowlist.some((entry) => entry.method === route.method && entry.path === route.path)) {
      throw new RouteRegistrationError(`${key}: public route is not on the public route allowlist`);
    }
    if (METHODS_WITH_BODY.has(route.method) !== (route.body !== undefined)) {
      throw new RouteRegistrationError(
        `${key}: a body schema is required for POST, PUT and PATCH and forbidden otherwise`,
      );
    }
    seen.add(key);
    registered.push({ method: route.method, path: route.path, action: route.action, access: route.access.kind });
    const method = route.method.toLowerCase() as Lowercase<HttpMethod>;
    router[method](route.path, (req, res) => handle(route, req, res));
  }
  return { router, registered: Object.freeze(registered) };
}

async function handle(route: AnyRoute, req: Request, res: Response): Promise<void> {
  const query = parseWith(route.query, req.query);
  if (!query.success) throw new HttpError(400, ErrorCode.VALIDATION_FAILED, 'Request validation failed', query.issues);

  let body: unknown = undefined;
  if (route.body !== undefined) {
    const parsed = parseWith(route.body, req.body ?? {});
    if (!parsed.success)
      throw new HttpError(400, ErrorCode.VALIDATION_FAILED, 'Request validation failed', parsed.issues);
    body = parsed.data;
  }

  const result = await route.handler({ query: query.data, body, requestId: getRequestId(res) });
  const projected = route.response.safeParse(result.body);
  if (!projected.success) {
    // Fail closed: a handler that returns fields outside its response schema is a bug,
    // and the extra fields might be sensitive. Nothing from the handler is sent.
    throw new Error(`Response projection failed for action ${route.action}`);
  }
  res.status(result.status).json(projected.data);
}
