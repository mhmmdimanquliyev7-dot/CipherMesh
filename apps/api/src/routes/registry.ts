import { ErrorCode, SESSION_COOKIE } from '@ciphermesh/shared';
import { parseWith, type z } from '@ciphermesh/validation';
import { Router, type Request, type Response } from 'express';
import { isIP } from 'node:net';
import { clearAuthCookie, readSingleCookie, type AuthCookieName } from '../auth/cookies';
import { requireStepUp, SESSION_POLICY, type Actor, type RequestMeta, type ResolveFailure } from '../auth/sessions';
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
 *   -> authentication (session cookie, central; Phase 3) -> input validation
 *   -> route gates (platform administrator, MFA-verified session, step-up; Phase 3)
 *   -> [room authorization: Phase 5, CM-T029] -> handler -> response projection -> error handler
 *
 * The caller's identity comes only from the server-side session row. No header, body or query
 * field is ever accepted as proof of identity (INV-05).
 */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/** Extra requirements of an authenticated route, enforced before its handler runs. */
export interface AuthenticatedRequirements {
  /** Step-up within 15 minutes ('standard') or 5 minutes ('strict'), CM-T021. */
  readonly stepUp?: 'standard' | 'strict';
  /** PLATFORM_ADMIN with an MFA-verified session (authorization model PA-xx). Others get 404. */
  readonly platformAdmin?: true;
}

export type RouteAccess =
  | { readonly kind: 'public'; readonly justification: string }
  | { readonly kind: 'authenticated'; readonly requires?: AuthenticatedRequirements };

export interface RouteRequest extends RequestMeta {
  /** Reads an authentication cookie that is present exactly once. */
  readonly cookie: (name: AuthCookieName) => string | undefined;
}

export interface RouteContext<Q, B> {
  readonly query: Q;
  readonly body: B;
  readonly requestId: string;
  readonly request: RouteRequest;
  /** Set for authenticated routes; use actorOf() in handlers. */
  readonly actor: Actor | undefined;
}

export interface RouteResult<R> {
  readonly status: number;
  readonly body: R;
  /** Complete Set-Cookie values, built only by src/auth/cookies.ts. */
  readonly cookies?: readonly string[];
}

/** The authenticated caller of an authenticated route. */
export function actorOf(ctx: { readonly actor: Actor | undefined }): Actor {
  if (ctx.actor === undefined) throw new Error('actorOf() used in a route without authentication');
  return ctx.actor;
}

/** Resolves the session cookie to an actor; supplied by app.ts. */
export interface Authenticator {
  authenticate(sessionToken: string | undefined): Promise<{ actor: Actor } | { failure: ResolveFailure }>;
  now(): Date;
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
  authenticator?: Authenticator,
): { readonly router: Router; readonly registered: readonly RegisteredRoute[] } {
  const router = Router();
  const seen = new Set<string>();
  const registered: RegisteredRoute[] = [];

  for (const route of routes) {
    const key = `${route.method} ${route.path}`;
    if (!ACTION_ID.test(route.action)) throw new RouteRegistrationError(`${key}: missing or malformed action ID`);
    if (seen.has(key)) throw new RouteRegistrationError(`${key}: registered twice`);
    const onAllowlist = publicAllowlist.some((entry) => entry.method === route.method && entry.path === route.path);
    if (route.access.kind === 'authenticated') {
      // Fail closed: without an authenticator, an authenticated route cannot be served.
      if (authenticator === undefined) {
        throw new RouteRegistrationError(`${key}: authenticated route registered without an authenticator`);
      }
      if (onAllowlist) throw new RouteRegistrationError(`${key}: authenticated route is on the public allowlist`);
    } else {
      if (route.access.justification.trim() === '') {
        throw new RouteRegistrationError(`${key}: a public route needs a justification`);
      }
      if (!onAllowlist) throw new RouteRegistrationError(`${key}: public route is not on the public route allowlist`);
    }
    if (METHODS_WITH_BODY.has(route.method) !== (route.body !== undefined)) {
      throw new RouteRegistrationError(
        `${key}: a body schema is required for POST, PUT and PATCH and forbidden otherwise`,
      );
    }
    seen.add(key);
    registered.push({ method: route.method, path: route.path, action: route.action, access: route.access.kind });
    const method = route.method.toLowerCase() as Lowercase<HttpMethod>;
    router[method](route.path, (req, res) => handle(route, req, res, authenticator));
  }
  return { router, registered: Object.freeze(registered) };
}

const MAX_USER_AGENT = 512;

function requestOf(req: Request, res: Response): RouteRequest {
  const ip = req.ip !== undefined && isIP(req.ip) !== 0 ? req.ip : null;
  const userAgent = req.get('user-agent')?.slice(0, MAX_USER_AGENT) ?? null;
  const cookieHeader = req.get('cookie');
  return { ip, userAgent, requestId: getRequestId(res), cookie: (name) => readSingleCookie(cookieHeader, name) };
}

async function authenticate(
  route: AnyRoute,
  request: RouteRequest,
  authenticator: Authenticator | undefined,
): Promise<Actor | undefined> {
  if (route.access.kind !== 'authenticated') return undefined;
  if (authenticator === undefined) throw new Error('Authenticated route without authenticator');
  const token = request.cookie(SESSION_COOKIE);
  const result = await authenticator.authenticate(token);
  if ('actor' in result) return result.actor;
  // A dead cookie is cleared so the browser stops presenting it.
  throw new HttpError(
    401,
    ErrorCode.UNAUTHENTICATED,
    'Authentication required',
    undefined,
    token === undefined ? {} : { 'set-cookie': clearAuthCookie(SESSION_COOKIE) },
  );
}

/** Route gates that depend only on the session (not on room membership). */
function applyGates(route: AnyRoute, actor: Actor | undefined, now: Date): void {
  if (route.access.kind !== 'authenticated' || actor === undefined) return;
  const requires = route.access.requires;
  if (requires?.platformAdmin === true) {
    // Non-administrators learn nothing about platform endpoints (authorization model section 7).
    if (actor.user.platformRole !== 'PLATFORM_ADMIN') {
      throw new HttpError(404, ErrorCode.NOT_FOUND, 'Resource not found');
    }
    if (actor.session.mfaVerifiedAt === null) {
      throw new HttpError(403, ErrorCode.MFA_REQUIRED, 'This action requires a session verified with MFA');
    }
  }
  if (requires?.stepUp !== undefined) {
    const window = requires.stepUp === 'strict' ? SESSION_POLICY.stepUpStrictMs : SESSION_POLICY.stepUpMs;
    if (requireStepUp(actor, window, now) !== undefined) {
      throw new HttpError(401, ErrorCode.STEP_UP_REQUIRED, 'Confirm your identity to continue');
    }
  }
}

async function handle(route: AnyRoute, req: Request, res: Response, authenticator?: Authenticator): Promise<void> {
  const request = requestOf(req, res);
  const actor = await authenticate(route, request, authenticator);

  const query = parseWith(route.query, req.query);
  if (!query.success) throw new HttpError(400, ErrorCode.VALIDATION_FAILED, 'Request validation failed', query.issues);

  let body: unknown = undefined;
  if (route.body !== undefined) {
    const parsed = parseWith(route.body, req.body ?? {});
    if (!parsed.success)
      throw new HttpError(400, ErrorCode.VALIDATION_FAILED, 'Request validation failed', parsed.issues);
    body = parsed.data;
  }

  if (authenticator !== undefined) applyGates(route, actor, authenticator.now());

  const result = await route.handler({ query: query.data, body, requestId: request.requestId, request, actor });
  const projected = route.response.safeParse(result.body);
  if (!projected.success) {
    // Fail closed: a handler that returns fields outside its response schema is a bug,
    // and the extra fields might be sensitive. Nothing from the handler is sent.
    throw new Error(`Response projection failed for action ${route.action}`);
  }
  if (result.cookies !== undefined && result.cookies.length > 0) res.setHeader('set-cookie', [...result.cookies]);
  res.status(result.status).json(projected.data);
}
