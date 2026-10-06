import {
  describeMatrixAction,
  ErrorCode,
  isRoomActionId,
  isUuidV4,
  SESSION_COOKIE,
  type RoomActionId,
  type RoomResourceFacts,
} from '@ciphermesh/shared';
import { parseWith, z } from '@ciphermesh/validation';
import { Router, type Request, type Response } from 'express';
import { isIP } from 'node:net';
import { clearAuthCookie, readSingleCookie, type AuthCookieName } from '../auth/cookies';
import { requireStepUp, SESSION_POLICY, type Actor, type RequestMeta, type ResolveFailure } from '../auth/sessions';
import type { RoomAccess, RoomAuthorizer, RoomMembershipScope } from '../authorization/rooms';
import { getRequestId } from '../http/context';
import { HttpError } from '../http/errors';

/**
 * Deny-by-default route registration (CM-T007, authorization model section 6).
 *
 * Every route declares an action ID, its access level, a query schema, a body schema
 * exactly when the method carries a body, a params schema exactly when the path has parameters,
 * and a response schema. Handlers can only answer through the response schema (explicit
 * projection). Routes are mounted only through this registry, so a route cannot silently skip a
 * pipeline step.
 *
 * The action ID says what the route authorizes (CM-T029): public routes declare no matrix action,
 * authenticated routes a self-service (SS-xx) or platform (PA-xx) action, and room routes a room
 * action (AZ-xx) of the shared matrix in packages/shared. The registry refuses to start when a
 * declaration is missing, unknown or inconsistent with the route's access.
 *
 * Request pipeline (app.ts):
 *   request ID -> security headers -> request log -> same-origin gate (state changes)
 *   -> JSON content-type gate -> JSON parsing with size limit
 *   -> authentication (session cookie, central; Phase 3) -> path parameters (404 when malformed)
 *   -> input validation
 *   -> room authorization (room routes: database-loaded membership and the matrix; CM-T029)
 *   -> route gates (platform administrator, MFA-verified session, step-up; Phase 3)
 *   -> handler -> response projection -> error handler
 *
 * The caller's identity comes only from the server-side session row, and the caller's room role
 * only from the membership row. No header, body or query field is ever accepted as proof of
 * identity or role (INV-05).
 */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/** Extra requirements of an authenticated route, enforced before its handler runs. */
export interface AuthenticatedRequirements {
  /** Step-up within 15 minutes ('standard') or 5 minutes ('strict'), CM-T021. */
  readonly stepUp?: 'standard' | 'strict';
  /** PLATFORM_ADMIN with an MFA-verified session (authorization model PA-xx). Others get 404. */
  readonly platformAdmin?: true;
}

/** Extra requirements of a room route. There is no platform administrator gate: PA-05. */
export interface RoomRequirements {
  readonly stepUp?: 'standard' | 'strict';
}

/** Input of a room route's resource loader: the database-loaded scope and the validated request. */
export interface RoomResourceInput<P, Q, B> {
  readonly room: RoomMembershipScope;
  readonly params: P;
  readonly query: Q;
  readonly body: B;
}

/**
 * A room-scoped route (OL-01): its path starts with /rooms/:roomId, its action is a room action
 * (AZ-xx), and every request is authorized centrally before the handler runs.
 */
export interface RoomRouteAccess<P = unknown, Q = unknown, B = unknown> {
  readonly kind: 'room';
  readonly requires?: RoomRequirements;
  /**
   * Required exactly when a cell of the action depends on the target object (own, recipient or
   * target roles), and forbidden otherwise. Loads the object by its identifier AND the scope's
   * room ID (OL-02) and returns its stored facts, or null when the room has no such object (404).
   */
  readonly resource?: (input: RoomResourceInput<P, Q, B>) => Promise<RoomResourceFacts | null>;
}

export type RouteAccess<P = unknown, Q = unknown, B = unknown> =
  | { readonly kind: 'public'; readonly justification: string }
  | { readonly kind: 'authenticated'; readonly requires?: AuthenticatedRequirements }
  | RoomRouteAccess<P, Q, B>;

export interface RouteRequest extends RequestMeta {
  /** Reads an authentication cookie that is present exactly once. */
  readonly cookie: (name: AuthCookieName) => string | undefined;
}

export interface RouteContext<Q, B, P = Readonly<Record<string, never>>> {
  readonly query: Q;
  readonly body: B;
  /** Validated path parameters. */
  readonly params: P;
  readonly requestId: string;
  readonly request: RouteRequest;
  /** Set for authenticated routes; use actorOf() in handlers. */
  readonly actor: Actor | undefined;
  /** Set for room routes once the central authorization allowed the request; use roomOf(). */
  readonly room: RoomAccess | undefined;
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

/** The caller's authorized access to the addressed room, in a room route. */
export function roomOf(ctx: { readonly room: RoomAccess | undefined }): RoomAccess {
  if (ctx.room === undefined) throw new Error('roomOf() used in a route without room authorization');
  return ctx.room;
}

/** Resolves the session cookie to an actor; supplied by app.ts. */
export interface Authenticator {
  authenticate(sessionToken: string | undefined): Promise<{ actor: Actor } | { failure: ResolveFailure }>;
  now(): Date;
}

type BodyOf<BS> = BS extends z.ZodType ? z.output<BS> : undefined;
type ParamsOf<PS> = PS extends z.ZodType ? z.output<PS> : Readonly<Record<string, never>>;

export interface RouteDefinition<
  QS extends z.ZodType,
  BS extends z.ZodType | undefined,
  RS extends z.ZodType,
  PS extends z.ZodType | undefined = undefined,
> {
  readonly method: HttpMethod;
  readonly path: string;
  readonly action: string;
  readonly access: RouteAccess<ParamsOf<PS>, z.output<QS>, BodyOf<BS>>;
  /** Object schema with exactly the path parameters; required exactly when the path has any. */
  readonly params?: PS;
  readonly query: QS;
  readonly body: BS;
  readonly response: RS;
  readonly handler: (
    ctx: RouteContext<z.output<QS>, BodyOf<BS>, ParamsOf<PS>>,
  ) => RouteResult<z.input<RS>> | Promise<RouteResult<z.input<RS>>>;
}

/** A route with its types erased, for heterogeneous route lists. */
export interface AnyRoute {
  readonly method: HttpMethod;
  readonly path: string;
  readonly action: string;
  readonly access: RouteAccess;
  readonly params?: z.ZodType | undefined;
  readonly query: z.ZodType;
  readonly body: z.ZodType | undefined;
  readonly response: z.ZodType;
  readonly handler: (
    ctx: RouteContext<unknown, unknown, unknown>,
  ) => RouteResult<unknown> | Promise<RouteResult<unknown>>;
}

export function defineRoute<
  QS extends z.ZodType,
  BS extends z.ZodType | undefined,
  RS extends z.ZodType,
  PS extends z.ZodType | undefined = undefined,
>(route: RouteDefinition<QS, BS, RS, PS>): AnyRoute {
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
/** A matrix action (AZ-xx, PA-xx, SS-xx) with an optional route suffix, such as AZ-02-ROOM-RENAME. */
const MATRIX_ACTION = /^((?:AZ|PA|SS)-[0-9]{2})(?:-[A-Z0-9]+)*$/;
/** Lowercase static segments and :named parameters only: no wildcards, optional or pattern parts. */
const PATH = /^(?:\/(?:[a-z0-9]+(?:-[a-z0-9]+)*|:[a-z][a-zA-Z0-9]*))+$/;
/** Room routes carry the room ID as the first parameter of the path (OL-01). */
const ROOM_PATH = /^\/rooms\/:roomId(?:\/|$)/;
/** Any path below /rooms/:param, or with a :roomId parameter anywhere, addresses a room. */
const NAMES_ROOM = /^\/rooms\/:|\/:roomId(?:\/|$)/;

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
  rooms?: RoomAuthorizer,
): { readonly router: Router; readonly registered: readonly RegisteredRoute[] } {
  const router = Router();
  const seen = new Set<string>();
  const registered: RegisteredRoute[] = [];

  for (const route of routes) {
    const key = `${route.method} ${route.path}`;
    if (!ACTION_ID.test(route.action)) throw new RouteRegistrationError(`${key}: missing or malformed action ID`);
    if (seen.has(key)) throw new RouteRegistrationError(`${key}: registered twice`);
    const onAllowlist = publicAllowlist.some((entry) => entry.method === route.method && entry.path === route.path);
    if (route.access.kind === 'public') {
      if (route.access.justification.trim() === '') {
        throw new RouteRegistrationError(`${key}: a public route needs a justification`);
      }
      if (!onAllowlist) throw new RouteRegistrationError(`${key}: public route is not on the public route allowlist`);
    } else {
      // Fail closed: without an authenticator, a route behind authentication cannot be served.
      if (authenticator === undefined) {
        throw new RouteRegistrationError(`${key}: ${route.access.kind} route registered without an authenticator`);
      }
      if (onAllowlist)
        throw new RouteRegistrationError(`${key}: ${route.access.kind} route is on the public allowlist`);
    }
    if (METHODS_WITH_BODY.has(route.method) !== (route.body !== undefined)) {
      throw new RouteRegistrationError(
        `${key}: a body schema is required for POST, PUT and PATCH and forbidden otherwise`,
      );
    }
    checkPathParameters(route, key);
    const roomAction = checkAuthorizationDeclaration(route, key, rooms);
    seen.add(key);
    registered.push({ method: route.method, path: route.path, action: route.action, access: route.access.kind });
    const method = route.method.toLowerCase() as Lowercase<HttpMethod>;
    router[method](route.path, (req, res) => handle(route, roomAction, req, res, authenticator, rooms));
  }
  return { router, registered: Object.freeze(registered) };
}

/** Path parameters must be declared by an object schema with exactly the same keys. */
function checkPathParameters(route: AnyRoute, key: string): void {
  if (!PATH.test(route.path)) {
    throw new RouteRegistrationError(`${key}: paths use lowercase static segments and :named parameters only`);
  }
  const names = route.path
    .split('/')
    .filter((segment) => segment.startsWith(':'))
    .map((segment) => segment.slice(1));
  if (new Set(names).size !== names.length) throw new RouteRegistrationError(`${key}: a path parameter repeats`);
  if (names.length === 0) {
    if (route.params !== undefined) {
      throw new RouteRegistrationError(`${key}: a params schema is declared but the path has no parameters`);
    }
    return;
  }
  const keys = route.params instanceof z.ZodObject ? Object.keys(route.params.shape) : [];
  if (keys.length !== names.length || !names.every((name) => keys.includes(name))) {
    throw new RouteRegistrationError(`${key}: the params schema must be an object with exactly the path parameters`);
  }
}

/**
 * Every route declares what it authorizes (authorization model section 6, CM-T029). Returns the
 * room action of a room route, which the central room authorization enforces on every request.
 */
function checkAuthorizationDeclaration(
  route: AnyRoute,
  key: string,
  rooms: RoomAuthorizer | undefined,
): RoomActionId | undefined {
  const matrixId = MATRIX_ACTION.exec(route.action)?.[1];
  const info = matrixId === undefined ? undefined : describeMatrixAction(matrixId);
  if (matrixId !== undefined && info === undefined) {
    throw new RouteRegistrationError(`${key}: ${matrixId} is not in the authorization matrix`);
  }
  const access = route.access;
  // OL-01 in both directions: a path that names a room is room-scoped, so it can only be served
  // after the central room authorization. Otherwise a route under /rooms/:roomId declared as
  // authenticated or public would carry a room ID without any membership check.
  if (NAMES_ROOM.test(route.path) && access.kind !== 'room') {
    throw new RouteRegistrationError(`${key}: a path that names a room must be a room route`);
  }
  if (access.kind === 'public') {
    if (info !== undefined) throw new RouteRegistrationError(`${key}: a public route cannot declare a matrix action`);
    return undefined;
  }
  if (info === undefined) {
    throw new RouteRegistrationError(`${key}: a route behind authentication must declare a matrix action (AZ, PA, SS)`);
  }
  if (info.stepUpAlways && access.requires?.stepUp === undefined) {
    throw new RouteRegistrationError(`${key}: ${info.id} requires a step-up in every profile`);
  }
  if (access.kind === 'authenticated') {
    if (info.scope !== 'self' && info.scope !== 'platform') {
      throw new RouteRegistrationError(`${key}: ${info.id} is not a self-service or platform action`);
    }
    if ((info.scope === 'platform') !== (access.requires?.platformAdmin === true)) {
      throw new RouteRegistrationError(`${key}: platform actions, and only they, need the platform administrator gate`);
    }
    return undefined;
  }
  if (info.scope !== 'room' || !isRoomActionId(info.id)) {
    throw new RouteRegistrationError(`${key}: a room route must declare a room action (AZ-xx)`);
  }
  if (info.inherited) {
    throw new RouteRegistrationError(`${key}: ${info.id} has no permission of its own; declare the item's read action`);
  }
  if (!ROOM_PATH.test(route.path)) throw new RouteRegistrationError(`${key}: a room route starts with /rooms/:roomId`);
  // Types erased by defineRoute could still carry the platform gate; it means nothing in a room.
  if ('platformAdmin' in (access.requires ?? {})) {
    throw new RouteRegistrationError(`${key}: PLATFORM_ADMIN has no room access (PA-05)`);
  }
  if (info.needsResource !== (access.resource !== undefined)) {
    throw new RouteRegistrationError(
      info.needsResource
        ? `${key}: ${info.id} depends on the target object and needs a resource loader`
        : `${key}: ${info.id} does not depend on the target object and takes no resource loader`,
    );
  }
  if (rooms === undefined) throw new RouteRegistrationError(`${key}: room route registered without a room authorizer`);
  return info.id;
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
  if (route.access.kind === 'public') return undefined;
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

/** The 404 of an unknown room, object or identifier; identical to every other not-found answer. */
const notFound = (): HttpError => new HttpError(404, ErrorCode.NOT_FOUND, 'Resource not found');

/**
 * Central room authorization (OL-01): the room ID comes from the validated path, the membership
 * from the database, the decision from the shared matrix. Runs before the step-up gate, so a
 * non-member learns nothing (404) and a member without the permission gets 403 before any prompt.
 */
async function authorizeRoom(
  route: AnyRoute,
  action: RoomActionId,
  actor: Actor | undefined,
  input: { readonly params: unknown; readonly query: unknown; readonly body: unknown; readonly requestId: string },
  rooms: RoomAuthorizer | undefined,
): Promise<RoomAccess> {
  if (actor === undefined || rooms === undefined || route.access.kind !== 'room') {
    throw new Error('Room route without authentication or room authorizer');
  }
  const roomId = (input.params as { readonly roomId?: unknown }).roomId;
  if (typeof roomId !== 'string' || !isUuidV4(roomId)) throw notFound();
  const loader = route.access.resource;
  return rooms.authorize({
    actor,
    roomId,
    action,
    requestId: input.requestId,
    ...(loader === undefined
      ? {}
      : {
          loadResource: (room: RoomMembershipScope) =>
            loader({ room, params: input.params, query: input.query, body: input.body }),
        }),
  });
}

/** Route gates that depend only on the session (not on room membership). */
function applyGates(route: AnyRoute, actor: Actor | undefined, now: Date): void {
  if (route.access.kind === 'public' || actor === undefined) return;
  if (route.access.kind === 'authenticated' && route.access.requires?.platformAdmin === true) {
    // Non-administrators learn nothing about platform endpoints (authorization model section 7).
    if (actor.user.platformRole !== 'PLATFORM_ADMIN') throw notFound();
    if (actor.session.mfaVerifiedAt === null) {
      throw new HttpError(403, ErrorCode.MFA_REQUIRED, 'This action requires a session verified with MFA');
    }
  }
  const stepUp = route.access.requires?.stepUp;
  if (stepUp !== undefined) {
    const window = stepUp === 'strict' ? SESSION_POLICY.stepUpStrictMs : SESSION_POLICY.stepUpMs;
    if (requireStepUp(actor, window, now) !== undefined) {
      throw new HttpError(401, ErrorCode.STEP_UP_REQUIRED, 'Confirm your identity to continue');
    }
  }
}

async function handle(
  route: AnyRoute,
  roomAction: RoomActionId | undefined,
  req: Request,
  res: Response,
  authenticator?: Authenticator,
  rooms?: RoomAuthorizer,
): Promise<void> {
  const request = requestOf(req, res);
  const actor = await authenticate(route, request, authenticator);

  // A path parameter names a resource. A malformed one names none, so it is the same 404 as an
  // unknown identifier (OL-02), never a validation error that would confirm the route's shape.
  let params: unknown = {};
  if (route.params !== undefined) {
    const parsed = parseWith(route.params, req.params);
    if (!parsed.success) throw notFound();
    params = parsed.data;
  }

  const query = parseWith(route.query, req.query);
  if (!query.success) throw new HttpError(400, ErrorCode.VALIDATION_FAILED, 'Request validation failed', query.issues);

  let body: unknown = undefined;
  if (route.body !== undefined) {
    const parsed = parseWith(route.body, req.body ?? {});
    if (!parsed.success)
      throw new HttpError(400, ErrorCode.VALIDATION_FAILED, 'Request validation failed', parsed.issues);
    body = parsed.data;
  }

  const room =
    roomAction === undefined
      ? undefined
      : await authorizeRoom(
          route,
          roomAction,
          actor,
          { params, query: query.data, body, requestId: request.requestId },
          rooms,
        );
  if (authenticator !== undefined) applyGates(route, actor, authenticator.now());

  const result = await route.handler({
    query: query.data,
    body,
    params,
    requestId: request.requestId,
    request,
    actor,
    room,
  });
  const projected = route.response.safeParse(result.body);
  if (!projected.success) {
    // Fail closed: a handler that returns fields outside its response schema is a bug,
    // and the extra fields might be sensitive. Nothing from the handler is sent.
    throw new Error(`Response projection failed for action ${route.action}`);
  }
  if (result.cookies !== undefined && result.cookies.length > 0) res.setHeader('set-cookie', [...result.cookies]);
  res.status(result.status).json(projected.data);
}
