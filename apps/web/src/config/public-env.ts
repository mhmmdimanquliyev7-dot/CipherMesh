/**
 * The web client's only configuration. Everything here is compiled into the public
 * JavaScript bundle, so only NEXT_PUBLIC_ values may be read and none may be secret.
 * This is the only web module allowed to read process.env (ESLint enforces this).
 */
function readApiBasePath(): string {
  const value = process.env['NEXT_PUBLIC_API_BASE_PATH'] ?? '/api';
  // Same-origin API only (ADR-011, INV-19): a relative path, never a full URL.
  if (!/^\/[a-z0-9/-]*$/.test(value) || value.startsWith('//')) {
    throw new Error('NEXT_PUBLIC_API_BASE_PATH must be a same-origin path such as /api');
  }
  return value;
}

export const publicEnv = Object.freeze({
  apiBasePath: readApiBasePath(),
});
