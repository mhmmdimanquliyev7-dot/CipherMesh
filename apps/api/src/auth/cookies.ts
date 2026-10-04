import { PREAUTH_COOKIE, SESSION_COOKIE } from '@ciphermesh/shared';

/**
 * Cookie handling for the two authentication cookies (session-and-csrf.md section 2).
 * Attributes are fixed and identical in every environment: HttpOnly, Secure, SameSite=Strict,
 * Path=/, no Domain (`__Host-` prefix). There is deliberately no option to weaken them.
 */
export type AuthCookieName = typeof SESSION_COOKIE | typeof PREAUTH_COOKIE;

export function serializeAuthCookie(name: AuthCookieName, value: string, maxAgeSeconds: number): string {
  const maxAge = Math.max(0, Math.floor(maxAgeSeconds));
  return `${name}=${value}; Max-Age=${String(maxAge)}; Path=/; Secure; HttpOnly; SameSite=Strict`;
}

/** A cookie deletion with the same attributes, so the browser matches and removes it. */
export function clearAuthCookie(name: AuthCookieName): string {
  return serializeAuthCookie(name, '', 0);
}

/**
 * Returns the value of a cookie that appears exactly once. A duplicated authentication cookie is
 * treated as absent, so an injected second cookie cannot be used to confuse which one is read.
 */
export function readSingleCookie(cookieHeader: string | undefined, name: AuthCookieName): string | undefined {
  if (cookieHeader === undefined || cookieHeader.length > 8192) return undefined;
  const values: string[] = [];
  for (const part of cookieHeader.split(';')) {
    const index = part.indexOf('=');
    if (index < 0) continue;
    if (part.slice(0, index).trim() === name) values.push(part.slice(index + 1).trim());
  }
  return values.length === 1 ? values[0] : undefined;
}
