// Content-Security-Policy construction for the static export (ADR-011, CM-T008).
// Pure functions only, so they can be unit tested without a build.
import { createHash } from 'node:crypto';

/** Script types the browser executes. JSON data blocks are not executed and need no hash. */
const EXECUTABLE_SCRIPT_TYPES = new Set(['', 'text/javascript', 'application/javascript', 'module']);

/**
 * Headers Nginx will set on every web response (deployment architecture section 4).
 * HSTS is added at the TLS edge in Phase 17 because it only makes sense over HTTPS.
 * @type {Readonly<Record<string, string>>}
 */
export const STATIC_SECURITY_HEADERS = Object.freeze({
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',
});

/**
 * Returns the bodies of inline scripts the browser would execute.
 * @param {string} html
 * @returns {string[]}
 */
export function extractInlineScripts(html) {
  const bodies = [];
  for (const match of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    const attributes = match[1] ?? '';
    const body = match[2] ?? '';
    if (/\ssrc\s*=/i.test(attributes)) continue;
    const type = /\stype\s*=\s*["']?([^"'\s>]+)/i.exec(attributes)?.[1]?.toLowerCase() ?? '';
    if (!EXECUTABLE_SCRIPT_TYPES.has(type) || body.length === 0) continue;
    bodies.push(body);
  }
  return bodies;
}

/**
 * Finds inline style elements and style attributes. A strict `style-src 'self'` blocks
 * both, so their presence must fail the build instead of weakening the policy.
 * @param {string} html
 * @returns {{ styleElements: number, styleAttributes: number }}
 */
export function findInlineStyles(html) {
  const withoutScripts = html.replace(/<script\b[\s\S]*?<\/script>/gi, '');
  return {
    styleElements: (withoutScripts.match(/<style\b/gi) ?? []).length,
    styleAttributes: (withoutScripts.match(/<[a-z][^>]*\sstyle\s*=/gi) ?? []).length,
  };
}

/**
 * @param {string} text
 * @returns {string} CSP hash source, e.g. 'sha256-...'
 */
export function sha256Source(text) {
  return `'sha256-${createHash('sha256').update(text, 'utf8').digest('base64')}'`;
}

/**
 * Builds the CSP. No 'unsafe-inline' and no 'unsafe-eval'. Since Phase 4, 'wasm-unsafe-eval' lets
 * the Argon2id WebAssembly module compile (ADR-010, LIB-03). It permits compiling WebAssembly
 * only: it does not allow eval(), new Function() or inline scripts, and the module itself is
 * part of a same-origin script bundle. The Argon2id Web Worker is a same-origin script, so
 * script-src 'self' covers it (worker-src falls back to script-src).
 *
 * Phase 7 (CM-T037 to CM-T041, deployment-architecture.md): connect-src adds exactly one origin,
 * the object storage that presigned URLs point to, so encrypted files travel between the browser
 * and storage without passing through the API; a URL to any other origin is refused by the
 * browser. img-src adds blob: for previews of decrypted raster images (never HTML or SVG).
 *
 * form-action 'none' (Phase 4, security finding SF-04-01): the client never submits an HTML form
 * natively; every form is handled by JavaScript and sent with fetch(). A native submission, which
 * is possible before hydration or when the bundle fails to load, would be a GET that carries the
 * typed values, such as the account password, in the URL. The browser now refuses it.
 * @param {readonly string[]} scriptHashes
 * @param {string} storageOrigin the object-storage origin, checked by storageOrigin()
 * @returns {string}
 */
export function buildCsp(scriptHashes, storageOrigin) {
  if (storageOrigin !== checkStorageOrigin(storageOrigin)) throw new Error('Invalid storage origin');
  const scriptSrc = ["'self'", "'wasm-unsafe-eval'", ...[...new Set(scriptHashes)].sort()].join(' ');
  return [
    "default-src 'none'",
    `script-src ${scriptSrc}`,
    "style-src 'self'",
    "img-src 'self' blob:",
    "font-src 'self'",
    `connect-src 'self' ${storageOrigin}`,
    "manifest-src 'self'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "object-src 'none'",
  ].join('; ');
}

/**
 * Where presigned URLs point in local builds: the HTTPS storage proxy of tests/e2e/static-server.mjs,
 * on another host name than the application (SF-07-01: cookies are not isolated by port).
 */
export const DEFAULT_STORAGE_ORIGIN = 'https://localhost:4174';

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]']);

/**
 * The object-storage origin for connect-src, from CM_STORAGE_ORIGIN at build time. It must be a
 * bare origin, over https except on loopback; anything else fails the build rather than
 * producing a weaker or broken policy.
 * @param {string | undefined} value
 * @returns {string}
 */
export function checkStorageOrigin(value) {
  const candidate = value === undefined || value === '' ? DEFAULT_STORAGE_ORIGIN : value;
  let url;
  try {
    url = new URL(candidate);
  } catch {
    throw new Error('CM_STORAGE_ORIGIN must be an origin such as https://storage.example');
  }
  const secure = url.protocol === 'https:' || (url.protocol === 'http:' && LOOPBACK.has(url.hostname));
  // A host name of letters, digits, dots and hyphens, or an IPv6 literal: never a CSP wildcard.
  const plainHost = /^(?:[a-z0-9-]+(?:\.[a-z0-9-]+)*|\[[0-9a-f:]+\])$/.test(url.hostname);
  if (!secure || !plainHost || url.origin !== candidate) {
    throw new Error('CM_STORAGE_ORIGIN must be an https origin (http only on loopback), without path');
  }
  return url.origin;
}
