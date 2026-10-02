import type { RequestHandler } from 'express';

/**
 * Headers for API responses. The API only ever returns JSON, so its CSP forbids
 * everything. HSTS is set by Nginx at the TLS edge (deployment architecture), not here,
 * because the API itself listens on plain HTTP inside the VM.
 */
export const API_SECURITY_HEADERS: Readonly<Record<string, string>> = {
  'Content-Security-Policy': "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',
  'Cache-Control': 'no-store',
};

export const securityHeaders: RequestHandler = (_req, res, next) => {
  for (const [name, value] of Object.entries(API_SECURITY_HEADERS)) res.setHeader(name, value);
  next();
};
