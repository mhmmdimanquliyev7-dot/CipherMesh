# infrastructure/nginx

Nginx reverse-proxy configuration: TLS termination, security headers (CSP, HSTS and others), rate limiting, request-size limits, static asset serving and /api proxying.

Status: not created yet. It is written and hardened in Phase 17 (CM-T066), not before, so no untested "production" configuration exists.

Input already available: every web build writes `apps/web/out-meta/security-headers.json`, the CSP with inline-script hashes plus the static security headers. The Phase 17 configuration must take its web headers from that file (ADR-011). See docs/cloud/deployment-architecture.md.
