# tests/e2e

Playwright tests (`pnpm test:e2e`) in Chromium, Firefox and WebKit. They run against the built static export (`pnpm build` first), served by `static-server.mjs` with the generated security headers from `apps/web/out-meta/security-headers.json`, the same headers Nginx will apply.

Phase 1: `web-shell.spec.ts` fails on any Content-Security-Policy violation, checks the policy contains no `unsafe-inline` or `unsafe-eval`, and checks the 404 page and headers.

Install the browsers once with `pnpm exec playwright install chromium firefox webkit`.
