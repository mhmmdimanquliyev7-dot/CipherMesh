# tests/security

Security regression suite (`pnpm test:security`). These tests must never be weakened, skipped or deleted to get a green build (CLAUDE.md section 8).

## Implemented (Phase 1)

| File | Proves | Threats and controls |
|---|---|---|
| `http-baseline.test.ts` | Security headers on every response; no framework disclosure; server-generated request IDs; no CORS grants; same-origin gate for state-changing requests (INV-19); secrets in headers, query strings and bodies never reach the log | T-12, T-13, T-15, INV-10, INV-19 |
| `route-inventory.test.ts` | The production app exposes exactly the allowlisted public routes; test routes are refused in production | T-05, T-06 (deny by default) |
| `startup-config.test.ts` | The real server process refuses invalid configuration, exits 1 and never echoes values | Principle 10, INV-10 |
| `malformed-requests.test.ts` | Malformed and dot-segment paths, oversized URLs and compressed bodies get generic errors; no crash, no decompression | T-14, T-15, T-26 |
| `lint-guards.test.ts` | ESLint rejects eval, `new Function`, `Math.random`, unsafe raw SQL, scattered `process.env`, WebCrypto outside the crypto package, child processes, `dangerouslySetInnerHTML`, Node built-ins and server imports in browser code | CLAUDE.md section 8, T-14, T-27 |

## Planned (not implemented yet)

These suites belong to later phases (docs/security/security-testing-plan.md). Nothing here pretends they exist:
`session` and `auth-abuse` (Phase 3), `crypto-invariants` and `browser-storage` (Phase 4), `authz-matrix` and `bola` (Phase 5), `identity` and `safety-code` (Phase 6), `canary-scan` and `upload` (Phase 7), `xss` (Phase 8), `burn` and `secret-envelope` (Phase 9), `policy-matrix` (Phase 10), `rekey` (Phase 11), `audit-tamper` (Phase 12), `key-injection` (after OCD-12), cloud configuration checks (Phases 17 to 19).
