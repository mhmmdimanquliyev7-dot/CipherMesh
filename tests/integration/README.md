# tests/integration

API integration tests (`pnpm test:integration`). They boot the real Express application on an ephemeral loopback port (`tests/helpers/api.ts`) and use `fetch`.

Phase 1: `api-foundation.test.ts` covers health and readiness, unknown routes, malformed, scalar and oversized JSON, unsupported content types and charsets, strict input validation, fail-closed response projection and generic internal errors.

From Phase 2 these tests also run against a real PostgreSQL instance.
