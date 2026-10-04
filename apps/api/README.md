# apps/api

Node.js + Express + TypeScript API (modular monolith) plus a worker entrypoint for scheduled jobs (expiry cleanup, audit verification and checkpoints).

Status: foundation (Phase 1). Only `GET /api/health` and `GET /api/ready` exist. Run with `pnpm dev`, build with `pnpm build`. Pipeline and route registry: docs/architecture/engineering-baseline.md section 4.

Rules:
- Every route is authenticated and authorized by default (deny by default). Public routes are an explicit allowlist.
- The API never receives Vault Passphrases, private keys, room keys, content keys or plaintext room content.
- Validate every request at the boundary with schemas from `packages/validation`.
- Every state-changing route, including login, passes the same-origin and request-header checks (INV-19).
- Content writes and invitations are rejected while a room is REKEY_REQUIRED or REKEYING, and every write must name the current key version (INV-07). The API never generates room key material or envelopes.
- See CLAUDE.md, docs/security/authorization-model.md and docs/security/security-policy-profiles.md.
