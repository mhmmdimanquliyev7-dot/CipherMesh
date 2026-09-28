# ADR-001: Monorepo architecture

- Status: Accepted
- Date: 2026-09-28
- Related: [CLAUDE.md](../../../CLAUDE.md), [system-overview.md](../system-overview.md)

## Context
CipherMesh has a browser client, an API with a worker, and code that both sides must agree on: request and response schemas, the policy catalogue, the authorization matrix, algorithm suite identifiers and canonical cryptographic contexts. The team is small and works to a university timeline. Contract drift between client and server would be both a bug source and a security risk, for example when the client and server disagree on a context field.

## Decision
- One Git repository with **pnpm workspaces**: `apps/web`, `apps/api`, `packages/crypto`, `packages/shared`, `packages/validation`, plus `prisma/`, `infrastructure/`, `tests/` and `docs/`.
- TypeScript in strict mode everywhere practical.
- The backend is a **modular monolith**: one API codebase and image with two entrypoints (API server and worker).
- No build orchestrator (Turborepo, Nx) initially. It can be added later if build times require it.
- Enforced boundaries: `apps/web` never imports `apps/api`; `packages/crypto` never imports Node-only or server code; server secrets never enter browser bundles.

## Alternatives Considered
- **Separate repositories for client and server:** clearer ownership, but duplicated schemas and contexts and cross-repository changes for every contract change.
- **npm or Yarn workspaces:** workable. pnpm was chosen for its strict dependency resolution (no undeclared "phantom" dependencies) and because recent versions do not run dependency lifecycle scripts unless allowlisted, which reduces supply-chain exposure.
- **Microservices:** rejected. They add network boundaries, service authentication and deployment complexity without improving the security properties this project must demonstrate.
- **Nx or Turborepo from the start:** unnecessary complexity at this size.

## Consequences
- Shared packages keep client and server in agreement; one CI pipeline and one lockfile.
- Workspace boundary rules must be enforced with lint rules and review.
- Changes to shared packages affect both applications and need tests on both sides.

## Security Implications
- One place to review cryptographic code (`packages/crypto`) and one set of schemas used at every trust boundary (`packages/validation`).
- One lockfile to audit and scan (T-27).
- Boundary rules prevent server-only code and secrets from being bundled into the browser (T-16).

## Status
Accepted. Review if the build becomes too slow or if a component must be deployed independently.
