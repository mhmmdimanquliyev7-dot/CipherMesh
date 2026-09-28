# ADR-011: Static Next.js export served by Nginx

- Status: **Proposed** (validate in Phase 1)
- Date: 2026-09-28
- Related: [deployment-architecture.md](../../cloud/deployment-architecture.md), [trust-boundaries.md](../trust-boundaries.md) TB-03, T-12, T-19, T-24, L-02

## Context
Next.js is the preferred frontend framework. In CipherMesh all security-relevant client logic (cryptography, decryption, rendering of plaintext) runs in the browser, and all dynamic data comes from the Express API. Running a Node.js server for server-side rendering or React Server Components would add another internet-facing runtime with its own vulnerability history, for example the Next.js middleware authorization bypass in March 2025 (CVE-2025-29927) and the React Server Components remote code execution vulnerability disclosed in December 2025 (CVE-2025-55182). Server-side rendering also brings a risk of handling plaintext on the server by mistake.

## Decision
- Build the web client with Next.js **static export** (`output: 'export'`) and serve the files from Nginx on the **same origin** as the API.
- No server-side rendering at runtime, no server actions, no Next.js middleware, no Next.js API routes. All data comes from the Express API.
- Routes are designed for static export: static pages with identifiers passed through client-side routing or query parameters, validated on use.
- The build pipeline computes hashes for any inline scripts and styles and injects them into the Nginx CSP; `'unsafe-inline'` and `'unsafe-eval'` are not used for scripts. Subresource Integrity is enabled where the build supports it.
- Content-hashed asset filenames with immutable caching; HTML served with `no-cache`.

## Alternatives Considered
- **Next.js server (SSR and RSC) in a container:** full framework features, but a larger attack surface, a runtime to patch, and the risk of server-side plaintext handling.
- **Managed frontend hosting (PaaS):** removes code delivery from the VM and could be adopted later (see [service-models.md](../../cloud/service-models.md) section 4); it changes the origin model (CORS, cookies, CSRF).
- **Vite with React as a single-page application:** simpler for a purely static client; Next.js remains preferred by the project, and switching would need a new ADR.

## Consequences
- Some Next.js features are unavailable: image optimization, middleware, runtime server components, incremental regeneration.
- Dynamic routes need a deliberate pattern; Phase 1 must prove the chosen pattern works with deep links and reloads.
- CSP hash generation must be automated in the build.

## Security Implications
- One less internet-facing server runtime (principle 12) and no server-side rendering of plaintext.
- The same origin for web and API keeps the cookie and CSRF model simple (ADR-008).
- Code-delivery trust (TB-03) remains: a compromised VM can still serve modified files (T-24, L-02). Published release hashes allow detection after the fact.

## Status
Proposed. Becomes Accepted when Phase 1 demonstrates the static export with the routing pattern and a strict CSP without `'unsafe-inline'` scripts.
