# ADR-011: Static Next.js export served by Nginx

- Status: **Accepted** for the static export and strict CSP (verified in Phase 1, 2026-10-02). The routing pattern for identifiers was confirmed with the first identifier route in Phase 5 (2026-10-06)
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
Accepted for the static export and its strict CSP. Confirming evidence from Phase 1:
- `next build` with `output: 'export'` (Next.js 16.3.6) produces a static site. The App Router emits a few inline scripts and no inline styles.
- `apps/web/scripts/generate-csp.mjs` hashes the inline scripts. The resulting policy has no `'unsafe-inline'` and no `'unsafe-eval'`, and the build fails if inline styles appear.
- Playwright loads the export under that policy in Chromium, Firefox and WebKit with zero CSP violations (`tests/e2e/web-shell.spec.ts`). A negative control with the hashes removed makes the test fail.

Identifier routing, confirmed in Phase 5 (CM-T030): a room is one static page, `/rooms/room`, with the room ID in the query string (`/rooms/room?id=<UUIDv4>`). The page reads the parameter with `useSearchParams` inside a Suspense boundary, validates it as a UUIDv4 before use and treats anything else like an unknown room. `tests/e2e/rooms.spec.ts` opens the page through the list, after a reload and by a direct visit, in Chromium, Firefox and WebKit, with zero CSP violations. The E2E server serves `rooms/room.html` for that path and ignores the query string, which never reaches a server-side renderer; the Nginx configuration (Phase 17) must map paths the same way, for example with `try_files $uri $uri.html`. The ID is not a secret (OL-09); it identifies the room the API then authorizes.
