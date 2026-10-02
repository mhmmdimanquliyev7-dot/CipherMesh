# Phase 1 Traceability

Status: Phase 1 implemented on 2026-10-02, awaiting project owner approval. Covers the backlog items of Phase 1 (CM-T006 to CM-T012) in [jira-backlog.md](jira-backlog.md). No item is DONE: DONE requires SECURITY REVIEW and TESTING in Jira and the full Definition of Done (CLAUDE.md section 14), including CI on a pull request, which cannot run before a GitHub remote exists.

## 1. Work items

| Item | Acceptance criterion | Implementation | Tests | Result |
|---|---|---|---|---|
| CM-T006 Monorepo, strict TypeScript, lint, format | Frozen install, lint and typecheck succeed | Root `package.json`, `pnpm-workspace.yaml`, `tsconfig.base.json`, `eslint.config.mjs`, `.prettierrc.json` | `pnpm install --frozen-lockfile`, `pnpm lint`, `pnpm typecheck` | Met |
| | Lint fails on eval, `new Function`, `Math.random`, unsafe raw SQL, `dangerouslySetInnerHTML` and forbidden cross-package imports | ESLint guards | `tests/security/lint-guards.test.ts` | Met; also covers scattered `process.env`, WebCrypto outside packages/crypto and child processes |
| | Dependency lifecycle scripts blocked unless allowlisted | `strictDepBuilds`, `allowBuilds` (esbuild explicitly denied), `minimumReleaseAge`, `blockExoticSubdeps` | Install output | Met |
| CM-T007 Secure API scaffold | Undeclared routes prevent startup; unknown routes return 404 | Route registry, public allowlist | `apps/api/src/routes/registry.test.ts`, `tests/security/route-inventory.test.ts` (includes a check that nothing bypasses the registry), integration tests | Met |
| | Non-JSON bodies return 415, oversized bodies 413 | Content-type gate, JSON parser with 128 KiB limit, no inflation | `tests/integration/api-foundation.test.ts`, `tests/security/malformed-requests.test.ts` | Met |
| | Errors return a stable code and request ID, never a stack trace | Error handler, `HttpError` | Integration tests (internal error, projection failure) | Met |
| | Missing or malformed configuration stops the process | `apps/api/src/config/env.ts` | `env.test.ts`, `tests/security/startup-config.test.ts` | Met |
| CM-T008 Static-export web app with strict CSP | Static export runs behind a local Nginx | Export plus `tests/e2e/static-server.mjs` applying the generated headers | `pnpm test:e2e` | **Partly met.** A Node test server applies the headers Nginx will use; real Nginx comes in Phase 17, because this phase must not create an untested production configuration |
| | CSP without `'unsafe-inline'` or `'unsafe-eval'` loads in Chromium, Firefox and WebKit | `apps/web/scripts/csp-lib.mjs`, `generate-csp.mjs` | `tests/e2e/web-shell.spec.ts`, `csp-lib.test.ts`, negative control | Met |
| | ADR-011 updated | ADR-011 Accepted for export and CSP | | Met; identifier routing confirmed in Phase 5 |
| CM-T009 Shared and validation packages | Strict schemas reject unknown keys, `__proto__` and malformed values | `packages/validation`, `packages/shared` | `validation.test.ts`, `shared.test.ts` | Met |
| | API validates requests and the client validates responses with the same schemas | API: registry validation and response projection. Tests parse real responses with the shared schemas | Integration tests | **Partly met.** The web shell does not call the API yet. The policy catalogue and authorization matrix skeletons are deferred to CM-T046 and CM-T029, to avoid unimplemented placeholders |
| CM-T010 Logging with redaction | Redaction unit tests for every listed field | `apps/api/src/logging` | `redact.test.ts`, `logger.test.ts` | Met |
| | Canary secrets sent through endpoints never appear in logs | Request log without bodies, query strings or headers | `tests/security/http-baseline.test.ts` | Met |
| CM-T011 Local development environment | One command starts database and storage; ports on 127.0.0.1 | `infrastructure/docker/compose.dev.yml`, `pnpm services:up` | Manual verification (EV-01-08) | Met |
| | No real credentials; emulator choice documented | `.env.example` placeholders; OD-03 in engineering-baseline.md | gitleaks | Met. Synthetic seed data is deferred to Phase 2, because no schema exists |
| CM-T012 CI pipeline | Pull requests cannot merge with failing checks | `.github/workflows/ci.yml` | actionlint | **Not met yet.** Needs the GitHub remote and branch protection ([github-repository-settings.md](github-repository-settings.md)) |
| | Actions pinned to commit SHAs; token read-only | Workflow pins and `permissions: contents: read` | actionlint | Met |
| | Branch protection and blocked-merge evidence | | | **Pending** (EV-01-02, EV-01-03). The PostgreSQL CI service is added in Phase 2 |

## 2. Work started ahead of its phase

| Item | What exists now | What remains |
|---|---|---|
| CM-T020 CSRF defences (Phase 3) | The same-origin gate with the custom-header check applies to every state-changing request (INV-19), with tests | Login and registration CSRF tests once those endpoints exist; the client-side request helper; the browser-engine `Origin` check |
| CM-T074 Security regression suite in CI | The security suite runs in CI with the other tests | Threat and control tags and the traceability table |
| CM-T076 Scanning and SBOM | Dependency audit, gitleaks and a CycloneDX SBOM in CI; weekly Dependabot | A weekly scheduled scan workflow and container image scanning (Phase 17) |

## 3. Security checkpoint (Phase 1)

| Check | Result |
|---|---|
| CSP without `'unsafe-inline'` or `'unsafe-eval'` works in three engines | Passed, with a negative control |
| Secret scan and dependency audit green | gitleaks: no leaks. `pnpm audit`: no known vulnerabilities |
| Dependency lifecycle scripts blocked | Yes |
| Development ports bound to localhost | PostgreSQL, the S3 emulator and both dev servers listen on 127.0.0.1 only |
| Security self-review of the phase | See the Phase 1 completion report; findings were fixed in the phase |

## 4. Evidence

The index is [../report/evidence/index.md](../report/evidence/index.md). The CI-based items (EV-01-01 CI run, EV-01-02 branch protection, EV-01-03 blocked merge) wait for the GitHub remote. Local equivalents are captured now.
