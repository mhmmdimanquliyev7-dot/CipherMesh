# Evidence Index

Rules: [../evidence-plan.md](../evidence-plan.md) section 2. Every file is redacted. Text exports are preferred over screenshots. Raw, unredacted captures go to the git-ignored `_raw/` folder and are never committed.

## Phase 0 and Phase 0.5

| ID | File or location | Date | Jira | Caption |
|---|---|---|---|---|
| EV-00-01 to EV-00-04 | Diagrams and tables in `docs/` | 2026-09-28 | CM-T002 to CM-T004 | Architecture, trust boundaries, key hierarchy, risk register (export when writing the report) |
| EV-00-08 | [../../security/architecture-gate-phase-0-5.md](../../security/architecture-gate-phase-0-5.md) | 2026-09-28 | CM-T082 | Phase 0.5 attack-focused architecture review |
| EV-00-09 | Baseline commit `cb3b2229788ab2bea023630905077582e02cdd69`, recorded in the evidence plan section 6 | 2026-09-28 | CM-T084 | Initial architecture checkpoint |
| EV-00-05, EV-00-06, EV-00-10 | Pending | | CM-T083 | Jira board, issue lifecycle and import result: captured after the manual Jira setup |

## Phase 1

| ID | File | Date | Jira | Caption |
|---|---|---|---|---|
| EV-01-01 (local part) | [phase-01/EV-01-01_install-format-lint-typecheck.txt](phase-01/EV-01-01_install-format-lint-typecheck.txt) | 2026-10-02 | CM-T006, CM-T012 | Fresh install from the lockfile; format, lint and typecheck all pass |
| EV-01-01 (CI run) | Pending | | CM-T012 | GitHub Actions run summary: needs the GitHub remote |
| EV-01-02, EV-01-03 | Pending | | CM-T012 | Branch protection and a blocked merge: manual tasks in [../../management/github-repository-settings.md](../../management/github-repository-settings.md) |
| EV-01-04 | [phase-01/EV-01-04_csp-and-e2e.txt](phase-01/EV-01-04_csp-and-e2e.txt) | 2026-10-02 | CM-T008 | Generated CSP without unsafe directives; zero violations in Chromium, Firefox and WebKit; negative control |
| EV-01-05 | [phase-01/EV-01-05_secret-scan.txt](phase-01/EV-01-05_secret-scan.txt) | 2026-10-02 | CM-T012 | gitleaks over the git history and the staged Phase 1 changes |
| EV-01-06 | [phase-01/EV-01-06a_build.txt](phase-01/EV-01-06a_build.txt), [phase-01/EV-01-06b_api-smoke.txt](phase-01/EV-01-06b_api-smoke.txt) | 2026-10-02 | CM-T007 | Build output; built API answers health, readiness and 404 with minimal, generic bodies |
| EV-01-07 | [phase-01/EV-01-07_dependency-audit-and-sbom.txt](phase-01/EV-01-07_dependency-audit-and-sbom.txt) | 2026-10-02 | CM-T012 | No known vulnerabilities; CycloneDX SBOM generated |
| EV-01-08 | [phase-01/EV-01-08_dev-services.txt](phase-01/EV-01-08_dev-services.txt) | 2026-10-02 | CM-T011 | PostgreSQL and the S3 emulator listen on 127.0.0.1 only; wrong credentials rejected |
| EV-01-09 | [phase-01/EV-01-09_test-results.txt](phase-01/EV-01-09_test-results.txt) | 2026-10-02 | CM-T007, CM-T009, CM-T010 | All 129 unit, integration and security tests pass, including redaction, CSRF gate and route inventory |
