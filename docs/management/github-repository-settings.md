# GitHub Repository Settings

Status: Phase 1 recommendation. **None of these settings is enabled yet**: the repository has no GitHub remote (CLAUDE.md section 12). When the remote is created, apply them by hand and capture the evidence listed. Related: CM-T012, [jira-workflow.md](jira-workflow.md), [../report/evidence-plan.md](../report/evidence-plan.md).

## 1. Settings to apply

| Area | Setting | Why | Evidence |
|---|---|---|---|
| Visibility | Private repository; access for the project team only | No exposure of findings or work in progress (T-34) | Settings screenshot |
| Account security | Two-factor authentication required for every collaborator | Protects the code-delivery path (T-24, T-27) | EV-19-08 |
| Branch protection on `main` | Require a pull request before merging, at least one approval where a second person exists, dismiss stale approvals | Change control (ISO/IEC 27001 control 8.32) | EV-01-02 |
| Branch protection on `main` | Require status checks: `Lint, types, tests, build, E2E`, `Dependency audit`, `Secret scan (gitleaks, full history)`; require branches to be up to date | CI gates from the security testing plan section 6 | EV-01-02, EV-01-03 |
| Branch protection on `main` | Block force pushes and deletions; include administrators | History stays auditable | EV-01-02 |
| Branch protection on `main` | Require linear history (optional) and signed commits (optional, recommended) | Readable history; commit authenticity | Settings screenshot |
| Actions | Allow only actions pinned to a full commit SHA (if the plan offers it); default `GITHUB_TOKEN` permissions read-only | Supply chain (T-27); the workflow already pins SHAs and requests `contents: read` | Settings screenshot |
| Security | Enable secret scanning and push protection | Second layer behind gitleaks (T-16) | Settings screenshot |
| Security | Enable Dependabot alerts and security updates; `.github/dependabot.yml` already schedules weekly version updates | Known-vulnerable dependencies (T-27) | Settings screenshot |
| Security | Enable private vulnerability reporting | Findings can be reported without public disclosure | Settings screenshot |
| Pull requests | Use the template in `.github/pull_request_template.md`; reference the Jira key in branch, commit and title | Traceability between Jira, code and evidence | Pull request screenshot |

## 2. First push

1. Create the empty private repository on GitHub. Do not let GitHub add a README or licence, so the history stays intact.
2. `git remote add origin <url>` and `git push -u origin main`.
3. Apply section 1 before any further work is pushed.
4. Open a test pull request with a deliberate formatting error to capture a blocked merge (EV-01-03). Then close it.

## 3. Status

| Setting | Status |
|---|---|
| All settings in section 1 | **Not configured. No remote exists yet.** Manual task for the project owner |
| CI workflow, Dependabot configuration, pull request template | Committed in the repository; active once the remote exists |
