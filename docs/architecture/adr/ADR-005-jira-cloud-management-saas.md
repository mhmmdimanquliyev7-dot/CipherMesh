# ADR-005: Jira Cloud as management SaaS

- Status: Accepted
- Date: 2026-09-28
- Related: [jira-workflow.md](../../management/jira-workflow.md), [jira-backlog.md](../../management/jira-backlog.md), [service-models.md](../../cloud/service-models.md), T-34

## Context
The Information Security Management Systems subject needs visible, documented change management: planned work, security review before release, tracked findings, corrective actions and evidence. The Cloud Security subject needs a clear SaaS example. GitHub already provides source control and pull requests.

## Decision
Use **Jira Cloud** for project management: epics, stories, tasks, bugs and security findings; the workflow BACKLOG, READY, IN PROGRESS, SECURITY REVIEW, TESTING, DONE; priorities P0 to P3; labels; releases for milestones. Link Jira and GitHub through issue keys in branch names, commit messages and pull requests. Jira is not part of the CipherMesh runtime and never holds production data or secrets. In Phase 0 the backlog is only specified; nothing is created in Jira yet.

## Alternatives Considered
- **GitHub Issues and Projects:** simpler and in one place, but weaker workflow enforcement (for example a mandatory security-review status) and a less distinct SaaS example.
- **Other SaaS trackers (for example Linear, Trello, YouTrack):** viable, but Jira is widely used in industry and in ISMS-oriented courses.
- **Self-hosted trackers:** would add infrastructure to secure without benefit to the project goals.

## Consequences
- Accounts, permissions and MFA must be managed for another service.
- The team captures screenshots and exports of the board and issue histories as evidence.
- Some manual effort to keep Jira and GitHub consistent.

## Security Implications
- Jira becomes a supplier under ISO/IEC 27001:2022 controls 5.19 to 5.23; its shared-responsibility split is in [shared-responsibility.md](../../cloud/shared-responsibility.md).
- Rules: MFA, team-only project, no secrets or production data, restricted detail for open security findings (T-34).

## Status
Accepted. Review if the university provides a different mandated tool.
