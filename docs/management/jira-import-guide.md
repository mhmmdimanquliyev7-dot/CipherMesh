# Jira Import Guide

Status: Phase 0.5. Nothing here connects to Jira automatically. You create the project and run the import by hand. Related: [jira-workflow.md](jira-workflow.md), [jira-backlog.md](jira-backlog.md), [jira-backlog.csv](jira-backlog.csv). Tracked as CM-T083.

Jira's menus and importer options change over time and differ between project types. Where this guide names a menu, treat it as a pointer. If a screen looks different, search Atlassian's help for "Import data from a CSV file".

## 1. Package contents

| File | Content |
|---|---|
| `jira-backlog.csv` | 16 epics and 87 work items. UTF-8, comma-separated, every field quoted; some fields span several lines |
| `jira-backlog.md` | The same backlog in readable form, the source the CSV was generated from |
| This guide | Project configuration, field mapping and checks |

## 2. The project to create

| Setting | Value |
|---|---|
| Product | Jira (Software) Cloud |
| Template | Kanban |
| Project type | **Team-managed** |
| Name | CipherMesh |
| Key | CM |
| Access | Private: only the project team |

**Why team-managed.** It is the simpler option, and it is enough for a single-person university project:
- statuses, transitions, issue types and fields are configured inside the project, with no site-level schemes;
- CSV import supports it.

A company-managed project is only needed for workflow validators or conditions (for example, blocking a transition until a field is filled), schemes shared across projects, or detailed permission schemes. None of those is required here.

**Why Kanban.** The work flows through phases rather than fixed sprints. Releases (M0 to M8) carry the milestones. Scrum would add sprint ceremonies without value for one person.

**Board.** Six columns, one per status. Keep Jira's separate Kanban backlog view off, so the board matches the documented workflow exactly. Turn it on later if the BACKLOG column grows too long. WIP limits: IN PROGRESS 3, SECURITY REVIEW 5.

**Account security.** Enable MFA on your Atlassian account before creating the project (T-34).

## 3. Workflow

Create the statuses with exactly these names. Jira shows them in capitals on the board.

| Status | Category |
|---|---|
| Backlog | To Do |
| Ready | To Do |
| In Progress | In Progress |
| Security Review | In Progress |
| Testing | In Progress |
| Done | Done |

Transitions:

| From | To | Used when |
|---|---|---|
| Backlog | Ready | Definition of Ready met |
| Ready | Backlog | Deprioritized |
| Ready | In Progress | Work started |
| In Progress | Ready | Work paused (optional) |
| In Progress | Security Review | Pull request open, CI green, documentation updated |
| **Security Review** | **In Progress** | **Security problems found: remediation** |
| Security Review | Testing | Security review passed |
| **Testing** | **In Progress** | **Tests failed or defects found: remediation** |
| Testing | Done | Definition of Done met |

In a team-managed project, open **Project settings > Workflow** (per issue type, or shared, depending on your version). Add the statuses. For each status, turn off "Allow all statuses to transition to this one" and draw the transitions above. There is deliberately no path from In Progress or Ready directly to Testing or Done.

If your plan does not let you restrict transitions, keep the defaults and follow the table as a documented rule. The issue history (evidence EV-00-06) then shows that every item passed SECURITY REVIEW.

## 4. Issue types

| Type | Use |
|---|---|
| Epic | CM-EPIC-01 to CM-EPIC-16 |
| Task | Every imported work item. Change it to Story where a capability is user-visible |
| Story | User-visible capability (optional) |
| Bug | Functional defect |
| Security Finding | Custom type for vulnerabilities, with the template in [jira-workflow.md](jira-workflow.md) section 7. If your project cannot add types, use Bug with the label `security-finding` |
| Subtask | Optional breakdown |

## 5. Fields

Built-in fields used: Summary, Description, Status, Priority, Labels, Parent, Fix versions (enable the **Releases** feature in the project settings).

Four custom fields, and no more, to avoid process overhead:

| Field | Type | Values | Issue types | Purpose |
|---|---|---|---|---|
| Security Impact | Dropdown | High, Medium, Low | Task, Story, Bug, Security Finding | Sets how deep the SECURITY REVIEW goes |
| Severity | Dropdown | Critical, High, Medium, Low | Security Finding, Bug | Technical severity of findings, separate from the scheduling priority |
| Evidence Required | Short text | Evidence IDs, for example `EV-07-01, EV-07-05` | Task, Story, Security Finding | Reminds you what to capture for the report |
| Phase | Dropdown | 0, 0.5, 1, 2, ..., 22 | All | Filters by roadmap phase. Releases group phases into milestones |

Threat IDs, CWE and CVSS stay in the description of security findings, not in fields.

## 6. Labels and components

Use **labels** for all twelve categories. The CSV uses these exact lowercase labels:

`architecture`, `cloud`, `crypto`, `security`, `frontend`, `backend`, `database`, `infrastructure`, `testing`, `documentation`, `risk`, `security-finding`

(Cryptography is `crypto`, and Security Finding is `security-finding`.)

Labels suit this project because the categories cut across each other, an issue often needs several, they exist in every project type, and the CSV importer fills them without configuration. **Components** are optional. If you want them, create components only for code areas (Web, API, Crypto package, Database, Infrastructure, Documentation) and assign them after import. Do not duplicate the label categories as components. The CSV does not set components.

## 7. Priorities

| CipherMesh | Jira default priority | Items |
|---|---|---|
| P0 Blocker / Critical | Highest | 11 |
| P1 High | High | 66 |
| P2 Medium | Medium | 8 |
| P3 Low | Low | 2 |

The CSV column `Priority` holds the Jira default names, so no renaming is needed. `CM Priority` is for reference only. Renaming the priorities (for example "Highest" to "P0 - Critical") is a site-wide setting under **Jira settings > Issues > Priorities** and affects every project on the site. If you rename them before importing, map the values during import (step 9.6).

## 8. Releases

Create these releases before importing, with exactly these names:

| Release | Phases |
|---|---|
| M0 Architecture Baseline | 0, 0.5 |
| M1 Foundation | 1, 2 |
| M2 Identity and Access | 3, 4, 5 |
| M3 Encrypted Collaboration | 6, 7, 8, 9 |
| M4 Governance and Key Lifecycle | 10, 11, 12 |
| M5 Visibility | 13, 14 |
| M6 Hardening and Test Automation | 15, 16 |
| M7 Cloud Deployment | 17, 18, 19 |
| M8 Assessment and Report | 20, 21, 22 |

## 9. Import steps

1. Complete sections 2 to 8 first.
2. Open the CSV importer. As a Jira administrator: **Settings > System > External system import > CSV**. Some sites also offer an import entry in the project or issue-search menus.
3. Upload `jira-backlog.csv`. Encoding UTF-8, delimiter comma.
4. Choose the project CipherMesh (CM).
5. Map the columns:

| CSV column | Map to | Notes |
|---|---|---|
| Issue ID | Issue ID | Import-only number that connects parents and dependencies (epics 1 to 16, tasks 1001 to 1087) |
| Parent ID | Parent (in some importers "Parent ID") | Connects each task to its epic |
| Issue Type | Issue Type | Epic or Task |
| Summary | Summary | Starts with the placeholder ID |
| Status | Status | See the note on statuses below |
| Priority | Priority | Jira default names |
| CM Priority | Do not map | Reference only |
| Labels (4 columns) | Labels | Map every Labels column |
| Fix Version | Fix version(s) | The releases must exist |
| Phase | Phase (custom) | |
| Security Impact | Security Impact (custom) | |
| Evidence Required | Evidence Required (custom) | |
| Epic, Epic Name | Do not map, unless the importer asks for an Epic Name for epic rows | Kept for checking |
| Placeholder ID, Dependencies | Do not map | Already in the summary and description |
| Blocked By (Issue ID) (3 columns) | Optional: see dependency links below | |
| Acceptance Criteria, Security Considerations | Do not map, or map to paragraph fields if you add them | Already in the description |
| Description | Description | Jira wiki markup: `h3.` headings, `*` bullets, `{{code}}` |

6. Map the values: Issue Type (Epic, Task), Status (Backlog, In Progress, Testing, Done), Priority (Highest, High, Medium, Low), Phase and Security Impact values, and release names.
7. Run the import and save the log.

**If parent mapping fails.** Some importers do not accept epic parents in the same file.
1. Import only the 16 epic rows first, filtering the CSV on Issue Type = Epic.
2. Note the keys Jira assigns, usually CM-1 to CM-16 in order.
3. In a copy of the CSV, replace each task's Parent ID with its epic's key. A spreadsheet lookup on the `Epic` column does this.
4. Import the tasks, mapping that column to Parent.

**If statuses cannot be imported.** Import everything as Backlog, then move 8 issues by hand: CM-T001 to CM-T005 and CM-T084 to Done, CM-T082 to Testing, and CM-EPIC-01 to In Progress.

**Dependency links are optional.** The dependencies are already readable in each description.
- If the importer offers a mapping for the "Blocks" link type, map the three `Blocked By (Issue ID)` columns. Then open one imported issue with dependencies and check that its prerequisites appear under "is blocked by".
- If the direction is reversed, or the option does not exist, skip link mapping. Add links later for the items you are actively working on.

## 10. Checks after import

| Check | Expected |
|---|---|
| Epics | 16 |
| Work items | 87 |
| Priorities of work items | Highest 11, High 66, Medium 8, Low 2 |
| Statuses | Done 6, Testing 1 (CM-T082), Backlog 80; CM-EPIC-01 In Progress |
| Work items without a parent epic | 0 |
| Work items per release | M0 8, M1 9, M2 19, M3 14, M4 13, M5 4, M6 4, M7 11, M8 5 |
| Labels in use | Only the twelve listed in section 6 |

Then:
- create filters for P0 items, the `security-finding` label, each epic, and "Evidence Required is not empty";
- set the WIP limits;
- capture the board and the import summary (EV-00-05, EV-00-10);
- move CM-T083 to Done through the workflow.

## 11. After the import

From now on, Jira is the source of truth for status, priority and scheduling. The markdown backlog and the CSV remain the Phase 0.5 baseline. Do not import the CSV again into a populated project, because that creates duplicates. Create new work, including security findings, directly in Jira.
