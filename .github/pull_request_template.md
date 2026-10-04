## Jira

CM-

## Change

<!-- What changed and why. -->

## Security impact

<!-- Which invariants (INV-xx), threats (T-xx) or controls are affected? "None" needs a reason. -->

## Tests

<!-- New or changed tests, including negative and authorization tests. -->

## Security review checklist (docs/management/jira-workflow.md section 5)

- [ ] Every new or changed endpoint declares its action and is authorized server-side; object-level rules hold.
- [ ] Inputs are validated with shared schemas; unknown fields are rejected.
- [ ] Responses use explicit projections; no sensitive fields are returned.
- [ ] Nothing sensitive is logged; the redaction list is updated for new sensitive fields.
- [ ] Cryptography uses only registered algorithms, canonical contexts and internal IVs; RSA-OAEP wraps 32-byte keys only (INV-17).
- [ ] Writes and invitations respect the room key state and current key version (INV-07).
- [ ] State-changing routes pass the same-origin and request-header checks (INV-19).
- [ ] Errors fail closed and reveal nothing internal.
- [ ] New dependencies are justified, scanned and recorded where required.
- [ ] No secrets in code, configuration, tests, screenshots or this pull request.
- [ ] Threat model, ADRs and limitations are updated where affected.
- [ ] No claim is stronger than the implementation provides.

## Evidence

<!-- Evidence IDs from docs/report/evidence-plan.md captured for this change, if any. -->
