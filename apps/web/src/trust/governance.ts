import type { IconName } from '../components/icons';

/**
 * The project's governing documents, as they exist in the repository (Phase 14 + Prompt 16.5,
 * CM-T061). The Trust Center lists them; it does not create policies. trust-content.test.ts
 * checks that every path exists. Areas without a dedicated document say where the rule lives.
 */
export interface PolicyDocument {
  readonly area: string;
  readonly icon: IconName;
  readonly title: string;
  readonly path: string;
  readonly governs: string;
}

export const POLICIES: readonly PolicyDocument[] = [
  {
    area: 'Information security policy',
    icon: 'trust',
    title: 'Engineering rules and security invariants',
    path: 'CLAUDE.md',
    governs: 'Mission, invariants INV-01 to INV-19, forbidden practices, Definition of Done (clause 5.2).',
  },
  {
    area: 'Security principles',
    icon: 'layers',
    title: 'Security principles',
    path: 'docs/security/security-principles.md',
    governs: 'Deny by default, fail closed, least privilege, defence in depth.',
  },
  {
    area: 'Access control',
    icon: 'members',
    title: 'Authorization model',
    path: 'docs/security/authorization-model.md',
    governs: 'Roles, the shared matrix, object-level rules and platform administration (5.15, 5.18, 8.3).',
  },
  {
    area: 'Classification and handling',
    icon: 'trust',
    title: 'Security policy profiles',
    path: 'docs/security/security-policy-profiles.md',
    governs: 'STANDARD, CONFIDENTIAL and RESTRICTED rooms and their handling rules PC-01 to PC-16 (5.12, 5.13).',
  },
  {
    area: 'Cryptography',
    icon: 'key',
    title: 'Crypto decisions and parameter register',
    path: 'docs/crypto/crypto-decisions.md',
    governs: 'Approved algorithms, parameters, libraries and forbidden practices (8.24).',
  },
  {
    area: 'Key management',
    icon: 'rotate',
    title: 'Key lifecycle',
    path: 'docs/crypto/key-lifecycle.md',
    governs: 'Creation, rotation, retirement, destruction and compromise response of every key.',
  },
  {
    area: 'Incident response',
    icon: 'alert',
    title: 'Runbook: lost or compromised identity key',
    path: 'docs/security/runbook-compromised-identity-key.md',
    governs:
      'User, administrator and operator steps after a key compromise (5.24 to 5.27). A general incident procedure is still open (CM-T080).',
  },
  {
    area: 'Secure development and change management',
    icon: 'settings',
    title: 'Jira workflow and security checklist',
    path: 'docs/management/jira-workflow.md',
    governs: 'BACKLOG to DONE with SECURITY REVIEW and TESTING gates, pull requests, findings (8.25, 8.32).',
  },
  {
    area: 'Risk management',
    icon: 'risk',
    title: 'Threat model and risk register',
    path: 'docs/threat-model/threat-model.md',
    governs: 'Assets, threats, likelihood and impact ratings, treatments and residual risk (6.1.2, 6.1.3).',
  },
  {
    area: 'Limitations and accepted risk',
    icon: 'minusCircle',
    title: 'Security limitations',
    path: 'docs/security/limitations.md',
    governs: 'What the design does not protect against, and what CipherMesh does about it.',
  },
  {
    area: 'Cloud services',
    icon: 'cloud',
    title: 'Shared responsibility',
    path: 'docs/cloud/shared-responsibility.md',
    governs: 'Provider and team responsibilities per service model (5.23).',
  },
  {
    area: 'Evidence',
    icon: 'evidence',
    title: 'Evidence plan',
    path: 'docs/report/evidence-plan.md',
    governs: 'What to capture per phase, how, and the redaction checklist (5.28).',
  },
];

/** Areas the Statement-of-Applicability style mapping does not cover with its own document yet. */
export const GOVERNANCE_GAPS: readonly string[] = [
  'A general incident-management procedure beyond the identity-key runbook (CM-T080).',
  'A backup and restore procedure with a tested restore (cloud workstream, EV-19-07).',
  'A data-retention policy document: retention rules exist in code and the data model, not as a policy.',
  'An access review record (CM-T080) and a management review record for the final report.',
];
