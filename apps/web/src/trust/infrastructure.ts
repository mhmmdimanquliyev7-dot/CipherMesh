import type { IconName } from '../components/icons';

/**
 * Deployment & Infrastructure (Phase 14 + Prompt 16.5, CM-T061). The designed architecture comes
 * from docs/cloud/deployment-architecture.md; the control register below separates three facts for
 * each control, as the Trust Center must:
 *   Design        the documents describe it (always cited);
 *   Configuration a file in this repository implements it, and where it applies;
 *   Verification  a captured evidence item shows that it works.
 * A control may be "verified" only when every cited evidence item is captured, and only for the
 * environment the evidence was taken in (trust-content.test.ts enforces both). Nothing has been
 * deployed to a cloud provider yet, so no cloud-side control is configured or verified.
 */

export type Scope = 'local' | 'ci' | 'cloud';

export interface CloudControl {
  readonly id: string;
  readonly name: string;
  readonly icon: IconName;
  readonly design: { readonly text: string; readonly source: string };
  readonly configuration:
    | {
        readonly state: 'configured';
        readonly scope: Scope;
        readonly text: string;
        readonly sources: readonly string[];
      }
    | { readonly state: 'not-configured'; readonly text: string };
  readonly verification:
    | { readonly state: 'verified'; readonly scope: Scope; readonly text: string; readonly evidence: readonly string[] }
    | { readonly state: 'not-verified'; readonly text: string; readonly planned: readonly string[] };
}

const DEPLOYMENT = 'docs/cloud/deployment-architecture.md';

export const CLOUD_CONTROLS: readonly CloudControl[] = [
  {
    id: 'tls',
    name: 'HTTPS and TLS',
    icon: 'lock',
    design: {
      text: 'Nginx terminates TLS 1.2 and 1.3 (Mozilla intermediate), HTTP redirects to HTTPS, HSTS after a staged rollout (CP-21).',
      source: DEPLOYMENT,
    },
    configuration: {
      state: 'not-configured',
      text: 'No Nginx configuration or certificate exists yet. The local test server uses a throwaway self-signed certificate.',
    },
    verification: {
      state: 'not-verified',
      text: 'A TLS scan of the deployed endpoint is planned.',
      planned: ['EV-17-04'],
    },
  },
  {
    id: 'headers',
    name: 'Security headers and Content Security Policy',
    icon: 'browser',
    design: {
      text: 'Strict CSP without unsafe-inline or unsafe-eval, frame denial, nosniff, no-referrer, COOP and CORP on every response.',
      source: DEPLOYMENT,
    },
    configuration: {
      state: 'configured',
      scope: 'local',
      text: 'The web build computes the CSP and header set (out-meta/security-headers.json). Serving it from Nginx in the cloud is not configured yet.',
      sources: ['apps/web/scripts/csp-lib.mjs', 'apps/web/scripts/generate-csp.mjs'],
    },
    verification: {
      state: 'verified',
      scope: 'local',
      text: 'Browser tests load every page under the generated policy with zero violations in Chromium, Firefox and WebKit.',
      evidence: ['EV-01-04'],
    },
  },
  {
    id: 'exposure',
    name: 'Firewall and network exposure',
    icon: 'network',
    design: {
      text: 'Only 443 and 80 are public; SSH from allowlisted addresses; the API, worker, database and Docker socket are never published.',
      source: DEPLOYMENT,
    },
    configuration: { state: 'not-configured', text: 'No provider or host firewall exists yet.' },
    verification: {
      state: 'not-verified',
      text: 'Firewall screenshots and an external port scan are planned.',
      planned: ['EV-17-02', 'EV-19-05'],
    },
  },
  {
    id: 'isolation',
    name: 'Service isolation and container hardening',
    icon: 'server',
    design: {
      text: 'Separate edge and internal Docker networks, non-root read-only containers, all capabilities dropped, images pinned by digest.',
      source: DEPLOYMENT,
    },
    configuration: { state: 'not-configured', text: 'There is no production Compose file or image yet.' },
    verification: {
      state: 'not-verified',
      text: 'docker inspect excerpts and a Docker Bench report are planned.',
      planned: ['EV-17-03', 'EV-19-04'],
    },
  },
  {
    id: 'dev-loopback',
    name: 'Development services bound to loopback',
    icon: 'database',
    design: {
      text: 'Local PostgreSQL and the S3 emulator listen on 127.0.0.1 only, with credentials enforced.',
      source: DEPLOYMENT,
    },
    configuration: {
      state: 'configured',
      scope: 'local',
      text: 'The development Compose file publishes both services on 127.0.0.1 with digest-pinned images.',
      sources: ['infrastructure/docker/compose.dev.yml'],
    },
    verification: {
      state: 'verified',
      scope: 'local',
      text: 'Listening sockets and refused wrong credentials were recorded.',
      evidence: ['EV-01-08'],
    },
  },
  {
    id: 'db-privileges',
    name: 'Least-privilege database roles',
    icon: 'database',
    design: {
      text: 'One role per component; runtime roles without DDL; no UPDATE or DELETE on audit tables; migration credentials never on the VM.',
      source: 'docs/security/database-security.md',
    },
    configuration: {
      state: 'configured',
      scope: 'local',
      text: 'Roles and grants are created by reviewed migrations, so a managed database receives the same grants.',
      sources: ['prisma/migrations', 'tests/database/privileges.test.ts'],
    },
    verification: {
      state: 'verified',
      scope: 'local',
      text: 'The grant matrix and refused DDL were tested against PostgreSQL 17.',
      evidence: ['EV-02-03'],
    },
  },
  {
    id: 'db-tls',
    name: 'Database connections with verified TLS',
    icon: 'database',
    design: {
      text: 'The managed database accepts only TLS from the VM, and clients verify the provider certificate (verify-full).',
      source: DEPLOYMENT,
    },
    configuration: {
      state: 'configured',
      scope: 'local',
      text: 'The API refuses database URLs with the wrong role or without the required TLS settings.',
      sources: ['apps/api/src/config/env.ts'],
    },
    verification: {
      state: 'not-verified',
      text: 'The URL rules are tested locally (EV-02-06); a refused non-TLS connection to the managed database is planned.',
      planned: ['EV-18-02'],
    },
  },
  {
    id: 'secrets',
    name: 'Secrets and environment configuration',
    icon: 'key',
    design: {
      text: 'Secrets as root-owned files mounted read-only; the API refuses to start when a secret is missing or malformed.',
      source: DEPLOYMENT,
    },
    configuration: {
      state: 'configured',
      scope: 'local',
      text: 'Startup configuration is validated against a schema and refused when incomplete or unsafe.',
      sources: ['apps/api/src/config/env.ts', 'tests/security/startup-config.test.ts'],
    },
    verification: {
      state: 'verified',
      scope: 'local',
      text: 'Startup refusal and redaction of configuration values are tested.',
      evidence: ['EV-02-06'],
    },
  },
  {
    id: 'storage',
    name: 'Private object storage and presigned URLs',
    icon: 'bucket',
    design: {
      text: 'Private bucket, public access blocked; browsers reach single objects through presigned URLs that expire within minutes.',
      source: DEPLOYMENT,
    },
    configuration: {
      state: 'configured',
      scope: 'local',
      text: 'The storage adapter signs one object, one method and one size per URL (CP-20); objects have random names.',
      sources: ['apps/api/src/storage/object-store.ts'],
    },
    verification: {
      state: 'verified',
      scope: 'local',
      text: 'Expired URLs are refused and objects carry random names, against the local S3 emulator. The cloud bucket policy is not verified yet.',
      evidence: ['EV-07-06', 'EV-07-02'],
    },
  },
  {
    id: 'supply-chain',
    name: 'Secret scanning and dependency checks',
    icon: 'evidence',
    design: {
      text: 'Every pull request runs gitleaks over the full history, a dependency audit and SBOM generation.',
      source: 'docs/security/security-testing-plan.md',
    },
    configuration: {
      state: 'configured',
      scope: 'ci',
      text: 'GitHub Actions run the scans on every pull request.',
      sources: ['.github/workflows/ci.yml'],
    },
    verification: {
      state: 'verified',
      scope: 'ci',
      text: 'Scan results and the SBOM are recorded.',
      evidence: ['EV-01-05', 'EV-01-07'],
    },
  },
  {
    id: 'logging',
    name: 'Logging with central redaction',
    icon: 'note',
    design: {
      text: 'Structured JSON logs with a central redaction list; no request bodies of sensitive endpoints.',
      source: DEPLOYMENT,
    },
    configuration: {
      state: 'configured',
      scope: 'local',
      text: 'Every log line passes the redaction module.',
      sources: ['apps/api/src/logging/redact.ts', 'apps/api/src/logging/logger.ts'],
    },
    verification: {
      state: 'verified',
      scope: 'local',
      text: 'Redaction tests search the log for every secret used in the suites.',
      evidence: ['EV-01-09'],
    },
  },
  {
    id: 'health',
    name: 'Health checks',
    icon: 'checkCircle',
    design: { text: 'Liveness and readiness probes that reveal a status word only.', source: DEPLOYMENT },
    configuration: {
      state: 'configured',
      scope: 'local',
      text: 'GET /health and GET /ready (readiness includes a cached database check).',
      sources: ['apps/api/src/routes/system.ts'],
    },
    verification: {
      state: 'verified',
      scope: 'local',
      text: 'The built API answered health, readiness and 404 with minimal bodies.',
      evidence: ['EV-01-06'],
    },
  },
  {
    id: 'backups',
    name: 'Backups and restore',
    icon: 'rotate',
    design: {
      text: 'Provider-managed database backups with point-in-time recovery, object versioning, and a team-tested restore.',
      source: DEPLOYMENT,
    },
    configuration: { state: 'not-configured', text: 'No managed database or bucket exists yet.' },
    verification: { state: 'not-verified', text: 'A restore test is planned.', planned: ['EV-19-07'] },
  },
  {
    id: 'hardening',
    name: 'VM hardening',
    icon: 'settings',
    design: {
      text: 'SSH keys only, no root login, host firewall, unattended upgrades, Lynis and Docker Bench reviews.',
      source: DEPLOYMENT,
    },
    configuration: { state: 'not-configured', text: 'No VM exists yet.' },
    verification: {
      state: 'not-verified',
      text: 'sshd, firewall and Lynis evidence are planned.',
      planned: ['EV-19-01', 'EV-19-02', 'EV-19-03'],
    },
  },
  {
    id: 'audit-chain',
    name: 'Tamper-evident audit ledger',
    icon: 'evidence',
    design: {
      text: 'Hash-chained audit events with signed checkpoints in a retention-locked bucket (ADR-009).',
      source: 'docs/architecture/adr/ADR-009-tamper-evident-audit-ledger.md',
    },
    configuration: {
      state: 'not-configured',
      text: 'Not implemented: Phase 12 was deferred by the project owner. Security events go to the redacted application log; the audit table only refuses updates and deletes.',
    },
    verification: {
      state: 'not-verified',
      text: 'Deferred with Phase 12.',
      planned: ['EV-12-01', 'EV-12-03', 'EV-12-04'],
    },
  },
];

/** Components of the deployment (deployment-architecture.md section 1, ADR-014). */
export interface Component {
  readonly id: string;
  readonly name: string;
  readonly icon: IconName;
  readonly exposure: 'public' | 'private' | 'none';
  readonly model: string;
  readonly role: string;
  /** What stands in for it on a development machine. */
  readonly local: string;
}

export const COMPONENTS: readonly Component[] = [
  {
    id: 'browser',
    name: 'User browser',
    icon: 'browser',
    exposure: 'public',
    model: 'Client',
    role: 'Runs the web client and all content cryptography.',
    local: 'Chromium, Firefox, WebKit',
  },
  {
    id: 'nginx',
    name: 'Nginx',
    icon: 'globe',
    exposure: 'public',
    model: 'IaaS VM (container)',
    role: 'TLS for the application and storage host names, security headers, rate limits, static files, /api proxy, signed object requests to storage.',
    local: 'The same image in the rehearsal (cm-rehearsal) and in CI on linux/arm64',
  },
  {
    id: 'api',
    name: 'API',
    icon: 'server',
    exposure: 'private',
    model: 'IaaS VM (container)',
    role: 'Authentication, authorization, policies, presigned URLs. Holds no content keys.',
    local: 'Node.js process',
  },
  {
    id: 'worker',
    name: 'Worker',
    icon: 'rotate',
    exposure: 'none',
    model: 'IaaS VM (container, timer)',
    role: 'Expiry cleanup, abandoned rekeys, cryptoperiods. No inbound traffic.',
    local: 'Node.js process',
  },
  {
    id: 'postgres',
    name: 'PostgreSQL',
    icon: 'database',
    exposure: 'private',
    model: 'IaaS VM (container, ADR-014)',
    role: 'Metadata, ciphertext of notes and secrets, wrapped keys. TLS 1.3 for the runtime roles; no superuser password.',
    local: 'PostgreSQL 17 container on 127.0.0.1',
  },
  {
    id: 'storage',
    name: 'Object storage (SeaweedFS)',
    icon: 'bucket',
    exposure: 'private',
    model: 'IaaS VM (container, ADR-014)',
    role: 'Encrypted file blobs in a private bucket, reached by browsers with presigned URLs through Nginx on a second host name.',
    local: 'S3 emulator container on 127.0.0.1',
  },
];
