import type { IconName } from '../components/icons';

/**
 * Deployment & Infrastructure (Phase 14 + Prompt 16.5, CM-T061). The designed architecture comes
 * from docs/cloud/deployment-architecture.md; the control register below separates three facts for
 * each control, as the Trust Center must:
 *   Design        the documents describe it (always cited);
 *   Configuration a file in this repository implements it, and where it applies;
 *   Verification  a captured evidence item shows that it works.
 * A control may be "verified" only when every cited evidence item is captured, and only for the
 * environment the evidence was taken in (trust-content.test.ts enforces both). The deployment is the
 * local Docker demonstration (ADR-014 priority of 2026-10-14); nothing runs at a cloud provider, so
 * no cloud-side control is configured or verified.
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
      text: 'Nginx terminates TLS 1.2 and 1.3 (Mozilla intermediate), refuses unknown host names, redirects HTTP to HTTPS; Let’s Encrypt certificates and staged HSTS on the cloud VM (CP-21, ADR-014).',
      source: DEPLOYMENT,
    },
    configuration: {
      state: 'configured',
      scope: 'local',
      text: 'The Nginx TLS settings run in the local Docker demonstration with a name-constrained local CA. Let’s Encrypt issuance (cm-tls) is prepared for the cloud VM and not used yet.',
      sources: [
        'infrastructure/nginx/snippets/tls.conf',
        'infrastructure/nginx/templates/conf.d/ciphermesh.conf.template',
        'infrastructure/deployment/bin/cm-tls',
      ],
    },
    verification: {
      state: 'verified',
      scope: 'local',
      text: 'Local Docker demonstration: TLS 1.3 negotiated, TLS 1.0, 1.1 and unknown names refused, HTTP redirected. A publicly trusted certificate is not verified anywhere yet (cloud evidence EV-17-04).',
      evidence: ['EV-17-09'],
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
      text: 'The web build computes the CSP and header set; Nginx serves exactly that set in the local Docker demonstration.',
      sources: [
        'apps/web/scripts/csp-lib.mjs',
        'apps/web/scripts/generate-csp.mjs',
        'infrastructure/nginx/render-security-headers.mjs',
      ],
    },
    verification: {
      state: 'verified',
      scope: 'local',
      text: 'Every page loads under the generated policy with zero violations in Chromium, Firefox and WebKit, in the test server and through Nginx in the local Docker demonstration.',
      evidence: ['EV-01-04', 'EV-17-09'],
    },
  },
  {
    id: 'exposure',
    name: 'Firewall and network exposure',
    icon: 'network',
    design: {
      text: 'Only 443 and 80 are public; SSH from allowlisted addresses; the API, worker, database, storage and Docker socket are never published.',
      source: DEPLOYMENT,
    },
    configuration: {
      state: 'configured',
      scope: 'local',
      text: 'Only Nginx publishes ports (on 127.0.0.1 in the local demonstration). The host firewall script for the cloud VM exists; no provider firewall exists because no VM exists.',
      sources: ['infrastructure/docker/compose.cloud.yml', 'infrastructure/deployment/bin/cm-firewall'],
    },
    verification: {
      state: 'not-verified',
      text: 'Exposure to the internet can only be verified on the cloud VM: firewall rules and an external scan are planned. Locally, the internal ports are refused (EV-17-09).',
      planned: ['EV-17-02', 'EV-19-05'],
    },
  },
  {
    id: 'isolation',
    name: 'Service isolation and container hardening',
    icon: 'server',
    design: {
      text: 'Separate edge network and internal app, data and storage networks without egress; non-root, read-only containers without capabilities; images pinned by digest.',
      source: DEPLOYMENT,
    },
    configuration: {
      state: 'configured',
      scope: 'local',
      text: 'The production Compose file and images run unchanged in the local Docker demonstration.',
      sources: ['infrastructure/docker/compose.cloud.yml', 'infrastructure/docker/Dockerfile'],
    },
    verification: {
      state: 'verified',
      scope: 'local',
      text: 'docker inspect in the local demonstration: non-root users, read-only root filesystems, capabilities dropped (PostgreSQL keeps five for its entrypoint), internal networks, only Nginx publishes ports; the database network cannot reach storage.',
      evidence: ['EV-17-09'],
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
      text: 'One role per component; runtime roles without DDL; no UPDATE or DELETE on audit tables; the migration password never stored on the server.',
      source: 'docs/security/database-security.md',
    },
    configuration: {
      state: 'configured',
      scope: 'local',
      text: 'Roles and grants are created by reviewed migrations; the deployment applies the same migrations as the migration role.',
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
      text: 'PostgreSQL accepts the runtime roles only over TLS 1.3, and they verify its certificate (verify-full against the deployment’s CA); the superuser has no password (ADR-014, CD-34).',
      source: DEPLOYMENT,
    },
    configuration: {
      state: 'configured',
      scope: 'local',
      text: 'HBA rules, the private database CA and the API’s URL rules run in the local Docker demonstration.',
      sources: [
        'infrastructure/postgres/pg_hba.conf',
        'infrastructure/postgres/postgresql.conf',
        'infrastructure/deployment/bin/cm-pki',
        'apps/api/src/config/env.ts',
      ],
    },
    verification: {
      state: 'verified',
      scope: 'local',
      text: 'Local demonstration: a login without TLS and a superuser network login are refused; the API’s sessions use TLS 1.3; the superuser has no password.',
      evidence: ['EV-17-09'],
    },
  },
  {
    id: 'secrets',
    name: 'Secrets and environment configuration',
    icon: 'key',
    design: {
      text: 'Secrets as files mounted read-only under /run/secrets, never environment variables; the API refuses to start when a secret is missing or malformed.',
      source: DEPLOYMENT,
    },
    configuration: {
      state: 'configured',
      scope: 'local',
      text: 'Configuration is validated at startup; secrets are generated by cm-secrets and read from files (<NAME>_FILE).',
      sources: [
        'apps/api/src/config/env.ts',
        'infrastructure/deployment/bin/cm-secrets',
        'tests/security/startup-config.test.ts',
      ],
    },
    verification: {
      state: 'verified',
      scope: 'local',
      text: 'Startup refusal and redaction are tested; in the local demonstration the API container’s environment holds only file paths and identifiers.',
      evidence: ['EV-02-06', 'EV-17-09'],
    },
  },
  {
    id: 'storage',
    name: 'Private object storage and presigned URLs',
    icon: 'bucket',
    design: {
      text: 'Private bucket; browsers reach single objects through presigned URLs that expire within minutes, on another host name, through a gateway that forwards only signed object requests.',
      source: DEPLOYMENT,
    },
    configuration: {
      state: 'configured',
      scope: 'local',
      text: 'The storage adapter signs one object, one method and one size per URL (CP-20); Nginx forwards only signed requests for object keys of the content bucket.',
      sources: [
        'apps/api/src/storage/object-store.ts',
        'infrastructure/nginx/templates/conf.d/ciphermesh.conf.template',
      ],
    },
    verification: {
      state: 'verified',
      scope: 'local',
      text: 'Expired URLs and random names tested against the emulator; in the local demonstration unsigned, listing, forged and cookie-carrying requests are refused.',
      evidence: ['EV-07-06', 'EV-07-02', 'EV-17-09'],
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
      text: 'Structured JSON logs with a central redaction list; no request bodies of sensitive endpoints; Nginx logs paths without query strings.',
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
    name: 'Health checks and measured platform status',
    icon: 'checkCircle',
    design: {
      text: 'Liveness and readiness probes that reveal a status word only; a measured platform status with its time, where stale data is never shown as healthy.',
      source: DEPLOYMENT,
    },
    configuration: {
      state: 'configured',
      scope: 'local',
      text: 'GET /health and GET /ready; the host status collector and the API’s freshness rules.',
      sources: [
        'apps/api/src/routes/system.ts',
        'apps/api/src/platform/status.ts',
        'infrastructure/deployment/bin/cm-status-collect',
      ],
    },
    verification: {
      state: 'verified',
      scope: 'local',
      text: 'The built API answered the probes with minimal bodies; the dashboard of the local demonstration shows measured states with their times and the cloud as not connected.',
      evidence: ['EV-01-06', 'EV-19-13'],
    },
  },
  {
    id: 'backups',
    name: 'Backups and restore',
    icon: 'rotate',
    design: {
      text: 'Encrypted backups (age, offline identity), a restore drill comparing every table and every file’s ciphertext digest, and a tested full restore (ADR-014).',
      source: 'docs/deployment/backup-and-restore.md',
    },
    configuration: {
      state: 'configured',
      scope: 'local',
      text: 'cm-backup, cm-restore-drill and cm-restore run in the local Docker demonstration.',
      sources: [
        'infrastructure/deployment/bin/cm-backup',
        'infrastructure/deployment/bin/cm-restore-drill',
        'infrastructure/deployment/bin/cm-restore',
      ],
    },
    verification: {
      state: 'verified',
      scope: 'local',
      text: 'Local demonstration: backup without plaintext canaries, identical tables and file objects in the drill, and a full restore after which the browsers decrypt the restored note and file. The drill on a cloud VM is not done (EV-19-07).',
      evidence: ['EV-17-09'],
    },
  },
  {
    id: 'hardening',
    name: 'VM hardening',
    icon: 'settings',
    design: {
      text: 'SSH keys only, no root login, host firewall, unattended upgrades, Lynis and Docker Bench reviews.',
      source: DEPLOYMENT,
    },
    configuration: {
      state: 'not-configured',
      text: 'The scripts for the Oracle VM exist (cm-host-setup, cm-firewall); they do not apply to a laptop, and no VM exists.',
    },
    verification: {
      state: 'not-verified',
      text: 'sshd, firewall and Lynis evidence are planned for the cloud VM.',
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
