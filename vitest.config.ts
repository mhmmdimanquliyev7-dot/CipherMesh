import { defineConfig } from 'vitest/config';

// Suites, matching docs/security/security-testing-plan.md: unit tests live next to the code,
// integration, security and database suites under tests/. The database suite needs the local
// PostgreSQL container (`pnpm services:up && pnpm db:bootstrap`) or the CI service container;
// it fails instead of skipping when PostgreSQL is unavailable.
export default defineConfig({
  test: {
    environment: 'node',
    // `pnpm test:coverage:crypto`: CLAUDE.md section 10 requires at least 90% of statements and
    // branches for packages/crypto. The run fails below the thresholds. `pnpm test:coverage:authz`
    // applies the same thresholds to the room authorization decision (Phase 5, CM-T029) by
    // overriding `include` on the command line, and since Phase 10 (CM-T046, CM-T047) to the
    // policy engine (packages/shared/src/policy.ts).
    coverage: {
      provider: 'v8',
      include: ['packages/crypto/src/**'],
      exclude: ['**/*.test.ts'],
      reporter: ['text-summary', 'text'],
      thresholds: { statements: 90, branches: 90, functions: 90, lines: 90 },
    },
    projects: [
      {
        test: {
          name: 'unit',
          include: ['packages/*/src/**/*.test.ts', 'apps/api/src/**/*.test.ts', 'apps/web/scripts/**/*.test.ts'],
        },
      },
      { test: { name: 'integration', include: ['tests/integration/**/*.test.ts'] } },
      { test: { name: 'security', include: ['tests/security/**/*.test.ts'] } },
      {
        // Authentication security suites (Phase 3): real API, real Argon2id, real PostgreSQL.
        test: {
          name: 'auth',
          include: ['tests/auth/**/*.test.ts'],
          globalSetup: ['tests/database/global-setup.ts'],
          testTimeout: 60_000,
          hookTimeout: 120_000,
        },
      },
      {
        // Vault and public-key directory suites (Phase 4): real API, real Argon2id at the
        // production parameters, real PostgreSQL, and vault records made by packages/crypto.
        test: {
          name: 'vault',
          include: ['tests/vault/**/*.test.ts'],
          globalSetup: ['tests/database/global-setup.ts'],
          testTimeout: 120_000,
          hookTimeout: 120_000,
        },
      },
      {
        // Room authorization suites (Phase 5): the real API and the central room authorizer,
        // real sessions and memberships in PostgreSQL as the least-privilege API role.
        test: {
          name: 'authz',
          include: ['tests/authz/**/*.test.ts'],
          // One file at a time: each file starts an API with its own pool and several clients as
          // cm_api, whose connection limit (40, database-security.md) is shared with the other
          // projects. Run in parallel they exceeded it.
          fileParallelism: false,
          globalSetup: ['tests/database/global-setup.ts'],
          testTimeout: 60_000,
          hookTimeout: 120_000,
        },
      },
      {
        // Encrypted file suites (Phase 7): the real API, PostgreSQL as cm_api and cm_worker, the
        // real local object storage (`pnpm services:up && pnpm storage:bootstrap`), and files
        // encrypted by packages/crypto. One file at a time, like authz (shared connection limit).
        test: {
          name: 'files',
          include: ['tests/files/**/*.test.ts'],
          fileParallelism: false,
          globalSetup: ['tests/database/global-setup.ts'],
          testTimeout: 60_000,
          hookTimeout: 120_000,
        },
      },
      {
        // Encrypted note suites (Phase 8): the real API, PostgreSQL as cm_api and cm_worker, and
        // notes encrypted by packages/crypto with room keys opened as the browser opens them. One
        // file at a time, like authz and files (shared connection limit).
        test: {
          name: 'notes',
          include: ['tests/notes/**/*.test.ts'],
          fileParallelism: false,
          globalSetup: ['tests/database/global-setup.ts'],
          testTimeout: 60_000,
          hookTimeout: 120_000,
        },
      },
      {
        // Recipient-bound secret suites (Phase 9): the real API (one or two instances), PostgreSQL
        // as cm_api and cm_worker, and secrets encrypted by packages/crypto for recipients
        // authenticated as the browser authenticates them. One file at a time (shared connection
        // limit; the concurrency suite holds row locks on purpose).
        test: {
          name: 'secrets',
          include: ['tests/secrets/**/*.test.ts'],
          fileParallelism: false,
          globalSetup: ['tests/database/global-setup.ts'],
          testTimeout: 60_000,
          hookTimeout: 120_000,
        },
      },
      {
        // Policy enforcement matrix (Phase 10, CM-T049): the real API, real sessions with real MFA
        // and step-ups, PostgreSQL as cm_api and the local object storage, every profile control
        // with allowed and denied requests. One file at a time (shared connection limit).
        test: {
          name: 'policy',
          include: ['tests/policy/**/*.test.ts'],
          fileParallelism: false,
          globalSetup: ['tests/database/global-setup.ts'],
          testTimeout: 60_000,
          hookTimeout: 120_000,
        },
      },
      {
        test: {
          name: 'database',
          include: ['tests/database/**/*.test.ts'],
          globalSetup: ['tests/database/global-setup.ts'],
          testTimeout: 60_000,
          hookTimeout: 120_000,
        },
      },
    ],
  },
});
