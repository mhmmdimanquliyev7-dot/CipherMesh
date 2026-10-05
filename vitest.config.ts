import { defineConfig } from 'vitest/config';

// Suites, matching docs/security/security-testing-plan.md: unit tests live next to the code,
// integration, security and database suites under tests/. The database suite needs the local
// PostgreSQL container (`pnpm services:up && pnpm db:bootstrap`) or the CI service container;
// it fails instead of skipping when PostgreSQL is unavailable.
export default defineConfig({
  test: {
    environment: 'node',
    // `pnpm test:coverage:crypto`: CLAUDE.md section 10 requires at least 90% of statements and
    // branches for packages/crypto. The run fails below the thresholds. The authorization module
    // and the policy engine join this list when they exist (Phase 5).
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
