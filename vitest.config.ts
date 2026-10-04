import { defineConfig } from 'vitest/config';

// Suites, matching docs/security/security-testing-plan.md: unit tests live next to the code,
// integration, security and database suites under tests/. The database suite needs the local
// PostgreSQL container (`pnpm services:up && pnpm db:bootstrap`) or the CI service container;
// it fails instead of skipping when PostgreSQL is unavailable.
export default defineConfig({
  test: {
    environment: 'node',
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
