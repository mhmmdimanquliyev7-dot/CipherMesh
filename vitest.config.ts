import { defineConfig } from 'vitest/config';

// Three suites, matching docs/security/security-testing-plan.md:
// unit tests live next to the code, integration and security suites under tests/.
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
    ],
  },
});
