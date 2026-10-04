// ESLint flat config. Encodes the forbidden practices of CLAUDE.md section 8 as errors.
import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';

const forbiddenSyntax = [
  { selector: "CallExpression[callee.name='eval']", message: 'eval is forbidden (CLAUDE.md section 8).' },
  { selector: "NewExpression[callee.name='Function']", message: 'new Function is forbidden (CLAUDE.md section 8).' },
  {
    selector: "MemberExpression[object.name='Math'][property.name='random']",
    message: 'Math.random is forbidden. Use the CSPRNG (CLAUDE.md section 7).',
  },
  {
    selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
    message: 'Render user content as text only (CLAUDE.md section 9).',
  },
  {
    selector: 'MemberExpression[property.name=/^\\$(query|execute)RawUnsafe$/]',
    message: 'Unsafe raw SQL is forbidden. Use parameterized tagged templates.',
  },
];

const processEnv = {
  object: 'process',
  property: 'env',
  message: 'Read configuration through the validated config module only (apps/api/src/config/env.ts).',
};
const webCrypto = {
  property: 'subtle',
  message: 'WebCrypto may only be used inside packages/crypto (no homemade cryptography elsewhere).',
};
const childProcess = [
  { name: 'child_process', message: 'Spawning processes from application code is forbidden.' },
  { name: 'node:child_process', message: 'Spawning processes from application code is forbidden.' },
];

export default tseslint.config(
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/.next/**',
      '**/out/**',
      '**/out-meta/**',
      '**/coverage/**',
      'playwright-report/**',
      'test-results/**',
      'apps/web/next-env.d.ts',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      globals: { ...globals.node },
      parserOptions: {
        projectService: { allowDefaultProject: ['*.mjs'] },
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      'no-restricted-syntax': ['error', ...forbiddenSyntax],
      'no-restricted-properties': ['error', processEnv, webCrypto],
      'no-restricted-imports': ['error', { paths: childProcess }],
      'no-console': 'error',
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true }],
      // Express recognises error handlers by their four parameters, so `_next` must stay.
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    },
  },
  {
    // The two configuration modules are the only places that read the environment.
    files: ['apps/api/src/config/env.ts', 'apps/web/src/config/public-env.ts'],
    rules: { 'no-restricted-properties': ['error', webCrypto] },
  },
  {
    files: ['packages/crypto/src/**'],
    rules: { 'no-restricted-properties': ['error', processEnv] },
  },
  {
    // Browser and isomorphic code: no Node built-ins, no server code.
    files: ['apps/web/src/**', 'packages/*/src/**'],
    ignores: ['**/*.test.ts'],
    languageOptions: { globals: { ...globals.browser } },
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: childProcess,
          patterns: [
            { group: ['node:*'], message: 'Browser-compatible code must not import Node built-ins.' },
            {
              group: ['@ciphermesh/api', '**/apps/api/**', '**/api/src/**'],
              message: 'The web client must never import server code.',
            },
          ],
        },
      ],
    },
  },
  {
    // Build scripts, tooling configuration and tests run in Node outside the application.
    files: ['**/scripts/**', 'tests/**', '*.config.*', '*.mjs', '**/*.test.ts'],
    rules: {
      'no-console': 'off',
      'no-restricted-imports': 'off',
      'no-restricted-properties': ['error', webCrypto],
    },
  },
  {
    files: ['**/*.mjs'],
    ...tseslint.configs.disableTypeChecked,
  },
);
