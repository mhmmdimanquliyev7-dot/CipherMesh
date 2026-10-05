import { fileURLToPath } from 'node:url';
import { ESLint } from 'eslint';
import { beforeAll, describe, expect, it } from 'vitest';

// Proves the ESLint guards for CLAUDE.md section 8 actually fire (CM-T006 acceptance
// criteria). Forbidden code is linted in the context of real files without touching them.
const root = fileURLToPath(new URL('../..', import.meta.url));
let eslint: ESLint;

async function ruleIdsFor(code: string, filePath: string): Promise<string[]> {
  const [result] = await eslint.lintText(code, { filePath: `${root}${filePath}` });
  return (result?.messages ?? []).map((message) => `${message.ruleId ?? 'parse'}: ${message.message}`);
}

// Type-aware linting builds one TypeScript program per project on first use. That takes tens of
// seconds on a busy machine (the generated Prisma client and, since Phase 4, the crypto package
// are part of them), so the programs are built once here and each test's timeout covers only
// its own lint call. The assertions are unchanged.
beforeAll(async () => {
  eslint = new ESLint({ cwd: root });
  for (const file of ['apps/api/src/app.ts', 'apps/web/src/app/page.tsx', 'packages/shared/src/http.ts']) {
    await ruleIdsFor('export const warmUp = 1;', file);
  }
}, 180_000);

describe('ESLint security guards', { timeout: 30_000 }, () => {
  it.each([
    ['eval', 'export const run = (s: string): unknown => eval(s);', 'eval is forbidden'],
    ['new Function', "export const f = new Function('return 1');", 'new Function is forbidden'],
    ['Math.random', 'export const r = Math.random();', 'Math.random is forbidden'],
    [
      'unsafe raw SQL',
      'declare const db: { $queryRawUnsafe(q: string): void };\ndb.$queryRawUnsafe("x");',
      'Unsafe raw SQL',
    ],
    ['scattered process.env', "export const p = process.env['API_PORT'];", 'validated config module'],
    ['WebCrypto outside packages/crypto', 'export const s = globalThis.crypto.subtle;', 'packages/crypto'],
    ['child processes', "import { exec } from 'node:child_process';\nexport { exec };", 'Spawning processes'],
    [
      'Prisma.raw (unparameterized SQL)',
      "declare const Prisma: { raw(q: string): unknown };\nexport const q = Prisma.raw('x');",
      'Prisma.raw builds unparameterized SQL',
    ],
    [
      'the Prisma client outside apps/api/src/db',
      "import { PrismaClient } from './generated/prisma/client';\nexport { PrismaClient };",
      'apps/api/src/db only',
    ],
    ['the pg driver outside apps/api/src/db', "import pg from 'pg';\nexport { pg };", 'apps/api/src/db only'],
  ])('rejects %s in API code', async (_label, code, expected) => {
    const messages = await ruleIdsFor(code, 'apps/api/src/app.ts');
    expect(messages.join('\n')).toContain(expected);
  });

  it('rejects dangerouslySetInnerHTML in the web client', async () => {
    const code = 'export const X = () => <div dangerouslySetInnerHTML={{ __html: "x" }} />;';
    expect((await ruleIdsFor(code, 'apps/web/src/app/page.tsx')).join('\n')).toContain(
      'Render user content as text only',
    );
  });

  it('rejects Node built-ins and server imports in browser code', async () => {
    const node = await ruleIdsFor(
      "import { readFile } from 'node:fs';\nexport { readFile };",
      'apps/web/src/app/page.tsx',
    );
    expect(node.join('\n')).toContain('must not import Node built-ins');
    const server = await ruleIdsFor(
      "import { createApp } from '../../../api/src/app';\nexport { createApp };",
      'apps/web/src/app/page.tsx',
    );
    expect(server.join('\n')).toContain('never import server code');
  });

  it('keeps shared packages browser-compatible', async () => {
    const messages = await ruleIdsFor(
      "import { createHash } from 'node:crypto';\nexport { createHash };",
      'packages/shared/src/http.ts',
    );
    expect(messages.join('\n')).toContain('must not import Node built-ins');
  });
});
