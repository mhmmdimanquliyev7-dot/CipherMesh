// `pnpm security:negative-controls`: proves that the security tests are real (Phase 3).
//
// For each control, one deliberate defect is written into a source file in the working tree, the
// tests that must catch it are run, and the original file is restored immediately afterwards
// (also on Ctrl+C or an error). A control passes only if the tests FAIL with the defect present.
// Finally the same tests run once on the unmodified code and must pass. Nothing is committed:
// each original file is kept in memory and written back on every exit path.
//
// Requires the database setup of the auth and database suites (pnpm services:up, db:bootstrap).
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';

/** @typedef {{ id: string, defect: string, file: string, edits: [string, string][], tests: string[] }} Control */

/** @type {Control[]} */
const CONTROLS = [
  {
    id: 'NC-03-01',
    defect: 'CSRF same-origin verification removed',
    file: 'apps/api/src/http/same-origin.ts',
    edits: [
      [
        'export function isSameOriginRequest(req: Request, appOrigin: string): boolean {',
        'export function isSameOriginRequest(req: Request, appOrigin: string): boolean {\n  if (appOrigin !== "") return true;',
      ],
    ],
    tests: ['tests/auth/csrf.test.ts'],
  },
  {
    id: 'NC-03-02',
    defect: 'Recovery codes made reusable',
    file: 'apps/api/src/db/auth-store.ts',
    edits: [
      [
        'where: { userId, codeDigest: new Uint8Array(digest), usedAt: null },',
        'where: { userId, codeDigest: new Uint8Array(digest) },',
      ],
    ],
    tests: ['tests/auth/recovery.test.ts'],
  },
  {
    id: 'NC-03-03',
    defect: 'MFA step removed from login',
    file: 'apps/api/src/auth/service.ts',
    edits: [['      if (account.mfaEnabled) {', '      if (account.mfaEnabled && account.id === "") {']],
    tests: ['tests/auth/mfa.test.ts'],
  },
  {
    id: 'NC-03-04',
    defect: 'TOTP time-step replay allowed',
    file: 'apps/api/src/db/auth-store.ts',
    edits: [
      [
        'where: { id: userId, OR: [{ mfaLastUsedStep: null }, { mfaLastUsedStep: { lt: BigInt(step) } }] },',
        'where: { id: userId },',
      ],
    ],
    tests: ['tests/auth/mfa.test.ts'],
  },
  {
    id: 'NC-03-05',
    defect: 'Password field no longer redacted in logs',
    file: 'apps/api/src/logging/redact.ts',
    edits: [
      ["  'password',\n  'passphrase',\n  'vaultPassphrase',", "  'passphrase',\n  'vaultPassphrase',"],
      ["  'password',\n  'passphrase',\n  'secret',", "  'passphrase',\n  'secret',"],
    ],
    tests: ['apps/api/src/logging/redact.test.ts'],
  },
  {
    id: 'NC-03-06',
    defect: 'Route mounted outside the route registry',
    file: 'apps/api/src/app.ts',
    edits: [
      [
        '  app.use(API_PREFIX, router);',
        "  app.get('/api/backdoor', (_req, res) => {\n    res.json({ ok: true });\n  });\n  app.use(API_PREFIX, router);",
      ],
    ],
    tests: ['tests/security/route-inventory.test.ts'],
  },
  {
    id: 'NC-03-07',
    defect: 'Session cookie readable by page scripts (HttpOnly removed)',
    file: 'apps/api/src/auth/cookies.ts',
    edits: [['; Secure; HttpOnly; SameSite=Strict`', '; Secure; SameSite=Strict`']],
    tests: ['apps/api/src/auth/primitives.test.ts', 'tests/auth/login.test.ts'],
  },
  {
    id: 'NC-03-08',
    defect: 'Step-up gate always satisfied',
    file: 'apps/api/src/auth/sessions.ts',
    edits: [
      [
        '  const at = actor.session.stepUpAt;',
        '  if (windowMs > 0) return undefined;\n  const at = actor.session.stepUpAt;',
      ],
    ],
    tests: ['tests/auth/step-up.test.ts'],
  },
  {
    id: 'NC-03-09',
    defect: 'Disabled accounts keep their sessions',
    file: 'apps/api/src/auth/sessions.ts',
    edits: [["  if (record.user.status !== 'ACTIVE') return { failure: 'disabled' };", '']],
    tests: ['tests/auth/session.test.ts'],
  },
  {
    id: 'NC-03-10',
    defect: 'Unknown accounts skip the dummy Argon2id verification (timing enumeration)',
    file: 'apps/api/src/auth/service.ts',
    edits: [['        await withHashing(() => hasher.verifyDummy(normalized));', '']],
    tests: ['tests/auth/login.test.ts'],
  },
];

/** @param {string[]} files */
const vitest = (files) =>
  spawnSync(process.execPath, ['node_modules/vitest/vitest.mjs', 'run', ...files], { encoding: 'utf8' });

/** Original contents of files currently mutated, restored on every exit path. */
/** @type {Map<string, string>} */
const originals = new Map();
const restoreAll = () => {
  for (const [file, content] of originals) writeFileSync(file, content);
  originals.clear();
};
process.on('SIGINT', () => {
  restoreAll();
  process.exit(130);
});
process.on('exit', restoreAll);

const results = [];
for (const control of CONTROLS) {
  const original = readFileSync(control.file, 'utf8');
  originals.set(control.file, original);
  let mutated = original;
  for (const [find, replace] of control.edits) {
    if (mutated.split(find).length !== 2) {
      restoreAll();
      throw new Error(`${control.id}: anchor not found exactly once in ${control.file}`);
    }
    mutated = mutated.replace(find, replace);
  }
  try {
    writeFileSync(control.file, mutated);
    const run = vitest(control.tests);
    results.push({ ...control, caught: run.status !== 0 });
  } finally {
    writeFileSync(control.file, original);
    originals.delete(control.file);
  }
}

const baseline = vitest([...new Set(CONTROLS.flatMap((c) => c.tests))]);

console.log('| ID | Deliberate defect | Detected by | Result |');
console.log('|---|---|---|---|');
for (const r of results) {
  console.log(`| ${r.id} | ${r.defect} | ${r.tests.join(', ')} | ${r.caught ? 'CAUGHT (tests failed)' : 'MISSED'} |`);
}
console.log(`\nBaseline on unmodified code: ${baseline.status === 0 ? 'PASS' : 'FAIL'}`);
const missed = results.filter((r) => !r.caught);
if (missed.length > 0 || baseline.status !== 0) process.exitCode = 1;
