// `pnpm security:negative-controls`: proves that the security tests are real (Phase 3, extended
// with the vault and cryptography controls of Phase 4 and the room authorization controls of
// Phase 5). `--only=<prefix>` runs a subset, for example `--only=NC-05`.
//
// For each control, one deliberate defect is written into a source file in the working tree, the
// tests that must catch it are run, and the original file is restored immediately afterwards
// (also on Ctrl+C or an error). A control passes only if the tests FAIL with the defect present.
// Finally the same tests run once on the unmodified code and must pass. Nothing is committed:
// each original file is kept in memory and written back on every exit path.
//
// Browser controls (with an `e2e` spec and test title) change the web client: the script rebuilds the static
// export, runs the Playwright test that must catch the defect in Chromium, and at the end rebuilds
// the unmodified export and runs those tests again. Every touched file is compared by SHA-256 with
// its original after the run. `--vitest-only` skips the browser controls.
//
// Requires the database setup of the auth and database suites (pnpm services:up, db:bootstrap), and
// for the browser controls a built API (pnpm build) and the Playwright browsers.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

/** @typedef {{ id: string, defect: string, file: string, edits: [string, string][], tests: string[], e2e?: { spec: string, title: string } }} Control */

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
  // ------------------------------------------------------------------ Phase 4: vault and crypto
  {
    id: 'NC-04-01',
    defect: 'Vault private-key AAD removed (wrapped keys no longer bound to their context)',
    file: 'packages/crypto/src/aead.ts',
    edits: [
      ['          additionalData: aad,', ''],
      [
        '      { name: AES_GCM.name, iv: sealed.iv, additionalData: aad, tagLength: AES_GCM.tagBytes * 8 },',
        '      { name: AES_GCM.name, iv: sealed.iv, tagLength: AES_GCM.tagBytes * 8 },',
      ],
    ],
    tests: ['packages/crypto/src/primitives.test.ts'],
  },
  {
    id: 'NC-04-02',
    defect: 'Fixed AES-GCM nonce (IV reuse under one key)',
    file: 'packages/crypto/src/aead.ts',
    edits: [
      [
        '  return { iv, ciphertext: await aesGcmEncryptWithIv(key, iv, plaintext, aad) };',
        '  iv.fill(0);\n  return { iv, ciphertext: await aesGcmEncryptWithIv(key, iv, plaintext, aad) };',
      ],
      ['  const ciphertext = await guarded(', '  iv.fill(0);\n  const ciphertext = await guarded('],
    ],
    tests: ['packages/crypto/src/primitives.test.ts', 'packages/crypto/src/vault.test.ts'],
  },
  {
    id: 'NC-04-03',
    defect: 'Directory response exposes wrapped private-key data',
    file: 'apps/api/src/vault/service.ts',
    edits: [
      [
        '      fingerprint: identity.fingerprint,',
        "      fingerprint: identity.fingerprint,\n      wrappedEncryptionKey: 'leak',",
      ],
    ],
    tests: ['tests/vault/reset-and-directory.test.ts'],
  },
  {
    id: 'NC-04-04',
    defect: 'Vault ownership bypassed (any ACTIVE vault returned)',
    file: 'apps/api/src/db/vault-store.ts',
    edits: [
      [
        "      const row = await db.userKeyPair.findFirst({ where: { userId, status: 'ACTIVE' }, select: vaultSelect });",
        "      const row = await db.userKeyPair.findFirst({ where: { status: 'ACTIVE', NOT: { userId: `${userId}x` } }, select: vaultSelect });",
      ],
    ],
    tests: ['tests/vault/reset-and-directory.test.ts', 'tests/vault/setup.test.ts'],
  },
  {
    id: 'NC-04-05',
    defect: 'Fingerprint computed over the encryption key only',
    file: 'packages/crypto/src/fingerprint.ts',
    edits: [['  return toHex(await sha256(statement));', '  return toHex(await sha256(encryptionKeySpki));']],
    tests: ['packages/crypto/src/identity.test.ts'],
  },
  {
    id: 'NC-04-06',
    defect: 'Unsupported vault format version accepted (downgrade)',
    file: 'packages/crypto/src/vault-format.ts',
    edits: [
      [
        '  if (wire.vaultVersion !== VAULT_VERSION) throw new CryptoError(CryptoErrorCode.UNSUPPORTED_VAULT_VERSION);',
        '',
      ],
    ],
    tests: ['packages/crypto/src/vault.test.ts'],
  },
  {
    id: 'NC-04-07',
    defect: 'Server accepts a vault re-wrap without verifying its signature',
    file: 'apps/api/src/vault/service.ts',
    edits: [
      [
        '      if (!(await verifyStatement(identity.signingPublicKey, statement, request.signature))) {',
        '      if (statement.length === 0) {',
      ],
    ],
    tests: ['tests/vault/rewrap.test.ts'],
  },
  {
    id: 'NC-04-08',
    defect: 'Argon2id floor and ceiling not enforced',
    file: 'packages/crypto/src/params.ts',
    edits: [
      [
        '  const { floor, ceiling } = VAULT_KDF;',
        '  if (params.memoryKiB !== -1) return true;\n  const { floor, ceiling } = VAULT_KDF;',
      ],
    ],
    tests: ['packages/crypto/src/argon2id.test.ts'],
  },
  {
    id: 'NC-04-09',
    defect: 'Unlocked private keys left extractable',
    file: 'packages/crypto/src/vault.ts',
    edits: [
      [
        '  return openWithKeys(input.record, identity, keys, false);',
        '  return openWithKeys(input.record, identity, keys, true);',
      ],
    ],
    tests: ['packages/crypto/src/vault.test.ts'],
  },
  {
    id: 'NC-04-10',
    defect: 'Canonical JSON without member sorting (RFC 8785 broken)',
    file: 'packages/crypto/src/canonical.ts',
    edits: [['        const names = Object.keys(value).sort();', '        const names = Object.keys(value);']],
    tests: ['packages/crypto/src/canonical.test.ts'],
  },
  {
    id: 'NC-04-11',
    defect: 'RSA-OAEP wrapper accepts values of any size (INV-17)',
    file: 'packages/crypto/src/rsa-oaep.ts',
    edits: [
      ['  if (value.length !== RSA_OAEP.wrappedValueBytes || label.length === 0) {', '  if (label.length === 0) {'],
    ],
    tests: ['packages/crypto/src/rsa-oaep.test.ts'],
  },
  {
    id: 'NC-04-12',
    defect: 'Vault Passphrase persisted in localStorage at unlock',
    file: 'apps/web/src/vault/controller.ts',
    edits: [
      [
        '  async unlock(passphrase: string): Promise<void> {',
        "  async unlock(passphrase: string): Promise<void> {\n    localStorage.setItem('cm-vault-cache', passphrase);",
      ],
    ],
    tests: [],
    e2e: { spec: 'tests/e2e/vault.spec.ts', title: 'setup, lock, unlock and passphrase change' },
  },
  {
    id: 'NC-04-13',
    defect: 'Vault Passphrase sent to the API at setup',
    file: 'apps/web/src/vault/controller.ts',
    edits: [
      [
        "      await this.#post('/vault', vaultRecordToWire(setup.record), vaultCreatedResponseSchema);",
        "      await this.#post('/vault', { ...vaultRecordToWire(setup.record), passphrase }, vaultCreatedResponseSchema);",
      ],
    ],
    tests: [],
    e2e: { spec: 'tests/e2e/vault.spec.ts', title: 'setup, lock, unlock and passphrase change' },
  },
  {
    id: 'NC-04-14',
    defect: 'Inactivity auto-lock disabled',
    file: 'apps/web/src/vault/controller.ts',
    edits: [["    if (performance.now() - this.#lastActivity >= AUTO_LOCK_MS) this.lock('inactivity');", '']],
    tests: [],
    e2e: { spec: 'tests/e2e/vault.spec.ts', title: 'the vault locks after 15 minutes' },
  },
  {
    id: 'NC-04-15',
    defect: "CSP allows native form submission again (form-action 'self', SF-04-01)",
    file: 'apps/web/scripts/csp-lib.mjs',
    edits: [['    "form-action \'none\'",', '    "form-action \'self\'",']],
    tests: ['apps/web/scripts/csp-lib.test.ts'],
  },
  {
    id: 'NC-04-16',
    defect: 'Submit buttons enabled before hydration (SF-04-01)',
    file: 'apps/web/src/components/ui.tsx',
    edits: [
      [
        '      disabled={disabled === true || !hydrated}\n      className="rounded bg-sky-600',
        '      disabled={disabled === true}\n      className="rounded bg-sky-600',
      ],
    ],
    tests: [],
    e2e: { spec: 'tests/e2e/web-shell.spec.ts', title: 'a form submitted before the client runs' },
  },
  {
    id: 'NC-04-17',
    defect: 'A failed background refresh replaces the unlocked vault by an error view (R-04-01)',
    file: 'apps/web/src/vault/controller.ts',
    edits: [["      if (this.#view.kind === 'unlocked') return;\n", '']],
    tests: [],
    e2e: { spec: 'tests/e2e/vault.spec.ts', title: 'a failed background refresh keeps the vault under the auto-lock' },
  },
  // ------------------------------------------------------- Phase 5: room authorization (CM-T029)
  {
    id: 'NC-05-01',
    defect: 'The registry trusts the path and skips the membership check (everyone is OWNER)',
    file: 'apps/api/src/routes/registry.ts',
    edits: [
      [
        '  return rooms.authorize({',
        "  return Promise.resolve({ roomId, membershipId: roomId, role: 'OWNER', room: { keyState: 'ACTIVE', securityProfile: 'STANDARD' }, action, resource: undefined });\n  return rooms.authorize({",
      ],
    ],
    tests: ['tests/authz/room-access.test.ts'],
  },
  {
    id: 'NC-05-02',
    defect: 'The room decision grants access without a membership',
    file: 'packages/shared/src/authorization.ts',
    edits: [
      [
        "  if (membership === null) return deny('NOT_A_MEMBER');",
        "  if (membership === null) return { allowed: true, role: 'VIEWER' };",
      ],
    ],
    tests: ['packages/shared/src/authorization.test.ts'],
  },
  {
    id: 'NC-05-03',
    defect: 'The membership lookup is not scoped to the addressed room (cross-room BOLA)',
    file: 'apps/api/src/db/room-access-store.ts',
    edits: [
      [
        "        where: { roomId, userId, status: 'ACTIVE', room: { status: 'ACTIVE' } },",
        "        where: { userId, status: 'ACTIVE', room: { status: 'ACTIVE' } },",
      ],
    ],
    tests: ['tests/authz/membership-lookup.test.ts'],
  },
  {
    id: 'NC-05-04',
    defect: 'The membership lookup accepts SUSPENDED, REMOVED and LEFT memberships',
    file: 'apps/api/src/db/room-access-store.ts',
    edits: [
      [
        "        where: { roomId, userId, status: 'ACTIVE', room: { status: 'ACTIVE' } },",
        "        where: { roomId, userId, room: { status: 'ACTIVE' } },",
      ],
    ],
    tests: ['tests/authz/membership-lookup.test.ts'],
  },
  {
    id: 'NC-05-05',
    defect: 'PLATFORM_ADMIN is treated as a room ADMIN without a membership',
    file: 'apps/api/src/authorization/rooms.ts',
    edits: [
      [
        '      const record = await deps.store.findActiveMembership(roomId, actor.userId);',
        "      const found = await deps.store.findActiveMembership(roomId, actor.userId);\n      const record = found ?? (actor.user.platformRole === 'PLATFORM_ADMIN' ? { membershipId: roomId, roomId, userId: actor.userId, role: 'ADMIN' as const, status: 'ACTIVE' as const, room: { status: 'ACTIVE' as const, keyState: 'ACTIVE' as const, securityProfile: 'STANDARD' as const } } : null);",
      ],
    ],
    tests: ['tests/authz/room-access.test.ts'],
  },
  {
    id: 'NC-05-06',
    defect: 'Matrix cell widened: an ADMIN may delete the room (AZ-04 is OWNER-only)',
    file: 'packages/shared/src/authorization.ts',
    edits: [
      [
        "  'AZ-04': { title: 'Delete room', rules: row(Y, N, N, N), stepUp: 'always' },",
        "  'AZ-04': { title: 'Delete room', rules: row(Y, Y, N, N), stepUp: 'always' },",
      ],
    ],
    tests: ['tests/security/authz-matrix.test.ts', 'packages/shared/src/authorization.test.ts'],
  },
  {
    id: 'NC-05-07',
    defect: 'Role ceilings checked loosely: one permitted role is enough (an ADMIN can create an ADMIN)',
    file: 'packages/shared/src/authorization.ts',
    edits: [
      [
        '      return touched.length > 0 && touched.every((r) => ceiling.includes(r))',
        '      return touched.length > 0 && touched.some((r) => ceiling.includes(r))',
      ],
    ],
    tests: ['packages/shared/src/authorization.test.ts', 'tests/authz/room-access.test.ts'],
  },
  {
    id: 'NC-05-08',
    defect: 'A room action is accepted on a route without room access (no membership check)',
    file: 'apps/api/src/routes/registry.ts',
    edits: [["    if (info.scope !== 'self' && info.scope !== 'platform') {", "    if (info.scope === 'none') {"]],
    tests: ['apps/api/src/routes/registry.test.ts'],
  },
  {
    id: 'NC-05-09',
    defect: 'A path below /rooms/:roomId may be declared without room access',
    file: 'apps/api/src/routes/registry.ts',
    edits: [
      [
        "  if (NAMES_ROOM.test(route.path) && access.kind !== 'room') {",
        '  if (NAMES_ROOM.test(route.path) && access.kind === undefined) {',
      ],
    ],
    tests: ['apps/api/src/routes/registry.test.ts'],
  },
  {
    id: 'NC-05-10',
    defect: 'Undecodable path parameters become unhandled 500 errors again (R-05-01)',
    file: 'apps/api/src/http/errors.ts',
    edits: [
      ['    if (isParameterDecodingError(err)) {', '    if (isParameterDecodingError(err) && req.path === "") {'],
    ],
    tests: ['tests/security/malformed-requests.test.ts'],
  },
];

/** @param {string[]} files */
const vitest = (files) =>
  spawnSync(process.execPath, ['node_modules/vitest/vitest.mjs', 'run', ...files], { encoding: 'utf8' });

const VITEST_ONLY = process.argv.includes('--vitest-only');
// `--only=NC-05` runs the controls whose ID starts with the prefix, for example one phase's.
const ONLY = process.argv.find((arg) => arg.startsWith('--only='))?.slice('--only='.length);
const controls = CONTROLS.filter(
  (c) => (!VITEST_ONLY || c.e2e === undefined) && (ONLY === undefined || c.id.startsWith(ONLY)),
);
if (controls.length === 0) throw new Error(`No negative control matches ${ONLY ?? 'the options'}`);

/** Rebuilds the static export like `pnpm --filter @ciphermesh/web build` (next build, then the CSP). */
const buildWeb = () => {
  const next = spawnSync(process.execPath, ['node_modules/next/dist/bin/next', 'build'], {
    cwd: 'apps/web',
    encoding: 'utf8',
  });
  if (next.status !== 0) return next.status ?? 1;
  return spawnSync(process.execPath, ['scripts/generate-csp.mjs'], { cwd: 'apps/web', encoding: 'utf8' }).status ?? 1;
};

/** Runs the browser tests with this title in Chromium. @param {{ spec: string, title: string }} e2e */
const playwright = (e2e) =>
  spawnSync(
    process.execPath,
    ['node_modules/@playwright/test/cli.js', 'test', e2e.spec, '--project=chromium', '-g', e2e.title],
    { encoding: 'utf8' },
  );

/** @param {string} file */
const sha256 = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');
/** @type {Map<string, string>} */
const checksums = new Map(controls.map((c) => [c.file, sha256(c.file)]));

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
for (const control of controls) {
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
    if (control.e2e === undefined) {
      results.push({ ...control, caught: vitest(control.tests).status !== 0, note: '' });
    } else if (buildWeb() !== 0) {
      // A defect that does not even build was not caught by a test: it counts as missed.
      results.push({ ...control, caught: false, note: '(build failed)' });
    } else {
      results.push({ ...control, caught: playwright(control.e2e).status !== 0, note: '' });
    }
  } finally {
    writeFileSync(control.file, original);
    originals.delete(control.file);
  }
}

restoreAll();
const changed = [...checksums].filter(([file, digest]) => sha256(file) !== digest).map(([file]) => file);
const baseline = vitest([...new Set(controls.flatMap((c) => c.tests))]);
const e2eTests = [...new Set(controls.flatMap((c) => (c.e2e === undefined ? [] : [JSON.stringify(c.e2e)])))].map(
  (key) => /** @type {{ spec: string, title: string }} */ (JSON.parse(key)),
);
let e2eBaseline = 0;
if (e2eTests.length > 0) {
  // Leave a clean export behind, built from the unmodified sources, and prove the tests pass on it.
  e2eBaseline = buildWeb();
  for (const e2e of e2eTests) if (e2eBaseline === 0) e2eBaseline = playwright(e2e).status ?? 1;
}

console.log('| ID | Deliberate defect | Detected by | Result |');
console.log('|---|---|---|---|');
for (const r of results) {
  const by = r.e2e === undefined ? r.tests.join(', ') : `${r.e2e.spec} "${r.e2e.title}" (Chromium)`;
  console.log(`| ${r.id} | ${r.defect} | ${by} | ${r.caught ? 'CAUGHT (tests failed)' : `MISSED ${r.note}`} |`);
}
console.log(`\nBaseline on unmodified code (Vitest): ${baseline.status === 0 ? 'PASS' : 'FAIL'}`);
if (e2eTests.length > 0) {
  console.log(`Baseline on unmodified code (rebuilt export, Playwright): ${e2eBaseline === 0 ? 'PASS' : 'FAIL'}`);
}
console.log(
  `Sources restored byte for byte (SHA-256, ${String(checksums.size)} files): ${changed.length === 0 ? 'YES' : `NO: ${changed.join(', ')}`}`,
);
const missed = results.filter((r) => !r.caught);
if (missed.length > 0 || baseline.status !== 0 || e2eBaseline !== 0 || changed.length > 0) process.exitCode = 1;
