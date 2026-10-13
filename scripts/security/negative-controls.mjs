// `pnpm security:negative-controls`: proves that the security tests are real (Phase 3, extended
// with the vault and cryptography controls of Phase 4, the room authorization controls of Phase 5,
// the cryptographic membership controls of Phase 6, the encrypted file controls of Phase 7, the
// encrypted note controls of Phase 8, the recipient-bound secret controls of Phase 9, the
// security policy controls of Phase 10 and the key rotation controls of Phase 11).
// `--only=<prefix>` runs a subset, for example `--only=NC-05`.
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

/**
 * `also` lists further files changed by the same defect. The room checks are repeated on purpose
 * (gate, locked re-check, store query), so a defect that must defeat an object-level test has to
 * defeat every layer at once (Phase 5, CM-T032).
 * @typedef {{ file: string, edits: [string, string][] }} Part
 * @typedef {{ id: string, defect: string, file: string, edits: [string, string][], also?: Part[], tests: string[], e2e?: { spec: string, title: string } }} Control
 */

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
      ['  describeMatrixAction,\n', '  currentPolicy,\n  describeMatrixAction,\n'],
      [
        '  return rooms.authorize({',
        "  return Promise.resolve({ roomId, membershipId: roomId, role: 'OWNER', room: { keyState: 'ACTIVE', securityProfile: 'STANDARD', policyVersion: 1 }, action, resource: undefined, policy: currentPolicy('STANDARD') });\n  return rooms.authorize({",
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
        "      const found = await deps.store.findActiveMembership(roomId, actor.userId);\n      const record = found ?? (actor.user.platformRole === 'PLATFORM_ADMIN' ? { membershipId: roomId, roomId, userId: actor.userId, role: 'ADMIN' as const, status: 'ACTIVE' as const, room: { status: 'ACTIVE' as const, keyState: 'ACTIVE' as const, securityProfile: 'STANDARD' as const, policyVersion: 1 } } : null);",
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
  // ---------------------------------------- Phase 5: rooms and membership administration (CM-T030/031)
  {
    id: 'NC-05-11',
    defect: 'The target member of a membership action is looked up outside the addressed room',
    file: 'apps/api/src/db/room-access-store.ts',
    edits: [
      [
        "        where: { roomId, userId, status: includeSuspended ? { in: ['ACTIVE', 'SUSPENDED'] } : 'ACTIVE' },",
        "        where: { userId, status: includeSuspended ? { in: ['ACTIVE', 'SUSPENDED'] } : 'ACTIVE' },",
      ],
    ],
    tests: ['tests/authz/membership-lookup.test.ts'],
  },
  {
    id: 'NC-05-12',
    defect: 'The membership locked inside a transaction is not limited to the addressed room',
    file: 'apps/api/src/db/room-store.ts',
    edits: [
      [
        "         WHERE room_id = ${roomId}::uuid AND user_id = ${userId}::uuid AND status IN ('ACTIVE', 'SUSPENDED')",
        "         WHERE (room_id = ${roomId}::uuid OR TRUE) AND user_id = ${userId}::uuid AND status IN ('ACTIVE', 'SUSPENDED')",
      ],
    ],
    tests: ['tests/authz/membership-lookup.test.ts'],
  },
  {
    id: 'NC-05-13',
    defect: 'Membership changes skip the re-authorization on locked state (stale gate decision)',
    file: 'apps/api/src/rooms/service.ts',
    edits: [['    reauthorizeRoomAction(events, request, {', '    ((..._args) => undefined)(events, request, {']],
    tests: ['tests/authz/membership-concurrency.test.ts'],
  },
  {
    id: 'NC-05-14',
    defect: 'Ownership validation bypassed: an ADMIN may transfer ownership (AZ-05 is OWNER-only)',
    file: 'packages/shared/src/authorization.ts',
    edits: [
      [
        "  'AZ-05': { title: 'Transfer ownership to an ADMIN', rules: row(targets('ADMIN'), N, N, N), stepUp: 'always' },",
        "  'AZ-05': { title: 'Transfer ownership to an ADMIN', rules: row(targets('ADMIN'), targets('ADMIN'), N, N), stepUp: 'always' },",
      ],
    ],
    tests: ['tests/authz/membership-admin.test.ts'],
  },
  {
    id: 'NC-05-15',
    defect: 'One-OWNER invariant broken: a transfer demotes the OWNER without promoting the target',
    file: 'apps/api/src/db/room-store.ts',
    edits: [
      [
        "        data: { role: 'OWNER', ...grantColumns(grant) },",
        "        data: { role: 'ADMIN', ...grantColumns(grant) },",
      ],
    ],
    tests: ['tests/authz/membership-admin.test.ts'],
  },
  {
    id: 'NC-05-16',
    defect: 'Disabling an account no longer suspends its room memberships (PA-03)',
    file: 'apps/api/src/auth/admin.ts',
    edits: [
      [
        '        const suspended = await rooms.suspendMemberships(userId, actor.userId, now);',
        '        const suspended = [];',
      ],
    ],
    tests: ['tests/authz/account-disable.test.ts'],
  },
  {
    id: 'NC-05-17',
    defect: 'The room list is not limited to the caller memberships (OL-08)',
    file: 'apps/api/src/db/room-store.ts',
    edits: [
      [
        "        where: {\n          userId,\n          status: 'ACTIVE',\n          room: { status: 'ACTIVE' },\n",
        "        where: {\n          status: 'ACTIVE',\n          room: { status: 'ACTIVE' },\n",
      ],
    ],
    tests: ['tests/authz/rooms-lifecycle.test.ts'],
  },
  // ----------------------------------------------------- Phase 5: BOLA and IDOR suite (CM-T032)
  // The room checks repeat on purpose (gate, locked re-check, store query). Each control below
  // removes every layer a request would meet, so the BOLA suite is the test that must catch it.
  {
    id: 'NC-05-18',
    defect:
      'Existence oracle: a target member found in another room is refused differently (403) from an invented one (404)',
    file: 'apps/api/src/authorization/rooms.ts',
    edits: [['  RESOURCE_OUTSIDE_ROOM: 404,', '  RESOURCE_OUTSIDE_ROOM: 403,']],
    also: [
      {
        file: 'apps/api/src/db/room-access-store.ts',
        edits: [
          [
            "        where: { roomId, userId, status: includeSuspended ? { in: ['ACTIVE', 'SUSPENDED'] } : 'ACTIVE' },",
            "        where: { userId, status: includeSuspended ? { in: ['ACTIVE', 'SUSPENDED'] } : 'ACTIVE' },",
          ],
        ],
      },
    ],
    tests: ['tests/authz/bola.test.ts'],
  },
  {
    id: 'NC-05-19',
    defect: 'A target member of another room is accepted and changed (target lookup, lock and room check all unscoped)',
    file: 'apps/api/src/db/room-access-store.ts',
    edits: [
      [
        "        where: { roomId, userId, status: includeSuspended ? { in: ['ACTIVE', 'SUSPENDED'] } : 'ACTIVE' },",
        "        where: { userId, status: includeSuspended ? { in: ['ACTIVE', 'SUSPENDED'] } : 'ACTIVE' },",
      ],
    ],
    also: [
      {
        file: 'apps/api/src/db/room-store.ts',
        edits: [
          [
            "         WHERE room_id = ${roomId}::uuid AND user_id = ${userId}::uuid AND status IN ('ACTIVE', 'SUSPENDED')",
            "         WHERE (room_id = ${roomId}::uuid OR TRUE) AND user_id = ${userId}::uuid AND status IN ('ACTIVE', 'SUSPENDED')",
          ],
        ],
      },
      {
        file: 'packages/shared/src/authorization.ts',
        edits: [["  if (resource.roomId !== input.roomId) return deny('RESOURCE_OUTSIDE_ROOM');", '']],
      },
    ],
    tests: ['tests/authz/bola.test.ts'],
  },
  {
    id: 'NC-05-20',
    defect:
      'A membership in room A authorizes room B (membership lookup, lock, mismatch check and room read all unscoped)',
    file: 'apps/api/src/db/room-access-store.ts',
    edits: [
      [
        "        where: { roomId, userId, status: 'ACTIVE', room: { status: 'ACTIVE' } },",
        "        where: { userId, status: 'ACTIVE', room: { status: 'ACTIVE' } },",
      ],
    ],
    also: [
      {
        file: 'apps/api/src/db/room-store.ts',
        edits: [
          [
            "         WHERE room_id = ${roomId}::uuid AND user_id = ${userId}::uuid AND status IN ('ACTIVE', 'SUSPENDED')",
            "         WHERE (room_id = ${roomId}::uuid OR TRUE) AND user_id = ${userId}::uuid AND status IN ('ACTIVE', 'SUSPENDED')",
          ],
          [
            "        where: { roomId, userId, status: 'ACTIVE', room: { status: 'ACTIVE' } },\n        select: {\n          role: true,\n          room: {",
            "        where: { userId, status: 'ACTIVE', room: { status: 'ACTIVE' } },\n        select: {\n          role: true,\n          room: {",
          ],
        ],
      },
      {
        file: 'packages/shared/src/authorization.ts',
        edits: [
          [
            '  if (membership.roomId !== input.roomId || membership.userId !== input.actorUserId) {',
            '  if (membership.userId !== input.actorUserId) {',
          ],
        ],
      },
    ],
    tests: ['tests/authz/bola.test.ts'],
  },
  {
    id: 'NC-05-21',
    defect: 'PLATFORM_ADMIN is treated as an ADMIN member of every room (gate and locked re-check)',
    file: 'apps/api/src/authorization/rooms.ts',
    edits: [
      [
        '      const record = await deps.store.findActiveMembership(roomId, actor.userId);',
        "      const found = await deps.store.findActiveMembership(roomId, actor.userId);\n      const record = found ?? (actor.user.platformRole === 'PLATFORM_ADMIN' ? { membershipId: roomId, roomId, userId: actor.userId, role: 'ADMIN' as const, status: 'ACTIVE' as const, room: { status: 'ACTIVE' as const, keyState: 'ACTIVE' as const, securityProfile: 'STANDARD' as const, policyVersion: 1 } } : null);",
      ],
    ],
    also: [
      {
        file: 'apps/api/src/rooms/service.ts',
        edits: [
          [
            '    const actorMembership = room === null ? null : await tx.lockMembership(access.roomId, actor.userId);',
            "    const lockedMembership = room === null ? null : await tx.lockMembership(access.roomId, actor.userId);\n    const actorMembership = lockedMembership ?? (room !== null && actor.user.platformRole === 'PLATFORM_ADMIN' ? { membershipId: access.roomId, roomId: access.roomId, userId: actor.userId, role: 'ADMIN' as const, status: 'ACTIVE' as const } : null);",
          ],
        ],
      },
    ],
    tests: ['tests/authz/bola.test.ts'],
  },
  {
    id: 'NC-05-22',
    defect: 'A room route ships without a reviewed BOLA case (the inventory must refuse it)',
    file: 'apps/api/src/routes/rooms.ts',
    edits: [
      [
        "  return [\n    defineRoute({\n      method: 'POST',\n      path: '/rooms',",
        "  return [\n    defineRoute({\n      method: 'GET',\n      path: '/rooms/:roomId/ping',\n      action: 'AZ-01-ROOM-PING',\n      access: { kind: 'room' },\n      params: roomParamsSchema,\n      query: emptyQuerySchema,\n      body: undefined,\n      response: roomDeletedResponseSchema,\n      handler: () => ({ status: 200, body: { status: 'deleting' as const } }),\n    }),\n    defineRoute({\n      method: 'POST',\n      path: '/rooms',",
      ],
    ],
    tests: ['tests/security/bola-inventory.test.ts'],
  },
  // ---------------------------------------------------------------- Phase 6: cryptographic membership
  {
    id: 'NC-06-01',
    defect: 'The browser skips the key-version signature check (a server-made key version is used, T-36)',
    file: 'packages/crypto/src/room-keys.ts',
    edits: [
      [
        '  if (!(await verifyStatementBy(creator, creatorRef, statement, keyVersion.signature))) throw authenticationFailed();',
        '  void statement;',
      ],
    ],
    tests: ['packages/crypto/src/room-keys.test.ts'],
  },
  {
    id: 'NC-06-02',
    defect: 'The browser skips the commitment check (a key that does not match the signed commitment is used, T-29)',
    file: 'packages/crypto/src/room-keys.ts',
    edits: [['    if (!bytesEqual(commitment, keyVersion.commitment)) {', '    if (commitment.length === 0) {']],
    tests: ['packages/crypto/src/room-keys.test.ts', 'tests/authz/room-keys.test.ts'],
  },
  {
    id: 'NC-06-03',
    defect: 'The envelope label no longer names the recipient user and key (envelopes become transferable, T-25)',
    file: 'packages/crypto/src/room-keys.ts',
    edits: [
      [
        '    recipientUserId: recipient.userId,\n    recipientKeyId: recipient.keyId,',
        '    recipientUserId: roomId,\n    recipientKeyId: roomId,',
      ],
    ],
    tests: ['packages/crypto/src/room-keys.test.ts'],
  },
  {
    id: 'NC-06-04',
    defect: 'An invitation without an envelope for the current key version is accepted (PC-07 version check removed)',
    file: 'apps/api/src/rooms/invitations.ts',
    edits: [['            requested.includes(room.currentKeyVersion) &&', '            requested.length > 0 &&']],
    tests: ['tests/authz/invitations.test.ts'],
  },
  {
    id: 'NC-06-05',
    defect: 'An ADMIN grant signed by someone who is not an OWNER confers ADMIN authority (authority chain)',
    file: 'packages/crypto/src/room-keys.ts',
    edits: [
      [
        "  for (const g of valid) if (g.role === 'ADMIN' && owners.has(grantor(g))) admins.add(subject(g));",
        "  for (const g of valid) if (g.role === 'ADMIN') admins.add(subject(g));",
      ],
    ],
    tests: ['packages/crypto/src/room-keys.test.ts'],
  },
  {
    id: 'NC-06-06',
    defect: "Another user can accept someone else's invitation (invitee filter removed from lookup and re-check)",
    file: 'apps/api/src/db/invitation-store.ts',
    edits: [['        where: { id: invitationId, inviteeUserId },', '        where: { id: invitationId },']],
    also: [
      {
        file: 'apps/api/src/rooms/invitations.ts',
        edits: [
          [
            "        if (invitation === null || invitation.inviteeUserId !== actor.userId) throw notFound();\n        if (invitation.status !== 'PENDING') throw notOpen();",
            "        if (invitation === null) throw notFound();\n        if (invitation.status !== 'PENDING') throw notOpen();",
          ],
        ],
      },
    ],
    tests: ['tests/authz/invitations.test.ts'],
  },
  {
    id: 'NC-06-07',
    defect:
      "Invitation acceptance no longer locks and re-checks the invitee's user row (an account disable can miss it)",
    file: 'apps/api/src/rooms/invitations.ts',
    edits: [
      [
        '        if (!(await tx.lockActiveUser(actor.userId))) throw unauthenticated();',
        '        void unauthenticated;',
      ],
    ],
    tests: ['tests/authz/invitation-concurrency.test.ts'],
  },
  {
    id: 'NC-06-08',
    defect: 'The API stores a new room without verifying the signed genesis and key-version statements',
    file: 'apps/api/src/rooms/service.ts',
    edits: [
      [
        '        creator === undefined ||\n        !(await verifyRoomCreation(creator, {',
        '        creator === undefined ||\n        !(await Promise.resolve(true) || await verifyRoomCreation(creator, {',
      ],
    ],
    tests: ['tests/authz/room-keys.test.ts'],
  },
  {
    id: 'NC-06-09',
    defect: 'The Safety Code is derived from the public, server-supplied commitment instead of the key material',
    file: 'packages/crypto/src/room-keys.ts',
    edits: [
      [
        '    return safetyCodeFromBits(opened.keyVersion, rsc);',
        '    return safetyCodeFromBits(opened.keyVersion, opened.commitment);',
      ],
    ],
    tests: ['packages/crypto/src/room-keys.test.ts'],
  },
  {
    id: 'NC-06-10',
    defect: 'The browser keeps the Room Safety Code in localStorage (INV-18)',
    file: 'apps/web/src/rooms/key-panel.tsx',
    edits: [
      [
        '  const rows = [code.words.slice(0, 3), code.words.slice(3, 6)];',
        "  localStorage.setItem('cm-last-safety-code', code.words.join(' '));\n  const rows = [code.words.slice(0, 3), code.words.slice(3, 6)];",
      ],
    ],
    tests: [],
    e2e: { spec: 'tests/e2e/room-keys.spec.ts', title: 'kept in the browser' },
  },
  // ------------------------------------------------------------------- Phase 7: encrypted files
  {
    id: 'NC-07-01',
    defect: 'The browser releases decrypted content that does not match the manifest size and plaintext hash',
    file: 'packages/crypto/src/files.ts',
    edits: [
      [
        '      if (plaintext.length !== manifest.size || !bytesEqual(await sha256(plaintext), manifest.sha256)) {',
        '      if (plaintext.length < 0) {',
      ],
    ],
    tests: ['packages/crypto/src/files.test.ts'],
  },
  {
    id: 'NC-07-02',
    defect: 'File content is no longer bound to its file ID in the AES-GCM AAD (cm.file.content)',
    file: 'packages/crypto/src/files.ts',
    edits: [
      [
        "  // The contexts validate the identifiers; build them before any key exists.\n  const contentAad = contextBytes('cm.file.content', { roomId, fileId });",
        "  // The contexts validate the identifiers; build them before any key exists.\n  const contentAad = contextBytes('cm.file.content', { roomId, fileId: roomId });",
      ],
      [
        "  const { roomId, fileId, keyVersion } = record;\n  const contentAad = contextBytes('cm.file.content', { roomId, fileId });",
        "  const { roomId, fileId, keyVersion } = record;\n  const contentAad = contextBytes('cm.file.content', { roomId, fileId: roomId });",
      ],
    ],
    tests: ['packages/crypto/src/files.test.ts'],
  },
  {
    id: 'NC-07-03',
    defect: 'A wrapped FEK is no longer bound to its file (cm.dek.wrap names the room instead of the file)',
    file: 'packages/crypto/src/files.ts',
    edits: [
      [
        "  return contextBytes('cm.dek.wrap', { roomId, keyVersion, itemType: 'file', itemId: fileId, revision: 0 });",
        "  return contextBytes('cm.dek.wrap', { roomId, keyVersion, itemType: 'file', itemId: roomId, revision: 0 });",
      ],
    ],
    tests: ['packages/crypto/src/files.test.ts'],
  },
  {
    id: 'NC-07-04',
    defect: 'Key material and download URLs of a file are served without the room and membership filter (BOLA)',
    file: 'apps/api/src/db/file-store.ts',
    edits: [
      [
        '        where: { id: fileId, ...readable(roomId, userId, now) },',
        "        where: { id: fileId, status: 'AVAILABLE' },",
      ],
    ],
    tests: ['tests/authz/bola.test.ts'],
  },
  {
    id: 'NC-07-05',
    defect: 'An upload is completed without asking storage whether the ciphertext arrived with the announced size',
    file: 'apps/api/src/files/service.ts',
    edits: [
      ['        stored = await storage.head(file.objectKey);', '        stored = { size: file.ciphertextSize };'],
    ],
    tests: ['tests/files/files-upload.test.ts'],
  },
  {
    id: 'NC-07-06',
    defect: 'Presigned upload URLs no longer sign the content length (storage accepts any size)',
    file: 'apps/api/src/storage/object-store.ts',
    edits: [
      [
        '      aws: { signQuery: true, allHeaders: true, datetime: amzDate(now) },',
        '      aws: { signQuery: true, allHeaders: false, datetime: amzDate(now) },',
      ],
    ],
    tests: ['tests/files/files-upload.test.ts'],
  },
  {
    id: 'NC-07-07',
    defect:
      'The upload request accepts unknown fields (a plaintext name, type or caller identity) instead of refusing them',
    file: 'packages/validation/src/files.ts',
    edits: [
      ['export const fileUploadRequestSchema = z.strictObject({', 'export const fileUploadRequestSchema = z.object({'],
    ],
    tests: ['tests/files/files-upload.test.ts'],
  },
  {
    id: 'NC-07-08',
    defect: 'VIEWERs in RESTRICTED rooms obtain file key material and download URLs (PC-12 removed)',
    file: 'apps/api/src/files/service.ts',
    edits: [
      [
        "    return access.role !== 'VIEWER' || access.policy.viewerMayObtainFileKeys;",
        "    return access.role !== 'VIEWER' || access.policy.viewerMayObtainFileKeys || true;",
      ],
    ],
    tests: ['tests/files/files-access.test.ts'],
  },
  {
    id: 'NC-07-09',
    defect: 'Expired files are still served until the worker runs (INV-14, expiry no longer checked at read time)',
    file: 'apps/api/src/db/file-store.ts',
    edits: [
      [
        '  OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],',
        '  OR: [{ expiresAt: null }, { expiresAt: { not: now } }],',
      ],
    ],
    tests: ['tests/files/files-access.test.ts'],
  },
  {
    id: 'NC-07-10',
    defect: 'The browser keeps decrypted file content in sessionStorage',
    file: 'apps/web/src/rooms/files.ts',
    edits: [
      [
        '  return { opened, bytes: await opened.decrypt(ciphertext) };',
        "  const plain = await opened.decrypt(ciphertext);\n  sessionStorage.setItem('cm-last-file', new TextDecoder().decode(plain.subarray(0, 256)));\n  return { opened, bytes: plain };",
      ],
    ],
    tests: [],
    e2e: { spec: 'tests/e2e/files.spec.ts', title: 'another member downloads the identical bytes' },
  },
  // ------------------------------------------------------------------- Phase 8: encrypted notes
  {
    id: 'NC-08-01',
    defect: 'Note content is no longer bound to its revision in the AES-GCM AAD (cm.note.content)',
    file: 'packages/crypto/src/notes.ts',
    edits: [
      [
        "  return contextBytes('cm.note.content', { roomId, noteId, revision });",
        "  return contextBytes('cm.note.content', { roomId, noteId, revision: revision > 0 ? 1 : 1 });",
      ],
    ],
    tests: ['packages/crypto/src/notes.test.ts'],
  },
  {
    id: 'NC-08-02',
    defect: 'A wrapped NEK uses the wrong wrapping context (cm.dek.wrap with itemType file instead of note)',
    file: 'packages/crypto/src/notes.ts',
    edits: [
      [
        "  return contextBytes('cm.dek.wrap', { roomId, keyVersion, itemType: 'note', itemId: noteId, revision });",
        "  return contextBytes('cm.dek.wrap', { roomId, keyVersion, itemType: 'file', itemId: noteId, revision });",
      ],
    ],
    tests: ['packages/crypto/src/notes.test.ts'],
  },
  {
    id: 'NC-08-03',
    defect: 'The browser accepts an authenticated note document that is not the canonical version-1 serialization',
    file: 'packages/crypto/src/notes.ts',
    edits: [['  if (!same) throw integrityFailed();', '  if (!same && same) throw integrityFailed();']],
    tests: ['packages/crypto/src/notes.test.ts'],
  },
  {
    id: 'NC-08-04',
    defect: 'A stale save silently overwrites a newer revision (no optimistic concurrency: last writer wins)',
    file: 'apps/api/src/notes/service.ts',
    edits: [
      [
        '        if (locked.revision !== input.expectedRevision) throw revisionConflict();\n',
        '        input = { ...input, expectedRevision: locked.revision };\n',
      ],
    ],
    tests: ['tests/notes/notes-lifecycle.test.ts'],
  },
  {
    id: 'NC-08-05',
    defect: 'One note is served without the room and membership filter (BOLA)',
    file: 'apps/api/src/db/note-store.ts',
    edits: [
      [
        '        where: { id: noteId, ...readable(roomId, userId, now) },',
        '        where: { id: noteId, deletedAt: null },',
      ],
    ],
    tests: ['tests/authz/bola.test.ts'],
  },
  {
    id: 'NC-08-06',
    defect: 'A note update is authorized as a read (AZ-20 instead of AZ-21): VIEWERs and other members may edit',
    file: 'apps/api/src/routes/notes.ts',
    edits: [
      [
        "      action: 'AZ-21-NOTE-UPDATE',\n      access: { kind: 'room', resource: noteResource },",
        "      action: 'AZ-20-NOTE-UPDATE',\n      access: { kind: 'room' },",
      ],
    ],
    also: [
      {
        file: 'apps/api/src/notes/service.ts',
        edits: [
          [
            "lockAndReauthorize(tx, actor, access.roomId, meta, 'AZ-21', async () => {",
            "lockAndReauthorize(tx, actor, access.roomId, meta, 'AZ-20', async () => {",
          ],
        ],
      },
    ],
    tests: ['tests/notes/notes-access.test.ts'],
  },
  {
    id: 'NC-08-07',
    defect: 'Note updates are accepted while the room is REKEY_REQUIRED (INV-07, PC-16)',
    file: 'apps/api/src/notes/service.ts',
    edits: [
      [
        "        }\n        if (room.keyState !== 'ACTIVE') throw rekeyRequired();\n        if (input.keyVersion !== room.currentKeyVersion) throw keyVersionStale();\n        if (locked.revision",
        '        }\n        if (input.keyVersion !== room.currentKeyVersion) throw keyVersionStale();\n        if (locked.revision',
      ],
    ],
    tests: ['tests/notes/notes-access.test.ts'],
  },
  {
    id: 'NC-08-08',
    defect: 'Expired notes are still served until the worker runs (INV-14, expiry no longer checked at read time)',
    file: 'apps/api/src/db/note-store.ts',
    edits: [
      [
        '  OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],',
        '  OR: [{ expiresAt: null }, { expiresAt: { not: now } }],',
      ],
    ],
    tests: ['tests/notes/notes-lifecycle.test.ts'],
  },
  {
    id: 'NC-08-09',
    defect: 'Note bodies are rendered as HTML (unsafe rendering of untrusted text, T-12)',
    file: 'apps/web/src/rooms/note-panel.tsx',
    edits: [
      [
        '                            data-testid="note-view-body"\n                          >\n                            {entry.opened.body === \'\' ? (\n                              <span className="text-slate-500">(empty)</span>\n                            ) : (\n                              entry.opened.body\n                            )}\n                          </div>',
        '                            data-testid="note-view-body"\n                            dangerouslySetInnerHTML={{ __html: entry.opened.body }}\n                          />',
      ],
    ],
    tests: [],
    e2e: { spec: 'tests/e2e/notes.spec.ts', title: 'XSS payloads in a note render as text' },
  },
  {
    id: 'NC-08-10',
    defect: 'The browser keeps decrypted note bodies in localStorage',
    file: 'apps/web/src/rooms/notes.ts',
    edits: [
      [
        '    return { view, opened: await open(roomId, view), ...flag };',
        '    const opened = await open(roomId, view);\n    localStorage.setItem(`cm-note-${view.id}`, opened.body);\n    return { view, opened, ...flag };',
      ],
    ],
    tests: [],
    e2e: { spec: 'tests/e2e/notes.spec.ts', title: 'is read by another member' },
  },
  // ------------------------------------------------------------ Phase 9: recipient-bound secrets
  {
    id: 'NC-09-01',
    defect: 'The SEK wrap label (cm.secret.sek-wrap) no longer binds the recipient key',
    file: 'packages/crypto/src/secrets.ts',
    edits: [['    recipientKeyId: keyId,\n', '    recipientKeyId: userId,\n']],
    tests: ['packages/crypto/src/secrets.test.ts'],
  },
  {
    id: 'NC-09-02',
    defect: 'The secret payload is no longer bound to its secret ID in the AES-GCM AAD (cm.secret.payload)',
    file: 'packages/crypto/src/secrets.ts',
    edits: [
      [
        "  return contextBytes('cm.secret.payload', { roomId, secretId });",
        "  return contextBytes('cm.secret.payload', { roomId, secretId: roomId });",
      ],
    ],
    tests: ['packages/crypto/src/secrets.test.ts'],
  },
  {
    id: 'NC-09-03',
    defect: 'A secret can be encrypted for a recipient key that was never authenticated against the room statements',
    file: 'packages/crypto/src/secrets.ts',
    edits: [
      [
        '  if (!authenticated.has(recipient) || !isSecretText(input.text)) throw invalidInput();',
        '  if (!isSecretText(input.text)) throw invalidInput();',
      ],
    ],
    tests: ['packages/crypto/src/secrets.test.ts'],
  },
  {
    id: 'NC-09-04',
    defect: 'Recipient authentication accepts any self-consistent identity the server names (key substitution, T-25)',
    file: 'packages/crypto/src/room-keys.ts',
    edits: [
      [
        '  if (!verified.isKeyHolder({ userId: identity.userId, keyId: identity.keyId })) throw authenticationFailed();\n',
        '',
      ],
    ],
    tests: ['packages/crypto/src/secrets.test.ts'],
  },
  {
    id: 'NC-09-05',
    defect: 'A burn-after-reading reveal no longer destroys the secret: it can be revealed again (INV-13)',
    file: 'apps/api/src/db/secret-store.ts',
    edits: [
      [
        `          status = CASE WHEN s.burn_after_reading THEN 'REVEALED'::"SecretStatus" ELSE s.status END,
          revealed_at = COALESCE(s.revealed_at, \${now}),
          destroyed_at = CASE WHEN s.burn_after_reading THEN \${now} ELSE s.destroyed_at END,
          wrapped_sek = CASE WHEN s.burn_after_reading THEN NULL ELSE s.wrapped_sek END,
          payload_iv = CASE WHEN s.burn_after_reading THEN NULL ELSE s.payload_iv END,
          payload_ciphertext = CASE WHEN s.burn_after_reading THEN NULL ELSE s.payload_ciphertext END`,
        `          status = s.status,
          revealed_at = CASE WHEN s.burn_after_reading THEN s.revealed_at ELSE COALESCE(s.revealed_at, \${now}) END`,
      ],
    ],
    tests: ['tests/secrets/secrets-lifecycle.test.ts'],
  },
  {
    id: 'NC-09-06',
    defect:
      'The reveal reads the secret without locks and checks its state in application memory (double release race)',
    file: 'apps/api/src/secrets/service.ts',
    edits: [
      [
        `        if (!(await tx.lockUploader(actor.userId))) throw notFound();
        let target: LockedSecret | null = null;
        await lockAndReauthorize(tx, actor, access.roomId, meta, 'AZ-24', async () => {`,
        `        let target: LockedSecret | null = null;
        await (async (_t: unknown, _a: unknown, _r: unknown, _m: unknown, _x: unknown, load: () => Promise<unknown>) => {
          await load();
        })(tx, actor, access.roomId, meta, 'AZ-24', async () => {`,
      ],
    ],
    also: [
      {
        file: 'apps/api/src/db/secret-store.ts',
        edits: [
          [
            '::uuid AND s.recipient_user_id = ${userId}::uuid\n           FOR UPDATE OF s`;',
            '::uuid AND s.recipient_user_id = ${userId}::uuid`;',
          ],
          ["             AND status = 'ACTIVE' AND expires_at > ${now}\n", '             AND expires_at > ${now}\n'],
          [
            "WHERE s.id = r.id AND s.status = 'ACTIVE' AND s.expires_at > ${now}",
            'WHERE s.id = r.id AND s.expires_at > ${now}',
          ],
        ],
      },
    ],
    tests: ['tests/secrets/secrets-concurrency.test.ts'],
  },
  {
    id: 'NC-09-07',
    defect: 'Expiry is no longer checked at the moment of the reveal (INV-14): an expired secret is released',
    file: 'apps/api/src/secrets/service.ts',
    edits: [["    if (secret.expiresAt.getTime() <= now.getTime()) return 'EXPIRED';\n", '']],
    also: [
      {
        file: 'apps/api/src/db/secret-store.ts',
        edits: [
          ["             AND status = 'ACTIVE' AND expires_at > ${now}\n", "             AND status = 'ACTIVE'\n"],
          [
            "WHERE s.id = r.id AND s.status = 'ACTIVE' AND s.expires_at > ${now}",
            "WHERE s.id = r.id AND s.status = 'ACTIVE'",
          ],
        ],
      },
    ],
    tests: ['tests/secrets/secrets-lifecycle.test.ts'],
  },
  {
    id: 'NC-09-08',
    defect: 'Any member may reveal a secret addressed to someone else (recipient rule removed at every layer, OL-06)',
    file: 'apps/api/src/routes/secrets.ts',
    edits: [
      [
        "      action: 'AZ-24-SECRET-REVEAL',\n      access: { kind: 'room', requires: { sensitive: 'SECRET_REVEAL' }, resource: recipientResource },",
        "      action: 'AZ-32-SECRET-REVEAL',\n      access: { kind: 'room', requires: { sensitive: 'SECRET_REVEAL' } },",
      ],
    ],
    also: [
      {
        file: 'apps/api/src/secrets/service.ts',
        edits: [["meta, 'AZ-24', async () => {", "meta, 'AZ-32', async () => {"]],
      },
      {
        file: 'apps/api/src/db/secret-store.ts',
        edits: [
          [' AND s.recipient_user_id = ${userId}::uuid\n', '\n'],
          ['             AND recipient_user_id = ${recipientUserId}::uuid\n', ''],
        ],
      },
    ],
    tests: ['tests/secrets/secrets-lifecycle.test.ts'],
  },
  {
    id: 'NC-09-09',
    defect: 'Secret revocation is authorized for every member (AZ-25 own and deny cells bypassed)',
    file: 'apps/api/src/routes/secrets.ts',
    edits: [
      [
        "      action: 'AZ-25-SECRET-REVOKE',\n      access: { kind: 'room', resource: senderResource },",
        "      action: 'AZ-32-SECRET-REVOKE',\n      access: { kind: 'room' },",
      ],
    ],
    also: [
      {
        file: 'apps/api/src/secrets/service.ts',
        edits: [["meta, 'AZ-25', async () => {", "meta, 'AZ-32', async () => {"]],
      },
    ],
    tests: ['tests/secrets/secrets-lifecycle.test.ts'],
  },
  {
    id: 'NC-09-10',
    defect: 'The browser reveals waiting secrets automatically when the list loads (no explicit action)',
    file: 'apps/web/src/rooms/secrets.ts',
    edits: [
      [
        '  return { secrets: page.secrets, nextCursor: page.nextCursor };',
        "  for (const s of page.secrets) if (s.status === 'ACTIVE') await revealSecret(roomId, s).catch(() => undefined);\n  return { secrets: page.secrets, nextCursor: page.nextCursor };",
      ],
    ],
    tests: [],
    e2e: { spec: 'tests/e2e/secrets.spec.ts', title: 'revealed once on an explicit click' },
  },
  {
    id: 'NC-09-11',
    defect: 'The browser keeps revealed secret text in sessionStorage',
    file: 'apps/web/src/rooms/secrets.ts',
    edits: [
      [
        '    return { secret: response.secret, text: opened.text };',
        '    sessionStorage.setItem(`cm-secret-${view.id}`, opened.text);\n    return { secret: response.secret, text: opened.text };',
      ],
    ],
    tests: [],
    e2e: { spec: 'tests/e2e/secrets.spec.ts', title: 'revealed once on an explicit click' },
  },
  // ------------------------------------------------- Phase 10: security policies (CM-T046 to CM-T049)
  {
    id: 'NC-10-01',
    defect: 'The room gate skips the profile access gates PC-01 and PC-02 (session facts replaced)',
    file: 'apps/api/src/authorization/rooms.ts',
    edits: [
      [
        '      const policy = enforceRoomAccess(deps.events, policyRequest, actor, record.room, request.now);',
        '      const policy = enforceRoomAccess(deps.events, policyRequest, { ...actor, session: { ...actor.session, mfaVerifiedAt: request.now, authenticatedAt: request.now } }, record.room, request.now);',
      ],
    ],
    tests: ['tests/policy/policy-matrix.test.ts'],
  },
  {
    id: 'NC-10-02',
    defect:
      "The profile change trusts the client's claim of the current profile (stale check removed, direction from the request)",
    file: 'apps/api/src/rooms/service.ts',
    edits: [
      [
        '        if (room.securityProfile !== input.expectedProfile) {',
        "        if ((room.securityProfile as string) === 'NEVER') {",
      ],
      [
        '        const change = profileChangeDirection(from, to);',
        '        const change = profileChangeDirection(currentPolicy(input.expectedProfile), to);',
      ],
      [
        '        const decision = decideProfileChange(from, to, actor.session, now);',
        '        const decision = decideProfileChange(currentPolicy(input.expectedProfile), to, actor.session, now);',
      ],
    ],
    tests: ['tests/policy/profile-change.test.ts'],
  },
  {
    id: 'NC-10-03',
    defect: 'PC-03 removed: sensitive operations in RESTRICTED rooms need no step-up (gate and locked re-check)',
    file: 'apps/api/src/authorization/rooms.ts',
    edits: [
      [
        '      if (request.sensitive !== undefined) {',
        "      if (request.sensitive !== undefined && actor.userId === '') {",
      ],
    ],
    also: [
      {
        file: 'apps/api/src/authorization/policy.ts',
        edits: [
          [
            '  if (sensitive) enforceSensitiveOperation(events, request, actor, policy, now);',
            "  if (sensitive && actor.userId === '') enforceSensitiveOperation(events, request, actor, policy, now);",
          ],
        ],
      },
    ],
    tests: ['tests/policy/policy-matrix.test.ts'],
  },
  {
    id: 'NC-10-04',
    defect: 'An expired step-up is accepted (the window of PC-03 and of the downgrade rule is not checked)',
    file: 'packages/shared/src/policy.ts',
    edits: [
      [
        '  return stepUpAt !== null && stepUpAt.getTime() <= now.getTime() && now.getTime() - stepUpAt.getTime() <= windowMs;',
        '  return stepUpAt !== null && stepUpAt.getTime() <= now.getTime() && windowMs > 0;',
      ],
    ],
    tests: ['tests/policy/policy-matrix.test.ts', 'tests/policy/profile-change.test.ts'],
  },
  {
    id: 'NC-10-05',
    defect: 'A profile downgrade needs no step-up within 5 minutes',
    file: 'packages/shared/src/policy.ts',
    edits: [
      [
        "    case 'DOWNGRADE':\n      return stepUpIsRecent(session.stepUpAt, PROFILE_CHANGE_RULES.downgradeStepUpMs, now)",
        "    case 'DOWNGRADE':\n      return stepUpIsRecent(session.stepUpAt, PROFILE_CHANGE_RULES.downgradeStepUpMs, now) || now.getTime() > 0",
      ],
    ],
    tests: ['tests/policy/profile-change.test.ts'],
  },
  {
    id: 'NC-10-06',
    defect: 'An upgrade does not shorten the expiry of existing files and notes (PC-08 clamping removed)',
    file: 'apps/api/src/db/policy-store.ts',
    edits: [['      if (contentMax !== null) {', '      if (contentMax !== null && contentMax < 0) {']],
    tests: ['tests/policy/profile-change.test.ts'],
  },
  {
    id: 'NC-10-07',
    defect: 'An unsupported stored policy version falls back to version 1 instead of failing closed',
    file: 'packages/shared/src/policy.ts',
    edits: [
      [
        '  return Object.hasOwn(CATALOGUE, key) ? CATALOGUE[key]?.[profile] : undefined;',
        "  return Object.hasOwn(CATALOGUE, key) ? CATALOGUE[key]?.[profile] : CATALOGUE['1']?.[profile];",
      ],
    ],
    tests: ['tests/policy/policy-matrix.test.ts'],
  },
  {
    id: 'NC-10-08',
    defect:
      'The locked re-check ignores the profile, so a change that commits first does not govern a waiting write (TOCTOU)',
    file: 'apps/api/src/rooms/service.ts',
    edits: [
      [
        '    const policy = reapplyRoomPolicy(events, { ...request, action }, actor, room, now, options.sensitive === true);',
        '    const policy = currentPolicy(room.securityProfile);',
      ],
    ],
    tests: ['tests/policy/profile-change.test.ts'],
  },
  {
    id: 'NC-10-09',
    defect: 'An upgrade keeps open invitations that break the new rules (PC-04, PC-05, PC-07 revocation removed)',
    file: 'apps/api/src/db/policy-store.ts',
    edits: [
      [
        '      const revokedIds = breaking.map((row) => row.id);',
        '      const revokedIds = breaking.map((row) => row.id).slice(0, 0);',
      ],
    ],
    tests: ['tests/policy/profile-change.test.ts'],
  },
  {
    id: 'NC-10-10',
    defect: 'An upgrade to RESTRICTED keeps re-readable secrets (mandatory burn not applied to existing secrets)',
    file: 'apps/api/src/db/policy-store.ts',
    edits: [
      [
        '      const secretsRevoked = to.secrets.burnMandatory',
        '      const secretsRevoked = to.secrets.burnMandatory && to.rank < 0',
      ],
    ],
    tests: ['tests/policy/profile-change.test.ts'],
  },
  {
    id: 'NC-10-11',
    defect: 'The FULL audit level records no envelope fetches or member-list views (PC-13)',
    file: 'apps/api/src/rooms/keys.ts',
    edits: [
      [
        "      if (auditLevelIncludes(access.policy.auditLevel, 'FULL')) {",
        "      if (auditLevelIncludes(access.policy.auditLevel, 'FULL') && access.roomId === '') {",
      ],
    ],
    also: [
      {
        file: 'apps/api/src/rooms/service.ts',
        edits: [
          [
            "      if (auditLevelIncludes(access.policy.auditLevel, 'FULL')) {",
            "      if (auditLevelIncludes(access.policy.auditLevel, 'FULL') && access.roomId === '') {",
          ],
        ],
      },
    ],
    tests: ['tests/policy/policy-matrix.test.ts'],
  },
  {
    id: 'NC-10-12',
    defect: 'The download-URL route forgets its PC-03 declaration',
    file: 'apps/api/src/routes/files.ts',
    edits: [
      [
        "      access: { kind: 'room', requires: { sensitive: 'FILE_DOWNLOAD_URL' } },",
        "      access: { kind: 'room' },",
      ],
    ],
    tests: ['tests/security/route-inventory.test.ts', 'tests/policy/policy-matrix.test.ts'],
  },
  // Phase 11 (CM-T050 to CM-T053): the rekey state machine, re-sharing, the identity procedure and
  // the engine fix SF-11-01. Defects that the API repeats in the database (staleness, the grant
  // history) are written into both layers, because each layer alone is caught by the other.
  {
    id: 'NC-11-01',
    defect: 'Any OWNER or ADMIN may finalize another member’s rekey operation (OL-13)',
    file: 'apps/api/src/rooms/rekey.ts',
    edits: [
      [
        '          if (operation.startedById !== actor.userId) {\n            throw notStarter(',
        "          if (operation.startedById !== actor.userId && actor.userId === '') {\n            throw notStarter(",
      ],
    ],
    tests: ['tests/rekey/rekey-lifecycle.test.ts'],
  },
  {
    id: 'NC-11-02',
    defect: 'Any ADMIN may cancel the OWNER’s rekey operation (OL-13)',
    file: 'apps/api/src/rooms/rekey.ts',
    edits: [
      [
        "        if (operation.startedById !== actor.userId && member.role !== 'OWNER') {",
        "        if (operation.startedById !== actor.userId && member.role !== 'OWNER' && member.role !== 'ADMIN') {",
      ],
    ],
    tests: ['tests/rekey/rekey-lifecycle.test.ts'],
  },
  {
    id: 'NC-11-03',
    defect: 'The key-version statement signature is not checked at finalize (T-36)',
    file: 'apps/api/src/rooms/rekey.ts',
    edits: [['          if (!statementOk) {', '          if (!statementOk && statementOk) {']],
    tests: ['tests/rekey/rekey-lifecycle.test.ts'],
  },
  {
    id: 'NC-11-04',
    defect: 'The recipient snapshot includes removed and departed members (T-21)',
    file: 'apps/api/src/db/rekey-store.ts',
    edits: [
      [
        "        where: { roomId, status: 'ACTIVE', user: { status: 'ACTIVE' } },",
        "        where: { roomId, status: { in: ['ACTIVE', 'REMOVED', 'LEFT'] }, user: { status: 'ACTIVE' } },",
      ],
    ],
    tests: ['tests/rekey/rekey-lifecycle.test.ts'],
  },
  {
    id: 'NC-11-05',
    defect: 'A membership change no longer makes a pending rekey STALE (API and database trigger)',
    file: 'apps/api/src/db/room-store.ts',
    edits: [
      [
        "       WHERE room_id = ${roomId}::uuid AND status = 'PENDING'\n      RETURNING id::text AS id, mode::text AS mode`;",
        "       WHERE room_id = ${roomId}::uuid AND status = 'PENDING' AND false\n      RETURNING id::text AS id, mode::text AS mode`;",
      ],
    ],
    also: [
      {
        file: 'prisma/migrations/20261011000000_key_rotation/migration.sql',
        edits: [
          [
            "     WHERE room_id = NEW.id AND status = 'PENDING';\n    IF NEW.key_state = 'REKEYING' THEN",
            "     WHERE room_id = NEW.id AND status = 'PENDING' AND false;\n    IF NEW.key_state = 'REKEYING' THEN",
          ],
        ],
      },
    ],
    tests: ['tests/rekey/rekey-lifecycle.test.ts'],
  },
  {
    id: 'NC-11-06',
    defect: 'An expired lease is still accepted at finalize (ADR-013 step 6)',
    file: 'apps/api/src/rooms/rekey.ts',
    edits: [
      [
        "          if (operation.leaseExpiresAt <= now) {\n            return { kind: 'closed', closed: await close(tx, room, operation, 'ABANDONED', 'LEASE_EXPIRED', now) };",
        "          if (operation.leaseExpiresAt <= now && false) {\n            return { kind: 'closed', closed: await close(tx, room, operation, 'ABANDONED', 'LEASE_EXPIRED', now) };",
      ],
    ],
    tests: ['tests/rekey/rekey-lifecycle.test.ts'],
  },
  {
    id: 'NC-11-07',
    defect: 'A different payload is answered as a retry of a completed rekey (idempotency)',
    file: 'apps/api/src/rooms/rekey.ts',
    edits: [
      [
        '            if (operation.payloadDigest !== null && sameBytes(operation.payloadDigest, payloadDigest)) {',
        '            if (operation.payloadDigest !== null) {',
      ],
    ],
    tests: ['tests/rekey/rekey-lifecycle.test.ts'],
  },
  {
    id: 'NC-11-08',
    defect: 'Starting a rekey in a RESTRICTED room needs no step-up (PC-03, route and locked row)',
    file: 'apps/api/src/routes/rekey.ts',
    edits: [
      ["      access: { kind: 'room', requires: { sensitive: 'START_REKEY' } },", "      access: { kind: 'room' },"],
    ],
    also: [
      {
        file: 'apps/api/src/rooms/rekey.ts',
        edits: [
          [
            "        const { room } = await lockAndReauthorize(tx, actor, access.roomId, meta, 'AZ-13', now, true);",
            "        const { room } = await lockAndReauthorize(tx, actor, access.roomId, meta, 'AZ-13', now, false);",
          ],
        ],
      },
    ],
    tests: ['tests/rekey/rekey-lifecycle.test.ts'],
  },
  {
    id: 'NC-11-09',
    defect: 'An ADMIN may re-share keys to another ADMIN (AZ-14 without the invitation role ceilings)',
    file: 'apps/api/src/rooms/rekey.ts',
    edits: [
      [
        '        if (!ceiling.allowed) throw roomDenial(events, request, ceiling.reason);',
        '        if (!ceiling.allowed && ceiling.allowed) throw roomDenial(events, request, ceiling.reason);',
      ],
    ],
    tests: ['tests/rekey/identity-reshare.test.ts'],
  },
  {
    id: 'NC-11-10',
    defect: 'A vault reset leaves the old identity’s envelopes in its rooms (CM-T053)',
    file: 'apps/api/src/db/room-store.ts',
    edits: [
      [
        '      await db.keyEnvelope.deleteMany({ where: { recipientUserId: userId, recipientKeyId: oldKeyId } });\n',
        '',
      ],
    ],
    tests: ['tests/rekey/identity-reshare.test.ts'],
  },
  {
    id: 'NC-11-11',
    defect: 'The grant history is not recorded, so a re-shared ADMIN’s earlier statements lose their authority',
    file: 'prisma/migrations/20261011000000_key_rotation/migration.sql',
    edits: [
      [
        '  IF NEW.grant_signature IS NOT NULL\n     AND (TG_OP',
        '  IF NEW.grant_signature IS NOT NULL AND false\n     AND (TG_OP',
      ],
    ],
    tests: ['tests/rekey/identity-reshare.test.ts'],
  },
  {
    id: 'NC-11-12',
    defect: 'The browser accepts a rekey snapshot that lists one user twice (recipient review)',
    file: 'packages/crypto/src/room-keys.ts',
    edits: [
      [
        '  if (users.size !== candidates.length || keys.size !== candidates.length) throw authenticationFailed();',
        '  if (users.size === -1 || keys.size === -1) throw authenticationFailed();',
      ],
    ],
    tests: ['packages/crypto/src/rekey.test.ts'],
  },
  {
    id: 'NC-11-13',
    defect: 'SF-11-01 regression: a 32-byte value with dropped leading zeros is refused again',
    file: 'packages/crypto/src/rsa-oaep.ts',
    edits: [
      ['  if (value.length > RSA_OAEP.wrappedValueBytes) {', '  if (value.length !== RSA_OAEP.wrappedValueBytes) {'],
    ],
    tests: ['packages/crypto/src/rsa-oaep.test.ts'],
  },
];

/** @param {string[]} files */
const vitest = (files) =>
  spawnSync(process.execPath, ['node_modules/vitest/vitest.mjs', 'run', ...files], { encoding: 'utf8' });

const VITEST_ONLY = process.argv.includes('--vitest-only');
// `--show-failures` prints the failing test names of every Vitest control to stderr.
const SHOW_FAILURES = process.argv.includes('--show-failures');
// `--only=NC-05` runs the controls whose ID starts with the prefix, for example one phase's.
const ONLY = process.argv.find((arg) => arg.startsWith('--only='))?.slice('--only='.length);
// `--only=NC-05-18,NC-05-19` takes several comma-separated ID prefixes.
const ONLY_PREFIXES = ONLY?.split(',').filter((p) => p !== '');
const controls = CONTROLS.filter(
  (c) =>
    (!VITEST_ONLY || c.e2e === undefined) &&
    (ONLY_PREFIXES === undefined || ONLY_PREFIXES.some((p) => c.id.startsWith(p))),
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
/** @param {Control} c @returns {Part[]} */
const partsOf = (c) => [{ file: c.file, edits: c.edits }, ...(c.also ?? [])];
const checksums = new Map(controls.flatMap((c) => partsOf(c).map((part) => [part.file, sha256(part.file)])));

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
  /** @type {Map<string, string>} */
  const mutations = new Map();
  for (const part of partsOf(control)) {
    const original = readFileSync(part.file, 'utf8');
    originals.set(part.file, original);
    let mutated = original;
    for (const [find, replace] of part.edits) {
      if (mutated.split(find).length !== 2) {
        restoreAll();
        throw new Error(`${control.id}: anchor not found exactly once in ${part.file}`);
      }
      mutated = mutated.replace(find, replace);
    }
    mutations.set(part.file, mutated);
  }
  try {
    for (const [file, mutated] of mutations) writeFileSync(file, mutated);
    if (control.e2e === undefined) {
      const run = vitest(control.tests);
      if (SHOW_FAILURES) {
        // The names of the tests that failed, to confirm the intended assertion caught the defect.
        const names = `${run.stdout}${run.stderr}`
          .split(/\r?\n/)
          .filter((l) => /^\s*FAIL /.test(l))
          .slice(0, 4);
        console.error(
          `${control.id}: ${names.length === 0 ? 'no FAIL lines' : names.map((l) => l.trim().slice(0, 170)).join(' | ')}`,
        );
      }
      results.push({ ...control, caught: run.status !== 0, note: '' });
    } else if (buildWeb() !== 0) {
      // A defect that does not even build was not caught by a test: it counts as missed.
      results.push({ ...control, caught: false, note: '(build failed)' });
    } else {
      results.push({ ...control, caught: playwright(control.e2e).status !== 0, note: '' });
    }
  } finally {
    for (const file of mutations.keys()) {
      writeFileSync(file, originals.get(file) ?? '');
      originals.delete(file);
    }
  }
}

restoreAll();
const changed = [...checksums].filter(([file, digest]) => sha256(file) !== digest).map(([file]) => file);
const baseline = vitest([...new Set(controls.flatMap((c) => c.tests))]);
if (baseline.status !== 0) {
  // A failing baseline invalidates the run: show which tests failed so the cause can be found.
  const failing = `${baseline.stdout}${baseline.stderr}`.split(/\r?\n/).filter((l) => / FAIL | Error:/.test(l));
  console.error(['Baseline failures:', ...failing.slice(0, 20)].join(String.fromCharCode(10)));
}
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
