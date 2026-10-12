import {
  createVault,
  CryptoErrorCode,
  isCryptoError,
  openSecret,
  storedSecretFromWire,
  vaultRecordToWire,
} from '@ciphermesh/crypto';
import { SECRET_LIMITS } from '@ciphermesh/shared';
import { randomBytes, randomUUID } from 'node:crypto';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { SecretValue } from '../../apps/api/src/config/secret';
import { createDatabase, type Database } from '../../apps/api/src/db/client';
import { runRoomCleanup } from '../../apps/api/src/db/room-cleanup';
import { runSecretCleanup } from '../../apps/api/src/db/secret-store';
import { createLogger } from '../../apps/api/src/logging/logger';
import { errorCode, startAuthApi, type AuthTestApi } from '../helpers/auth';
import { loadDatabaseTestEnv, testDatabase } from '../helpers/database';
import { insert, secretRow } from '../helpers/db-fixtures';
import { inviteAndAccept, vaultOf } from '../helpers/room-crypto';
import { createRoom, mfaPersonWithVault, personWithVault, stepUp, type Person } from '../helpers/rooms';
import {
  createdSecret,
  createSecret,
  inFromNow,
  listSecrets,
  openRevealed,
  reveal,
  revoke,
  secretBody,
  type SecretView,
} from '../helpers/secrets';
import { newPassphrase, runner } from '../helpers/vault';

// Phase 9, CM-T043 and CM-T044: recipient-bound secrets end to end against the real API and
// PostgreSQL, with secrets encrypted and decrypted by packages/crypto as the browser does. Who may
// create, list, reveal and revoke (AZ-23, AZ-24, AZ-25, AZ-32 with OL-06 and OL-14), the burn
// transaction (INV-13), expiry at reveal time (INV-14), the profile rules PC-09 and PC-10, the
// write lock (PC-16), the Phase 9 limits (D-09-03, D-09-04), the revocations when a recipient
// leaves or replaces their identity (D-09-06), the worker cleanup, and canary scans of every row
// and event. Concurrency is tests/secrets/secrets-concurrency.test.ts; cross-room and outsider
// attacks are tests/authz/bola.test.ts. Every text is synthetic.
let api: AuthTestApi;
let db: pg.Client;
let worker: Database;
let owner: Person;
let admin: Person;
let member: Person;
let otherMember: Person;
let viewer: Person;
let roomId: string;

const CANARY = 'phase9-burn-canary-c4f1d8';

beforeAll(async () => {
  loadDatabaseTestEnv();
  api = await startAuthApi();
  db = await testDatabase(inject('databaseName')).connect('api');
  worker = createDatabase({
    url: new SecretValue(testDatabase(inject('databaseName')).url('worker')),
    logger: createLogger({ level: 'fatal', sink: { write: () => undefined } }),
    poolMax: 1,
  });
  [owner, admin, member, otherMember, viewer] = [
    await personWithVault(api, db),
    await personWithVault(api, db),
    await personWithVault(api, db),
    await personWithVault(api, db),
    await personWithVault(api, db),
  ];
  roomId = await createRoom(owner, 'STANDARD', 'Secrets room');
  await inviteAndAccept(owner, roomId, admin, 'ADMIN');
  await inviteAndAccept(owner, roomId, member, 'MEMBER');
  await inviteAndAccept(owner, roomId, otherMember, 'MEMBER');
  await inviteAndAccept(owner, roomId, viewer, 'VIEWER');
}, 240_000);
afterAll(async () => {
  await api.close();
  await worker.close();
  await db.end();
});

interface Row {
  status: string;
  wrapped_sek: Buffer | null;
  payload_ciphertext: Buffer | null;
  payload_iv: Buffer | null;
  revealed_at: Date | null;
  destroyed_at: Date | null;
}
const row = async (id: string): Promise<Row | undefined> =>
  (await db.query<Row>('SELECT * FROM secrets WHERE id = $1', [id])).rows[0];
const rowText = async (id: string): Promise<string> =>
  JSON.stringify((await db.query('SELECT * FROM secrets WHERE id = $1', [id])).rows);

/** A room of the given profile (set in the database; the profile gates are CM-T047, L-42). */
/**
 * A room created with the profile, with a sender and a recipient who meet its access requirements
 * (PC-01, PC-02: MFA-verified sessions), since Phase 10 checks them on every room request.
 */
async function roomWithProfile(
  profile: 'CONFIDENTIAL' | 'RESTRICTED',
): Promise<{ readonly id: string; readonly sender: Person; readonly recipient: Person }> {
  const roomOwner = await mfaPersonWithVault(api, db);
  const sender = await mfaPersonWithVault(api, db);
  const id = await createRoom(roomOwner, profile, `Secrets ${profile} room`);
  if (profile === 'RESTRICTED') await stepUp(api, roomOwner, roomOwner.secret);
  await inviteAndAccept(
    roomOwner,
    id,
    sender,
    'MEMBER',
    profile === 'RESTRICTED' ? { confirmedFingerprint: vaultOf(sender).identity.fingerprint } : {},
  );
  return { id, sender, recipient: roomOwner };
}

// --------------------------------------------------------------- creation and reveal (DF-09)

describe('burn-after-reading: one reveal, then the ciphertext is gone (INV-13)', () => {
  it('stores only ciphertext, reveals once to the recipient and destroys the material in that transaction', async () => {
    const text = `${CANARY} burn once`;
    const { response, secretId } = await createSecret(member, roomId, otherMember, text);
    expect(response.status, JSON.stringify(response.body)).toBe(201);
    const created = response.body['secret'] as SecretView;
    expect(Object.keys(response.body)).toEqual(['secret']);
    expect(created).toMatchObject({
      id: secretId,
      senderId: member.userId,
      recipientUserId: otherMember.userId,
      recipientKeyId: vaultOf(otherMember).identity.keyId,
      status: 'ACTIVE',
      burnAfterReading: true,
      revealedAt: null,
      destroyedAt: null,
    });
    // The row holds AES-GCM ciphertext, its IV, the 384-byte wrapped SEK, suite and identifiers.
    const stored = await row(secretId);
    expect(stored?.wrapped_sek?.length).toBe(384);
    expect(stored?.payload_iv?.length).toBe(12);
    expect(await rowText(secretId)).not.toContain(CANARY);
    expect(JSON.stringify(api.events)).not.toContain(CANARY);

    api.events.length = 0;
    const first = await reveal(otherMember, roomId, secretId);
    expect(first.status, JSON.stringify(first.body)).toBe(200);
    expect((await openRevealed(otherMember, roomId, first)).text).toBe(text);
    expect(first.body['secret']).toMatchObject({ status: 'REVEALED' });
    const burned = await row(secretId);
    expect(burned).toMatchObject({ status: 'REVEALED', wrapped_sek: null, payload_ciphertext: null, payload_iv: null });
    expect(burned?.revealed_at).not.toBeNull();
    expect(burned?.destroyed_at).not.toBeNull();
    expect(api.events.map((e) => [e.name, e.details])).toEqual([
      ['SECRET_REVEALED', { roomId, secretId, burned: true }],
    ]);

    const second = await reveal(otherMember, roomId, secretId);
    expect(second.status).toBe(409);
    expect(errorCode(second)).toBe('SECRET_UNAVAILABLE');
    expect(JSON.stringify(second.body)).not.toContain('ciphertext');
    expect(api.events.at(-1)).toMatchObject({
      name: 'SECRET_REVEAL_REFUSED',
      outcome: 'DENIED',
      details: { roomId, secretId, reason: 'STATUS_REVEALED' },
    });
    expect((await listSecrets(otherMember, roomId)).find((s) => s.id === secretId)?.status).toBe('REVEALED');
  });

  it('GET requests never consume a secret: listing repeatedly changes no row', async () => {
    const secretId = await createdSecret(member, roomId, otherMember, `${CANARY} list`);
    const before = await rowText(secretId);
    for (let i = 0; i < 5; i += 1) {
      const listed = await listSecrets(otherMember, roomId);
      const entry = listed.find((s) => s.id === secretId);
      expect(entry?.status).toBe('ACTIVE');
      expect(Object.keys(entry ?? {}).sort()).toEqual(
        [
          'burnAfterReading',
          'createdAt',
          'destroyedAt',
          'expiresAt',
          'id',
          'recipientKeyId',
          'recipientUserId',
          'revealedAt',
          'senderId',
          'status',
        ].sort(),
      );
    }
    // There is no GET for one secret, and a GET on the reveal path is not a route.
    expect((await otherMember.browser.request('GET', `/rooms/${roomId}/secrets/${secretId}`)).status).toBe(404);
    expect((await otherMember.browser.request('GET', `/rooms/${roomId}/secrets/${secretId}/reveal`)).status).toBe(404);
    expect(await rowText(secretId)).toBe(before);
  });

  it('only the recipient can reveal: sender, OWNER, ADMIN and other members get 404 and change nothing', async () => {
    const secretId = await createdSecret(member, roomId, otherMember, `${CANARY} recipient only`);
    const before = await rowText(secretId);
    for (const who of [member, owner, admin, viewer]) {
      const response = await reveal(who, roomId, secretId);
      expect(response.status).toBe(404);
      expect(errorCode(response)).toBe('NOT_FOUND');
    }
    expect(await rowText(secretId)).toBe(before);
    expect((await reveal(otherMember, roomId, secretId)).status).toBe(200);
  });

  it('other members cannot unwrap the SEK with their own keys, even holding the ciphertext', async () => {
    const secretId = await createdSecret(member, roomId, otherMember, `${CANARY} not yours`, {
      burnAfterReading: false,
    });
    const response = await reveal(otherMember, roomId, secretId);
    const view = response.body['secret'] as SecretView;
    const wire = response.body['ciphertext'] as {
      suite: string;
      wrappedSek: string;
      payloadIv: string;
      ciphertext: string;
    };
    for (const thief of [owner, admin, viewer]) {
      // The thief relabels the record as theirs: the OAEP label then names their key, but the SEK
      // was wrapped to the recipient's key, so the unwrap fails.
      const relabelled = storedSecretFromWire(roomId, {
        ...wire,
        secretId: view.id,
        recipientUserId: thief.userId,
        recipientKeyId: vaultOf(thief).identity.keyId,
      });
      let caught: unknown;
      try {
        await openSecret(vaultOf(thief), relabelled);
      } catch (error) {
        caught = error;
      }
      expect(isCryptoError(caught, CryptoErrorCode.AUTHENTICATION_FAILED)).toBe(true);
    }
  });

  it('a secret without burn-after-reading stays redeemable until expiry or revocation (D-09-02)', async () => {
    const text = `${CANARY} keep`;
    const secretId = await createdSecret(member, roomId, otherMember, text, { burnAfterReading: false });
    const first = await reveal(otherMember, roomId, secretId);
    const second = await reveal(otherMember, roomId, secretId);
    expect([first.status, second.status]).toEqual([200, 200]);
    expect((await openRevealed(otherMember, roomId, second)).text).toBe(text);
    const kept = await row(secretId);
    expect(kept?.status).toBe('ACTIVE');
    expect(kept?.wrapped_sek?.length).toBe(384);
    expect((first.body['secret'] as SecretView).revealedAt).toBe((second.body['secret'] as SecretView).revealedAt);
    expect((await revoke(member, roomId, secretId)).status).toBe(200);
    expect(errorCode(await reveal(otherMember, roomId, secretId))).toBe('SECRET_UNAVAILABLE');
  });
});

// ------------------------------------------------------------------ canary scan (INV-01, INV-10)

describe('no secret text anywhere on the server', () => {
  it('finds no canary in any table, the log or the security events (EV-09-05)', async () => {
    const burnCanary = `CANARY-BURN-${randomBytes(6).toString('hex')}`;
    const keepCanary = `CANARY-KEEP-${randomBytes(6).toString('hex')}`;
    const burned = await createdSecret(
      member,
      roomId,
      otherMember,
      `${burnCanary}
`.repeat(10),
    );
    const kept = await createdSecret(owner, roomId, viewer, keepCanary, { burnAfterReading: false });
    expect((await reveal(otherMember, roomId, burned)).status).toBe(200);
    expect((await reveal(viewer, roomId, kept)).status).toBe(200);
    expect((await reveal(otherMember, roomId, burned)).status).toBe(409);
    expect((await revoke(owner, roomId, kept)).status).toBe(200);
    const forms = (text: string): string[] => [
      text,
      Buffer.from(text).toString('hex'),
      Buffer.from(text).toString('base64'),
      Buffer.from(text).toString('base64url'),
      Buffer.from(text, 'utf16le').toString('hex'),
    ];
    const tables = (
      await db.query<{ table_name: string }>(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name <> '_prisma_migrations'",
      )
    ).rows.map((r) => r.table_name);
    expect(tables).toContain('secrets');
    let dump = '';
    for (const table of tables) {
      dump += JSON.stringify((await db.query(`SELECT row_to_json(t)::text AS row FROM ${table} t`)).rows);
    }
    const log = `${api.logText()}${JSON.stringify(api.events)}`;
    for (const canary of [burnCanary, keepCanary]) {
      for (const form of forms(canary)) {
        expect(dump.includes(form), `database contains ${form}`).toBe(false);
        expect(log.includes(form), `log contains ${form}`).toBe(false);
      }
    }
    // Events name identifiers, flags and reason codes only (INV-10).
    for (const event of api.events.filter((e) => e.name.startsWith('SECRET_'))) {
      expect(
        Object.keys(event.details ?? {}).every((k) =>
          ['roomId', 'secretId', 'burnAfterReading', 'burned', 'reason'].includes(k),
        ),
        JSON.stringify(event),
      ).toBe(true);
    }
  });
});

// -------------------------------------------------------------------- creation rules (AZ-23)

describe('creation: who, for whom, how long (AZ-23, OL-03, PC-09, PC-10, D-09-03)', () => {
  it('VIEWERs cannot create; every other role can, for any ACTIVE member including a VIEWER', async () => {
    const refused = await createSecret(viewer, roomId, member, 'x');
    expect(refused.response.status).toBe(403);
    for (const sender of [owner, admin, member]) {
      expect((await createSecret(sender, roomId, viewer, `${CANARY} to viewer`)).response.status).toBe(201);
    }
  });

  it('refuses the sender as recipient, non-members, and a key that is not the recipient’s ACTIVE key', async () => {
    const outsider = await personWithVault(api, db);
    const invalid = async (overrides: Record<string, unknown>, recipient: Person = otherMember) => {
      const { body } = await secretBody(member, roomId, recipient, 'x');
      const response = await member.browser.request('POST', `/rooms/${roomId}/secrets`, { ...body, ...overrides });
      return [response.status, errorCode(response)];
    };
    const expected = [422, 'SECRET_RECIPIENT_INVALID'];
    expect(await invalid({ recipientUserId: member.userId, recipientKeyId: vaultOf(member).identity.keyId })).toEqual(
      expected,
    );
    expect(
      await invalid({ recipientUserId: outsider.userId, recipientKeyId: vaultOf(outsider).identity.keyId }),
    ).toEqual(expected);
    expect(await invalid({ recipientKeyId: vaultOf(viewer).identity.keyId })).toEqual(expected);
    expect(await invalid({ recipientKeyId: randomUUID() })).toEqual(expected);
  });

  it('enforces the lifetime: at least five minutes, at most the profile maximum (PC-09)', async () => {
    const MINUTE = 60_000;
    const DAY = 24 * 60 * MINUTE;
    const status = async (room: string, expiresAt: string, recipient: Person = otherMember) =>
      (await createSecret(member, room, recipient, 'x', { expiresAt })).response;
    for (const tooShort of [inFromNow(-MINUTE), inFromNow(4 * MINUTE)]) {
      const response = await status(roomId, tooShort);
      expect([response.status, errorCode(response)]).toEqual([422, 'EXPIRY_NOT_ALLOWED']);
    }
    expect((await status(roomId, inFromNow(7 * DAY - MINUTE))).status).toBe(201);
    expect(errorCode(await status(roomId, inFromNow(7 * DAY + MINUTE)))).toBe('EXPIRY_NOT_ALLOWED');
    const inRoom = async (room: Awaited<ReturnType<typeof roomWithProfile>>, expiresAt: string) =>
      (await createSecret(room.sender, room.id, room.recipient, 'x', { expiresAt })).response;
    const confidential = await roomWithProfile('CONFIDENTIAL');
    expect((await inRoom(confidential, inFromNow(72 * 60 * MINUTE - MINUTE, api.clock.now()))).status).toBe(201);
    expect(errorCode(await inRoom(confidential, inFromNow(72 * 60 * MINUTE + MINUTE, api.clock.now())))).toBe(
      'EXPIRY_NOT_ALLOWED',
    );
    const restricted = await roomWithProfile('RESTRICTED');
    expect((await inRoom(restricted, inFromNow(DAY - MINUTE, api.clock.now()))).status).toBe(201);
    expect(errorCode(await inRoom(restricted, inFromNow(DAY + MINUTE, api.clock.now())))).toBe('EXPIRY_NOT_ALLOWED');
  });

  it('burn-after-reading is mandatory in RESTRICTED rooms and optional elsewhere (PC-10)', async () => {
    const restricted = await roomWithProfile('RESTRICTED');
    const send = (room: Awaited<ReturnType<typeof roomWithProfile>>, burnAfterReading: boolean) =>
      createSecret(room.sender, room.id, room.recipient, 'x', {
        burnAfterReading,
        expiresAt: inFromNow(60 * 60_000, api.clock.now()),
      });
    const refused = await send(restricted, false);
    expect([refused.response.status, errorCode(refused.response)]).toEqual([422, 'BURN_REQUIRED']);
    expect((await send(restricted, true)).response.status).toBe(201);
    const confidential = await roomWithProfile('CONFIDENTIAL');
    expect((await send(confidential, false)).response.status).toBe(201);
  });

  it('refuses a reused secret ID, and fields the schema does not know', async () => {
    const { body, secretId } = await secretBody(member, roomId, otherMember, 'x');
    expect((await member.browser.request('POST', `/rooms/${roomId}/secrets`, body)).status).toBe(201);
    const again = await member.browser.request('POST', `/rooms/${roomId}/secrets`, body);
    expect([again.status, errorCode(again)]).toEqual([409, 'SECRET_ID_UNAVAILABLE']);
    for (const extra of [{ text: CANARY }, { senderId: owner.userId }, { status: 'REVEALED' }, { sek: 'AAAA' }]) {
      const fresh = await secretBody(member, roomId, otherMember, 'x');
      const response = await member.browser.request('POST', `/rooms/${roomId}/secrets`, { ...fresh.body, ...extra });
      expect(response.status, JSON.stringify(extra)).toBe(400);
    }
    expect(secretId).toBeDefined();
  });

  it('refuses creation while the room is write-locked (PC-16), but still reveals and revokes', async () => {
    const locked = await createRoom(owner, 'STANDARD', 'Secrets locked room');
    await inviteAndAccept(owner, locked, member, 'MEMBER');
    const toReveal = await createdSecret(owner, locked, member, `${CANARY} locked reveal`);
    const toRevoke = await createdSecret(owner, locked, member, 'locked revoke');
    await db.query(
      `UPDATE rooms SET key_state = 'REKEY_REQUIRED', rekey_reasons = '{MEMBER_REMOVED}', rekey_required_since = now(),
              membership_epoch = membership_epoch + 1 WHERE id = $1`,
      [locked],
    );
    const refused = await createSecret(owner, locked, member, 'x');
    expect([refused.response.status, errorCode(refused.response)]).toEqual([409, 'REKEY_REQUIRED']);
    expect((await reveal(member, locked, toReveal)).status).toBe(200);
    expect((await revoke(owner, locked, toRevoke)).status).toBe(200);
  });

  it('limits the ACTIVE secrets one account has sent (D-09-04); expired ones do not count', async () => {
    const sender = await personWithVault(api, db);
    const room = await createRoom(sender, 'STANDARD', 'Secrets quota room');
    await inviteAndAccept(sender, room, member, 'MEMBER');
    const recipient = { userId: member.userId, keyId: vaultOf(member).identity.keyId };
    for (let i = 0; i < SECRET_LIMITS.maxActiveSentPerAccount - 1; i += 1) {
      await insert(db, 'secrets', secretRow({ roomId: room, ownerId: sender.userId } as never, recipient));
    }
    // An expired ACTIVE row (not yet swept) does not count.
    await insert(
      db,
      'secrets',
      secretRow({ roomId: room, ownerId: sender.userId } as never, recipient, {
        created_at: new Date(Date.now() - 3_600_000),
        expires_at: new Date(Date.now() - 60_000),
      }),
    );
    expect((await createSecret(sender, room, member, 'the last one')).response.status).toBe(201);
    const over = await createSecret(sender, room, member, 'one too many');
    expect([over.response.status, errorCode(over.response)]).toEqual([409, 'SECRET_LIMIT_REACHED']);
  }, 120_000);
});

// ------------------------------------------------------------------ lists (AZ-32, OL-14)

describe('metadata lists (AZ-32, OL-14)', () => {
  it('MEMBERs and VIEWERs see what they sent or received; OWNER and ADMIN see the whole room', async () => {
    const room = await createRoom(owner, 'STANDARD', 'Secrets list room');
    await inviteAndAccept(owner, room, admin, 'ADMIN');
    await inviteAndAccept(owner, room, member, 'MEMBER');
    await inviteAndAccept(owner, room, otherMember, 'MEMBER');
    await inviteAndAccept(owner, room, viewer, 'VIEWER');
    const toOther = await createdSecret(member, room, otherMember, 'member to other');
    const toViewer = await createdSecret(admin, room, viewer, 'admin to viewer');
    const ids = async (who: Person) => (await listSecrets(who, room)).map((s) => s.id).sort();
    expect(await ids(member)).toEqual([toOther]);
    expect(await ids(otherMember)).toEqual([toOther]);
    expect(await ids(viewer)).toEqual([toViewer]);
    expect(await ids(owner)).toEqual([toOther, toViewer].sort());
    expect(await ids(admin)).toEqual([toOther, toViewer].sort());
    const listing = await owner.browser.request('GET', `/rooms/${room}/secrets`);
    expect(JSON.stringify(listing.body)).not.toMatch(/wrappedSek|ciphertext|payload/);
  });
});

// ------------------------------------------------------------------ revocation (AZ-25)

describe('revocation (AZ-25): OWNER and ADMIN any, MEMBERs their own, VIEWERs none', () => {
  it('applies the matrix with the stored sender, and destroys the material', async () => {
    const own = await createdSecret(member, roomId, otherMember, `${CANARY} revoke own`);
    const others = await createdSecret(otherMember, roomId, member, 'revoke others');
    expect((await revoke(viewer, roomId, own)).status).toBe(403);
    // The recipient (a MEMBER who did not send it) cannot revoke it either.
    expect((await revoke(member, roomId, others)).status).toBe(403);
    expect((await revoke(member, roomId, own)).status).toBe(200);
    expect(await row(own)).toMatchObject({ status: 'REVOKED', wrapped_sek: null, payload_ciphertext: null });
    expect(errorCode(await revoke(member, roomId, own))).toBe('SECRET_UNAVAILABLE');
    expect(errorCode(await reveal(otherMember, roomId, own))).toBe('SECRET_UNAVAILABLE');
    for (const who of [admin, owner]) {
      const id = await createdSecret(otherMember, roomId, member, 'revoked by an administrator');
      expect((await revoke(who, roomId, id)).status).toBe(200);
    }
    expect(errorCode(await revoke(owner, roomId, randomUUID()))).toBe('NOT_FOUND');
  });
});

// ------------------------------------------------------------------ expiry (INV-14) and cleanup

describe('expiry is enforced at reveal time; the worker destroys the material afterwards', () => {
  it('refuses an expired secret before the worker runs, then the worker marks it EXPIRED without material', async () => {
    const secretId = await createdSecret(member, roomId, otherMember, `${CANARY} expiring`, {
      expiresAt: inFromNow(10 * 60_000, api.clock.now()),
    });
    api.clock.advance(11 * 60_000);
    try {
      const before = await rowText(secretId);
      const response = await reveal(otherMember, roomId, secretId);
      expect([response.status, errorCode(response)]).toEqual([409, 'SECRET_UNAVAILABLE']);
      expect(await rowText(secretId)).toBe(before);
      expect((await listSecrets(otherMember, roomId)).find((s) => s.id === secretId)?.status).toBe('EXPIRED');
      expect(errorCode(await revoke(member, roomId, secretId))).toBe('SECRET_UNAVAILABLE');
      const cleaned = await runSecretCleanup(worker.prisma, api.clock.now());
      expect(cleaned.expired).toBeGreaterThanOrEqual(1);
      expect(await row(secretId)).toMatchObject({ status: 'EXPIRED', wrapped_sek: null, payload_ciphertext: null });
      expect(errorCode(await reveal(otherMember, roomId, secretId))).toBe('SECRET_UNAVAILABLE');
    } finally {
      api.clock.advance(-11 * 60_000);
    }
  });

  it('revokes the secrets of a room being deleted, and only then lets the room become DELETED', async () => {
    const doomed = await createRoom(owner, 'STANDARD', 'Secrets doomed room');
    await inviteAndAccept(owner, doomed, member, 'MEMBER');
    const secretId = await createdSecret(owner, doomed, member, `${CANARY} doomed`);
    await db.query("UPDATE rooms SET status = 'DELETING', deleted_at = now() WHERE id = $1", [doomed]);
    await runSecretCleanup(worker.prisma, new Date());
    expect(await row(secretId)).toMatchObject({ status: 'REVOKED', wrapped_sek: null, payload_ciphertext: null });
    await runRoomCleanup(worker.prisma);
    const { rows } = await db.query<{ status: string }>('SELECT status::text AS status FROM rooms WHERE id = $1', [
      doomed,
    ]);
    expect(rows[0]?.status).toBe('DELETED');
  });
});

// ----------------------------------------------------- the recipient leaves (D-09-06)

describe('a recipient who leaves the room or replaces their identity loses their pending secrets', () => {
  it('removal revokes the secrets addressed to the member, in the removal transaction', async () => {
    const leaving = await personWithVault(api, db);
    const room = await createRoom(owner, 'STANDARD', 'Secrets removal room');
    await inviteAndAccept(owner, room, leaving, 'MEMBER');
    await inviteAndAccept(owner, room, member, 'MEMBER');
    const toLeaving = await createdSecret(member, room, leaving, `${CANARY} to the leaving member`);
    const fromLeaving = await createdSecret(leaving, room, member, 'from the leaving member');
    const removed = await owner.browser.request('POST', `/rooms/${room}/members/${leaving.userId}/remove`, {});
    expect(removed.status, JSON.stringify(removed.body)).toBe(200);
    expect(await row(toLeaving)).toMatchObject({ status: 'REVOKED', wrapped_sek: null });
    // A secret the removed member sent stays for its recipient, who is still a member.
    expect((await row(fromLeaving))?.status).toBe('ACTIVE');
    expect((await reveal(leaving, room, toLeaving)).status).toBe(404);
    expect((await reveal(member, room, fromLeaving)).status).toBe(200);
  });

  it('a vault reset revokes the secrets wrapped to the retired identity key', async () => {
    const resetting = await personWithVault(api, db);
    const room = await createRoom(owner, 'STANDARD', 'Secrets reset room');
    await inviteAndAccept(owner, room, resetting, 'MEMBER');
    const secretId = await createdSecret(owner, room, resetting, `${CANARY} to the old key`);
    await stepUp(api, resetting);
    const fresh = await createVault({
      userId: resetting.userId,
      passphrase: newPassphrase(),
      account: { email: resetting.email, displayName: 'Synthetic Test User' },
      runner,
    });
    api.events.length = 0;
    const reset = await resetting.browser.request('POST', '/vault/reset', {
      supersedesKeyId: vaultOf(resetting).identity.keyId,
      vault: vaultRecordToWire(fresh.record),
    });
    expect(reset.status, JSON.stringify(reset.body)).toBe(201);
    expect(await row(secretId)).toMatchObject({ status: 'REVOKED', wrapped_sek: null, payload_ciphertext: null });
    expect(api.events.find((e) => e.name === 'SECRET_REVOKED')?.details).toEqual({
      roomId: room,
      secretId,
      reason: 'RECIPIENT_KEY_CHANGED',
    });
    // The member's new identity holds no room key yet (CM-T053, L-44), so nobody can send to it.
    expect(errorCode(await reveal(resetting, room, secretId))).toBe('SECRET_UNAVAILABLE');
  }, 120_000);
});

// ------------------------------------------------------------- the database guard (migration)

describe('the database refuses to resurrect a destroyed secret, even for a privileged writer', () => {
  it('rejects every transition out of REVEALED, EXPIRED and REVOKED, and ciphertext changes while ACTIVE', async () => {
    const burned = await createdSecret(member, roomId, otherMember, 'resurrect me');
    expect((await reveal(otherMember, roomId, burned)).status).toBe(200);
    const attempt = async (sql: string, params: unknown[]) => {
      try {
        await db.query(sql, params);
        return 'none';
      } catch (error) {
        return (error as { code?: string }).code;
      }
    };
    expect(
      await attempt(
        "UPDATE secrets SET status = 'ACTIVE', destroyed_at = NULL, wrapped_sek = $2, payload_ciphertext = $3, payload_iv = $4 WHERE id = $1",
        [burned, Buffer.alloc(384, 1), Buffer.alloc(64, 1), Buffer.alloc(12, 1)],
      ),
    ).not.toBe('none');
    expect(await attempt('UPDATE secrets SET revealed_at = now() WHERE id = $1', [burned])).toBe('23000');
    const active = await createdSecret(member, roomId, otherMember, 'keep me');
    expect(
      await attempt('UPDATE secrets SET payload_ciphertext = $2 WHERE id = $1', [active, Buffer.alloc(64, 2)]),
    ).toBe('23000');
    expect(await attempt("UPDATE secrets SET expires_at = now() + interval '1 day' WHERE id = $1", [active])).toBe(
      '23000',
    );
    expect(await attempt('UPDATE secrets SET recipient_user_id = $2 WHERE id = $1', [active, member.userId])).toBe(
      '23000',
    );
    expect(await attempt('DELETE FROM secrets WHERE id = $1', [active])).toBe('42501');
  });
});
