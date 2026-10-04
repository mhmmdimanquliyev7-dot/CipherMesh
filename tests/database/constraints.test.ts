import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { afterAll, beforeAll, beforeEach, afterEach, describe, expect, inject, it } from 'vitest';
import {
  DUMMY,
  fileRow,
  insert,
  insertKeyPair,
  insertMember,
  insertRoom,
  insertStatement,
  insertUser,
  noteRow,
  secretRow,
  auditRow,
  type RoomFixture,
} from '../helpers/db-fixtures';
import { loadDatabaseTestEnv, sqlStateInSavepoint, SQLSTATE, testDatabase } from '../helpers/database';

// Schema constraints of CM-T013, exercised as the least-privilege API role (cm_api). Each test
// runs in a transaction that is rolled back. Expected failures are asserted by SQLSTATE so a
// test cannot pass because of an unrelated error.
loadDatabaseTestEnv();
const db = testDatabase(inject('databaseName'));
let api: pg.Client;

beforeAll(async () => {
  api = await db.connect('api');
});
afterAll(async () => {
  await api.end();
});
beforeEach(async () => {
  await api.query('BEGIN');
});
afterEach(async () => {
  await api.query('ROLLBACK');
});

const attempt = (table: string, row: Record<string, unknown>): Promise<string> =>
  sqlStateInSavepoint(api, ...insertStatement(table, row));
const run = (sql: string, values: unknown[] = []): Promise<string> => sqlStateInSavepoint(api, sql, values);

function rekeyRow(room: RoomFixture, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    room_id: room.roomId,
    started_by_id: room.ownerId,
    mode: 'MANUAL',
    base_version: 1,
    target_version: 2,
    membership_epoch: 0,
    recipient_set_digest: DUMMY.digest(),
    lease_expires_at: new Date(Date.now() + 600_000),
    ...overrides,
  };
}

async function invitationRow(
  room: RoomFixture,
  overrides: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const invitee = await insertUser(api);
  const inviteeKey = await insertKeyPair(api, invitee);
  return {
    room_id: room.roomId,
    invitee_user_id: invitee,
    invitee_key_id: inviteeKey,
    invited_by_id: room.ownerId,
    role: 'MEMBER',
    status: 'PENDING',
    expires_at: new Date(Date.now() + 86_400_000),
    ...overrides,
  };
}

describe('baseline fixtures', () => {
  it('a complete room with key version, owner and envelope satisfies every constraint', async () => {
    const room = await insertRoom(api);
    await insert(api, 'encrypted_files', fileRow(room));
    await insert(api, 'encrypted_notes', noteRow(room));
    await insert(api, 'secrets', secretRow(room, { userId: room.ownerId, keyId: room.ownerKeyId }));
    const { rows } = await api.query('SELECT count(*)::int AS n FROM room_members WHERE room_id = $1', [room.roomId]);
    expect(rows[0]).toEqual({ n: 1 });
  });
});

describe('partial unique indexes (data-model 4.5 to 4.9.1)', () => {
  it('allows one ACTIVE key pair per user, and keeps superseded keys without private keys', async () => {
    const user = await insertUser(api);
    await insertKeyPair(api, user);
    expect(await attempt('user_key_pairs', await keyPairRow(user))).toBe(SQLSTATE.uniqueViolation);
    expect(
      await attempt(
        'user_key_pairs',
        await keyPairRow(user, { status: 'SUPERSEDED', encrypted_private_key: null, superseded_at: new Date() }),
      ),
    ).toBe('none');
  });

  it('allows exactly one ACTIVE OWNER per room', async () => {
    const room = await insertRoom(api);
    const second = await insertUser(api);
    expect(await attempt('room_members', memberRow(room.roomId, second, { role: 'OWNER' }))).toBe(
      SQLSTATE.uniqueViolation,
    );
    expect(await attempt('room_members', memberRow(room.roomId, second, { role: 'ADMIN' }))).toBe('none');
  });

  it('allows one current membership per user and room, and a new one after removal', async () => {
    const room = await insertRoom(api);
    const user = await insertUser(api);
    const first = await insertMember(api, room.roomId, user);
    expect(await attempt('room_members', memberRow(room.roomId, user))).toBe(SQLSTATE.uniqueViolation);
    await api.query(
      `UPDATE room_members SET status = 'REMOVED', removed_at = now(), removal_reason = 'REMOVED_BY_ADMIN' WHERE id = $1`,
      [first],
    );
    expect(await attempt('room_members', memberRow(room.roomId, user))).toBe('none');
  });

  it('allows one ACTIVE key version per room and unique version numbers', async () => {
    const room = await insertRoom(api);
    const version = (v: number, status: string, extra: Record<string, unknown> = {}): Record<string, unknown> => ({
      room_id: room.roomId,
      version: v,
      status,
      commitment: DUMMY.digest(),
      algorithm_suite: 'CM1',
      reasons: '{MANUAL}',
      created_by_id: room.ownerId,
      ...extra,
    });
    expect(await attempt('room_key_versions', version(2, 'ACTIVE'))).toBe(SQLSTATE.uniqueViolation);
    expect(await attempt('room_key_versions', version(1, 'RETIRED', { retired_at: new Date() }))).toBe(
      SQLSTATE.uniqueViolation,
    );
  });

  it('allows one PENDING rekey operation per room (ADR-013)', async () => {
    const room = await insertRoom(api);
    await insert(api, 'rekey_operations', rekeyRow(room));
    expect(await attempt('rekey_operations', rekeyRow(room))).toBe(SQLSTATE.uniqueViolation);
    expect(
      await attempt(
        'rekey_operations',
        rekeyRow(room, { status: 'ABANDONED', closed_at: new Date(), closed_reason: 'LEASE_EXPIRED' }),
      ),
    ).toBe('none');
  });

  it('allows one open invitation per invitee and room', async () => {
    const room = await insertRoom(api);
    const row = await invitationRow(room);
    await insert(api, 'invitations', row);
    expect(await attempt('invitations', { ...row })).toBe(SQLSTATE.uniqueViolation);
    expect(await attempt('invitations', { ...row, status: 'DECLINED', responded_at: new Date() })).toBe('none');
  });

  it('treats email addresses case-insensitively', async () => {
    await insertUser(api, { email: 'synthetic.case@example.test' });
    expect(await attempt('users', userRow({ email: 'Synthetic.CASE@Example.TEST' }))).toBe(SQLSTATE.uniqueViolation);
  });

  it('stores at most one envelope per room, key version and recipient key', async () => {
    const room = await insertRoom(api);
    expect(await attempt('key_envelopes', envelopeRow(room))).toBe(SQLSTATE.uniqueViolation);
  });
});

describe('composite foreign keys', () => {
  it('rejects an envelope whose recipient key belongs to another user', async () => {
    const room = await insertRoom(api);
    const other = await insertUser(api);
    const otherKey = await insertKeyPair(api, other);
    // The owner's row with the other user's key: the key does not belong to the recipient.
    expect(await attempt('key_envelopes', envelopeRow(room, { recipient_key_id: otherKey }))).toBe(
      SQLSTATE.foreignKeyViolation,
    );
    expect(
      await attempt('key_envelopes', envelopeRow(room, { recipient_user_id: other, recipient_key_id: otherKey })),
    ).toBe('none');
  });

  it('rejects envelopes, files and notes for a key version the room does not have', async () => {
    const room = await insertRoom(api);
    const otherRoom = await insertRoom(api);
    expect(await attempt('key_envelopes', envelopeRow(room, { key_version: 2 }))).toBe(SQLSTATE.foreignKeyViolation);
    expect(await attempt('encrypted_files', fileRow(room, { key_version: 2 }))).toBe(SQLSTATE.foreignKeyViolation);
    expect(await attempt('encrypted_notes', noteRow(room, { key_version: 3 }))).toBe(SQLSTATE.foreignKeyViolation);
    // Version 1 of another room does not satisfy the reference either.
    await api.query('DELETE FROM key_envelopes WHERE room_id = $1', [otherRoom.roomId]);
    expect(await attempt('encrypted_files', fileRow(room, { room_id: randomUUID() }))).toBe(
      SQLSTATE.foreignKeyViolation,
    );
  });

  it('rejects a secret wrapped for a key that is not the recipient key', async () => {
    const room = await insertRoom(api);
    const recipient = await insertUser(api);
    const recipientKey = await insertKeyPair(api, recipient);
    expect(await attempt('secrets', secretRow(room, { userId: recipient, keyId: room.ownerKeyId }))).toBe(
      SQLSTATE.foreignKeyViolation,
    );
    expect(await attempt('secrets', secretRow(room, { userId: recipient, keyId: recipientKey }))).toBe('none');
  });

  it('rejects a membership that points to an invitation of another room', async () => {
    const room = await insertRoom(api);
    const otherRoom = await insertRoom(api);
    const invitation = await invitationRow(otherRoom);
    const invitationId = randomUUID();
    await insert(api, 'invitations', { id: invitationId, ...invitation });
    expect(
      await attempt(
        'room_members',
        memberRow(room.roomId, String(invitation['invitee_user_id']), { invitation_id: invitationId }),
      ),
    ).toBe(SQLSTATE.foreignKeyViolation);
  });
});

describe('CHECK constraints: what the database refuses to store', () => {
  it.each([
    ['a plaintext password', 'correct horse battery staple'],
    ['a bcrypt hash', '$2b$12$abcdefghijklmnopqrstuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu'],
    ['an Argon2i (not id) hash', '$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA'],
  ])('rejects %s as password_hash (INV-11)', async (_label, value) => {
    expect(await attempt('users', userRow({ password_hash: value }))).toBe(SQLSTATE.checkViolation);
  });

  it('rejects an ACTIVE key pair without its encrypted private key, and a retired one that keeps it', async () => {
    const user = await insertUser(api);
    expect(await attempt('user_key_pairs', await keyPairRow(user, { encrypted_private_key: null }))).toBe(
      SQLSTATE.checkViolation,
    );
    expect(await attempt('user_key_pairs', await keyPairRow(user, { status: 'REVOKED', revoked_at: new Date() }))).toBe(
      SQLSTATE.checkViolation,
    );
  });

  it.each([
    ['an SPKI that is not RSA-3072 sized', { public_key_spki: DUMMY.ciphertext(294) }],
    ['an upper-case fingerprint', { public_key_fingerprint: 'A'.repeat(64) }],
    ['a short fingerprint', { public_key_fingerprint: 'a'.repeat(63) }],
    ['a KDF below the Argon2id floor (CP-04)', { kdf_memory_kib: 4096 }],
    ['a single KDF iteration', { kdf_iterations: 1 }],
    ['another KDF', { kdf_algorithm: 'pbkdf2' }],
    ['a short salt', { kdf_salt: DUMMY.ciphertext(8) }],
    ['a 16-byte IV', { private_key_iv: DUMMY.ciphertext(16) }],
    ['a private key too short to be ciphertext of a PKCS#8 key', { encrypted_private_key: DUMMY.ciphertext(32) }],
    ['an unknown algorithm suite', { algorithm_suite: 'CM2' }],
  ])('rejects a key pair with %s', async (_label, override) => {
    const user = await insertUser(api);
    expect(await attempt('user_key_pairs', await keyPairRow(user, override))).toBe(SQLSTATE.checkViolation);
  });

  it.each([
    ['383 bytes', 383],
    ['385 bytes', 385],
    ['a content-sized payload', 4096],
  ])('rejects an envelope of %s: RSA-OAEP-3072 output is exactly 384 bytes (INV-17)', async (_label, size) => {
    const room = await insertRoom(api);
    const member = await insertUser(api);
    const key = await insertKeyPair(api, member);
    expect(
      await attempt(
        'key_envelopes',
        envelopeRow(room, { recipient_user_id: member, recipient_key_id: key, wrapped_key: DUMMY.ciphertext(size) }),
      ),
    ).toBe(SQLSTATE.checkViolation);
  });

  it('rejects a secret whose payload or wrapped SEK survives burning (INV-13)', async () => {
    const room = await insertRoom(api);
    const recipient = { userId: room.ownerId, keyId: room.ownerKeyId };
    const burned = { status: 'REVEALED', revealed_at: new Date(), destroyed_at: new Date() };
    expect(await attempt('secrets', secretRow(room, recipient, burned))).toBe(SQLSTATE.checkViolation);
    expect(
      await attempt('secrets', secretRow(room, recipient, { ...burned, wrapped_sek: null, payload_iv: null })),
    ).toBe(SQLSTATE.checkViolation);
    expect(
      await attempt(
        'secrets',
        secretRow(room, recipient, { ...burned, wrapped_sek: null, payload_ciphertext: null, payload_iv: null }),
      ),
    ).toBe('none');
    expect(await attempt('secrets', secretRow(room, recipient, { wrapped_sek: DUMMY.ciphertext(256) }))).toBe(
      SQLSTATE.checkViolation,
    );
  });

  it('rejects a deleted file that keeps its wrapped FEK or manifest, and an oversized file (CP-19)', async () => {
    const room = await insertRoom(api);
    const deleted = { status: 'DELETED', deleted_at: new Date() };
    expect(await attempt('encrypted_files', fileRow(room, deleted))).toBe(SQLSTATE.checkViolation);
    expect(await attempt('encrypted_files', fileRow(room, { ...deleted, wrapped_dek: null }))).toBe(
      SQLSTATE.checkViolation,
    );
    expect(
      await attempt('encrypted_files', fileRow(room, { ...deleted, wrapped_dek: null, manifest_ciphertext: null })),
    ).toBe('none');
    expect(await attempt('encrypted_files', fileRow(room, { ciphertext_size: 52428817 }))).toBe(
      SQLSTATE.checkViolation,
    );
    expect(await attempt('encrypted_files', fileRow(room, { wrapped_dek: DUMMY.ciphertext(32) }))).toBe(
      SQLSTATE.checkViolation,
    );
    expect(await attempt('encrypted_files', fileRow(room, { object_key: '../other-bucket/x' }))).toBe(
      SQLSTATE.checkViolation,
    );
    expect(await attempt('encrypted_files', fileRow(room, { status: 'AVAILABLE' }))).toBe(SQLSTATE.checkViolation);
  });

  it('rejects a deleted note that keeps its ciphertext or wrapped NEK', async () => {
    const room = await insertRoom(api);
    expect(await attempt('encrypted_notes', noteRow(room, { deleted_at: new Date() }))).toBe(SQLSTATE.checkViolation);
    expect(
      await attempt('encrypted_notes', noteRow(room, { deleted_at: new Date(), ciphertext: null, wrapped_dek: null })),
    ).toBe('none');
    expect(await attempt('encrypted_notes', noteRow(room, { content_iv: DUMMY.ciphertext(8) }))).toBe(
      SQLSTATE.checkViolation,
    );
  });

  it('keeps the room key state consistent with its rekey reasons (INV-07)', async () => {
    const room = await insertRoom(api);
    expect(await run(`UPDATE rooms SET key_state = 'REKEY_REQUIRED' WHERE id = $1`, [room.roomId])).toBe(
      SQLSTATE.checkViolation,
    );
    expect(await run(`UPDATE rooms SET rekey_reasons = '{MEMBER_REMOVED}' WHERE id = $1`, [room.roomId])).toBe(
      SQLSTATE.checkViolation,
    );
    expect(
      await run(
        `UPDATE rooms SET key_state = 'REKEY_REQUIRED', rekey_reasons = '{MEMBER_REMOVED}', rekey_required_since = now() WHERE id = $1`,
        [room.roomId],
      ),
    ).toBe('none');
    expect(await run(`UPDATE rooms SET key_state = 'ACTIVE' WHERE id = $1`, [room.roomId])).toBe(
      SQLSTATE.checkViolation,
    );
  });

  it('only allows a rekey operation that targets the next version', async () => {
    const room = await insertRoom(api);
    expect(await attempt('rekey_operations', rekeyRow(room, { target_version: 3 }))).toBe(SQLSTATE.checkViolation);
    expect(await attempt('rekey_operations', rekeyRow(room, { status: 'COMPLETED', closed_at: new Date() }))).toBe(
      SQLSTATE.checkViolation,
    );
  });

  it('enforces the two-person rule for invitation approval and never invites an OWNER', async () => {
    const room = await insertRoom(api);
    const self = await invitationRow(room, { approved_by_id: room.ownerId, approved_at: new Date() });
    expect(await attempt('invitations', self)).toBe(SQLSTATE.checkViolation);
    const owner = await invitationRow(room, { role: 'OWNER' });
    expect(await attempt('invitations', owner)).toBe(SQLSTATE.invalidTextRepresentation);
  });

  it('records exactly one of account ID or identifier HMAC per login attempt, never a raw identifier', async () => {
    const user = await insertUser(api);
    expect(await attempt('login_attempts', { outcome: 'BAD_CREDENTIALS' })).toBe(SQLSTATE.checkViolation);
    expect(
      await attempt('login_attempts', { outcome: 'BAD_CREDENTIALS', user_id: user, identifier_hmac: DUMMY.digest() }),
    ).toBe(SQLSTATE.checkViolation);
    expect(
      await attempt('login_attempts', {
        outcome: 'BAD_CREDENTIALS',
        identifier_hmac: Buffer.from('someone@example.test'),
      }),
    ).toBe(SQLSTATE.checkViolation);
    expect(await attempt('login_attempts', { outcome: 'BAD_CREDENTIALS', identifier_hmac: DUMMY.digest() })).toBe(
      'none',
    );
  });

  it('rejects identifiers that are not UUIDv4', async () => {
    const owner = await insertUser(api);
    const room = (id: string): Record<string, unknown> => ({
      id,
      name: 'Synthetic room',
      security_profile: 'STANDARD',
      policy_version: 1,
      created_by_id: owner,
    });
    expect(await attempt('rooms', room('6ba7b810-9dad-11d1-80b4-00c04fd430c8'))).toBe(SQLSTATE.checkViolation); // v1
    expect(await attempt('rooms', room('00000000-0000-0000-0000-000000000000'))).toBe(SQLSTATE.checkViolation);
    expect(await attempt('rooms', room(randomUUID()))).toBe('none');
  });

  it('keeps sessions within their absolute lifetime and digests at 32 bytes', async () => {
    const user = await insertUser(api);
    const now = Date.now();
    const session = (extra: Record<string, unknown>): Record<string, unknown> => ({
      user_id: user,
      token_digest: DUMMY.digest(),
      last_seen_at: new Date(now),
      idle_expires_at: new Date(now + 1_800_000),
      absolute_expires_at: new Date(now + 43_200_000),
      authenticated_at: new Date(now),
      ...extra,
    });
    expect(await attempt('sessions', session({ idle_expires_at: new Date(now + 50_000_000) }))).toBe(
      SQLSTATE.checkViolation,
    );
    expect(await attempt('sessions', session({ token_digest: Buffer.from('raw-session-token-value') }))).toBe(
      SQLSTATE.checkViolation,
    );
    expect(await attempt('sessions', session({ revoked_at: new Date() }))).toBe(SQLSTATE.checkViolation);
    expect(await attempt('sessions', session({}))).toBe('none');
  });

  it('rejects malformed audit events', async () => {
    expect(await attempt('audit_events', auditRow(1, { details: '[]' }))).toBe(SQLSTATE.checkViolation);
    expect(await attempt('audit_events', auditRow(1, { actor_type: 'USER' }))).toBe(SQLSTATE.checkViolation);
    expect(await attempt('audit_events', auditRow(1, { action: 'drop table' }))).toBe(SQLSTATE.checkViolation);
    expect(await attempt('audit_events', auditRow(1, { prev_hash: DUMMY.ciphertext(31) }))).toBe(
      SQLSTATE.checkViolation,
    );
    expect(await attempt('audit_events', auditRow(0))).toBe(SQLSTATE.checkViolation);
  });
});

describe('write-once identity columns', () => {
  it('never changes a public identity key after upload, but allows status changes', async () => {
    const user = await insertUser(api);
    const key = await insertKeyPair(api, user);
    expect(
      await run('UPDATE user_key_pairs SET public_key_spki = $2 WHERE id = $1', [key, DUMMY.ciphertext(422).fill(1)]),
    ).toBe(SQLSTATE.integrityConstraintViolation);
    expect(
      await run(`UPDATE user_key_pairs SET public_key_fingerprint = $2 WHERE id = $1`, [key, 'b'.repeat(64)]),
    ).toBe(SQLSTATE.integrityConstraintViolation);
    expect(
      await run(
        `UPDATE user_key_pairs SET status = 'SUPERSEDED', encrypted_private_key = NULL, superseded_at = now() WHERE id = $1`,
        [key],
      ),
    ).toBe('none');
  });

  it('never changes the commitment of a key version', async () => {
    const room = await insertRoom(api);
    expect(
      await run('UPDATE room_key_versions SET commitment = $2 WHERE room_id = $1', [
        room.roomId,
        DUMMY.ciphertext(32).fill(7),
      ]),
    ).toBe(SQLSTATE.integrityConstraintViolation);
    expect(
      await run(`UPDATE room_key_versions SET wrap_count = wrap_count + 1 WHERE room_id = $1`, [room.roomId]),
    ).toBe('none');
  });
});

function userRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    email: `synthetic-${randomUUID()}@example.test`,
    display_name: 'Synthetic Test User',
    password_hash: '$argon2id$v=19$m=19456,t=2,p=1$U1lOVEhFVElD$U1lOVEhFVElD',
    password_changed_at: new Date(),
    ...overrides,
  };
}

async function keyPairRow(userId: string, overrides: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
  return Promise.resolve({
    id: randomUUID(),
    user_id: userId,
    status: 'ACTIVE',
    algorithm_suite: 'CM1',
    public_key_spki: DUMMY.spki(),
    public_key_fingerprint: randomUUID().replaceAll('-', '').padEnd(64, 'f'),
    encrypted_private_key: DUMMY.encryptedPrivateKey(),
    private_key_iv: DUMMY.iv(),
    kdf_algorithm: 'argon2id',
    kdf_memory_kib: 19456,
    kdf_iterations: 2,
    kdf_parallelism: 1,
    kdf_salt: DUMMY.salt(),
    ...overrides,
  });
}

function memberRow(roomId: string, userId: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { room_id: roomId, user_id: userId, role: 'MEMBER', first_key_version: 1, ...overrides };
}

function envelopeRow(room: RoomFixture, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    room_id: room.roomId,
    key_version: 1,
    recipient_user_id: room.ownerId,
    recipient_key_id: room.ownerKeyId,
    status: 'ACTIVE',
    wrapped_key: DUMMY.rsaCiphertext(),
    algorithm: 'RSA-OAEP-3072-SHA256',
    created_by_id: room.ownerId,
    ...overrides,
  };
}
