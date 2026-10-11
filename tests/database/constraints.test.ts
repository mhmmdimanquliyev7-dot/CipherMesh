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
    grantor_key_id: room.ownerKeyId,
    grant_signature: DUMMY.signature(),
    role: 'MEMBER',
    status: 'PENDING',
    expires_at: new Date(Date.now() + 86_400_000),
    ...overrides,
  };
}

/** A key-version row of the fixture room (DUMMY commitment and signature). */
function versionRow(room: RoomFixture, v: number, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    room_id: room.roomId,
    version: v,
    status: 'RETIRED',
    retired_at: new Date(),
    commitment: DUMMY.digest(),
    algorithm_suite: 'CM1',
    reasons: '{MANUAL}',
    created_by_id: room.ownerId,
    created_by_key_id: room.ownerKeyId,
    previous_commitment: v === 1 ? null : DUMMY.digest(),
    recipient_user_ids: [room.ownerId],
    recipient_key_ids: [room.ownerKeyId],
    statement_signature: DUMMY.signature(),
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
        await keyPairRow(user, {
          status: 'SUPERSEDED',
          encrypted_private_key: null,
          encrypted_signing_private_key: null,
          superseded_at: new Date(),
        }),
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
    expect(await attempt('room_key_versions', versionRow(room, 2, { status: 'ACTIVE', retired_at: null }))).toBe(
      SQLSTATE.uniqueViolation,
    );
    expect(await attempt('room_key_versions', versionRow(room, 1))).toBe(SQLSTATE.uniqueViolation);
    expect(await attempt('room_key_versions', versionRow(room, 2))).toBe('none');
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

describe('signed room statements (Phase 6, ADR-015 section 4)', () => {
  it('stores a genesis statement completely or not at all, with a 64-byte signature', async () => {
    const owner = await insertUser(api);
    const ownerKey = await insertKeyPair(api, owner);
    const room = (extra: Record<string, unknown>) => ({
      id: randomUUID(),
      name: 'Synthetic room',
      security_profile: 'STANDARD',
      policy_version: 1,
      created_by_id: owner,
      ...extra,
    });
    expect(await attempt('rooms', room({ creator_key_id: ownerKey, genesis_signature: DUMMY.signature() }))).toBe(
      'none',
    );
    // Rooms created before Phase 6 have neither (L-43).
    expect(await attempt('rooms', room({}))).toBe('none');
    expect(await attempt('rooms', room({ creator_key_id: ownerKey }))).toBe(SQLSTATE.checkViolation);
    expect(await attempt('rooms', room({ genesis_signature: DUMMY.signature() }))).toBe(SQLSTATE.checkViolation);
    expect(await attempt('rooms', room({ creator_key_id: ownerKey, genesis_signature: DUMMY.ciphertext(63) }))).toBe(
      SQLSTATE.checkViolation,
    );
    // The genesis signer must be an identity of the creator.
    const other = await insertUser(api);
    const otherKey = await insertKeyPair(api, other);
    expect(await attempt('rooms', room({ creator_key_id: otherKey, genesis_signature: DUMMY.signature() }))).toBe(
      SQLSTATE.foreignKeyViolation,
    );
  });

  it('requires a previous commitment exactly for versions after 1, and a bounded signed recipient list', async () => {
    const room = await insertRoom(api);
    expect(await attempt('room_key_versions', versionRow(room, 2, { previous_commitment: null }))).toBe(
      SQLSTATE.checkViolation,
    );
    expect(await attempt('room_key_versions', versionRow(room, 2, { previous_commitment: DUMMY.ciphertext(31) }))).toBe(
      SQLSTATE.checkViolation,
    );
    const many = Array.from({ length: 101 }, () => room.ownerId);
    for (const recipients of [
      { recipient_user_ids: [], recipient_key_ids: [] },
      { recipient_user_ids: null, recipient_key_ids: null },
      { recipient_user_ids: [room.ownerId], recipient_key_ids: [] },
      { recipient_user_ids: [room.ownerId, null], recipient_key_ids: [room.ownerKeyId, room.ownerKeyId] },
      { recipient_user_ids: many, recipient_key_ids: many.map(() => room.ownerKeyId) },
    ]) {
      expect(await attempt('room_key_versions', versionRow(room, 2, recipients)), JSON.stringify(recipients)).toBe(
        SQLSTATE.checkViolation,
      );
    }
    expect(await attempt('room_key_versions', versionRow(room, 2, { statement_signature: DUMMY.ciphertext(65) }))).toBe(
      SQLSTATE.checkViolation,
    );
    // The statement is signed by an identity of the version's creator.
    const other = await insertUser(api);
    expect(
      await attempt('room_key_versions', versionRow(room, 2, { created_by_key_id: await insertKeyPair(api, other) })),
    ).toBe(SQLSTATE.foreignKeyViolation);
  });

  it('stores a membership grant completely or not at all, for identities of the member and the grantor', async () => {
    const room = await insertRoom(api);
    const user = await insertUser(api);
    const userKey = await insertKeyPair(api, user);
    const grant = {
      subject_key_id: userKey,
      grant_role: 'ADMIN',
      grantor_user_id: room.ownerId,
      grantor_key_id: room.ownerKeyId,
      grant_signature: DUMMY.signature(),
    };
    expect(await attempt('room_members', memberRow(room.roomId, user, grant))).toBe('none');
    for (const missing of Object.keys(grant)) {
      const partial: Record<string, unknown> = { ...grant, [missing]: null };
      expect(await attempt('room_members', memberRow(room.roomId, user, partial)), missing).toBe(
        SQLSTATE.checkViolation,
      );
    }
    // A grant for someone else's key, or signed by a key that is not the grantor's, is refused
    // (fresh members, so the one-current-membership index is not what refuses them).
    const second = await insertUser(api);
    expect(
      await attempt('room_members', memberRow(room.roomId, second, { ...grant, subject_key_id: room.ownerKeyId })),
    ).toBe(SQLSTATE.foreignKeyViolation);
    const third = await insertUser(api);
    const thirdKey = await insertKeyPair(api, third);
    expect(
      await attempt(
        'room_members',
        memberRow(room.roomId, third, { ...grant, subject_key_id: thirdKey, grantor_key_id: userKey }),
      ),
    ).toBe(SQLSTATE.foreignKeyViolation);
  });

  it("refuses an invitation grant by a key that is not the inviter's, or with a malformed signature", async () => {
    const room = await insertRoom(api);
    const stranger = await insertUser(api);
    const strangerKey = await insertKeyPair(api, stranger);
    expect(await attempt('invitations', await invitationRow(room, { grantor_key_id: strangerKey }))).toBe(
      SQLSTATE.foreignKeyViolation,
    );
    expect(await attempt('invitations', await invitationRow(room, { grant_signature: DUMMY.ciphertext(32) }))).toBe(
      SQLSTATE.checkViolation,
    );
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
    // The same rule for the signing key of the identity bundle (ADR-015).
    expect(await attempt('user_key_pairs', await keyPairRow(user, { encrypted_signing_private_key: null }))).toBe(
      SQLSTATE.checkViolation,
    );
    expect(
      await attempt(
        'user_key_pairs',
        await keyPairRow(user, { status: 'SUPERSEDED', encrypted_private_key: null, superseded_at: new Date() }),
      ),
    ).toBe(SQLSTATE.checkViolation);
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
    // Identity signing key and vault format (ADR-015, migration 20261005000000)
    ['a signing key that is not a 91-byte P-256 SPKI', { signing_public_key_spki: DUMMY.ciphertext(120) }],
    ['a binding signature that is not 64 bytes', { identity_signature: DUMMY.ciphertext(72) }],
    ['a 16-byte signing-key IV', { signing_private_key_iv: DUMMY.ciphertext(16) }],
    [
      'a signing-key ciphertext too short for a wrapped PKCS#8 key',
      { encrypted_signing_private_key: DUMMY.ciphertext(32) },
    ],
    ['a signing-key ciphertext of content size', { encrypted_signing_private_key: DUMMY.ciphertext(300) }],
    ['an encryption-key ciphertext of content size', { encrypted_private_key: DUMMY.ciphertext(4096) }],
    ['an unknown vault format version', { vault_version: 2 }],
    ['KDF memory above the ceiling (CP-04)', { kdf_memory_kib: 262145 }],
    ['KDF passes above the ceiling', { kdf_iterations: 11 }],
    ['KDF parallelism above the ceiling', { kdf_parallelism: 5 }],
    ['a re-wrap time before creation', { created_at: new Date(), rewrapped_at: new Date(Date.now() - 60_000) }],
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

describe('encrypted file lifecycle (Phase 7, migration 20261007000000_encrypted_files)', () => {
  it('accepts only server-generated object keys and an object deletion marker on tombstones', async () => {
    const room = await insertRoom(api);
    for (const objectKey of [
      `rooms/${randomUUID()}`,
      'f/short',
      `f/${'a'.repeat(42)}/`,
      `report.pdf-${'a'.repeat(40)}`,
    ]) {
      expect(await attempt('encrypted_files', fileRow(room, { object_key: objectKey })), objectKey).toBe(
        SQLSTATE.checkViolation,
      );
    }
    expect(await attempt('encrypted_files', fileRow(room, { object_deleted_at: new Date() }))).toBe(
      SQLSTATE.checkViolation,
    );
  });

  it('keeps identity columns write-once, lets key material only disappear and DELETED stay final', async () => {
    const room = await insertRoom(api);
    const row = fileRow(room);
    await insert(api, 'encrypted_files', row);
    const id = row['id'];
    const someoneElse = await insertUser(api);
    for (const [sql, values] of [
      ['UPDATE encrypted_files SET object_key = $2 WHERE id = $1', [`f/${'b'.repeat(43)}`]],
      ['UPDATE encrypted_files SET key_version = 2 WHERE id = $1', []],
      ['UPDATE encrypted_files SET uploader_id = $2 WHERE id = $1', [someoneElse]],
      ['UPDATE encrypted_files SET ciphertext_sha256 = $2 WHERE id = $1', [DUMMY.digest().fill(7)]],
      ['UPDATE encrypted_files SET content_iv = $2 WHERE id = $1', [DUMMY.iv().fill(7)]],
      ['UPDATE encrypted_files SET wrapped_dek = $2 WHERE id = $1', [DUMMY.wrappedDek().fill(7)]],
      ['UPDATE encrypted_files SET manifest_ciphertext = $2 WHERE id = $1', [DUMMY.ciphertext().fill(7)]],
    ] as const) {
      expect(await run(sql, [id, ...values]), sql).toBe(SQLSTATE.integrityConstraintViolation);
    }
    expect(await run("UPDATE encrypted_files SET status = 'AVAILABLE', uploaded_at = now() WHERE id = $1", [id])).toBe(
      'none',
    );
    expect(
      await run("UPDATE encrypted_files SET status = 'PENDING_UPLOAD', uploaded_at = NULL WHERE id = $1", [id]),
    ).toBe(SQLSTATE.integrityConstraintViolation);
    expect(await run("UPDATE encrypted_files SET expires_at = now() + interval '1 day' WHERE id = $1", [id])).toBe(
      'none',
    );
    expect(await run("UPDATE encrypted_files SET expires_at = now() + interval '2 days' WHERE id = $1", [id])).toBe(
      SQLSTATE.integrityConstraintViolation,
    );
    expect(await run('UPDATE encrypted_files SET expires_at = NULL WHERE id = $1', [id])).toBe(
      SQLSTATE.integrityConstraintViolation,
    );
    const tombstone =
      "UPDATE encrypted_files SET status = 'DELETED', wrapped_dek = NULL, manifest_ciphertext = NULL, deleted_at = now() WHERE id = $1";
    expect(await run(tombstone, [id])).toBe('none');
    expect(await run("UPDATE encrypted_files SET status = 'AVAILABLE' WHERE id = $1", [id])).toBe(
      SQLSTATE.integrityConstraintViolation,
    );
    expect(await run('UPDATE encrypted_files SET object_deleted_at = now() WHERE id = $1', [id])).toBe('none');
    expect(
      await run("UPDATE encrypted_files SET object_deleted_at = now() + interval '1 hour' WHERE id = $1", [id]),
    ).toBe(SQLSTATE.integrityConstraintViolation);
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
        `UPDATE user_key_pairs SET status = 'SUPERSEDED', encrypted_private_key = NULL,
           encrypted_signing_private_key = NULL, superseded_at = now() WHERE id = $1`,
        [key],
      ),
    ).toBe('none');
  });

  it('never changes the signing key or the binding signature, but allows a re-wrap (ADR-015)', async () => {
    const user = await insertUser(api);
    const key = await insertKeyPair(api, user);
    expect(
      await run('UPDATE user_key_pairs SET signing_public_key_spki = $2 WHERE id = $1', [
        key,
        DUMMY.ciphertext(91).fill(2),
      ]),
    ).toBe(SQLSTATE.integrityConstraintViolation);
    expect(
      await run('UPDATE user_key_pairs SET identity_signature = $2 WHERE id = $1', [key, DUMMY.ciphertext(64).fill(3)]),
    ).toBe(SQLSTATE.integrityConstraintViolation);
    // A passphrase change replaces the salt, parameters, IVs and ciphertexts of the same identity.
    expect(
      await run(
        `UPDATE user_key_pairs SET kdf_salt = $2, kdf_iterations = 4, private_key_iv = $3,
           encrypted_private_key = $4, signing_private_key_iv = $3, encrypted_signing_private_key = $5,
           rewrapped_at = now() WHERE id = $1`,
        [
          key,
          DUMMY.ciphertext(16).fill(4),
          DUMMY.ciphertext(12).fill(5),
          DUMMY.ciphertext(1810).fill(6),
          DUMMY.ciphertext(154).fill(7),
        ],
      ),
    ).toBe('none');
  });

  it('a retired identity can never become ACTIVE again', async () => {
    const user = await insertUser(api);
    const key = await insertKeyPair(api, user);
    await run(
      `UPDATE user_key_pairs SET status = 'SUPERSEDED', encrypted_private_key = NULL,
         encrypted_signing_private_key = NULL, superseded_at = now() WHERE id = $1`,
      [key],
    );
    expect(
      await run(
        `UPDATE user_key_pairs SET status = 'ACTIVE', encrypted_private_key = $2, encrypted_signing_private_key = $3,
           superseded_at = NULL WHERE id = $1`,
        [key, DUMMY.encryptedPrivateKey(), DUMMY.encryptedSigningPrivateKey()],
      ),
    ).toBe(SQLSTATE.integrityConstraintViolation);
  });

  it('never replaces a signed statement: genesis, key-version statement or invitation grant (ADR-015)', async () => {
    const room = await insertRoom(api);
    for (const [sql, values] of [
      ['UPDATE rooms SET genesis_signature = $2 WHERE id = $1', [room.roomId, DUMMY.signature().fill(1)]],
      ['UPDATE rooms SET creator_key_id = NULL, genesis_signature = NULL WHERE id = $1', [room.roomId]],
      [
        'UPDATE room_key_versions SET statement_signature = $2 WHERE room_id = $1',
        [room.roomId, DUMMY.signature().fill(1)],
      ],
      ['UPDATE room_key_versions SET recipient_user_ids = $2 WHERE room_id = $1', [room.roomId, [randomUUID()]]],
      ['UPDATE room_key_versions SET created_by_key_id = $2 WHERE room_id = $1', [room.roomId, randomUUID()]],
    ] as const) {
      expect(await run(sql, [...values]), sql).toBe(SQLSTATE.integrityConstraintViolation);
    }
    const invitationId = randomUUID();
    await insert(api, 'invitations', { id: invitationId, ...(await invitationRow(room)) });
    for (const [column, value] of [
      ['grant_signature', DUMMY.signature().fill(2)],
      ['role', 'ADMIN'],
      ['expires_at', new Date(Date.now() + 999_000_000)],
      ['invitee_key_id', randomUUID()],
    ] as const) {
      expect(await run(`UPDATE invitations SET ${column} = $2 WHERE id = $1`, [invitationId, value]), column).toBe(
        SQLSTATE.integrityConstraintViolation,
      );
    }
    // Status and timestamps stay updatable.
    expect(await run(`UPDATE invitations SET status = 'REVOKED' WHERE id = $1`, [invitationId])).toBe('none');
    expect(await run(`UPDATE rooms SET name = 'Renamed' WHERE id = $1`, [room.roomId])).toBe('none');
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
    signing_public_key_spki: DUMMY.signingSpki(),
    public_key_fingerprint: randomUUID().replaceAll('-', '').padEnd(64, 'f'),
    identity_signature: DUMMY.signature(),
    encrypted_private_key: DUMMY.encryptedPrivateKey(),
    private_key_iv: DUMMY.iv(),
    encrypted_signing_private_key: DUMMY.encryptedSigningPrivateKey(),
    signing_private_key_iv: DUMMY.iv(),
    vault_version: 1,
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
