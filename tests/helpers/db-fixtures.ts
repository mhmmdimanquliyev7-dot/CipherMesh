import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { PLACEHOLDER_PHC } from '../../scripts/db/synthetic';

// Row fixtures for the database tests. They insert through the given client, normally the
// least-privilege cm_api role, so fixtures can only do what the API role may do.
//
// DUMMY BYTES: every binary value below is a fixed filler pattern of the size the schema
// requires. It is NOT ciphertext, NOT a key and NOT derived from any secret; it only exercises
// length and nullability constraints. Real ciphertext and keys are produced by packages/crypto
// in the browser from Phase 4 on, and are never generated for the database.
export const dummyBytes = (length: number, fill = 0xa5): Buffer => Buffer.alloc(length, fill);

export const DUMMY = {
  digest: () => dummyBytes(32),
  iv: () => dummyBytes(12),
  salt: () => dummyBytes(16),
  spki: () => dummyBytes(422),
  rsaCiphertext: () => dummyBytes(384),
  wrappedDek: () => dummyBytes(48),
  ciphertext: (length = 64) => dummyBytes(length),
  encryptedPrivateKey: () => dummyBytes(1810),
} as const;

/** A syntactically valid Argon2id PHC string that no password produces (not a real hash). */
export { PLACEHOLDER_PHC };

const hexFingerprint = (): string => randomUUID().replaceAll('-', '').padEnd(64, '0');

export async function insertUser(client: pg.Client, overrides: Record<string, unknown> = {}): Promise<string> {
  const id = randomUUID();
  const row = {
    id,
    email: `synthetic-${id}@example.test`,
    display_name: 'Synthetic Test User',
    password_hash: PLACEHOLDER_PHC,
    password_changed_at: new Date(),
    ...overrides,
  };
  await insert(client, 'users', row);
  return row.id;
}

export async function insertKeyPair(
  client: pg.Client,
  userId: string,
  overrides: Record<string, unknown> = {},
): Promise<string> {
  const row = {
    id: randomUUID(),
    user_id: userId,
    status: 'ACTIVE',
    algorithm_suite: 'CM1',
    public_key_spki: DUMMY.spki(),
    public_key_fingerprint: hexFingerprint(),
    encrypted_private_key: DUMMY.encryptedPrivateKey(),
    private_key_iv: DUMMY.iv(),
    kdf_algorithm: 'argon2id',
    kdf_memory_kib: 65536,
    kdf_iterations: 3,
    kdf_parallelism: 1,
    kdf_salt: DUMMY.salt(),
    ...overrides,
  };
  await insert(client, 'user_key_pairs', row);
  return row.id;
}

export interface RoomFixture {
  readonly roomId: string;
  readonly ownerId: string;
  readonly ownerKeyId: string;
}

/** A room with key version 1, its OWNER membership and the owner's envelope. */
export async function insertRoom(client: pg.Client, ownerId?: string): Promise<RoomFixture> {
  const owner = ownerId ?? (await insertUser(client));
  const ownerKeyId = await insertKeyPair(client, owner);
  const roomId = randomUUID();
  await insert(client, 'rooms', {
    id: roomId,
    name: 'Synthetic room',
    security_profile: 'STANDARD',
    policy_version: 1,
    created_by_id: owner,
  });
  await insert(client, 'room_key_versions', {
    room_id: roomId,
    version: 1,
    status: 'ACTIVE',
    commitment: DUMMY.digest(),
    algorithm_suite: 'CM1',
    reasons: '{INITIAL}',
    created_by_id: owner,
  });
  await insert(client, 'room_members', {
    room_id: roomId,
    user_id: owner,
    role: 'OWNER',
    first_key_version: 1,
  });
  await insert(client, 'key_envelopes', {
    room_id: roomId,
    key_version: 1,
    recipient_user_id: owner,
    recipient_key_id: ownerKeyId,
    status: 'ACTIVE',
    wrapped_key: DUMMY.rsaCiphertext(),
    algorithm: 'RSA-OAEP-3072-SHA256',
    created_by_id: owner,
  });
  return { roomId, ownerId: owner, ownerKeyId };
}

export async function insertMember(
  client: pg.Client,
  roomId: string,
  userId: string,
  overrides: Record<string, unknown> = {},
): Promise<string> {
  const row = {
    id: randomUUID(),
    room_id: roomId,
    user_id: userId,
    role: 'MEMBER',
    first_key_version: 1,
    ...overrides,
  };
  await insert(client, 'room_members', row);
  return row.id;
}

export function fileRow(room: RoomFixture, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: randomUUID(),
    room_id: room.roomId,
    uploader_id: room.ownerId,
    key_version: 1,
    status: 'PENDING_UPLOAD',
    algorithm_suite: 'CM1',
    wrapped_dek: DUMMY.wrappedDek(),
    dek_iv: DUMMY.iv(),
    content_iv: DUMMY.iv(),
    manifest_ciphertext: DUMMY.ciphertext(),
    manifest_iv: DUMMY.iv(),
    object_key: `rooms/${randomUUID()}`,
    ciphertext_size: 1024,
    ciphertext_sha256: DUMMY.digest(),
    ...overrides,
  };
}

export function noteRow(room: RoomFixture, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: randomUUID(),
    room_id: room.roomId,
    author_id: room.ownerId,
    updated_by_id: room.ownerId,
    revision: 1,
    key_version: 1,
    algorithm_suite: 'CM1',
    wrapped_dek: DUMMY.wrappedDek(),
    dek_iv: DUMMY.iv(),
    ciphertext: DUMMY.ciphertext(),
    content_iv: DUMMY.iv(),
    ciphertext_sha256: DUMMY.digest(),
    ...overrides,
  };
}

export function secretRow(
  room: RoomFixture,
  recipient: { userId: string; keyId: string },
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    id: randomUUID(),
    room_id: room.roomId,
    sender_id: room.ownerId,
    recipient_user_id: recipient.userId,
    recipient_key_id: recipient.keyId,
    burn_after_reading: true,
    algorithm_suite: 'CM1',
    wrapped_sek: DUMMY.rsaCiphertext(),
    wrap_algorithm: 'RSA-OAEP-3072-SHA256',
    payload_ciphertext: DUMMY.ciphertext(),
    payload_iv: DUMMY.iv(),
    expires_at: new Date(Date.now() + 3_600_000),
    ...overrides,
  };
}

export function auditRow(seq: number, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    seq,
    occurred_at: new Date(),
    actor_type: 'SYSTEM',
    action: 'SYNTHETIC_TEST_EVENT',
    outcome: 'SUCCESS',
    details: '{}',
    prev_hash: DUMMY.digest(),
    event_hash: DUMMY.digest(),
    hash_version: 1,
    ...overrides,
  };
}

/**
 * INSERT with parameter placeholders only. Table and column names come from this file, never
 * from input; they are still quoted as identifiers.
 */
export async function insert(client: pg.Client, table: string, row: Record<string, unknown>): Promise<void> {
  await client.query(...insertStatement(table, row));
}

/** Builds the INSERT statement for sqlStateInSavepoint. */
export function insertStatement(table: string, row: Record<string, unknown>): [string, unknown[]] {
  const columns = Object.keys(row);
  const quoted = columns.map((c) => `"${c.replaceAll('"', '""')}"`).join(', ');
  const placeholders = columns.map((_, i) => `$${i + 1}`).join(', ');
  return [`INSERT INTO "${table.replaceAll('"', '""')}" (${quoted}) VALUES (${placeholders})`, Object.values(row)];
}
