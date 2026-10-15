import { createPublicKey, hkdfSync, randomUUID, verify as nodeVerify } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { generateDataKey, unwrapDataKey, wrapDataKey } from './aead';
import { contextBytes } from './contexts';
import { CryptoErrorCode, isCryptoError } from './errors';
import { importKeyMaterial, deriveWrappingKey } from './hkdf';
import { generateIdentity, type PublicIdentity } from './identity';
import { rsaOaepDecryptRaw } from './internal/raw';
import { sortRecipients, type RecipientRef } from './recipients';
import {
  computeSafetyCode,
  createInitialRoomKey,
  createRekeyKeys,
  openRoomKey,
  reviewRekeyRecipients,
  signMembershipGrant,
  type RoomKeyBundle,
  type SignedKeyVersion,
  type SignedMembershipGrant,
} from './room-keys';
import { rekeyKeysToWire } from './room-format';
import { keyVersionStatement } from './room-statements';
import { signStatement } from './signing';
import type { Bytes } from './types';
import type { UnlockedVault } from './vault';

// Building a room with members generates several RSA-3072 key pairs. Alone that takes about a
// second, but in a full run (every project in parallel, and the negative-control baseline) it has
// reached Vitest's 5 s default (observed twice on 2026-10-15, once at 5051 ms, passing alone each
// time). The tests' assertions are unchanged; only the time they may take.
vi.setConfig({ testTimeout: 60_000 });

// Phase 11 (CM-T050, CM-T051, ADR-013, ADR-015 section 4): a rekey made in a browser. Fresh key
// material, the signed key-version statement with the previous commitment, one envelope per
// recipient, and the verification rule applied to the new version by every recipient, including
// the tamper cases (T-21, T-29, T-36). Independent cross-checks use Node.js crypto (OpenSSL).

const ZERO_SALT = Buffer.alloc(32);
const json = (value: unknown): Buffer => Buffer.from(JSON.stringify(value), 'utf8');

async function person(): Promise<UnlockedVault> {
  const generated = await generateIdentity(randomUUID());
  return {
    identity: generated.identity,
    encryptionPrivateKey: generated.encryptionPrivateKey,
    signingPrivateKey: generated.signingPrivateKey,
  };
}
/** A new identity for the same user, as after a vault reset (key-lifecycle section 3). */
async function resetOf(v: UnlockedVault): Promise<UnlockedVault> {
  const generated = await generateIdentity(v.identity.userId);
  return {
    identity: generated.identity,
    encryptionPrivateKey: generated.encryptionPrivateKey,
    signingPrivateKey: generated.signingPrivateKey,
  };
}
const self = (v: UnlockedVault): RecipientRef => ({ userId: v.identity.userId, keyId: v.identity.keyId });
const publicOf = (v: UnlockedVault): PublicIdentity => ({
  userId: v.identity.userId,
  keyId: v.identity.keyId,
  suite: v.identity.suite,
  encryptionKeySpki: v.identity.encryptionKeySpki,
  signingKeySpki: v.identity.signingKeySpki,
  bindingSignature: v.identity.bindingSignature,
  fingerprint: v.identity.fingerprint,
});
const envelopeLabel = (roomId: string, keyVersion: number, to: RecipientRef) =>
  contextBytes('cm.room.envelope', {
    roomId,
    keyVersion,
    recipientUserId: to.userId,
    recipientKeyId: to.keyId,
    suite: 'CM1',
  });

async function rejects(promise: Promise<unknown>, code: string): Promise<void> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  expect(isCryptoError(caught), String(caught)).toBe(true);
  expect((caught as { code: string }).code).toBe(code);
}
const refused = (promise: Promise<unknown>) => rejects(promise, CryptoErrorCode.KEY_AUTHENTICATION_FAILED);

/**
 * A room with an OWNER, an ADMIN (OWNER grant) and a MEMBER (ADMIN grant), every one holding
 * version 1 (the OWNER through the recipient list, the others through their grants), as the
 * server would serve it.
 */
async function roomWithMembers() {
  const owner = await person();
  const admin = await person();
  const member = await person();
  const roomId = randomUUID();
  const { keys } = await createInitialRoomKey(owner, roomId);
  const rkm1 = await rsaOaepDecryptRaw(
    owner.encryptionPrivateKey,
    keys.envelope,
    envelopeLabel(roomId, 1, self(owner)),
  );
  const signedGrant = async (
    grantor: UnlockedVault,
    subject: UnlockedVault,
    role: 'ADMIN' | 'MEMBER',
  ): Promise<SignedMembershipGrant> => ({
    roomId,
    subjectUserId: subject.identity.userId,
    subjectKeyId: subject.identity.keyId,
    role,
    grantorUserId: grantor.identity.userId,
    grantorKeyId: grantor.identity.keyId,
    signature: (await signMembershipGrant(grantor, { roomId, subject: subject.identity, role })).signature,
  });
  const grants = [await signedGrant(owner, admin, 'ADMIN'), await signedGrant(admin, member, 'MEMBER')];
  const genesis = {
    roomId,
    creatorUserId: owner.identity.userId,
    creatorKeyId: owner.identity.keyId,
    signature: keys.genesisSignature,
  };
  const v1: SignedKeyVersion = {
    roomId,
    keyVersion: 1,
    commitment: keys.commitment,
    previousCommitment: null,
    creatorUserId: owner.identity.userId,
    creatorKeyId: owner.identity.keyId,
    recipients: [self(owner)],
    signature: keys.keyVersionSignature,
  };
  const identities = [owner, admin, member].map(publicOf);
  /** The bundle of version 1 for one person (each holds an envelope wrapped to their key). */
  const v1For = async (who: UnlockedVault): Promise<RoomKeyBundle> => ({
    roomId,
    genesis,
    keyVersion: v1,
    grants,
    identities,
    envelope: await wrapTo(who, 1, rkm1),
  });
  const wrapTo = async (who: UnlockedVault, keyVersion: number, rkm: Bytes): Promise<Bytes> => {
    const { wrap32 } = await import('./rsa-oaep');
    return wrap32(who.identity.encryptionPublicKey, rkm, envelopeLabel(roomId, keyVersion, self(who)));
  };
  return { roomId, owner, admin, member, rkm1, genesis, v1, grants, identities, v1For };
}

type Room = Awaited<ReturnType<typeof roomWithMembers>>;

/** Version 2 as the server would serve it to `who`, from the finalize payload of `keys`. */
function v2For(
  room: Room,
  creator: UnlockedVault,
  keys: Awaited<ReturnType<typeof createRekeyKeys>>['keys'],
  who: UnlockedVault,
  extra: { readonly identities?: readonly PublicIdentity[] } = {},
): RoomKeyBundle {
  const envelope = keys.envelopes.find((e) => e.userId === who.identity.userId && e.keyId === who.identity.keyId);
  if (envelope === undefined) throw new Error('no envelope for this person');
  return {
    roomId: room.roomId,
    genesis: room.genesis,
    keyVersion: {
      roomId: room.roomId,
      keyVersion: keys.keyVersion,
      commitment: keys.commitment,
      previousCommitment: room.v1.commitment,
      creatorUserId: creator.identity.userId,
      creatorKeyId: creator.identity.keyId,
      recipients: keys.envelopes.map((e) => ({ userId: e.userId, keyId: e.keyId })),
      signature: keys.signature,
    },
    grants: room.grants,
    identities: [...room.identities, ...(extra.identities ?? [])],
    envelope: envelope.wrappedKey,
    verifiedPreviousCommitment: room.v1.commitment,
  };
}

describe('createRekeyKeys: a new key version made in the browser (CM-T050, DF-10)', () => {
  it('draws fresh material, commits to it, signs the statement and wraps it once per recipient', async () => {
    const room = await roomWithMembers();
    const recipients = [room.owner, room.admin, room.member].map((p) => p.identity);
    const { keys, opened } = await createRekeyKeys(room.admin, {
      roomId: room.roomId,
      base: await room.v1For(room.admin),
      recipients,
    });
    expect(keys.keyVersion).toBe(2);
    expect(opened.keyVersion).toBe(2);
    // Canonical order, exactly the recipients, one envelope each.
    expect(keys.envelopes.map((e) => ({ userId: e.userId, keyId: e.keyId }))).toEqual(
      sortRecipients(recipients.map((r) => ({ userId: r.userId, keyId: r.keyId }))),
    );
    // Every envelope opens (OpenSSL-independent label check is in room-keys.test.ts) to the same
    // 32 bytes, which are not RKM_1, and whose HKDF commitment Node.js computes independently.
    const holders = [room.owner, room.admin, room.member];
    const values = await Promise.all(
      holders.map(async (p) => {
        const e = keys.envelopes.find((x) => x.userId === p.identity.userId);
        return rsaOaepDecryptRaw(
          p.encryptionPrivateKey,
          e?.wrappedKey ?? new Uint8Array(),
          envelopeLabel(room.roomId, 2, self(p)),
        );
      }),
    );
    for (const value of values) expect(Buffer.from(value).equals(Buffer.from(values[0] ?? []))).toBe(true);
    const rkm2 = Buffer.from(values[0] ?? []);
    expect(rkm2.length).toBe(32);
    expect(rkm2.equals(Buffer.from(room.rkm1))).toBe(false);
    const info = json({ ctx: 'cm.room.commitment', keyVersion: 2, roomId: room.roomId, v: 1 });
    expect(Buffer.from(keys.commitment).equals(Buffer.from(hkdfSync('sha256', rkm2, ZERO_SALT, info, 32)))).toBe(true);
    // The signature verifies with OpenSSL over the canonical statement, previous commitment included.
    const statement = keyVersionStatement({
      roomId: room.roomId,
      keyVersion: 2,
      commitment: keys.commitment,
      previousCommitment: room.v1.commitment,
      creatorUserId: room.admin.identity.userId,
      creatorKeyId: room.admin.identity.keyId,
      recipients: keys.envelopes.map((e) => ({ userId: e.userId, keyId: e.keyId })),
    });
    const spki = createPublicKey({ key: Buffer.from(room.admin.identity.signingKeySpki), format: 'der', type: 'spki' });
    expect(nodeVerify('sha256', statement, { key: spki, dsaEncoding: 'ieee-p1363' }, Buffer.from(keys.signature))).toBe(
      true,
    );
    // The wire form carries public values and ciphertext only.
    const wire = rekeyKeysToWire(keys);
    expect(Object.keys(wire).sort()).toEqual(['commitment', 'envelopes', 'statementSignature', 'targetVersion']);
    expect(JSON.stringify(wire)).not.toContain(rkm2.toString('base64url'));
  });

  it('every recipient verifies version 2, chained to version 1, with one Safety Code that differs from v1', async () => {
    const room = await roomWithMembers();
    const { keys } = await createRekeyKeys(room.admin, {
      roomId: room.roomId,
      base: await room.v1For(room.admin),
      recipients: [room.owner, room.admin, room.member].map((p) => p.identity),
    });
    const codes = new Set<string>();
    for (const p of [room.owner, room.admin, room.member]) {
      const opened = await openRoomKey(p, v2For(room, room.admin, keys, p));
      expect(opened.authorization).toEqual({ kind: 'recipient-list' });
      expect(opened.creator.userId).toBe(room.admin.identity.userId);
      codes.add((await computeSafetyCode(opened)).words.join(' '));
    }
    expect(codes.size).toBe(1);
    const v1Code = await computeSafetyCode(await openRoomKey(room.owner, await room.v1For(room.owner)));
    expect(codes.has(v1Code.words.join(' '))).toBe(false);
  });

  it('a departed member holding RKM_1 cannot unwrap a DEK created after the rekey (CM-T051, L-04)', async () => {
    const room = await roomWithMembers();
    // The MEMBER is removed: the snapshot holds only the OWNER and the ADMIN.
    const { keys, opened } = await createRekeyKeys(room.admin, {
      roomId: room.roomId,
      base: await room.v1For(room.admin),
      recipients: [room.owner.identity, room.admin.identity],
    });
    expect(keys.envelopes.some((e) => e.userId === room.member.identity.userId)).toBe(false);
    const dek = await generateDataKey();
    const fileId = randomUUID();
    const aad = (keyVersion: number) =>
      contextBytes('cm.dek.wrap', { roomId: room.roomId, keyVersion, itemType: 'file', itemId: fileId, revision: 0 });
    const wrapped = await wrapDataKey(dek, opened.wrappingKey, aad(2));
    // What the departed member can derive from the key material they kept.
    const old = await importKeyMaterial(room.rkm1.slice());
    for (const keyVersion of [1, 2]) {
      const rwk = await deriveWrappingKey(
        old,
        contextBytes('cm.room.dek-wrap-key', { roomId: room.roomId, keyVersion }),
      );
      await rejects(unwrapDataKey(wrapped, rwk, aad(2)), CryptoErrorCode.AUTHENTICATION_FAILED);
    }
    // Neither can they open another recipient's envelope under their own key.
    const ownerEnvelope = keys.envelopes.find((e) => e.userId === room.owner.identity.userId);
    await refused(
      openRoomKey(room.member, {
        ...v2For(room, room.admin, keys, room.owner),
        envelope: ownerEnvelope?.wrappedKey ?? new Uint8Array(),
      }),
    );
  });

  it('refuses inputs that would make an unusable or unattributed version', async () => {
    const room = await roomWithMembers();
    const base = await room.v1For(room.admin);
    const make = (recipients: readonly UnlockedVault[], roomId = room.roomId, b = base) =>
      createRekeyKeys(room.admin, { roomId, base: b, recipients: recipients.map((p) => p.identity) });
    await rejects(make([room.owner, room.member]), CryptoErrorCode.INVALID_INPUT); // without the creator
    await rejects(make([room.admin, room.admin]), CryptoErrorCode.INVALID_INPUT); // duplicate
    await rejects(make([]), CryptoErrorCode.INVALID_INPUT);
    await rejects(make([room.admin], randomUUID()), CryptoErrorCode.INVALID_INPUT); // base of another room
    // A base version the creator cannot verify (forged statement) produces nothing.
    const forged = { ...base, keyVersion: { ...base.keyVersion, commitment: new Uint8Array(32).fill(7) } };
    await refused(make([room.admin], room.roomId, forged));
    // A MEMBER can make bytes, but no member accepts a version they signed (authority, ADR-015).
    const byMember = await createRekeyKeys(room.member, {
      roomId: room.roomId,
      base: await room.v1For(room.member),
      recipients: [room.owner.identity, room.member.identity],
    });
    await refused(openRoomKey(room.owner, v2For(room, room.member, byMember.keys, room.owner)));
  });
});

describe('opening a rekeyed version refuses every tampered field (ADR-015 section 4, T-36)', () => {
  async function rekeyed() {
    const room = await roomWithMembers();
    const { keys } = await createRekeyKeys(room.admin, {
      roomId: room.roomId,
      base: await room.v1For(room.admin),
      recipients: [room.owner, room.admin, room.member].map((p) => p.identity),
    });
    return { room, keys, good: v2For(room, room.admin, keys, room.member) };
  }

  it('accepts the untouched version and refuses each modified statement field', async () => {
    const { room, good } = await rekeyed();
    await expect(openRoomKey(room.member, good)).resolves.toBeDefined();
    const kv = good.keyVersion;
    const variants: Partial<RoomKeyBundle['keyVersion']>[] = [
      { commitment: new Uint8Array(32).fill(1) },
      { previousCommitment: new Uint8Array(32).fill(2) },
      { keyVersion: 3 },
      { creatorUserId: room.owner.identity.userId, creatorKeyId: room.owner.identity.keyId },
      { recipients: kv.recipients.filter((r) => r.userId !== room.owner.identity.userId) },
      { recipients: [...kv.recipients].reverse() },
    ];
    for (const change of variants) {
      const bundle = { ...good, keyVersion: { ...kv, ...change } };
      await expect(openRoomKey(room.member, bundle)).rejects.toSatisfy(isCryptoError);
    }
    const flipped = new Uint8Array(kv.signature);
    flipped[10] = (flipped[10] ?? 0) ^ 0x01;
    await refused(openRoomKey(room.member, { ...good, keyVersion: { ...kv, signature: flipped } }));
    // A statement of this version moved to another room.
    await refused(openRoomKey(room.member, { ...good, roomId: randomUUID() }));
  });

  it('refuses a fork: a v2 whose previous commitment is not the v1 this client verified', async () => {
    const { room, keys } = await rekeyed();
    // The server shows this member another, validly signed chain: v1' then a v2 bound to v1'.
    const forkedPrevious = new Uint8Array(32).fill(9);
    const statement = keyVersionStatement({
      roomId: room.roomId,
      keyVersion: 2,
      commitment: keys.commitment,
      previousCommitment: forkedPrevious,
      creatorUserId: room.admin.identity.userId,
      creatorKeyId: room.admin.identity.keyId,
      recipients: keys.envelopes.map((e) => ({ userId: e.userId, keyId: e.keyId })),
    });
    const signature = await signStatement(room.admin.signingPrivateKey, statement);
    const bundle = v2For(room, room.admin, keys, room.member);
    await refused(
      openRoomKey(room.member, {
        ...bundle,
        keyVersion: { ...bundle.keyVersion, previousCommitment: forkedPrevious, signature },
      }),
    );
  });

  it('refuses an envelope of another recipient, another version or another room (cross-recipient substitution)', async () => {
    const { room, keys, good } = await rekeyed();
    const of = (who: UnlockedVault) => keys.envelopes.find((e) => e.userId === who.identity.userId)?.wrappedKey;
    await refused(openRoomKey(room.member, { ...good, envelope: of(room.owner) ?? new Uint8Array() }));
    // RKM_2 wrapped to the member under version 1's label, and under another room's label.
    const rkm2 = await rsaOaepDecryptRaw(
      room.owner.encryptionPrivateKey,
      of(room.owner) ?? new Uint8Array(),
      envelopeLabel(room.roomId, 2, self(room.owner)),
    );
    const { wrap32 } = await import('./rsa-oaep');
    const underV1 = await wrap32(
      room.member.identity.encryptionPublicKey,
      rkm2,
      envelopeLabel(room.roomId, 1, self(room.member)),
    );
    await refused(openRoomKey(room.member, { ...good, envelope: underV1 }));
    const otherRoom = await wrap32(
      room.member.identity.encryptionPublicKey,
      rkm2,
      envelopeLabel(randomUUID(), 2, self(room.member)),
    );
    await refused(openRoomKey(room.member, { ...good, envelope: otherRoom }));
    // Malformed envelope sizes are refused before decryption.
    await refused(openRoomKey(room.member, { ...good, envelope: new Uint8Array(383) }));
  });

  it("refuses a version signed by an ADMIN's new key (after a vault reset) that no grant names", async () => {
    const { room, keys } = await rekeyed();
    // The ADMIN reset their vault. The new key holds no grant yet: it cannot verify version 1, so
    // the package will not make a version from it...
    const resetAdmin = await resetOf(room.admin);
    const attempt = await createRekeyKeys(resetAdmin, {
      roomId: room.roomId,
      base: await room.v1For(resetAdmin),
      recipients: [room.owner.identity, resetAdmin.identity],
    }).catch((e: unknown) => e);
    expect(isCryptoError(attempt, CryptoErrorCode.KEY_AUTHENTICATION_FAILED)).toBe(true);
    // ...and a version signed by it anyway (a server holding that key) is refused by members,
    // although the old key's ADMIN grant still authorizes what the old key signed (L-46).
    const recipients = keys.envelopes.map((e) => ({ userId: e.userId, keyId: e.keyId }));
    const signature = await signStatement(
      resetAdmin.signingPrivateKey,
      keyVersionStatement({
        roomId: room.roomId,
        keyVersion: 2,
        commitment: keys.commitment,
        previousCommitment: room.v1.commitment,
        creatorUserId: resetAdmin.identity.userId,
        creatorKeyId: resetAdmin.identity.keyId,
        recipients,
      }),
    );
    const good = v2For(room, room.admin, keys, room.member, { identities: [publicOf(resetAdmin)] });
    await expect(openRoomKey(room.member, good)).resolves.toBeDefined();
    await refused(
      openRoomKey(room.member, {
        ...good,
        keyVersion: {
          ...good.keyVersion,
          creatorUserId: resetAdmin.identity.userId,
          creatorKeyId: resetAdmin.identity.keyId,
          signature,
        },
      }),
    );
  });
});

describe('reviewRekeyRecipients: the snapshot is checked before any key is made (ADR-013 step 2.1)', () => {
  it('verifies every identity and flags a key the room has never signed (after a vault reset)', async () => {
    const room = await roomWithMembers();
    const resetMember = await resetOf(room.member);
    const reviewed = await reviewRekeyRecipients(room.admin, await room.v1For(room.admin), [
      publicOf(room.owner),
      publicOf(room.admin),
      publicOf(resetMember),
    ]);
    expect(reviewed.map((r) => [r.identity.userId, r.knownHolder])).toEqual([
      [room.owner.identity.userId, true],
      [room.admin.identity.userId, true],
      [room.member.identity.userId, false],
    ]);
  });

  it('refuses duplicates, a snapshot without this client, an empty one and a forged identity', async () => {
    const room = await roomWithMembers();
    const base = await room.v1For(room.admin);
    await refused(reviewRekeyRecipients(room.admin, base, [publicOf(room.admin), publicOf(room.admin)]));
    await refused(reviewRekeyRecipients(room.admin, base, [publicOf(room.admin), publicOf(await resetOf(room.admin))]));
    await refused(reviewRekeyRecipients(room.admin, base, [publicOf(room.owner)]));
    await refused(reviewRekeyRecipients(room.admin, base, []));
    // A key the server attached to the member's user ID: the binding signature names another user.
    const intruder = await person();
    const substituted = { ...publicOf(intruder), userId: room.member.identity.userId };
    await refused(reviewRekeyRecipients(room.admin, base, [publicOf(room.admin), substituted]));
    // Statements that do not verify for this client stop the review.
    await refused(
      reviewRekeyRecipients(room.admin, { ...base, genesis: { ...base.genesis, signature: new Uint8Array(64) } }, [
        publicOf(room.admin),
      ]),
    );
  });
});
