import { hkdfSync, randomUUID } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import { contextBytes } from './contexts';
import { toBase64Url } from './encoding';
import { CryptoErrorCode, isCryptoError } from './errors';
import { generateIdentity } from './identity';
import {
  grantProofToWire,
  invitationKeysToWire,
  openRoomKeys,
  roomCreationKeysToWire,
  roomKeyBundlesFromWire,
  type EnvelopeWire,
  type RoomKeyMaterialWire,
} from './room-format';
import { createInitialRoomKey, createInvitationKeys, signMembershipGrant } from './room-keys';
import { keyVersionStatement } from './room-statements';
import { wrap32 } from './rsa-oaep';
import { signStatement } from './signing';
import { publicIdentityToWire } from './vault-format';
import type { UnlockedVault } from './vault';

// The wire layer of Phase 6 (room-format.ts): what POST /rooms and the invitation routes send and
// what GET key-versions and GET envelopes return. Server data is untrusted: anything malformed
// must fail closed as KEY_AUTHENTICATION_FAILED, never as a partial key set.
let owner: UnlockedVault;
let roomId: string;
let material: RoomKeyMaterialWire;
let envelopes: EnvelopeWire[];

async function vault(): Promise<UnlockedVault> {
  const g = await generateIdentity(randomUUID());
  return { identity: g.identity, encryptionPrivateKey: g.encryptionPrivateKey, signingPrivateKey: g.signingPrivateKey };
}

const self = (v: UnlockedVault) => ({ userId: v.identity.userId, keyId: v.identity.keyId });
const refused = async (fn: () => unknown): Promise<void> => {
  let caught: unknown;
  try {
    await fn();
  } catch (error) {
    caught = error;
  }
  expect(isCryptoError(caught, CryptoErrorCode.KEY_AUTHENTICATION_FAILED), String(caught)).toBe(true);
};

beforeAll(async () => {
  owner = await vault();
  roomId = randomUUID();
  const { keys } = await createInitialRoomKey(owner, roomId);
  const wire = roomCreationKeysToWire(keys);
  material = {
    genesis: {
      creatorUserId: owner.identity.userId,
      creatorKeyId: owner.identity.keyId,
      suite: 'CM1',
      signature: wire.genesisSignature,
    },
    keyVersions: [
      {
        keyVersion: 1,
        status: 'ACTIVE',
        suite: 'CM1',
        commitment: wire.commitment,
        previousCommitment: null,
        creatorUserId: owner.identity.userId,
        creatorKeyId: owner.identity.keyId,
        recipients: [self(owner)],
        signature: wire.keyVersionSignature,
      },
    ],
    grants: [],
    identities: [{ userId: owner.identity.userId, ...publicIdentityToWire(owner.identity) }],
  };
  envelopes = [{ keyVersion: 1, recipientKeyId: owner.identity.keyId, wrappedKey: wire.envelope }];
}, 120_000);

describe('room key wire format (CM-T033, CM-T036)', () => {
  it('turns what the server serves into bundles that open, and the creation keys into plain base64url', async () => {
    const bundles = roomKeyBundlesFromWire(roomId, self(owner), material, envelopes);
    expect(bundles).toHaveLength(1);
    const opened = await openRoomKeys(owner, bundles);
    expect(opened.map((k) => k.keyVersion)).toEqual([1]);
    const { keys } = await createInitialRoomKey(owner, randomUUID());
    expect(roomCreationKeysToWire(keys)).toEqual({
      creatorKeyId: owner.identity.keyId,
      commitment: toBase64Url(keys.commitment),
      envelope: toBase64Url(keys.envelope),
      genesisSignature: toBase64Url(keys.genesisSignature),
      keyVersionSignature: toBase64Url(keys.keyVersionSignature),
    });
  });

  it('skips versions without an envelope for this identity key and DESTROYED versions', () => {
    const other = { userId: randomUUID(), keyId: randomUUID() };
    expect(roomKeyBundlesFromWire(roomId, other, material, envelopes)).toEqual([]);
    const destroyed = { ...material, keyVersions: material.keyVersions.map((v) => ({ ...v, status: 'DESTROYED' })) };
    expect(roomKeyBundlesFromWire(roomId, self(owner), destroyed, envelopes)).toEqual([]);
  });

  it('a room without a genesis statement (created before Phase 6, L-43) has no keys to open', () => {
    expect(roomKeyBundlesFromWire(roomId, self(owner), { ...material, genesis: null }, envelopes)).toEqual([]);
  });

  it('fails closed on malformed or unsupported server data', async () => {
    const v1 = material.keyVersions[0];
    if (v1 === undefined) throw new Error('fixture');
    const bad = (change: Partial<RoomKeyMaterialWire>) => () =>
      roomKeyBundlesFromWire(roomId, self(owner), { ...material, ...change }, envelopes);
    await refused(bad({ genesis: { ...(material.genesis as object), suite: 'CM2' } as never }));
    await refused(bad({ keyVersions: [{ ...v1, suite: 'CM2' }] }));
    await refused(bad({ keyVersions: [{ ...v1, commitment: v1.commitment.slice(1) }] }));
    await refused(bad({ keyVersions: [{ ...v1, commitment: '+'.repeat(43) }] }));
    await refused(bad({ keyVersions: [{ ...v1, signature: 'AA' }] }));
    await refused(bad({ keyVersions: [{ ...v1, previousCommitment: 'AA' }] }));
    await refused(bad({ genesis: { ...(material.genesis as object), signature: 'A' } as never }));
    await refused(
      bad({
        grants: [
          {
            subjectUserId: randomUUID(),
            subjectKeyId: randomUUID(),
            role: 'ROOT',
            grantorUserId: randomUUID(),
            grantorKeyId: randomUUID(),
            signature: 'AA',
          },
        ],
      }),
    );
    await refused(
      bad({
        grants: [
          {
            subjectUserId: randomUUID(),
            subjectKeyId: randomUUID(),
            role: 'MEMBER',
            grantorUserId: randomUUID(),
            grantorKeyId: randomUUID(),
            signature: 'AA',
          },
        ],
      }),
    );
    await refused(bad({ identities: [{ ...(material.identities[0] as object), suite: 'CM2' } as never] }));
    await refused(() =>
      roomKeyBundlesFromWire(roomId, self(owner), material, [{ ...(envelopes[0] as EnvelopeWire), wrappedKey: 'AA' }]),
    );
  });

  it('opens a chain of versions and refuses a fork of the previous commitment (T-32)', async () => {
    const v1 = material.keyVersions[0];
    if (v1 === undefined) throw new Error('fixture');
    // A synthetic version 2 signed by the creator (the real rekey is Phase 11).
    const rkm = new Uint8Array(32).fill(5);
    const commitment = new Uint8Array(
      hkdfSync('sha256', rkm, Buffer.alloc(32), contextBytes('cm.room.commitment', { roomId, keyVersion: 2 }), 32),
    );
    const sign = (previous: Uint8Array<ArrayBuffer>) =>
      signStatement(
        owner.signingPrivateKey,
        keyVersionStatement({
          roomId,
          keyVersion: 2,
          commitment,
          previousCommitment: previous,
          creatorUserId: owner.identity.userId,
          creatorKeyId: owner.identity.keyId,
          recipients: [self(owner)],
        }),
      );
    const label = contextBytes('cm.room.envelope', {
      roomId,
      keyVersion: 2,
      recipientUserId: owner.identity.userId,
      recipientKeyId: owner.identity.keyId,
      suite: 'CM1',
    });
    const envelope2 = toBase64Url(await wrap32(owner.identity.encryptionPublicKey, rkm.slice(), label));
    const withV2 = async (previous: Uint8Array<ArrayBuffer>) => ({
      ...material,
      keyVersions: [
        { ...v1, status: 'RETIRED' },
        {
          ...v1,
          keyVersion: 2,
          commitment: toBase64Url(commitment),
          previousCommitment: toBase64Url(previous),
          signature: toBase64Url(await sign(previous)),
        },
      ],
    });
    const all = [...envelopes, { keyVersion: 2, recipientKeyId: owner.identity.keyId, wrappedKey: envelope2 }];
    const honest = await withV2(new Uint8Array(Buffer.from(v1.commitment, 'base64url')));
    const opened = await openRoomKeys(owner, roomKeyBundlesFromWire(roomId, self(owner), honest, all));
    expect(opened.map((k) => k.keyVersion)).toEqual([1, 2]);
    // Version 2 names a previous commitment that is not the one this client verified for version 1.
    const forked = await withV2(new Uint8Array(32).fill(9));
    await refused(() => openRoomKeys(owner, roomKeyBundlesFromWire(roomId, self(owner), forked, all)));
  });

  it('encodes invitation keys and grant proofs for the requests', async () => {
    const invitee = await vault();
    const bundles = roomKeyBundlesFromWire(roomId, self(owner), material, envelopes);
    const keys = await createInvitationKeys(owner, { roomId, bundles, invitee: invitee.identity, role: 'MEMBER' });
    const wire = invitationKeysToWire(keys);
    expect(wire.envelopes.map((e) => e.keyVersion)).toEqual([1]);
    expect(Buffer.from(wire.envelopes[0]?.wrappedKey ?? '', 'base64url')).toHaveLength(384);
    expect(Buffer.from(wire.grantSignature, 'base64url')).toHaveLength(64);
    const proof = await signMembershipGrant(owner, { roomId, subject: invitee.identity, role: 'ADMIN' });
    expect(grantProofToWire(proof)).toEqual({
      subjectKeyId: invitee.identity.keyId,
      signature: toBase64Url(proof.signature),
    });
  });
});
