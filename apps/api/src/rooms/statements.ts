import {
  fromBase64Url,
  genesisStatement,
  keyVersionStatement,
  membershipGrantStatement,
  publicIdentityToWire,
  verifyPublicIdentity,
  verifyStatementBy,
  type PublicIdentityWire,
  type VerifiedIdentity,
} from '@ciphermesh/crypto/identity';
import type { RoomRole } from '@ciphermesh/shared';
import type { IdentityRecord } from '../db/room-key-store';

/**
 * Server-side checks of the signed room statements (ADR-015 section 4, Phase 6). The API rebuilds
 * the canonical statements with the same builders the browsers use (@ciphermesh/crypto/identity)
 * and verifies each signature under the signer's stored, verified public identity before it stores
 * anything. This is defence in depth and keeps garbage out of the database; the members' browsers
 * verify everything again, because a compromised server could skip these checks (T-36).
 *
 * Nothing here touches room key material: the server never has any (INV-01, INV-04).
 */

export const toBytes = (value: Uint8Array): Uint8Array<ArrayBuffer> => new Uint8Array(value);

/** Strict, canonical base64url decoding to an exact size, or undefined. */
export function decodeExact(text: string, length: number): Uint8Array<ArrayBuffer> | undefined {
  try {
    return fromBase64Url(text, length);
  } catch {
    return undefined;
  }
}

/** Verifies a stored identity row as every client does (binding signature, fingerprint, key formats). */
export async function verifiedIdentity(record: IdentityRecord): Promise<VerifiedIdentity | undefined> {
  if (record.algorithmSuite !== 'CM1') return undefined;
  try {
    return await verifyPublicIdentity({
      userId: record.userId,
      keyId: record.keyId,
      suite: 'CM1',
      encryptionKeySpki: toBytes(record.publicKeySpki),
      signingKeySpki: toBytes(record.signingPublicKeySpki),
      bindingSignature: toBytes(record.identitySignature),
      fingerprint: record.publicKeyFingerprint,
    });
  } catch {
    return undefined;
  }
}

/** A stored identity in the wire form of the directory and the signer list. */
export function identityToWire(record: IdentityRecord): PublicIdentityWire & { readonly userId: string } {
  return {
    userId: record.userId,
    ...publicIdentityToWire({
      userId: record.userId,
      keyId: record.keyId,
      suite: 'CM1',
      encryptionKeySpki: toBytes(record.publicKeySpki),
      signingKeySpki: toBytes(record.signingPublicKeySpki),
      bindingSignature: toBytes(record.identitySignature),
      fingerprint: record.publicKeyFingerprint,
    }),
  };
}

const self = (identity: VerifiedIdentity) => ({ userId: identity.userId, keyId: identity.keyId });

/** cm.room.genesis and the version-1 cm.room.key-version statement of a new room (CM-T033). */
export async function verifyRoomCreation(
  creator: VerifiedIdentity,
  input: {
    readonly roomId: string;
    readonly commitment: Uint8Array;
    readonly genesisSignature: Uint8Array;
    readonly keyVersionSignature: Uint8Array;
  },
): Promise<boolean> {
  try {
    const ids = { roomId: input.roomId, creatorUserId: creator.userId, creatorKeyId: creator.keyId };
    const genesisOk = await verifyStatementBy(
      creator,
      self(creator),
      genesisStatement(ids),
      toBytes(input.genesisSignature),
    );
    const versionOk = await verifyStatementBy(
      creator,
      self(creator),
      keyVersionStatement({
        ...ids,
        keyVersion: 1,
        commitment: toBytes(input.commitment),
        previousCommitment: null,
        recipients: [self(creator)],
      }),
      toBytes(input.keyVersionSignature),
    );
    return genesisOk && versionOk;
  } catch {
    return false;
  }
}

/** cm.room.membership-grant signed by `grantor` for `subject` with `role` (CM-T034, AZ-05, AZ-10). */
export async function verifyGrant(
  grantor: VerifiedIdentity,
  input: {
    readonly roomId: string;
    readonly subjectUserId: string;
    readonly subjectKeyId: string;
    readonly role: RoomRole;
    readonly signature: Uint8Array;
  },
): Promise<boolean> {
  try {
    return await verifyStatementBy(
      grantor,
      self(grantor),
      membershipGrantStatement({
        roomId: input.roomId,
        subjectUserId: input.subjectUserId,
        subjectKeyId: input.subjectKeyId,
        role: input.role,
        grantorUserId: grantor.userId,
        grantorKeyId: grantor.keyId,
      }),
      toBytes(input.signature),
    );
  } catch {
    return false;
  }
}
