import { contextBytes, type CanonicalBytes } from './contexts';
import { toBase64Url } from './encoding';
import { CryptoError, CryptoErrorCode } from './errors';
import type { VerifiedIdentity } from './identity';
import { ROOM_KEYS, SUITE, type RoomRole } from './params';
import type { RecipientRef } from './recipients';
import { verifyStatement } from './signing';
import type { Bytes } from './types';

/**
 * Signed room statements (ADR-015 section 4, as specified in Phase 6). Three canonical statements,
 * each signed with the ECDSA P-256 identity key (CP-26) of the user it names as signer:
 *
 *   cm.room.genesis           {roomId, creatorUserId, creatorKeyId, suite}
 *       signed by the room creator; the root of the room's authority chain.
 *   cm.room.membership-grant  {roomId, subjectUserId, subjectKeyId, role, grantorUserId, grantorKeyId}
 *       signed by the grantor: the inviter for an invitation, the OWNER for every ADMIN grant and
 *       every ownership transfer (role OWNER).
 *   cm.room.key-version       {roomId, keyVersion, commitment, previousCommitment, suite,
 *                              creatorUserId, creatorKeyId, recipients}
 *       signed by the OWNER or ADMIN who created version v; `recipients` is the sorted list of
 *       user and identity key IDs that received an envelope when the version was created.
 *
 * The room ID is a field of every statement, so a statement of one room never verifies for
 * another. This module only builds bytes and checks signatures against public keys; it holds no
 * private key, so the API uses it too (@ciphermesh/crypto/identity) and verifies exactly the bytes
 * that browsers sign. What a signature means for authority is decided in room-keys.ts.
 */

export interface GenesisStatement {
  readonly roomId: string;
  readonly creatorUserId: string;
  readonly creatorKeyId: string;
}

export interface MembershipGrantStatement {
  readonly roomId: string;
  readonly subjectUserId: string;
  readonly subjectKeyId: string;
  readonly role: RoomRole;
  readonly grantorUserId: string;
  readonly grantorKeyId: string;
}

export interface KeyVersionStatement {
  readonly roomId: string;
  readonly keyVersion: number;
  /** RKC_v = HKDF(RKM_v, info = cm.room.commitment {roomId, keyVersion}), 32 bytes. */
  readonly commitment: Bytes;
  /** RKC_(v-1) for a rekeyed version; null exactly for version 1. */
  readonly previousCommitment: Bytes | null;
  readonly creatorUserId: string;
  readonly creatorKeyId: string;
  /** Sorted by user ID, then key ID (recipients.ts); the builder refuses any other order. */
  readonly recipients: readonly RecipientRef[];
}

export function genesisStatement(s: GenesisStatement): CanonicalBytes {
  return contextBytes('cm.room.genesis', {
    roomId: s.roomId,
    creatorUserId: s.creatorUserId,
    creatorKeyId: s.creatorKeyId,
    suite: SUITE,
  });
}

export function membershipGrantStatement(s: MembershipGrantStatement): CanonicalBytes {
  return contextBytes('cm.room.membership-grant', {
    roomId: s.roomId,
    subjectUserId: s.subjectUserId,
    subjectKeyId: s.subjectKeyId,
    role: s.role,
    grantorUserId: s.grantorUserId,
    grantorKeyId: s.grantorKeyId,
  });
}

/**
 * Builds the key-version statement. Version 1 has no previous commitment and every later version
 * has one; anything else is refused before any bytes are produced.
 */
export function keyVersionStatement(s: KeyVersionStatement): CanonicalBytes {
  if ((s.keyVersion === 1) !== (s.previousCommitment === null)) {
    throw new CryptoError(CryptoErrorCode.INVALID_INPUT);
  }
  if (s.commitment.length !== ROOM_KEYS.commitmentBytes) throw new CryptoError(CryptoErrorCode.INVALID_INPUT);
  return contextBytes('cm.room.key-version', {
    roomId: s.roomId,
    keyVersion: s.keyVersion,
    commitment: toBase64Url(s.commitment),
    previousCommitment: s.previousCommitment === null ? null : toBase64Url(s.previousCommitment),
    suite: SUITE,
    creatorUserId: s.creatorUserId,
    creatorKeyId: s.creatorKeyId,
    recipients: s.recipients,
  });
}

/**
 * Verifies a statement signature under a verified identity that must be the named signer. False
 * for a different user or key ID, a malformed signature or a wrong signature.
 */
export async function verifyStatementBy(
  signer: VerifiedIdentity,
  expected: { readonly userId: string; readonly keyId: string },
  statement: CanonicalBytes,
  signature: Bytes,
): Promise<boolean> {
  if (signer.userId !== expected.userId || signer.keyId !== expected.keyId) return false;
  return verifyStatement(signer.signingPublicKey, statement, signature);
}
