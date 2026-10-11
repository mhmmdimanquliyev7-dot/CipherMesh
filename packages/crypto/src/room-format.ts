import { fromBase64Url, toBase64Url } from './encoding';
import { CryptoError, CryptoErrorCode } from './errors';
import { ECDSA, RSA_OAEP, ROOM_KEYS, ROOM_ROLES, type RoomRole } from './params';
import type { RecipientRef } from './recipients';
import type { InvitationKeys, OpenedRoomKey, RoomCreationKeys, RoomKeyBundle } from './room-keys';
import { openRoomKey } from './room-keys';
import type { Bytes } from './types';
import type { UnlockedVault } from './vault';
import { publicIdentityFromWire, type PublicIdentityWire } from './vault-format';

/**
 * Wire format of room keys (Phase 6): what POST /rooms and POST /rooms/{id}/invitations send, and
 * what GET /rooms/{id}/key-versions and GET /rooms/{id}/envelopes return. Binary values are
 * unpadded base64url (CP-15). Everything that comes from the server is decoded strictly to exact
 * sizes; anything malformed is KEY_AUTHENTICATION_FAILED, because it is untrusted key metadata and
 * the key it describes is refused (fail closed, ADR-015 section 4).
 */

export interface RoomKeyMaterialWire {
  readonly genesis: {
    readonly creatorUserId: string;
    readonly creatorKeyId: string;
    readonly suite: string;
    readonly signature: string;
  } | null;
  readonly keyVersions: readonly {
    readonly keyVersion: number;
    readonly status: string;
    readonly suite: string;
    readonly commitment: string;
    readonly previousCommitment: string | null;
    readonly creatorUserId: string;
    readonly creatorKeyId: string;
    readonly recipients: readonly RecipientRef[];
    readonly signature: string;
  }[];
  readonly grants: readonly {
    readonly subjectUserId: string;
    readonly subjectKeyId: string;
    readonly role: string;
    readonly grantorUserId: string;
    readonly grantorKeyId: string;
    readonly signature: string;
  }[];
  readonly identities: readonly (PublicIdentityWire & { readonly userId: string })[];
}

export interface EnvelopeWire {
  readonly keyVersion: number;
  readonly recipientKeyId: string;
  readonly wrappedKey: string;
}

const refused = (): CryptoError => new CryptoError(CryptoErrorCode.KEY_AUTHENTICATION_FAILED);

function decode(text: string, length: number): Bytes {
  try {
    return fromBase64Url(text, length);
  } catch {
    throw refused();
  }
}

const isRole = (value: string): value is RoomRole => (ROOM_ROLES as readonly string[]).includes(value);

/**
 * The bundles this client can try to open: one per key version that has an envelope for its own
 * identity key. Versions without such an envelope are skipped (for example history the room's
 * profile did not share, PC-07). A missing genesis means a room created before Phase 6 (L-43): it
 * has no key, so there is nothing to open.
 */
export function roomKeyBundlesFromWire(
  roomId: string,
  self: RecipientRef,
  material: RoomKeyMaterialWire,
  envelopes: readonly EnvelopeWire[],
): RoomKeyBundle[] {
  const genesis = material.genesis;
  if (genesis === null) return [];
  if (genesis.suite !== 'CM1') throw refused();
  const identities = material.identities.map((wire) => {
    try {
      return publicIdentityFromWire(wire, wire.userId);
    } catch {
      throw refused();
    }
  });
  const grants = material.grants.map((g) => {
    if (!isRole(g.role)) throw refused();
    return {
      roomId,
      subjectUserId: g.subjectUserId,
      subjectKeyId: g.subjectKeyId,
      role: g.role,
      grantorUserId: g.grantorUserId,
      grantorKeyId: g.grantorKeyId,
      signature: decode(g.signature, ECDSA.signatureBytes),
    };
  });
  const bundles: RoomKeyBundle[] = [];
  for (const version of material.keyVersions) {
    if (version.status === 'DESTROYED') continue;
    const own = envelopes.find((e) => e.keyVersion === version.keyVersion && e.recipientKeyId === self.keyId);
    if (own === undefined) continue;
    if (version.suite !== 'CM1') throw refused();
    bundles.push({
      roomId,
      genesis: {
        roomId,
        creatorUserId: genesis.creatorUserId,
        creatorKeyId: genesis.creatorKeyId,
        signature: decode(genesis.signature, ECDSA.signatureBytes),
      },
      keyVersion: {
        roomId,
        keyVersion: version.keyVersion,
        commitment: decode(version.commitment, ROOM_KEYS.commitmentBytes),
        previousCommitment:
          version.previousCommitment === null ? null : decode(version.previousCommitment, ROOM_KEYS.commitmentBytes),
        creatorUserId: version.creatorUserId,
        creatorKeyId: version.creatorKeyId,
        recipients: version.recipients.map((r) => ({ userId: r.userId, keyId: r.keyId })),
        signature: decode(version.signature, ECDSA.signatureBytes),
      },
      grants,
      identities,
      envelope: decode(own.wrappedKey, RSA_OAEP.ciphertextBytes),
    });
  }
  return bundles.sort((a, b) => a.keyVersion.keyVersion - b.keyVersion.keyVersion);
}

/**
 * Opens every bundle in version order. A version whose predecessor this client also opened must
 * name that predecessor's commitment, which exposes a forked chain to clients that hold both
 * (ADR-015, T-32). Any refused version stops the whole room: no partial key set is returned.
 */
export async function openRoomKeys(vault: UnlockedVault, bundles: readonly RoomKeyBundle[]): Promise<OpenedRoomKey[]> {
  const opened: OpenedRoomKey[] = [];
  for (const bundle of [...bundles].sort((a, b) => a.keyVersion.keyVersion - b.keyVersion.keyVersion)) {
    const previous = opened.find((o) => o.keyVersion === bundle.keyVersion.keyVersion - 1);
    opened.push(
      await openRoomKey(
        vault,
        previous === undefined ? bundle : { ...bundle, verifiedPreviousCommitment: previous.commitment },
      ),
    );
  }
  return opened;
}

/** The `keys` object of POST /rooms. */
export function roomCreationKeysToWire(keys: RoomCreationKeys) {
  return {
    creatorKeyId: keys.creatorKeyId,
    commitment: toBase64Url(keys.commitment),
    envelope: toBase64Url(keys.envelope),
    genesisSignature: toBase64Url(keys.genesisSignature),
    keyVersionSignature: toBase64Url(keys.keyVersionSignature),
  };
}

/** The key part of POST /rooms/{id}/invitations. */
export function invitationKeysToWire(keys: InvitationKeys) {
  return {
    grantSignature: toBase64Url(keys.grantSignature),
    envelopes: keys.envelopes.map((e) => ({ keyVersion: e.keyVersion, wrappedKey: toBase64Url(e.wrappedKey) })),
  };
}

/** A signed grant in the form of the role-change and transfer requests. */
export function grantProofToWire(proof: { readonly subjectKeyId: string; readonly signature: Bytes }) {
  return { subjectKeyId: proof.subjectKeyId, signature: toBase64Url(proof.signature) };
}
