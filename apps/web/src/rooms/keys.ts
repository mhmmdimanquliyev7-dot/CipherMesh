import {
  authenticateSecretRecipient,
  computeSafetyCode,
  CryptoErrorCode,
  createInitialRoomKey,
  createInvitationKeys,
  grantProofToWire,
  invitationKeysToWire,
  isCryptoError,
  openRoomKey,
  publicIdentityFromWire,
  roomCreationKeysToWire,
  roomKeyBundlesFromWire,
  signMembershipGrant,
  verifyPublicIdentity,
  type OpenedRoomKey,
  type RoomKeyBundle,
  type SafetyCode,
  type SecretRecipient,
  type UnlockedVault,
  type VerifiedIdentity,
} from '@ciphermesh/crypto';
import {
  envelopesResponseSchema,
  invitationCreatedResponseSchema,
  keyVersionsResponseSchema,
  memberIdentityResponseSchema,
  recordedResponseSchema,
  roomSummarySchema,
  type RoomInvitation,
} from '@ciphermesh/validation';
import { api } from '../lib/api';
import { vaultController } from '../vault/controller';

/**
 * Room keys in this tab (Phase 6, CM-T033 to CM-T036, CM-T085). All cryptography is done by
 * @ciphermesh/crypto with the unlocked identity keys (vaultController.withUnlockedVault); this
 * module only sequences it with the API and keeps the opened keys.
 *
 * Memory only: opened room keys are non-extractable CryptoKeys held in a private map. They are
 * never put into React state, browser storage, cookies, URLs or the DOM, and the map is cleared
 * whenever the vault drops its keys (lock, auto-lock, sign-out, identity change). There is no
 * "remember room key" feature. Raw room key material exists only inside the crypto package while
 * a key is created, opened or wrapped for an invitee, and is overwritten afterwards (L-15).
 *
 * A key is used only after the verification rule of ADR-015 section 4 passed in this browser; the
 * server's word is never enough. A refused key is reported (AZ-29) with its version only.
 */

/** Thrown when the room has no key this identity can open (no envelope for it, L-43, CM-T053). */
export class RoomKeyMissing extends Error {
  readonly code = 'ROOM_KEY_MISSING';
  constructor() {
    super('No room key for your current identity');
    this.name = 'RoomKeyMissing';
  }
}

type Listener = () => void;

class RoomKeys {
  readonly #opened = new Map<string, readonly OpenedRoomKey[]>();
  readonly #listeners = new Set<Listener>();

  constructor() {
    vaultController.onKeysDropped(() => {
      this.clear();
    });
  }

  readonly subscribe = (listener: Listener): (() => void) => {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  };

  /** Whether this tab holds verified keys for the room (for rendering only; never the keys). */
  isOpen(roomId: string): boolean {
    return this.#opened.has(roomId);
  }

  clear(): void {
    if (this.#opened.size === 0) return;
    this.#opened.clear();
    for (const listener of this.#listeners) listener();
  }

  #store(roomId: string, keys: readonly OpenedRoomKey[]): void {
    this.#opened.set(roomId, keys);
    for (const listener of this.#listeners) listener();
  }

  async #bundles(vault: UnlockedVault, roomId: string): Promise<RoomKeyBundle[]> {
    const [material, envelopes] = await Promise.all([
      api('GET', `/rooms/${roomId}/key-versions`, keyVersionsResponseSchema),
      api('GET', `/rooms/${roomId}/envelopes`, envelopesResponseSchema),
    ]);
    return roomKeyBundlesFromWire(
      roomId,
      { userId: vault.identity.userId, keyId: vault.identity.keyId },
      material,
      envelopes.envelopes,
    );
  }

  /** Reports a refused key version: the version and the kind of failure only (AZ-29). */
  async #report(roomId: string, keyVersion: number, error: unknown): Promise<void> {
    const problem = isCryptoError(error, CryptoErrorCode.KEY_COMMITMENT_MISMATCH)
      ? 'COMMITMENT_MISMATCH'
      : 'AUTHENTICATION_FAILED';
    try {
      await api('POST', `/rooms/${roomId}/key-reports`, recordedResponseSchema, { keyVersion, problem });
    } catch {
      // The refusal stands whether or not the report reaches the server.
    }
  }

  /**
   * Fetches and verifies every key version this identity holds, oldest first. Any refused version
   * stops the whole room: no partial key set is kept, and the refusal is reported.
   */
  async open(roomId: string): Promise<readonly OpenedRoomKey[]> {
    const opened = await vaultController.withUnlockedVault(async (vault) => {
      const bundles = await this.#bundles(vault, roomId);
      if (bundles.length === 0) throw new RoomKeyMissing();
      const keys: OpenedRoomKey[] = [];
      for (const bundle of bundles) {
        const previous = keys.find((k) => k.keyVersion === bundle.keyVersion.keyVersion - 1);
        try {
          keys.push(
            await openRoomKey(
              vault,
              previous === undefined ? bundle : { ...bundle, verifiedPreviousCommitment: previous.commitment },
            ),
          );
        } catch (error) {
          await this.#report(roomId, bundle.keyVersion.keyVersion, error);
          throw error;
        }
      }
      return keys;
    });
    this.#store(roomId, opened);
    return opened;
  }

  /** The newest opened key version of the room, if this tab holds one. */
  current(roomId: string): OpenedRoomKey | undefined {
    return this.#opened.get(roomId)?.at(-1);
  }

  /**
   * A specific opened key version of the room (Phase 7): a file names the version that wrapped
   * its FEK, which need not be the newest. Undefined when this tab holds no verified key for it.
   */
  version(roomId: string, keyVersion: number): OpenedRoomKey | undefined {
    return this.#opened.get(roomId)?.find((k) => k.keyVersion === keyVersion);
  }

  /** The Room Safety Code of the newest opened version, computed here (INV-18). */
  async safetyCode(roomId: string): Promise<SafetyCode | undefined> {
    const key = this.current(roomId);
    return key === undefined ? undefined : computeSafetyCode(key);
  }

  /** Creates a room with key version 1 made in this browser (CM-T033, DF-05). */
  async createRoom(name: string, securityProfile: string): Promise<string> {
    const { roomId, opened } = await vaultController.withUnlockedVault(async (vault) => {
      const id = crypto.randomUUID();
      const { keys, opened: key } = await createInitialRoomKey(vault, id);
      const created = await api('POST', '/rooms', roomSummarySchema, {
        roomId: id,
        name,
        securityProfile,
        keys: roomCreationKeysToWire(keys),
      });
      return { roomId: created.id, opened: key };
    });
    this.#store(roomId, [opened]);
    return roomId;
  }

  /**
   * Invites a verified identity (CM-T034, DF-06): every key version this browser holds and the
   * profile allows is verified again, wrapped to the invitee and the grant signed here.
   */
  async invite(input: {
    readonly roomId: string;
    readonly invitee: VerifiedIdentity;
    readonly role: 'ADMIN' | 'MEMBER' | 'VIEWER';
    readonly confirmedFingerprint: string | null;
    readonly currentVersionOnly: boolean;
  }): Promise<RoomInvitation> {
    return vaultController.withUnlockedVault(async (vault) => {
      const all = await this.#bundles(vault, input.roomId);
      const newest = all.at(-1);
      if (newest === undefined) throw new RoomKeyMissing();
      const keys = await createInvitationKeys(vault, {
        roomId: input.roomId,
        bundles: input.currentVersionOnly ? [newest] : all,
        invitee: input.invitee,
        role: input.role,
      });
      const created = await api('POST', `/rooms/${input.roomId}/invitations`, invitationCreatedResponseSchema, {
        inviteeUserId: input.invitee.userId,
        inviteeKeyId: input.invitee.keyId,
        role: input.role,
        confirmedFingerprint: input.confirmedFingerprint,
        ...invitationKeysToWire(keys),
      });
      return created.invitation;
    });
  }

  /**
   * Authenticates the member a secret is for (Phase 9, CM-T043): the member's current identity,
   * with the member's own signed grant chain, must be named by the room's verified statements for
   * this client (ADR-015 section 4). The server's word about the member's key is never enough; a
   * key it substituted is refused before anything is wrapped to it (T-25).
   */
  async secretRecipient(roomId: string, memberId: string): Promise<SecretRecipient> {
    return vaultController.withUnlockedVault(async (vault) => {
      const [member, material, envelopes] = await Promise.all([
        api('GET', `/rooms/${roomId}/members/${memberId}/identity`, memberIdentityResponseSchema),
        api('GET', `/rooms/${roomId}/key-versions`, keyVersionsResponseSchema),
        api('GET', `/rooms/${roomId}/envelopes`, envelopesResponseSchema),
      ]);
      const bundles = roomKeyBundlesFromWire(
        roomId,
        { userId: vault.identity.userId, keyId: vault.identity.keyId },
        {
          ...material,
          grants: [...material.grants, ...member.authority.grants],
          identities: [...material.identities, ...member.authority.identities],
        },
        envelopes.envelopes,
      );
      const newest = bundles.at(-1);
      if (newest === undefined) throw new RoomKeyMissing();
      // Chain the newest version to the previous one when this tab verified it (as open() does).
      const previous = this.version(roomId, newest.keyVersion.keyVersion - 1);
      const bundle = previous === undefined ? newest : { ...newest, verifiedPreviousCommitment: previous.commitment };
      return authenticateSecretRecipient(vault, bundle, publicIdentityFromWire(member.identity, member.userId));
    });
  }

  /**
   * Signs the OWNER's grant for an ADMIN promotion or an ownership transfer (ADR-015 section 4)
   * for the member's current identity, which is verified here first.
   */
  async grant(roomId: string, memberId: string, role: 'ADMIN' | 'OWNER') {
    return vaultController.withUnlockedVault(async (vault) => {
      const response = await api('GET', `/rooms/${roomId}/members/${memberId}/identity`, memberIdentityResponseSchema);
      const subject = await verifyPublicIdentity(publicIdentityFromWire(response.identity, response.userId));
      return grantProofToWire(await signMembershipGrant(vault, { roomId, subject, role }));
    });
  }
}

/** The room keys of this tab. */
export const roomKeys = new RoomKeys();
