import {
  authenticateSecretRecipient,
  computeSafetyCode,
  CryptoErrorCode,
  createInitialRoomKey,
  createInvitationKeys,
  createRekeyKeys,
  formatFingerprint,
  grantProofToWire,
  grantsFromWire,
  invitationKeysToWire,
  isCryptoError,
  openRoomKey,
  publicIdentityFromWire,
  rekeyKeysToWire,
  reviewRekeyRecipients,
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
  rekeyCancelledResponseSchema,
  rekeyFinalizedResponseSchema,
  rekeyStartedResponseSchema,
  reshareResponseSchema,
  roomKeyStateResponseSchema,
  roomSummarySchema,
  type RekeyStartedResponse,
  type RoomInvitation,
  type RoomKeyStateResponse,
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

/** One recipient of a rekey as this browser checked it, for the review list (no keys). */
export interface RekeyRecipientView {
  readonly userId: string;
  readonly displayName: string;
  readonly kind: 'MEMBER' | 'INVITEE';
  /** The fingerprint computed here from the verified keys, in groups of four. */
  readonly fingerprint: string;
  /** False for a key the room's signed statements never named (after a vault reset): compare it. */
  readonly knownHolder: boolean;
}

/** A started rekey operation, reviewed in this tab and waiting for the reviewer's confirmation. */
interface PendingReview {
  readonly roomId: string;
  readonly started: RekeyStartedResponse;
  readonly recipients: readonly VerifiedIdentity[];
}

/** Thrown when a rekey is finalized in a tab that did not review its snapshot (or the vault locked). */
export class RekeyReviewMissing extends Error {
  readonly code = 'REKEY_REVIEW_MISSING';
  constructor() {
    super('Start the rotation again');
    this.name = 'RekeyReviewMissing';
  }
}

class RoomKeys {
  readonly #opened = new Map<string, readonly OpenedRoomKey[]>();
  readonly #listeners = new Set<Listener>();
  /** Reviewed rekey snapshots by operation ID: public identities only, dropped with the vault keys. */
  readonly #reviews = new Map<string, PendingReview>();

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
    this.#reviews.clear();
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

  // ------------------------------------------------------------------- key rotation (Phase 11)

  /** AZ-15: the room's key state, reasons, cryptoperiod and live rekey operation. */
  keyState(roomId: string): Promise<RoomKeyStateResponse> {
    return api('GET', `/rooms/${roomId}/rekey-operations/current`, roomKeyStateResponseSchema);
  }

  /**
   * Starts a rekey (AZ-13, ADR-013 step 1) and checks the server's recipient snapshot here before any
   * key is made (step 2.1): the room's statements must verify for this browser and every recipient's
   * identity must verify on its own. Returns the list to show for review; nothing is created yet.
   */
  async startRekey(roomId: string): Promise<{ started: RekeyStartedResponse; recipients: RekeyRecipientView[] }> {
    return vaultController.withUnlockedVault(async (vault) => {
      const started = await api('POST', `/rooms/${roomId}/rekey-operations`, rekeyStartedResponseSchema, {});
      const base = await this.#base(vault, roomId, started.operation.baseVersion);
      const reviewed = await reviewRekeyRecipients(
        vault,
        {
          ...base,
          grants: [...base.grants, ...grantsFromWire(roomId, started.grants)],
          identities: [...base.identities, ...started.identities.map((i) => publicIdentityFromWire(i, i.userId))],
        },
        started.recipients.map((r) => publicIdentityFromWire(r.identity, r.userId)),
      );
      this.#reviews.set(started.operation.id, { roomId, started, recipients: reviewed.map((r) => r.identity) });
      return {
        started,
        recipients: reviewed.map((r, i) => ({
          userId: r.identity.userId,
          displayName: started.recipients[i]?.displayName ?? '',
          kind: started.recipients[i]?.kind ?? 'MEMBER',
          fingerprint: formatFingerprint(r.identity.fingerprint).join(' '),
          knownHolder: r.knownHolder,
        })),
      };
    });
  }

  /**
   * Makes key version v+1 for the reviewed recipients (ADR-013 step 2), sends the commitment, the
   * signed statement and the envelopes (step 3), and then opens the room's keys again from what the
   * server serves: the new version counts only after it passed the verification rule here, never
   * because the server answered 200. Returns the verified new version.
   */
  async finalizeRekey(roomId: string, operationId: string): Promise<number> {
    const review = this.#reviews.get(operationId);
    if (review === undefined || review.roomId !== roomId) throw new RekeyReviewMissing();
    const target = await vaultController.withUnlockedVault(async (vault) => {
      const base = await this.#base(vault, roomId, review.started.operation.baseVersion);
      const { keys } = await createRekeyKeys(vault, { roomId, base, recipients: review.recipients });
      const done = await api(
        'POST',
        `/rooms/${roomId}/rekey-operations/${operationId}/finalize`,
        rekeyFinalizedResponseSchema,
        rekeyKeysToWire(keys),
      );
      return done.keyVersion;
    });
    this.#reviews.delete(operationId);
    const opened = await this.open(roomId);
    if (opened.at(-1)?.keyVersion !== target) throw new RoomKeyMissing();
    return target;
  }

  /** AZ-13, OL-13: the starter or the OWNER cancels a live operation; the room stays as locked as it was. */
  async cancelRekey(roomId: string, operationId: string): Promise<void> {
    this.#reviews.delete(operationId);
    await api('POST', `/rooms/${roomId}/rekey-operations/${operationId}/cancel`, rekeyCancelledResponseSchema, {});
  }

  /** A member's current identity, verified here, for the fingerprint shown before a re-share. */
  async memberIdentity(roomId: string, memberId: string): Promise<VerifiedIdentity> {
    const response = await api('GET', `/rooms/${roomId}/members/${memberId}/identity`, memberIdentityResponseSchema);
    return verifyPublicIdentity(publicIdentityFromWire(response.identity, response.userId));
  }

  /**
   * AZ-14 (CM-T053): wraps the versions the profile allows to the member's verified current identity
   * and signs a grant for the member's role, exactly as for an invitation; the server re-checks it.
   */
  async reshare(input: {
    readonly roomId: string;
    readonly member: VerifiedIdentity;
    readonly role: 'ADMIN' | 'MEMBER' | 'VIEWER';
    readonly confirmedFingerprint: string | null;
    readonly currentVersionOnly: boolean;
  }): Promise<number[]> {
    return vaultController.withUnlockedVault(async (vault) => {
      const all = await this.#bundles(vault, input.roomId);
      const newest = all.at(-1);
      if (newest === undefined) throw new RoomKeyMissing();
      const keys = await createInvitationKeys(vault, {
        roomId: input.roomId,
        bundles: input.currentVersionOnly ? [newest] : all,
        invitee: input.member,
        role: input.role,
      });
      const wire = invitationKeysToWire(keys);
      const path = `/rooms/${input.roomId}/members/${input.member.userId}/reshare`;
      const done = await api('POST', path, reshareResponseSchema, {
        subjectKeyId: input.member.keyId,
        confirmedFingerprint: input.confirmedFingerprint,
        grantSignature: wire.grantSignature,
        envelopes: wire.envelopes,
      });
      return done.keyVersions;
    });
  }

  /** The bundle of the base version (the newest this identity holds), chained when this tab verified v-1. */
  async #base(vault: UnlockedVault, roomId: string, baseVersion: number): Promise<RoomKeyBundle> {
    const bundles = await this.#bundles(vault, roomId);
    const base = bundles.at(-1);
    if (base?.keyVersion.keyVersion !== baseVersion) throw new RoomKeyMissing();
    const previous = this.version(roomId, baseVersion - 1);
    return previous === undefined ? base : { ...base, verifiedPreviousCommitment: previous.commitment };
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
