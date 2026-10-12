import { fromBase64Url } from '@ciphermesh/crypto/identity';
import {
  ErrorCode,
  FILE_LIMITS,
  FILE_QUOTAS,
  auditLevelIncludes,
  type RoomActionId,
  type RoomResourceFacts,
} from '@ciphermesh/shared';
import type { SecurityEventSink } from '../auth/security-events';
import type { Actor, RequestMeta } from '../auth/sessions';
import { policyOf, reapplyRoomPolicy } from '../authorization/policy';
import { reauthorizeRoomAction, roomDenial, type RoomAccess } from '../authorization/rooms';
import { FileIdUnavailableError, type FileRecord } from '../db/file-store';
import type { ListPosition, LockedMembership, LockedRoom, RoomStore } from '../db/room-store';
import { HttpError } from '../http/errors';
import { factsOf } from '../rooms/service';
import { newObjectKey, StorageError, type ObjectStore, type StorageCapability } from '../storage/object-store';

/**
 * Encrypted files (Phase 7, CM-T037 to CM-T041; DF-07, DF-08, data-model 4.11 and 5).
 *
 * The API never sees a file's content, name, type or plaintext hash, nor its FEK: the browser
 * encrypts and wraps everything with a verified room key and sends ciphertext, the wrapped FEK,
 * IVs and public sizes and hashes (INV-01, INV-16). The API decides who may store and fetch which
 * ciphertext, and hands out presigned URLs for one object, one method and a short time (OL-07).
 *
 * Upload (AZ-16). One transaction locks the uploader's user row, the room and the membership (the
 * established order), re-checks the matrix on that state, then requires: the room's key state
 * ACTIVE (PC-16, REKEY_REQUIRED), the named key version current (KEY_VERSION_STALE), the expiry
 * the profile allows (PC-08), an unused file ID, the quotas (CM-T041), and one more wrap under the
 * key version (CP-16). The file is inserted as PENDING_UPLOAD with a random object key, and the
 * browser receives a presigned PUT for exactly that size. Completion (by the uploader only) checks
 * the stored object's size with HEAD before the same locks and checks again; only then is the
 * file AVAILABLE. A size mismatch, a write lock or a stale key version cancels the upload: the
 * row becomes a tombstone and the object is deleted.
 *
 * Read (AZ-17): only AVAILABLE, unexpired files (INV-14) of the room, for an ACTIVE member. PC-12
 * withholds key material and download URLs from VIEWERs in RESTRICTED rooms.
 *
 * Delete (AZ-18, own for MEMBER): a tombstone in one transaction (wrapped FEK and manifest NULL),
 * then the object is deleted at once; if storage fails, the worker retries (CM-T040).
 */

export interface FileServiceDependencies {
  readonly store: RoomStore;
  readonly transaction: <T>(fn: (store: RoomStore) => Promise<T>) => Promise<T>;
  readonly storage: ObjectStore;
  readonly events: SecurityEventSink;
  readonly clock: () => Date;
}

export interface FileUploadInput {
  readonly fileId: string;
  readonly keyVersion: number;
  readonly suite: 'CM1';
  readonly wrappedFek: string;
  readonly fekIv: string;
  readonly manifest: string;
  readonly manifestIv: string;
  readonly contentIv: string;
  readonly ciphertextSize: number;
  readonly ciphertextSha256: string;
  readonly expiresAt: string | null;
}

const notFound = (): HttpError => new HttpError(404, ErrorCode.NOT_FOUND, 'Resource not found');
const rekeyRequired = (): HttpError =>
  new HttpError(409, ErrorCode.REKEY_REQUIRED, 'The room key must be rotated before new content can be added');
const keyVersionStale = (): HttpError =>
  new HttpError(
    409,
    ErrorCode.KEY_VERSION_STALE,
    'The file was encrypted with a key version that is no longer current',
  );
const storageUnavailable = (): HttpError =>
  new HttpError(503, ErrorCode.STORAGE_UNAVAILABLE, 'File storage is not available right now');
const notPending = (): HttpError =>
  new HttpError(409, ErrorCode.FILE_NOT_PENDING, 'This upload is not waiting for completion');

type CancelReason = 'SIZE_MISMATCH' | 'EXPIRED' | 'REKEY_REQUIRED' | 'KEY_VERSION_STALE';

const CANCEL_ERROR: Readonly<Record<CancelReason, () => HttpError>> = {
  SIZE_MISMATCH: () =>
    new HttpError(422, ErrorCode.UPLOAD_SIZE_MISMATCH, 'The stored file does not match the announced size'),
  EXPIRED: () => new HttpError(409, ErrorCode.UPLOAD_EXPIRED, 'The upload was not completed in time'),
  REKEY_REQUIRED: rekeyRequired,
  KEY_VERSION_STALE: keyVersionStale,
};

export function createFileService(deps: FileServiceDependencies) {
  const { store, transaction, storage, events, clock } = deps;

  /**
   * Locks the room and the actor's membership (in that order) and decides again on that state:
   * the matrix, then the room's policy gates on the locked profile (PC-01, PC-02; CM-T047).
   */
  async function lockAndReauthorize(
    tx: RoomStore,
    actor: Actor,
    roomId: string,
    meta: RequestMeta,
    action: RoomActionId,
    resource?: () => Promise<RoomResourceFacts | null>,
  ): Promise<{ readonly room: LockedRoom; readonly member: LockedMembership }> {
    const request = { actorUserId: actor.userId, requestId: meta.requestId };
    const room = await tx.lockRoom(roomId);
    const member = room === null ? null : await tx.lockMembership(roomId, actor.userId);
    let facts: RoomResourceFacts | undefined;
    if (room !== null && member !== null && resource !== undefined) {
      const loaded = await resource();
      if (loaded === null) throw roomDenial(events, { ...request, action }, 'RESOURCE_NOT_FOUND');
      facts = loaded;
    }
    reauthorizeRoomAction(events, request, {
      actorUserId: actor.userId,
      roomId,
      membership: factsOf(room, member),
      action,
      ...(facts === undefined ? {} : { resource: facts }),
    });
    if (room === null || member === null) throw notFound();
    reapplyRoomPolicy(events, { ...request, action }, actor, room, clock(), false);
    return { room, member };
  }

  /** PC-12: VIEWERs in RESTRICTED rooms never obtain file key material or ciphertext. */
  function mayObtainKeyMaterial(access: RoomAccess): boolean {
    return access.role !== 'VIEWER' || access.policy.viewerMayObtainFileKeys;
  }

  function requireKeyMaterialAccess(actor: Actor, access: RoomAccess, meta: RequestMeta): void {
    if (mayObtainKeyMaterial(access)) return;
    events.record({
      name: 'ROOM_ACCESS_DENIED',
      outcome: 'DENIED',
      actorUserId: actor.userId,
      requestId: meta.requestId,
      details: { action: access.action, reason: 'PROFILE_PC_12' },
    });
    throw new HttpError(403, ErrorCode.FORBIDDEN, 'You do not have permission for this action');
  }

  /** PC-08: the expiry the profile requires and allows, measured from now. */
  function checkExpiry(room: LockedRoom, expiresAt: Date | null, now: Date): void {
    const rules = policyOf(room).contentExpiry;
    const refuse = (): HttpError =>
      new HttpError(422, ErrorCode.EXPIRY_NOT_ALLOWED, 'The expiry is missing or outside what this room allows');
    if (expiresAt === null) {
      if (rules.required) throw refuse();
      return;
    }
    if (expiresAt.getTime() <= now.getTime()) throw refuse();
    if (rules.maxMs !== null && expiresAt.getTime() > now.getTime() + rules.maxMs) throw refuse();
  }

  function decode(value: string): Uint8Array {
    try {
      return fromBase64Url(value);
    } catch {
      throw new HttpError(400, ErrorCode.VALIDATION_FAILED, 'Request validation failed');
    }
  }

  function record(
    name: 'FILE_UPLOADED' | 'FILE_UPLOAD_CANCELLED' | 'FILE_DOWNLOAD_ISSUED' | 'FILE_DELETED' | 'REKEY_REQUIRED',
    actor: Actor,
    meta: RequestMeta,
    details: Readonly<Record<string, string | number | boolean>>,
  ): void {
    events.record({ name, outcome: 'SUCCESS', actorUserId: actor.userId, requestId: meta.requestId, details });
  }

  /** Deletes an object now if storage answers; the worker retries tombstones it could not clear. */
  async function deleteObjectSoon(fileId: string, objectKey: string): Promise<void> {
    try {
      await storage.delete(objectKey);
      await store.markObjectDeleted(fileId, clock());
    } catch {
      // The tombstone is committed; `pnpm worker:retention` deletes the object later (CM-T040).
    }
  }

  /** Cancels an upload: tombstone in its own transaction, then the object. */
  async function cancelUpload(
    actor: Actor,
    access: RoomAccess,
    file: { readonly id: string; readonly objectKey: string },
    reason: CancelReason,
    meta: RequestMeta,
  ): Promise<HttpError> {
    await transaction((tx) => tx.tombstoneFile(access.roomId, file.id, clock()));
    await deleteObjectSoon(file.id, file.objectKey);
    record('FILE_UPLOAD_CANCELLED', actor, meta, { roomId: access.roomId, fileId: file.id, reason });
    return CANCEL_ERROR[reason]();
  }

  return {
    /** AZ-17 list: readable files, newest first; key material only where PC-12 allows it. */
    async listFiles(
      actor: Actor,
      access: RoomAccess,
      after: ListPosition | undefined,
      take: number,
    ): Promise<{ readonly files: FileRecord[]; readonly keyMaterial: boolean }> {
      const files = await store.listRoomFiles(access.roomId, actor.userId, clock(), after, take);
      return { files, keyMaterial: mayObtainKeyMaterial(access) };
    },

    /** AZ-17 key material of one file (DF-08 step 1). Denied to VIEWERs in RESTRICTED rooms (PC-12). */
    async readFile(actor: Actor, access: RoomAccess, fileId: string, meta: RequestMeta): Promise<FileRecord> {
      requireKeyMaterialAccess(actor, access, meta);
      const file = await store.readRoomFile(access.roomId, fileId, actor.userId, clock());
      if (file === null) throw notFound();
      return file;
    },

    /** AZ-16 (DF-07): the PENDING_UPLOAD row and a presigned PUT for exactly the ciphertext size. */
    async startUpload(
      actor: Actor,
      access: RoomAccess,
      input: FileUploadInput,
      meta: RequestMeta,
    ): Promise<{ readonly file: FileRecord; readonly upload: StorageCapability }> {
      if (!storage.available) throw storageUnavailable();
      const now = clock();
      const expiresAt = input.expiresAt === null ? null : new Date(input.expiresAt);
      const values = {
        wrappedDek: decode(input.wrappedFek),
        dekIv: decode(input.fekIv),
        contentIv: decode(input.contentIv),
        manifestCiphertext: decode(input.manifest),
        manifestIv: decode(input.manifestIv),
        ciphertextSha256: decode(input.ciphertextSha256),
      };
      const objectKey = newObjectKey();
      const outcome = await transaction(async (tx) => {
        if (!(await tx.lockUploader(actor.userId))) throw notFound();
        const { room } = await lockAndReauthorize(tx, actor, access.roomId, meta, 'AZ-16');
        if (room.keyState !== 'ACTIVE') throw rekeyRequired();
        if (input.keyVersion !== room.currentKeyVersion) throw keyVersionStale();
        checkExpiry(room, expiresAt, now);
        if (await tx.fileIdUsed(input.fileId)) throw new FileIdUnavailableError();
        const usage = await tx.storageUsage(room.id, actor.userId);
        if (
          usage.userPending >= FILE_QUOTAS.pendingUploadsPerUser ||
          usage.roomBytes + input.ciphertextSize > FILE_QUOTAS.perRoomBytes ||
          usage.userBytes + input.ciphertextSize > FILE_QUOTAS.perUserBytes
        ) {
          throw new HttpError(409, ErrorCode.FILE_QUOTA_EXCEEDED, 'The storage quota for this upload is exhausted');
        }
        if (!(await tx.consumeWrap(room.id, input.keyVersion, now))) return { kind: 'wrap-limit' as const };
        const file = await tx.insertPendingFile({
          id: input.fileId,
          roomId: room.id,
          uploaderId: actor.userId,
          keyVersion: input.keyVersion,
          algorithmSuite: input.suite,
          ...values,
          objectKey,
          ciphertextSize: input.ciphertextSize,
          expiresAt,
          now,
        });
        return { kind: 'ok' as const, file };
      }).catch((error: unknown) => {
        if (error instanceof FileIdUnavailableError) {
          throw new HttpError(409, ErrorCode.FILE_ID_UNAVAILABLE, 'This file ID cannot be used');
        }
        throw error;
      });
      if (outcome.kind === 'wrap-limit') {
        record('REKEY_REQUIRED', actor, meta, { roomId: access.roomId, reason: 'WRAP_LIMIT_REACHED' });
        throw rekeyRequired();
      }
      try {
        return { file: outcome.file, upload: await storage.presignUpload(objectKey, input.ciphertextSize, now) };
      } catch (error) {
        if (error instanceof StorageError) throw storageUnavailable();
        throw error;
      }
    },

    /** AZ-16 completion by the uploader (DF-07): AVAILABLE only after storage confirms the size. */
    async completeUpload(actor: Actor, access: RoomAccess, fileId: string, meta: RequestMeta): Promise<FileRecord> {
      const file = await store.findRoomFile(access.roomId, fileId, true);
      // Another member's upload is invisible: completion belongs to the uploader alone (OL-04).
      if (file === null || file.uploaderId !== actor.userId) throw notFound();
      if (file.status !== 'PENDING_UPLOAD') throw notPending();
      if (clock().getTime() > file.createdAt.getTime() + FILE_LIMITS.completionWindowMs) {
        throw await cancelUpload(actor, access, file, 'EXPIRED', meta);
      }
      let stored: { readonly size: number } | null;
      try {
        stored = await storage.head(file.objectKey);
      } catch {
        throw storageUnavailable();
      }
      if (stored === null) {
        throw new HttpError(409, ErrorCode.UPLOAD_INCOMPLETE, 'The encrypted file has not reached storage yet');
      }
      if (stored.size !== file.ciphertextSize) throw await cancelUpload(actor, access, file, 'SIZE_MISMATCH', meta);

      const outcome = await transaction(async (tx) => {
        const { room } = await lockAndReauthorize(tx, actor, access.roomId, meta, 'AZ-16');
        const locked = await tx.lockRoomFile(room.id, fileId);
        if (locked === null || locked.uploaderId !== actor.userId) throw notFound();
        if (locked.status !== 'PENDING_UPLOAD') throw notPending();
        // Uploads pending when the room was write-locked are cancelled (DF-07, PC-16).
        const cancel: CancelReason | undefined =
          room.keyState !== 'ACTIVE'
            ? 'REKEY_REQUIRED'
            : locked.keyVersion !== room.currentKeyVersion
              ? 'KEY_VERSION_STALE'
              : undefined;
        if (cancel !== undefined) {
          await tx.tombstoneFile(room.id, fileId, clock());
          return { kind: 'cancelled' as const, reason: cancel };
        }
        const completed = await tx.completeFile(room.id, fileId, actor.userId, clock());
        if (completed === null) throw notPending();
        return { kind: 'ok' as const, file: completed };
      });
      if (outcome.kind === 'cancelled') {
        await deleteObjectSoon(file.id, file.objectKey);
        record('FILE_UPLOAD_CANCELLED', actor, meta, { roomId: access.roomId, fileId, reason: outcome.reason });
        throw CANCEL_ERROR[outcome.reason]();
      }
      record('FILE_UPLOADED', actor, meta, {
        roomId: access.roomId,
        fileId,
        keyVersion: outcome.file.keyVersion,
        ciphertextSize: outcome.file.ciphertextSize,
      });
      return outcome.file;
    },

    /** AZ-17 download (DF-08): a presigned GET valid 60 seconds, as an attachment (CP-20). */
    async downloadUrl(actor: Actor, access: RoomAccess, fileId: string, meta: RequestMeta): Promise<StorageCapability> {
      requireKeyMaterialAccess(actor, access, meta);
      const now = clock();
      const file = await store.readRoomFile(access.roomId, fileId, actor.userId, now);
      if (file === null) throw notFound();
      let download: StorageCapability;
      try {
        download = await storage.presignDownload(file.objectKey, now);
      } catch {
        throw storageUnavailable();
      }
      // PC-13: download-URL issuance is recorded at the EXTENDED and FULL audit levels.
      if (auditLevelIncludes(access.policy.auditLevel, 'EXTENDED')) {
        record('FILE_DOWNLOAD_ISSUED', actor, meta, { roomId: access.roomId, fileId });
      }
      return download;
    },

    /** AZ-18 (CM-T040): tombstone now, object at once or by the worker. */
    async deleteFile(actor: Actor, access: RoomAccess, fileId: string, meta: RequestMeta): Promise<void> {
      const objectKey = await transaction(async (tx) => {
        let target: Awaited<ReturnType<RoomStore['lockRoomFile']>> = null;
        const { room } = await lockAndReauthorize(tx, actor, access.roomId, meta, 'AZ-18', async () => {
          target = await tx.lockRoomFile(access.roomId, fileId);
          return target === null || target.status === 'DELETED'
            ? null
            : { roomId: target.roomId, createdById: target.uploaderId };
        });
        const locked = target as Awaited<ReturnType<RoomStore['lockRoomFile']>>;
        if (locked === null || !(await tx.tombstoneFile(room.id, fileId, clock()))) throw notFound();
        return locked.objectKey;
      });
      await deleteObjectSoon(fileId, objectKey);
      record('FILE_DELETED', actor, meta, { roomId: access.roomId, fileId });
    },
  };
}

export type FileService = ReturnType<typeof createFileService>;
