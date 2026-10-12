import { toBase64Url } from '@ciphermesh/crypto/identity';
import { FILE_LIST_PAGE_SIZE } from '@ciphermesh/shared';
import {
  emptyBodySchema,
  emptyQuerySchema,
  fileDeletedResponseSchema,
  fileDownloadResponseSchema,
  fileListQuerySchema,
  fileListResponseSchema,
  fileParamsSchema,
  fileResponseSchema,
  fileUploadRequestSchema,
  fileUploadResponseSchema,
  formatListCursor,
  parseListCursor,
  roomParamsSchema,
} from '@ciphermesh/validation';
import type { FileRecord } from '../db/file-store';
import type { RoomStore } from '../db/room-store';
import type { FileService } from '../files/service';
import { actorOf, defineRoute, roomOf, type AnyRoute } from './registry';

/**
 * Encrypted file routes (Phase 7, CM-T037 to CM-T041; DF-07, DF-08). Every route is a room route:
 * the registry authorizes it centrally against the caller's database-loaded membership before the
 * handler runs (OL-01, INV-05), and file objects are loaded by file ID AND room ID (OL-02). No
 * route accepts or returns a file name, type, plaintext hash, FEK or room key; the responses carry
 * ciphertext references, the wrapped FEK and the encrypted manifest (INV-01, INV-16), and
 * presigned storage URLs for one object and one method (OL-07, CP-20).
 *
 *   GET  /rooms/{roomId}/files                      AZ-17  readable files, key material per PC-12
 *   POST /rooms/{roomId}/files                      AZ-16  PENDING_UPLOAD and a presigned PUT
 *   GET  /rooms/{roomId}/files/{fileId}             AZ-17  key material of one file (PC-12)
 *   POST /rooms/{roomId}/files/{fileId}/complete    AZ-16  AVAILABLE after the size check (uploader)
 *   POST /rooms/{roomId}/files/{fileId}/download-url AZ-17 presigned GET, 60 seconds (PC-12)
 *   POST /rooms/{roomId}/files/{fileId}/delete      AZ-18  tombstone; own files for MEMBERs
 */

const iso = (date: Date | null): string | null => (date === null ? null : date.toISOString());

/** The explicit projection of a file. `withKeyMaterial` is false where PC-12 withholds it. */
function fileView(file: FileRecord, withKeyMaterial: boolean) {
  return {
    id: file.id,
    uploaderId: file.uploaderId,
    keyVersion: file.keyVersion,
    suite: 'CM1' as const,
    status: file.status,
    ciphertextSize: file.ciphertextSize,
    ciphertextSha256: toBase64Url(file.ciphertextSha256),
    expiresAt: iso(file.expiresAt),
    createdAt: file.createdAt.toISOString(),
    uploadedAt: iso(file.uploadedAt),
    keyMaterial: withKeyMaterial
      ? {
          wrappedFek: toBase64Url(file.wrappedDek),
          fekIv: toBase64Url(file.dekIv),
          manifest: toBase64Url(file.manifestCiphertext),
          manifestIv: toBase64Url(file.manifestIv),
          contentIv: toBase64Url(file.contentIv),
        }
      : null,
  };
}

export function fileRoutes(files: FileService, store: RoomStore): readonly AnyRoute[] {
  return [
    defineRoute({
      method: 'GET',
      path: '/rooms/:roomId/files',
      action: 'AZ-17-FILE-LIST',
      access: { kind: 'room' },
      params: roomParamsSchema,
      query: fileListQuerySchema,
      body: undefined,
      response: fileListResponseSchema,
      handler: async (ctx) => {
        const after = ctx.query.cursor === undefined ? undefined : parseListCursor(ctx.query.cursor);
        const { files: page, keyMaterial } = await files.listFiles(
          actorOf(ctx),
          roomOf(ctx),
          after,
          FILE_LIST_PAGE_SIZE + 1,
        );
        const visible = page.slice(0, FILE_LIST_PAGE_SIZE);
        const last = visible.at(-1);
        return {
          status: 200,
          body: {
            files: visible.map((file) => fileView(file, keyMaterial)),
            nextCursor:
              page.length > FILE_LIST_PAGE_SIZE && last !== undefined
                ? formatListCursor(last.createdAt, last.id)
                : null,
          },
        };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/files',
      action: 'AZ-16-FILE-UPLOAD',
      access: { kind: 'room' },
      params: roomParamsSchema,
      query: emptyQuerySchema,
      body: fileUploadRequestSchema,
      response: fileUploadResponseSchema,
      handler: async (ctx) => {
        const { file, upload } = await files.startUpload(actorOf(ctx), roomOf(ctx), ctx.body, ctx.request);
        return {
          status: 201,
          body: { file: fileView(file, true), upload: { url: upload.url, expiresAt: upload.expiresAt.toISOString() } },
        };
      },
    }),
    defineRoute({
      method: 'GET',
      path: '/rooms/:roomId/files/:fileId',
      action: 'AZ-17-FILE-READ',
      access: { kind: 'room' },
      params: fileParamsSchema,
      query: emptyQuerySchema,
      body: undefined,
      response: fileResponseSchema,
      handler: async (ctx) => ({
        status: 200,
        body: { file: fileView(await files.readFile(actorOf(ctx), roomOf(ctx), ctx.params.fileId, ctx.request), true) },
      }),
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/files/:fileId/complete',
      action: 'AZ-16-FILE-COMPLETE',
      access: { kind: 'room' },
      params: fileParamsSchema,
      query: emptyQuerySchema,
      body: emptyBodySchema,
      response: fileResponseSchema,
      handler: async (ctx) => ({
        status: 200,
        body: {
          file: fileView(await files.completeUpload(actorOf(ctx), roomOf(ctx), ctx.params.fileId, ctx.request), true),
        },
      }),
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/files/:fileId/download-url',
      action: 'AZ-17-FILE-DOWNLOAD',
      access: { kind: 'room', requires: { sensitive: 'FILE_DOWNLOAD_URL' } },
      params: fileParamsSchema,
      query: emptyQuerySchema,
      body: emptyBodySchema,
      response: fileDownloadResponseSchema,
      handler: async (ctx) => {
        const download = await files.downloadUrl(actorOf(ctx), roomOf(ctx), ctx.params.fileId, ctx.request);
        return { status: 200, body: { download: { url: download.url, expiresAt: download.expiresAt.toISOString() } } };
      },
    }),
    defineRoute({
      method: 'POST',
      path: '/rooms/:roomId/files/:fileId/delete',
      action: 'AZ-18-FILE-DELETE',
      access: {
        kind: 'room',
        // OL-02, OL-04: the file is loaded by its ID and the room ID; the stored uploader decides `own`.
        resource: async ({ room, params }) => {
          const file = await store.findRoomFile(room.roomId, params.fileId);
          return file === null ? null : { roomId: file.roomId, createdById: file.uploaderId };
        },
      },
      params: fileParamsSchema,
      query: emptyQuerySchema,
      body: emptyBodySchema,
      response: fileDeletedResponseSchema,
      handler: async (ctx) => {
        await files.deleteFile(actorOf(ctx), roomOf(ctx), ctx.params.fileId, ctx.request);
        return { status: 200, body: { status: 'DELETED' as const } };
      },
    }),
  ];
}
