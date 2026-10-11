import {
  CryptoError,
  CryptoErrorCode,
  encryptedFileToWire,
  encryptFile,
  FILES,
  openFile,
  storedFileFromWire,
  type OpenedFile,
} from '@ciphermesh/crypto';
import { PREVIEWABLE_IMAGE_TYPES } from '@ciphermesh/shared';
import {
  fileDeletedResponseSchema,
  fileDownloadResponseSchema,
  fileListResponseSchema,
  fileResponseSchema,
  fileUploadResponseSchema,
  type FileRecordView,
} from '@ciphermesh/validation';
import { api } from '../lib/api';
import { RoomKeyMissing, roomKeys } from './keys';

/**
 * Encrypted files in this tab (Phase 7, CM-T038 to CM-T041; DF-07, DF-08). All cryptography is
 * done by @ciphermesh/crypto with room keys this browser verified (roomKeys, ADR-015 section 4);
 * this module sequences it with the API and object storage.
 *
 * - Upload: the file's bytes, name and type are encrypted here under a fresh FEK, which is
 *   wrapped under the room's current RWK_v. The API receives ciphertext references, the wrapped
 *   FEK and the encrypted manifest; storage receives the ciphertext through a presigned PUT. The
 *   plaintext, the name and the FEK never leave the browser (INV-01, INV-16).
 * - Download: the ciphertext comes from storage through a presigned GET. Nothing is shown or saved
 *   unless the wrapped FEK, the manifest and the content all authenticate and the content matches
 *   the manifest's plaintext hash; a failure is an integrity error with no plaintext.
 * - Nothing is persisted: no plaintext, name, FEK or URL goes into browser storage, caches or the
 *   URL bar. Object URLs for a download or a preview are revoked as soon as they are used. Requests
 *   to storage carry no cookies (credentials: 'omit') and the page's CSP allows only the storage
 *   origin.
 */

/** A file as this tab can show it: server metadata, plus the decrypted manifest when available. */
export interface FileEntry {
  readonly view: FileRecordView;
  /** The decrypted manifest; undefined when this tab holds no key or PC-12 withholds the key material. */
  readonly opened?: OpenedFile;
  /** Set when the manifest failed authentication: the file is shown as damaged, never opened. */
  readonly damaged?: boolean;
}

export type UploadStage = 'reading' | 'encrypting' | 'uploading' | 'finishing';

export class FileTooLarge extends Error {
  readonly code = 'FILE_TOO_LARGE';
  constructor() {
    super('The file is larger than the limit');
    this.name = 'FileTooLarge';
  }
}

/** The PUT to object storage failed; the pending upload was cancelled. */
export class StorageTransferFailed extends Error {
  readonly code = 'STORAGE_TRANSFER_FAILED';
  constructor() {
    super('The encrypted file could not be transferred');
    this.name = 'StorageTransferFailed';
  }
}

// --------------------------------------------------------------------- names and types (T-11)

// eslint-disable-next-line no-control-regex -- the class is the point: it removes control characters
const CONTROL_OR_BIDI = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g;
const MIME_TYPE = /^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*$/;

/**
 * The name stored in the encrypted manifest: the browser's file name without control and
 * bidirectional-override characters, at most 255 UTF-16 code units, never empty.
 */
export function manifestName(name: string): string {
  const cleaned = name.replace(CONTROL_OR_BIDI, '').trim().slice(0, FILES.maxNameLength).replace(LONE_SURROGATE, '');
  return cleaned === '' ? 'file' : cleaned;
}

/** The MIME type stored in the manifest: the browser's lower-case type, or '' when unusual. */
export function manifestType(type: string): string {
  const lower = type.toLowerCase();
  return lower.length <= FILES.maxTypeLength && MIME_TYPE.test(lower) ? lower : '';
}

const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$/i;

/**
 * A name safe to offer as a download: no path separators, reserved or control characters, no
 * leading dots (hidden files), no reserved device names. The decrypted name is untrusted text
 * chosen by the uploader; it never decides where the file is saved.
 */
export function safeDownloadName(name: string): string {
  let cleaned = name
    .replace(CONTROL_OR_BIDI, '')
    .replace(/[/\\:*?"<>|]/g, '_')
    .replace(/^[.\s]+/, '')
    .replace(/[.\s]+$/, '')
    .slice(0, 200);
  if (WINDOWS_RESERVED.test(cleaned)) cleaned = `_${cleaned}`;
  return cleaned === '' ? 'download' : cleaned;
}

/** Extensions that run code or render active content when opened (CM-T041 warning, T-11). */
const RISKY_EXTENSIONS = new Set([
  'exe',
  'msi',
  'bat',
  'cmd',
  'com',
  'scr',
  'pif',
  'cpl',
  'ps1',
  'psm1',
  'vbs',
  'vbe',
  'js',
  'jse',
  'wsf',
  'wsh',
  'hta',
  'jar',
  'sh',
  'bash',
  'zsh',
  'command',
  'app',
  'dmg',
  'pkg',
  'deb',
  'rpm',
  'apk',
  'appimage',
  'lnk',
  'reg',
  'dll',
  'html',
  'htm',
  'xhtml',
  'svg',
  'mht',
  'xml',
  'docm',
  'xlsm',
  'pptm',
  'iso',
  'img',
]);

export function isRiskyName(name: string): boolean {
  const extension = /\.([A-Za-z0-9]+)$/.exec(name.trim())?.[1]?.toLowerCase();
  return extension !== undefined && RISKY_EXTENSIONS.has(extension);
}

/** Raster images only, judged by the decrypted type; SVG and HTML never render (CM-T041). */
export function isPreviewable(opened: OpenedFile): boolean {
  return PREVIEWABLE_IMAGE_TYPES.includes(opened.type);
}

// ------------------------------------------------------------------------------ operations

function recordOf(roomId: string, view: FileRecordView) {
  if (view.keyMaterial === null) throw new CryptoError(CryptoErrorCode.FILE_INTEGRITY_FAILED);
  return storedFileFromWire(roomId, {
    fileId: view.id,
    keyVersion: view.keyVersion,
    suite: view.suite,
    ciphertextSize: view.ciphertextSize,
    ciphertextSha256: view.ciphertextSha256,
    ...view.keyMaterial,
  });
}

/** Opens a file's manifest with the key version that wrapped its FEK, if this tab verified it. */
async function open(roomId: string, view: FileRecordView): Promise<OpenedFile> {
  const key = roomKeys.version(roomId, view.keyVersion);
  if (key === undefined) throw new RoomKeyMissing();
  return openFile(key, recordOf(roomId, view));
}

/** One page of the room's readable files, with names decrypted where this tab can. */
export async function listFiles(
  roomId: string,
  cursor?: string,
): Promise<{ readonly entries: FileEntry[]; readonly nextCursor: string | null }> {
  const page = await api(
    'GET',
    `/rooms/${roomId}/files${cursor === undefined ? '' : `?cursor=${encodeURIComponent(cursor)}`}`,
    fileListResponseSchema,
  );
  const entries: FileEntry[] = [];
  for (const view of page.files) {
    if (view.keyMaterial === null || roomKeys.version(roomId, view.keyVersion) === undefined) {
      entries.push({ view });
      continue;
    }
    try {
      entries.push({ view, opened: await open(roomId, view) });
    } catch {
      // An unauthenticated manifest is never shown; the file is marked damaged instead.
      entries.push({ view, damaged: true });
    }
  }
  return { entries, nextCursor: page.nextCursor };
}

/**
 * PUT of the ciphertext with fetch and credentials 'omit', so no cookie reaches storage under any
 * engine's credential rules (finding SF-07-01: WebKit attached the session cookie to an
 * XMLHttpRequest with withCredentials = false sent to another port of the same host). Fetch gives
 * no upload progress; the stage is shown instead.
 */
async function putCiphertext(url: string, ciphertext: Uint8Array): Promise<void> {
  let response: Response;
  try {
    response = await fetch(url, {
      method: 'PUT',
      body: new Blob([new Uint8Array(ciphertext)]),
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    });
  } catch {
    throw new StorageTransferFailed();
  }
  if (response.status !== 200) throw new StorageTransferFailed();
}

/**
 * Encrypts and uploads a file to the room under its newest verified key version (DF-07). The
 * caller passes the expiry the room's profile asks for (PC-08); the API checks it again.
 */
export async function uploadFile(
  roomId: string,
  file: File,
  expiresAt: string | null,
  onStage: (stage: UploadStage, progress?: number) => void,
): Promise<void> {
  if (file.size > FILES.maxPlaintextBytes) throw new FileTooLarge();
  const key = roomKeys.current(roomId);
  if (key === undefined) throw new RoomKeyMissing();
  onStage('reading');
  const content = new Uint8Array(await file.arrayBuffer());
  onStage('encrypting');
  const encrypted = await encryptFile(key, {
    fileId: crypto.randomUUID(),
    name: manifestName(file.name),
    type: manifestType(file.type),
    content,
  });
  content.fill(0);
  const started = await api('POST', `/rooms/${roomId}/files`, fileUploadResponseSchema, {
    ...encryptedFileToWire(encrypted),
    expiresAt,
  });
  onStage('uploading');
  try {
    await putCiphertext(started.upload.url, encrypted.content.ciphertext);
  } catch (error) {
    // Cancel the pending upload at once; the worker would otherwise remove it later.
    await api('POST', `/rooms/${roomId}/files/${encrypted.fileId}/delete`, fileDeletedResponseSchema, {}).catch(
      () => undefined,
    );
    throw error;
  }
  onStage('finishing');
  await api('POST', `/rooms/${roomId}/files/${encrypted.fileId}/complete`, fileResponseSchema, {});
}

/** Fetches, authenticates and decrypts a file (DF-08). Returns the plaintext only after every check. */
export async function decryptFile(
  roomId: string,
  fileId: string,
): Promise<{ readonly opened: OpenedFile; readonly bytes: Uint8Array }> {
  const { file } = await api('GET', `/rooms/${roomId}/files/${fileId}`, fileResponseSchema);
  const opened = await open(roomId, file);
  const { download } = await api(
    'POST',
    `/rooms/${roomId}/files/${fileId}/download-url`,
    fileDownloadResponseSchema,
    {},
  );
  let ciphertext: Uint8Array<ArrayBuffer>;
  try {
    const response = await fetch(download.url, {
      method: 'GET',
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    });
    if (!response.ok) throw new StorageTransferFailed();
    ciphertext = new Uint8Array(await response.arrayBuffer());
  } catch {
    throw new StorageTransferFailed();
  }
  return { opened, bytes: await opened.decrypt(ciphertext) };
}

/**
 * Saves decrypted bytes through a temporary object URL with a sanitized name, always as opaque
 * bytes (never rendered by this page). The saved file is outside CipherMesh's protection.
 */
export function saveToDevice(name: string, bytes: Uint8Array): void {
  const url = URL.createObjectURL(new Blob([new Uint8Array(bytes)], { type: 'application/octet-stream' }));
  try {
    const link = document.createElement('a');
    link.href = url;
    link.download = safeDownloadName(name);
    link.rel = 'noopener';
    link.click();
  } finally {
    // Give the browser a moment to start the download before the URL disappears.
    setTimeout(() => {
      URL.revokeObjectURL(url);
    }, 1_000);
    bytes.fill(0);
  }
}

/** An object URL for an image preview of an allowlisted raster type; the caller revokes it. */
export function previewUrl(opened: OpenedFile, bytes: Uint8Array): string {
  if (!isPreviewable(opened)) throw new CryptoError(CryptoErrorCode.INVALID_INPUT);
  return URL.createObjectURL(new Blob([new Uint8Array(bytes)], { type: opened.type }));
}

export async function deleteFile(roomId: string, fileId: string): Promise<void> {
  await api('POST', `/rooms/${roomId}/files/${fileId}/delete`, fileDeletedResponseSchema, {});
}
