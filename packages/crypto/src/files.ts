import { decrypt, encrypt, generateDataKey, unwrapDataKey, wrapDataKey, type Sealed } from './aead';
import { canonicalBytes } from './canonical';
import { contextBytes, type CanonicalBytes } from './contexts';
import { bytesEqual, fromBase64Url, isWellFormedUnicode, toBase64Url, utf8Decode, wipe } from './encoding';
import { CryptoError, CryptoErrorCode } from './errors';
import { sha256 } from './hash';
import { AES_GCM, FILES, SHA256_BYTES, SUITE } from './params';
import type { OpenedRoomKey } from './room-keys';
import type { Bytes } from './types';

/**
 * Encrypted files (Phase 7, CM-T038, CM-T039; cryptographic-architecture section 6.1, DF-07, DF-08).
 *
 *   FEK      = fresh random AES-256-GCM key, one per file (INV-03)
 *   content  = AES-256-GCM(FEK, file bytes, AAD = cm.file.content {roomId, fileId})
 *   manifest = AES-256-GCM(FEK, JCS {v, name, type, size, sha256}, AAD = cm.file.manifest {roomId, fileId})
 *   wrapped  = AES-256-GCM wrap of the FEK under RWK_v, AAD = cm.dek.wrap
 *              {roomId, keyVersion, itemType: 'file', itemId: fileId, revision: 0}
 *   ctHash   = SHA-256(content ciphertext), a public storage-integrity reference (CD-09)
 *
 * The whole file is one AES-GCM message (CP-19, at most 50 MiB): the tag authenticates every byte
 * and the length, so truncation, reordering or substitution of any part fails authentication.
 * There are no chunks; a chunked design needs its own ADR (OCD-09). Every IV is generated inside
 * the AES-GCM wrapper (INV-02), and the FEK encrypts exactly two messages (CP-16).
 *
 * The room key must have passed the Phase 6 verification rule (openRoomKey): this module only
 * accepts an OpenedRoomKey, whose RWK_v is a non-extractable wrapping key. The FEK leaves this
 * module only as AES-GCM ciphertext; on download it is unwrapped as a non-extractable,
 * decrypt-only key held inside the returned OpenedFile. Nothing is stored.
 *
 * Decryption fails closed: the wrapped FEK, the manifest and the content must all authenticate,
 * and the decrypted content must match the manifest's size and plaintext hash, before any byte
 * is returned. The plaintext hash and the file name exist only inside the encrypted manifest
 * (INV-16).
 */

/** What the uploader's browser sends to the API: ciphertext, wrapped key and public references. */
export interface EncryptedFile {
  readonly roomId: string;
  readonly fileId: string;
  readonly keyVersion: number;
  readonly suite: typeof SUITE;
  readonly wrappedFek: Sealed;
  readonly manifest: Sealed;
  /** The content ciphertext (with its tag) for object storage, and its IV for the database. */
  readonly content: Sealed;
  readonly ciphertextSha256: Bytes;
}

/** A file record as the API returned it, decoded. Every value is untrusted until openFile checks it. */
export interface StoredFile {
  readonly roomId: string;
  readonly fileId: string;
  readonly keyVersion: number;
  readonly suite: string;
  readonly wrappedFek: Sealed;
  readonly manifest: Sealed;
  readonly contentIv: Bytes;
  readonly ciphertextSize: number;
  readonly ciphertextSha256: Bytes;
}

/** The decrypted manifest of a file, and its key, ready to decrypt the content. */
export interface OpenedFile {
  readonly roomId: string;
  readonly fileId: string;
  readonly keyVersion: number;
  /** The file name chosen by the uploader. Untrusted text: render as text, sanitize before saving. */
  readonly name: string;
  /** The MIME type the uploader's browser reported, or ''. Untrusted: never used to render content. */
  readonly type: string;
  readonly size: number;
  /**
   * Checks the downloaded ciphertext against the record, authenticates and decrypts it, and
   * checks the plaintext against the manifest. Returns the plaintext only if every check passes.
   */
  decrypt(ciphertext: Bytes): Promise<Bytes>;
}

const integrityFailed = (): CryptoError => new CryptoError(CryptoErrorCode.FILE_INTEGRITY_FAILED);
const invalidInput = (): CryptoError => new CryptoError(CryptoErrorCode.INVALID_INPUT);

/**
 * C0 controls, DEL, C1 controls and the bidirectional marks and overrides: never part of a file name.
 * A right-to-left override can make "photo\u202Egnp.exe" display as "photoexe.png" (T-11).
 */
// eslint-disable-next-line no-control-regex -- the class is the point: it rejects control characters
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/;
/** A lower-case MIME type without parameters, as browsers report for File.type, or ''. */
const MIME_TYPE = /^(?:[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*)?$/;

function isFileName(name: unknown): name is string {
  return (
    typeof name === 'string' &&
    name.length >= 1 &&
    name.length <= FILES.maxNameLength &&
    isWellFormedUnicode(name) &&
    !CONTROL_CHARACTERS.test(name)
  );
}

function isMimeType(type: unknown): type is string {
  return typeof type === 'string' && type.length <= FILES.maxTypeLength && MIME_TYPE.test(type);
}

function isFileSize(size: unknown): size is number {
  return typeof size === 'number' && Number.isSafeInteger(size) && size >= 0 && size <= FILES.maxPlaintextBytes;
}

function dekWrapContext(roomId: string, keyVersion: number, fileId: string): CanonicalBytes {
  return contextBytes('cm.dek.wrap', { roomId, keyVersion, itemType: 'file', itemId: fileId, revision: 0 });
}

/**
 * Encrypts a file in the browser with a fresh FEK under the given verified room key version. The
 * caller chooses the file ID (UUIDv4, part of every context) and gives the plaintext name, type
 * and bytes; nothing of them leaves this function except as ciphertext.
 */
export async function encryptFile(
  roomKey: OpenedRoomKey,
  input: { readonly fileId: string; readonly name: string; readonly type: string; readonly content: Bytes },
): Promise<EncryptedFile> {
  const { roomId, keyVersion } = roomKey;
  const { fileId, name, type, content } = input;
  if (!(content instanceof Uint8Array) || !isFileSize(content.length)) throw invalidInput();
  if (!isFileName(name) || !isMimeType(type)) throw invalidInput();
  // The contexts validate the identifiers; build them before any key exists.
  const contentAad = contextBytes('cm.file.content', { roomId, fileId });
  const manifestAad = contextBytes('cm.file.manifest', { roomId, fileId });
  const wrapAad = dekWrapContext(roomId, keyVersion, fileId);

  const plaintextHash = await sha256(content);
  const manifestBytes = canonicalBytes({
    v: FILES.manifestVersion,
    name,
    type,
    size: content.length,
    sha256: toBase64Url(plaintextHash),
  });
  const fek = await generateDataKey();
  try {
    const sealedContent = await encrypt(fek, content, contentAad);
    const sealedManifest = await encrypt(fek, manifestBytes, manifestAad);
    const wrappedFek = await wrapDataKey(fek, roomKey.wrappingKey, wrapAad);
    return {
      roomId,
      fileId,
      keyVersion,
      suite: SUITE,
      wrappedFek,
      manifest: sealedManifest,
      content: sealedContent,
      ciphertextSha256: await sha256(sealedContent.ciphertext),
    };
  } finally {
    wipe(manifestBytes, plaintextHash);
  }
}

interface Manifest {
  readonly name: string;
  readonly type: string;
  readonly size: number;
  readonly sha256: Bytes;
}

const MANIFEST_FIELDS = ['name', 'sha256', 'size', 'type', 'v'];

/** Parses manifest format version 1. Anything else is refused; nothing is guessed. */
function parseManifest(bytes: Bytes): Manifest {
  let value: unknown;
  try {
    value = JSON.parse(utf8Decode(bytes));
  } catch {
    throw integrityFailed();
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw integrityFailed();
  const record = value as Record<string, unknown>;
  if (record['v'] !== FILES.manifestVersion) {
    throw new CryptoError(
      typeof record['v'] === 'number' ? CryptoErrorCode.FILE_FORMAT_UNSUPPORTED : CryptoErrorCode.FILE_INTEGRITY_FAILED,
    );
  }
  const keys = Object.keys(record).sort();
  if (keys.length !== MANIFEST_FIELDS.length || keys.some((key, i) => key !== MANIFEST_FIELDS[i])) {
    throw integrityFailed();
  }
  const { name, type, size, sha256: hash } = record;
  if (!isFileName(name) || !isMimeType(type) || !isFileSize(size) || typeof hash !== 'string') throw integrityFailed();
  let digest: Bytes;
  try {
    digest = fromBase64Url(hash, SHA256_BYTES);
  } catch {
    throw integrityFailed();
  }
  return { name, type, size, sha256: digest };
}

/**
 * Opens a stored file with the verified room key version that wrapped its FEK: unwraps the FEK as
 * a non-extractable decrypt-only key and authenticates and parses the manifest. The caller picks
 * the key version the record names; a key of another room or version is refused.
 */
export async function openFile(roomKey: OpenedRoomKey, record: StoredFile): Promise<OpenedFile> {
  if (record.suite !== SUITE) throw new CryptoError(CryptoErrorCode.FILE_FORMAT_UNSUPPORTED);
  if (roomKey.roomId !== record.roomId || roomKey.keyVersion !== record.keyVersion) throw invalidInput();
  if (
    record.wrappedFek.ciphertext.length !== FILES.wrappedFekBytes ||
    record.contentIv.length !== AES_GCM.ivBytes ||
    record.ciphertextSha256.length !== SHA256_BYTES ||
    !Number.isSafeInteger(record.ciphertextSize) ||
    record.ciphertextSize < AES_GCM.tagBytes
  ) {
    throw integrityFailed();
  }
  const { roomId, fileId, keyVersion } = record;
  const contentAad = contextBytes('cm.file.content', { roomId, fileId });
  const manifestAad = contextBytes('cm.file.manifest', { roomId, fileId });
  const fek = await unwrapDataKey(record.wrappedFek, roomKey.wrappingKey, dekWrapContext(roomId, keyVersion, fileId));
  const manifestBytes = await decrypt(fek, record.manifest, manifestAad);
  let manifest: Manifest;
  try {
    manifest = parseManifest(manifestBytes);
  } finally {
    wipe(manifestBytes);
  }
  // The stored ciphertext size is public metadata; it must agree with the authenticated manifest.
  if (manifest.size + AES_GCM.tagBytes !== record.ciphertextSize) throw integrityFailed();
  const contentIv = new Uint8Array(record.contentIv);
  const ciphertextSha256 = new Uint8Array(record.ciphertextSha256);

  return {
    roomId,
    fileId,
    keyVersion,
    name: manifest.name,
    type: manifest.type,
    size: manifest.size,
    async decrypt(ciphertext: Bytes): Promise<Bytes> {
      if (!(ciphertext instanceof Uint8Array) || ciphertext.length !== manifest.size + AES_GCM.tagBytes) {
        throw integrityFailed();
      }
      // An early storage-integrity check; the decisive check is the AES-GCM tag below.
      if (!bytesEqual(await sha256(ciphertext), ciphertextSha256)) throw integrityFailed();
      const plaintext = await decrypt(fek, { iv: contentIv, ciphertext }, contentAad);
      if (plaintext.length !== manifest.size || !bytesEqual(await sha256(plaintext), manifest.sha256)) {
        wipe(plaintext);
        throw integrityFailed();
      }
      return plaintext;
    },
  };
}
