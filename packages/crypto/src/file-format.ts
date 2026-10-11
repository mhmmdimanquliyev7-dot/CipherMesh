import { fromBase64Url, toBase64Url } from './encoding';
import { CryptoError, CryptoErrorCode } from './errors';
import type { EncryptedFile, StoredFile } from './files';
import { AES_GCM, FILES, SHA256_BYTES } from './params';

/**
 * Wire format of encrypted files (Phase 7, DF-07, DF-08): binary values as unpadded base64url
 * (CP-15). The content ciphertext itself never travels through the API; the browser sends it to
 * object storage with the presigned URL. What the API stores and returns is exactly this record.
 */
export interface EncryptedFileWire {
  readonly fileId: string;
  readonly keyVersion: number;
  readonly suite: string;
  readonly wrappedFek: string;
  readonly fekIv: string;
  readonly manifest: string;
  readonly manifestIv: string;
  readonly contentIv: string;
  readonly ciphertextSize: number;
  readonly ciphertextSha256: string;
}

/** The upload request fields for an encrypted file (the API adds the room from the path). */
export function encryptedFileToWire(file: EncryptedFile): EncryptedFileWire {
  return {
    fileId: file.fileId,
    keyVersion: file.keyVersion,
    suite: file.suite,
    wrappedFek: toBase64Url(file.wrappedFek.ciphertext),
    fekIv: toBase64Url(file.wrappedFek.iv),
    manifest: toBase64Url(file.manifest.ciphertext),
    manifestIv: toBase64Url(file.manifest.iv),
    contentIv: toBase64Url(file.content.iv),
    ciphertextSize: file.content.ciphertext.length,
    ciphertextSha256: toBase64Url(file.ciphertextSha256),
  };
}

/**
 * Decodes a file record the API returned for the room in the request path. Malformed values are
 * an integrity failure: nothing the server sends is trusted before openFile authenticates it.
 */
export function storedFileFromWire(roomId: string, wire: EncryptedFileWire): StoredFile {
  try {
    return {
      roomId,
      fileId: wire.fileId,
      keyVersion: wire.keyVersion,
      suite: wire.suite,
      wrappedFek: {
        iv: fromBase64Url(wire.fekIv, AES_GCM.ivBytes),
        ciphertext: fromBase64Url(wire.wrappedFek, FILES.wrappedFekBytes),
      },
      manifest: { iv: fromBase64Url(wire.manifestIv, AES_GCM.ivBytes), ciphertext: fromBase64Url(wire.manifest) },
      contentIv: fromBase64Url(wire.contentIv, AES_GCM.ivBytes),
      ciphertextSize: wire.ciphertextSize,
      ciphertextSha256: fromBase64Url(wire.ciphertextSha256, SHA256_BYTES),
    };
  } catch {
    throw new CryptoError(CryptoErrorCode.FILE_INTEGRITY_FAILED);
  }
}
