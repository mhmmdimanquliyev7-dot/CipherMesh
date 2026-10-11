// Browser side of `pnpm bench:files` (scripts/bench/files-browsers.mjs), the browser memory and
// time benchmark that CP-19 asks for before its 50 MiB single-shot limit is confirmed. It runs the
// real @ciphermesh/crypto file code under the production Content-Security-Policy. The room key is
// derived from random bytes exactly as openRoomKey derives RWK_v (the signature checks are tested
// elsewhere); content is synthetic. Only timings, sizes and booleans leave the page.
import { CryptoErrorCode, encryptFile, FILES, isCryptoError, openFile, type OpenedRoomKey } from '@ciphermesh/crypto';
import { contextBytes } from '../../../packages/crypto/src/contexts';
import { deriveWrappingKey, importKeyMaterial } from '../../../packages/crypto/src/hkdf';

interface Row {
  readonly sizeMiB: number;
  readonly encryptMs: number;
  readonly decryptMs: number;
  readonly roundTripOk: boolean;
  /**
   * Memory of the page right after the round trip, while plaintext, ciphertext and the decrypted
   * copy are all alive (performance.measureUserAgentSpecificMemory, ArrayBuffers included; Chromium
   * only, and only in a cross-origin isolated page). Null where the engine does not report it.
   */
  readonly pageMemoryMiB: number | null;
}

export interface FilesBenchResult {
  readonly userAgent: string;
  readonly rows: Row[];
  /** One byte over CP-19 is refused before anything is encrypted. */
  readonly oversizeRefused: boolean;
}

async function roomKey(): Promise<OpenedRoomKey> {
  const roomId = crypto.randomUUID();
  const material = await importKeyMaterial(crypto.getRandomValues(new Uint8Array(32)));
  const wrappingKey = await deriveWrappingKey(
    material,
    contextBytes('cm.room.dek-wrap-key', { roomId, keyVersion: 1 }),
  );
  return { roomId, keyVersion: 1, material, wrappingKey } as unknown as OpenedRoomKey;
}

/** Synthetic content: a repeating random block (getRandomValues gives at most 64 KiB per call). */
function content(size: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(size);
  const block = crypto.getRandomValues(new Uint8Array(65_536));
  for (let at = 0; at < size; at += block.length) bytes.set(block.subarray(0, Math.min(block.length, size - at)), at);
  return bytes;
}

async function pageMemoryMiB(): Promise<number | null> {
  const measure = (performance as unknown as { measureUserAgentSpecificMemory?: () => Promise<{ bytes: number }> })
    .measureUserAgentSpecificMemory;
  if (!crossOriginIsolated || measure === undefined) return null;
  try {
    return Math.round((await measure.call(performance)).bytes / 2 ** 20);
  } catch {
    return null;
  }
}

async function run(): Promise<FilesBenchResult> {
  const key = await roomKey();
  const rows: Row[] = [];
  for (const sizeMiB of [1, 10, 50]) {
    const plaintext = content(sizeMiB * 2 ** 20);
    const t0 = performance.now();
    const file = await encryptFile(key, {
      fileId: crypto.randomUUID(),
      name: 'bench.bin',
      type: '',
      content: plaintext,
    });
    const t1 = performance.now();
    const opened = await openFile(key, {
      roomId: key.roomId,
      fileId: file.fileId,
      keyVersion: 1,
      suite: file.suite,
      wrappedFek: file.wrappedFek,
      manifest: file.manifest,
      contentIv: file.content.iv,
      ciphertextSize: file.content.ciphertext.length,
      ciphertextSha256: file.ciphertextSha256,
    });
    const decrypted = await opened.decrypt(file.content.ciphertext);
    const t2 = performance.now();
    let same = decrypted.length === plaintext.length;
    for (let i = 0; same && i < plaintext.length; i += 4099) same = decrypted[i] === plaintext[i];
    rows.push({
      sizeMiB,
      encryptMs: t1 - t0,
      decryptMs: t2 - t1,
      roundTripOk: same,
      // Measured while plaintext, the encrypted file and the decrypted copy are still referenced.
      pageMemoryMiB: decrypted.length === plaintext.length && file.fileId !== '' ? await pageMemoryMiB() : null,
    });
  }
  let oversizeRefused = false;
  try {
    await encryptFile(key, {
      fileId: crypto.randomUUID(),
      name: 'big.bin',
      type: '',
      content: new Uint8Array(FILES.maxPlaintextBytes + 1),
    });
  } catch (error) {
    oversizeRefused = isCryptoError(error, CryptoErrorCode.INVALID_INPUT);
  }
  return { userAgent: navigator.userAgent, rows, oversizeRefused };
}

(window as unknown as { runFilesBench: () => Promise<FilesBenchResult> }).runFilesBench = run;
