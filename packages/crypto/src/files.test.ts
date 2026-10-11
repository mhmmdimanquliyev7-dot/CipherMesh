import {
  createCipheriv,
  createDecipheriv,
  createHash,
  hkdfSync,
  randomBytes as nodeRandom,
  randomUUID,
} from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import { generateDataKey, unwrapDataKey, wrapDataKey } from './aead';
import { canonicalBytes } from './canonical';
import { contextBytes } from './contexts';
import { fromBase64Url, toBase64Url } from './encoding';
import { CryptoErrorCode, isCryptoError } from './errors';
import { encryptedFileToWire, storedFileFromWire, type EncryptedFileWire } from './file-format';
import { encryptFile, openFile, type EncryptedFile, type StoredFile } from './files';
import { deriveWrappingKey, importKeyMaterial } from './hkdf';
import { FILES } from './params';
import type { OpenedRoomKey } from './room-keys';
import type { Bytes } from './types';

// Encrypted files (Phase 7, CM-T038, CM-T039). Known answers come from an independent
// implementation: Node.js crypto (OpenSSL) derives RWK_v with HKDF-SHA-256 and encrypts or wraps
// with AES-256-GCM using the documented contexts, in both directions. The tamper tests flip bits
// in every stored part and move parts between rooms, files, versions and contexts; each must fail
// without releasing plaintext (threat-model T-07).

const ZERO_SALT = Buffer.alloc(32);
const bytes = (value: Uint8Array | Buffer): Bytes => new Uint8Array(value);

interface TestRoomKey {
  readonly key: OpenedRoomKey;
  readonly rwk: Buffer;
}

/** A room key version as openRoomKey derives it (the verification itself is tested in room-keys). */
async function roomKey(roomId: string = randomUUID(), keyVersion = 1, material = nodeRandom(32)): Promise<TestRoomKey> {
  const info = contextBytes('cm.room.dek-wrap-key', { roomId, keyVersion });
  const rwk = Buffer.from(hkdfSync('sha256', material, ZERO_SALT, info, 32));
  const hkdfKey = await importKeyMaterial(bytes(material));
  const key = {
    roomId,
    keyVersion,
    commitment: new Uint8Array(32),
    material: hkdfKey,
    wrappingKey: await deriveWrappingKey(hkdfKey, info),
  } as unknown as OpenedRoomKey;
  return { key, rwk };
}

function gcmEncrypt(key: Buffer, iv: Buffer, plaintext: Buffer, aad: Uint8Array): Buffer {
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

function gcmDecrypt(key: Buffer, iv: Uint8Array, sealed: Uint8Array, aad: Uint8Array): Buffer {
  const data = Buffer.from(sealed);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(data.subarray(-16));
  return Buffer.concat([decipher.update(data.subarray(0, -16)), decipher.final()]);
}

const sha = (data: Uint8Array): Buffer => createHash('sha256').update(data).digest();
const wrapAad = (roomId: string, keyVersion: number, fileId: string) =>
  contextBytes('cm.dek.wrap', { roomId, keyVersion, itemType: 'file', itemId: fileId, revision: 0 });

/** A stored file built entirely with Node.js crypto from the documented format. */
function nodeFile(
  room: TestRoomKey,
  content: Buffer,
  manifest: Record<string, unknown> | Buffer = {},
  fileId = randomUUID(),
): { record: StoredFile; ciphertext: Bytes } {
  const { roomId, keyVersion } = room.key;
  const fek = nodeRandom(32);
  const fekIv = nodeRandom(12);
  const manifestIv = nodeRandom(12);
  const contentIv = nodeRandom(12);
  const manifestBytes = Buffer.isBuffer(manifest)
    ? manifest
    : Buffer.from(
        canonicalBytes({
          v: 1,
          name: 'report.pdf',
          type: 'application/pdf',
          size: content.length,
          sha256: toBase64Url(sha(content)),
          ...(manifest as Record<string, never>),
        }),
      );
  const ciphertext = gcmEncrypt(fek, contentIv, content, contextBytes('cm.file.content', { roomId, fileId }));
  return {
    record: {
      roomId,
      fileId,
      keyVersion,
      suite: 'CM1',
      wrappedFek: {
        iv: bytes(fekIv),
        ciphertext: bytes(gcmEncrypt(room.rwk, fekIv, fek, wrapAad(roomId, keyVersion, fileId))),
      },
      manifest: {
        iv: bytes(manifestIv),
        ciphertext: bytes(
          gcmEncrypt(fek, manifestIv, manifestBytes, contextBytes('cm.file.manifest', { roomId, fileId })),
        ),
      },
      contentIv: bytes(contentIv),
      ciphertextSize: ciphertext.length,
      ciphertextSha256: bytes(sha(ciphertext)),
    },
    ciphertext: bytes(ciphertext),
  };
}

/** The stored record and object an uploader's browser produced. */
const stored = (file: EncryptedFile): { record: StoredFile; ciphertext: Bytes } => ({
  record: {
    roomId: file.roomId,
    fileId: file.fileId,
    keyVersion: file.keyVersion,
    suite: file.suite,
    wrappedFek: file.wrappedFek,
    manifest: file.manifest,
    contentIv: file.content.iv,
    ciphertextSize: file.content.ciphertext.length,
    ciphertextSha256: file.ciphertextSha256,
  },
  ciphertext: file.content.ciphertext,
});

async function rejects(promise: Promise<unknown>, code: string): Promise<void> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  expect(isCryptoError(caught), String(caught)).toBe(true);
  expect((caught as { code: string }).code).toBe(code);
}

const flip = (data: Uint8Array, index = 0): Bytes => {
  const copy = new Uint8Array(data);
  const at = index < 0 ? copy.length + index : index;
  copy[at] = (copy[at] ?? 0) ^ 0x01;
  return copy;
};

const AUTH = CryptoErrorCode.AUTHENTICATION_FAILED;
const INTEGRITY = CryptoErrorCode.FILE_INTEGRITY_FAILED;

describe('encrypted files: format against an independent implementation', () => {
  let room: TestRoomKey;
  beforeAll(async () => {
    room = await roomKey();
  });

  it('opens a file made by Node.js crypto from the documented contexts and manifest', async () => {
    const content = Buffer.from('Synthetic quarterly figures, not real data.\n', 'utf8');
    const { record, ciphertext } = nodeFile(room, content);
    const opened = await openFile(room.key, record);
    expect([opened.name, opened.type, opened.size]).toEqual(['report.pdf', 'application/pdf', content.length]);
    expect(Buffer.from(await opened.decrypt(ciphertext)).equals(content)).toBe(true);
  });

  it('produces records that Node.js crypto decrypts with RWK_v and the documented contexts', async () => {
    const fileId = randomUUID();
    const content = bytes(Buffer.from('known plaintext for the interoperability check'));
    const file = await encryptFile(room.key, { fileId, name: 'notes.txt', type: 'text/plain', content });
    const { roomId, keyVersion } = room.key;
    const fek = gcmDecrypt(
      room.rwk,
      file.wrappedFek.iv,
      file.wrappedFek.ciphertext,
      wrapAad(roomId, keyVersion, fileId),
    );
    expect(fek.length).toBe(32);
    const plain = gcmDecrypt(
      fek,
      file.content.iv,
      file.content.ciphertext,
      contextBytes('cm.file.content', { roomId, fileId }),
    );
    expect(plain.equals(Buffer.from(content))).toBe(true);
    const manifest = gcmDecrypt(
      fek,
      file.manifest.iv,
      file.manifest.ciphertext,
      contextBytes('cm.file.manifest', { roomId, fileId }),
    );
    // RFC 8785: members sorted, no whitespace; the plaintext hash only inside the manifest (CD-09).
    expect(manifest.toString('utf8')).toBe(
      `{"name":"notes.txt","sha256":"${toBase64Url(sha(content))}","size":${String(content.length)},"type":"text/plain","v":1}`,
    );
    expect(Buffer.from(file.ciphertextSha256).equals(sha(file.content.ciphertext))).toBe(true);
    expect([file.wrappedFek.ciphertext.length, file.wrappedFek.iv.length, file.content.iv.length]).toEqual([
      48, 12, 12,
    ]);
    expect(file.content.ciphertext.length).toBe(content.length + 16);
    expect(file.suite).toBe('CM1');
  });

  it('uses a fresh FEK and fresh IVs for every file, even for identical content', async () => {
    const content = bytes(Buffer.alloc(64, 7));
    const input = { name: 'same.bin', type: '', content };
    const a = await encryptFile(room.key, { ...input, fileId: randomUUID() });
    const b = await encryptFile(room.key, { ...input, fileId: randomUUID() });
    const values = [a, b].flatMap((f) => [
      toBase64Url(f.wrappedFek.ciphertext),
      toBase64Url(f.wrappedFek.iv),
      toBase64Url(f.content.iv),
      toBase64Url(f.manifest.iv),
      toBase64Url(f.content.ciphertext),
    ]);
    expect(new Set(values).size).toBe(values.length);
  });
});

describe('encrypted files: round trips and limits', () => {
  let room: TestRoomKey;
  beforeAll(async () => {
    room = await roomKey();
  });

  it.each([0, 1, 15, 16, 17, 4096, 1_000_003])('round-trips %i bytes', async (size) => {
    const content = bytes(nodeRandom(size));
    const file = await encryptFile(room.key, { fileId: randomUUID(), name: 'data.bin', type: '', content });
    const { record, ciphertext } = stored(file);
    const opened = await openFile(room.key, record);
    expect(opened.size).toBe(size);
    expect(Buffer.from(await opened.decrypt(ciphertext)).equals(Buffer.from(content))).toBe(true);
  });

  it('accepts exactly the CP-19 limit and refuses one byte more', async () => {
    const max = new Uint8Array(FILES.maxPlaintextBytes);
    const file = await encryptFile(room.key, { fileId: randomUUID(), name: 'max.bin', type: '', content: max });
    expect(file.content.ciphertext.length).toBe(FILES.maxPlaintextBytes + 16);
    const { record, ciphertext } = stored(file);
    expect((await (await openFile(room.key, record)).decrypt(ciphertext)).length).toBe(FILES.maxPlaintextBytes);
    await rejects(
      encryptFile(room.key, {
        fileId: randomUUID(),
        name: 'big.bin',
        type: '',
        content: new Uint8Array(FILES.maxPlaintextBytes + 1),
      }),
      CryptoErrorCode.INVALID_INPUT,
    );
  });

  it('keeps names with spaces, accents and emoji, and refuses names that could disguise a file', async () => {
    const name = 'Résumé – final 📄.pdf';
    const file = await encryptFile(room.key, {
      fileId: randomUUID(),
      name,
      type: 'application/pdf',
      content: bytes(Buffer.from('x')),
    });
    expect((await openFile(room.key, stored(file).record)).name).toBe(name);
    const content = bytes(Buffer.from('x'));
    for (const bad of [
      '',
      'a'.repeat(256),
      'evil\u0000.exe',
      'line\nbreak',
      'bell\u0007',
      '\ud800lone',
      'c1\u0085',
      'photo\u202egnp.exe',
      'iso\u2066late',
    ]) {
      await rejects(
        encryptFile(room.key, { fileId: randomUUID(), name: bad, type: '', content }),
        CryptoErrorCode.INVALID_INPUT,
      );
    }
    for (const type of ['Text/HTML', 'text/html; charset=utf-8', 'html', `x/${'y'.repeat(130)}`]) {
      await rejects(
        encryptFile(room.key, { fileId: randomUUID(), name: 'a', type, content }),
        CryptoErrorCode.INVALID_INPUT,
      );
    }
    await rejects(
      encryptFile(room.key, { fileId: 'not-a-uuid', name: 'a', type: '', content }),
      CryptoErrorCode.INVALID_INPUT,
    );
  });
});

describe('encrypted files: tampering and substitution fail closed', () => {
  let room: TestRoomKey;
  let file: EncryptedFile;
  let record: StoredFile;
  let ciphertext: Bytes;
  const content = bytes(Buffer.from('Synthetic canary CM-FILE-CANARY-TAMPER, no real data.'));

  beforeAll(async () => {
    room = await roomKey();
    file = await encryptFile(room.key, { fileId: randomUUID(), name: 'tamper.txt', type: 'text/plain', content });
    ({ record, ciphertext } = stored(file));
  });

  it.each([
    [
      'wrapped FEK',
      (r: StoredFile) => ({ ...r, wrappedFek: { ...r.wrappedFek, ciphertext: flip(r.wrappedFek.ciphertext, 5) } }),
    ],
    [
      'wrapped FEK tag',
      (r: StoredFile) => ({ ...r, wrappedFek: { ...r.wrappedFek, ciphertext: flip(r.wrappedFek.ciphertext, -1) } }),
    ],
    ['FEK IV', (r: StoredFile) => ({ ...r, wrappedFek: { ...r.wrappedFek, iv: flip(r.wrappedFek.iv) } })],
    [
      'manifest',
      (r: StoredFile) => ({ ...r, manifest: { ...r.manifest, ciphertext: flip(r.manifest.ciphertext, 3) } }),
    ],
    [
      'manifest tag',
      (r: StoredFile) => ({ ...r, manifest: { ...r.manifest, ciphertext: flip(r.manifest.ciphertext, -1) } }),
    ],
    ['manifest IV', (r: StoredFile) => ({ ...r, manifest: { ...r.manifest, iv: flip(r.manifest.iv) } })],
  ])('refuses a bit flip in the %s before any content is decrypted', async (_part, tamper) => {
    await rejects(openFile(room.key, tamper(record)), AUTH);
  });

  it('refuses bit flips in the content, its tag and its IV', async () => {
    for (const changed of [flip(ciphertext, 0), flip(ciphertext, 20), flip(ciphertext, -1)]) {
      // The record's ciphertext hash no longer matches: the early storage check refuses it.
      await rejects((await openFile(room.key, record)).decrypt(changed), INTEGRITY);
      // A record whose hash was replaced to match: the AES-GCM tag still refuses it.
      const forged = { ...record, ciphertextSha256: bytes(sha(changed)) };
      await rejects((await openFile(room.key, forged)).decrypt(changed), AUTH);
    }
    await rejects(
      (await openFile(room.key, { ...record, contentIv: flip(record.contentIv) })).decrypt(ciphertext),
      AUTH,
    );
  });

  it('refuses truncated, extended or empty content and a record with another size', async () => {
    const opened = await openFile(room.key, record);
    for (const changed of [
      ciphertext.subarray(0, -1),
      ciphertext.subarray(0, 16),
      new Uint8Array(0),
      bytes(Buffer.concat([ciphertext, Buffer.from([0])])),
    ]) {
      await rejects(opened.decrypt(bytes(changed)), INTEGRITY);
      const forged = { ...record, ciphertextSha256: bytes(sha(changed)), ciphertextSize: changed.length };
      await expect(openFile(room.key, forged).then((o) => o.decrypt(bytes(changed)))).rejects.toSatisfy(
        (e: unknown) => isCryptoError(e, INTEGRITY) || isCryptoError(e, AUTH),
      );
    }
    await rejects(openFile(room.key, { ...record, ciphertextSize: record.ciphertextSize + 1 }), INTEGRITY);
  });

  it('refuses a wrapped FEK moved to another file, and content or manifest of another file', async () => {
    const other = stored(
      await encryptFile(room.key, { fileId: randomUUID(), name: 'other.txt', type: 'text/plain', content }),
    );
    // The wrapped FEK is bound to its file ID by cm.dek.wrap.
    await rejects(openFile(room.key, { ...other.record, wrappedFek: record.wrappedFek }), AUTH);
    // Same room, same key version, but another file's manifest: different FEK and file ID.
    await rejects(openFile(room.key, { ...record, manifest: other.record.manifest }), AUTH);
    // Another file's content object under this file's record.
    await rejects((await openFile(room.key, record)).decrypt(other.ciphertext), INTEGRITY);
    const forged = { ...record, ciphertextSha256: other.record.ciphertextSha256, contentIv: other.record.contentIv };
    await rejects((await openFile(room.key, forged)).decrypt(other.ciphertext), AUTH);
  });

  it('refuses a file record moved to another room or key version', async () => {
    const otherRoom = await roomKey();
    // The caller must use the key the record names; another room or version is refused outright.
    await rejects(openFile(otherRoom.key, record), CryptoErrorCode.INVALID_INPUT);
    await rejects(openFile((await roomKey(room.key.roomId, 2)).key, record), CryptoErrorCode.INVALID_INPUT);
    // Even if the record were relabelled to match another room or version, the AAD binds it.
    await rejects(openFile(otherRoom.key, { ...record, roomId: otherRoom.key.roomId }), AUTH);
    const version2 = await roomKey(room.key.roomId, 2);
    await rejects(openFile(version2.key, { ...record, keyVersion: 2 }), AUTH);
  });

  it('refuses a key that is not the room key of that version (different key material)', async () => {
    const impostor = await roomKey(room.key.roomId, room.key.keyVersion);
    await rejects(openFile(impostor.key, record), AUTH);
  });

  it('refuses a FEK wrapped for another item type or revision (wrong wrapping context)', async () => {
    const { roomId, keyVersion } = room.key;
    const fek = await generateDataKey();
    for (const aad of [
      contextBytes('cm.dek.wrap', { roomId, keyVersion, itemType: 'note', itemId: record.fileId, revision: 0 }),
      contextBytes('cm.dek.wrap', { roomId, keyVersion, itemType: 'file', itemId: record.fileId, revision: 1 }),
    ]) {
      const wrapped = await wrapDataKey(fek, room.key.wrappingKey, aad);
      await rejects(openFile(room.key, { ...record, wrappedFek: wrapped }), AUTH);
    }
  });

  it('refuses an unsupported suite and malformed record values', async () => {
    await rejects(openFile(room.key, { ...record, suite: 'CM2' }), CryptoErrorCode.FILE_FORMAT_UNSUPPORTED);
    await rejects(openFile(room.key, { ...record, contentIv: new Uint8Array(11) }), INTEGRITY);
    await rejects(openFile(room.key, { ...record, ciphertextSha256: new Uint8Array(31) }), INTEGRITY);
    await rejects(openFile(room.key, { ...record, ciphertextSize: 15 }), INTEGRITY);
    await rejects(openFile(room.key, { ...record, ciphertextSize: 1.5 }), INTEGRITY);
    await rejects(
      openFile(room.key, {
        ...record,
        wrappedFek: { ...record.wrappedFek, ciphertext: record.wrappedFek.ciphertext.subarray(0, 47) },
      }),
      INTEGRITY,
    );
  });
});

describe('encrypted files: manifests from a malicious uploader', () => {
  let room: TestRoomKey;
  const content = Buffer.from('synthetic');
  beforeAll(async () => {
    room = await roomKey();
  });

  it('refuses a manifest version it does not know', async () => {
    await rejects(
      openFile(room.key, nodeFile(room, content, { v: 2 }).record),
      CryptoErrorCode.FILE_FORMAT_UNSUPPORTED,
    );
  });

  it.each([
    ['not JSON', Buffer.from('not json')],
    ['invalid UTF-8', Buffer.from([0x7b, 0xff, 0x7d])],
    ['an array', Buffer.from('[1]')],
    ['a string version', Buffer.from('{"v":"1"}')],
  ])('refuses a manifest that is %s', async (_case, manifest) => {
    await rejects(openFile(room.key, nodeFile(room, content, manifest).record), INTEGRITY);
  });

  it.each([
    ['an extra field', { html: '<script>' }],
    ['a control character in the name', { name: 'a\u0000b' }],
    ['a right-to-left override in the name', { name: 'photo\u202egnp.exe' }],
    ['an empty name', { name: '' }],
    ['a type that is not a MIME type', { type: 'text/html; charset=utf-8' }],
    ['a negative size', { size: -1 }],
    ['a size above CP-19', { size: FILES.maxPlaintextBytes + 1 }],
    ['a malformed hash', { sha256: 'abc' }],
  ])('refuses a manifest with %s', async (_case, fields) => {
    await rejects(openFile(room.key, nodeFile(room, content, fields).record), INTEGRITY);
  });

  it('refuses content that authenticates but does not match the manifest size or hash', async () => {
    const wrongSize = nodeFile(room, content, { size: content.length - 1 });
    await rejects(openFile(room.key, wrongSize.record), INTEGRITY);
    const wrongHash = nodeFile(room, content, { sha256: toBase64Url(sha(Buffer.from('other'))) });
    const opened = await openFile(room.key, wrongHash.record);
    await rejects(opened.decrypt(wrongHash.ciphertext), INTEGRITY);
  });
});

describe('encrypted files: wire format', () => {
  it('round-trips through base64url and refuses malformed values', async () => {
    const room = await roomKey();
    const file = await encryptFile(room.key, {
      fileId: randomUUID(),
      name: 'wire.txt',
      type: 'text/plain',
      content: bytes(Buffer.from('wire')),
    });
    const wire = encryptedFileToWire(file);
    expect(Object.keys(wire).sort()).toEqual([
      'ciphertextSha256',
      'ciphertextSize',
      'contentIv',
      'fekIv',
      'fileId',
      'keyVersion',
      'manifest',
      'manifestIv',
      'suite',
      'wrappedFek',
    ]);
    expect(JSON.stringify(wire)).not.toContain('wire.txt');
    const record = storedFileFromWire(room.key.roomId, wire);
    expect(Buffer.from(await (await openFile(room.key, record)).decrypt(file.content.ciphertext)).toString()).toBe(
      'wire',
    );
    const broken: EncryptedFileWire[] = [
      { ...wire, wrappedFek: wire.wrappedFek.slice(1) },
      { ...wire, fekIv: `${wire.fekIv}A` },
      { ...wire, contentIv: '!!' },
      { ...wire, ciphertextSha256: toBase64Url(new Uint8Array(31)) },
      { ...wire, manifest: 'a=' },
    ];
    for (const bad of broken) {
      expect(() => storedFileFromWire(room.key.roomId, bad)).toThrow(
        expect.objectContaining({ code: CryptoErrorCode.FILE_INTEGRITY_FAILED }) as Error,
      );
    }
    expect(fromBase64Url(wire.ciphertextSha256).length).toBe(32);
  });
});

describe('data-key wrapping', () => {
  it('creates encrypt-only DEKs and unwraps them as non-extractable decrypt-only keys', async () => {
    const room = await roomKey();
    const dek = await generateDataKey();
    expect(dek.extractable).toBe(true);
    expect([...dek.usages]).toEqual(['encrypt']);
    const aad = wrapAad(room.key.roomId, 1, randomUUID());
    const wrapped = await wrapDataKey(dek, room.key.wrappingKey, aad);
    const unwrapped = await unwrapDataKey(wrapped, room.key.wrappingKey, aad);
    expect(unwrapped.extractable).toBe(false);
    expect([...unwrapped.usages]).toEqual(['decrypt']);
    await rejects(unwrapDataKey({ ...wrapped, iv: new Uint8Array(11) }, room.key.wrappingKey, aad), AUTH);
    await rejects(wrapDataKey(dek, room.key.wrappingKey, new Uint8Array(0) as never), CryptoErrorCode.INVALID_INPUT);
  });
});
