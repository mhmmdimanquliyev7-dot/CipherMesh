import { createCipheriv, createDecipheriv, hkdfSync, randomBytes as nodeRandom, randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { canonicalBytes } from './canonical';
import { contextBytes } from './contexts';
import { fromBase64Url, toBase64Url } from './encoding';
import { CryptoErrorCode, isCryptoError } from './errors';
import { deriveWrappingKey, importKeyMaterial } from './hkdf';
import { noteCiphertextToWire, storedNoteFromWire, type StoredNoteWire } from './note-format';
import { encryptNote, isNoteTitle, noteDocumentBytes, openNote, type EncryptedNote, type StoredNote } from './notes';
import { NOTES } from './params';
import type { OpenedRoomKey } from './room-keys';
import type { Bytes } from './types';

// Encrypted notes (Phase 8, CM-T042, DF-12). Known answers come from an independent implementation:
// Node.js crypto (OpenSSL) derives RWK_v with HKDF-SHA-256 and encrypts or wraps with AES-256-GCM
// under the documented contexts, in both directions. The tamper tests change every stored part and
// move parts between notes, rooms, key versions, revisions and wrapping contexts; each must fail
// without releasing a title or body (threat-model T-07, T-32). Every text here is synthetic.

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

function gcmEncrypt(key: Buffer, iv: Buffer, plaintext: Uint8Array, aad: Uint8Array): Buffer {
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

const contentAad = (roomId: string, noteId: string, revision: number) =>
  contextBytes('cm.note.content', { roomId, noteId, revision });
const wrapAad = (
  roomId: string,
  keyVersion: number,
  noteId: string,
  revision: number,
  itemType: 'note' | 'file' = 'note',
) => contextBytes('cm.dek.wrap', { roomId, keyVersion, itemType, itemId: noteId, revision });

/** A stored note built entirely with Node.js crypto from the documented format. */
function nodeNote(
  room: TestRoomKey,
  document: Record<string, unknown> | Uint8Array = { v: 1, title: 'Synthetic title', body: 'Synthetic body' },
  options: { noteId?: string; revision?: number; nek?: Buffer } = {},
): StoredNote {
  const { roomId, keyVersion } = room.key;
  const noteId = options.noteId ?? randomUUID();
  const revision = options.revision ?? 1;
  const nek = options.nek ?? nodeRandom(32);
  const nekIv = nodeRandom(12);
  const contentIv = nodeRandom(12);
  const plaintext = document instanceof Uint8Array ? document : canonicalBytes(document as never);
  return {
    roomId,
    noteId,
    revision,
    keyVersion,
    suite: 'CM1',
    wrappedNek: {
      iv: bytes(nekIv),
      ciphertext: bytes(gcmEncrypt(room.rwk, nekIv, nek, wrapAad(roomId, keyVersion, noteId, revision))),
    },
    content: {
      iv: bytes(contentIv),
      ciphertext: bytes(gcmEncrypt(nek, contentIv, plaintext, contentAad(roomId, noteId, revision))),
    },
  };
}

const stored = (note: EncryptedNote): StoredNote => ({
  roomId: note.roomId,
  noteId: note.noteId,
  revision: note.revision,
  keyVersion: note.keyVersion,
  suite: note.suite,
  wrappedNek: note.wrappedNek,
  content: note.content,
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
const INTEGRITY = CryptoErrorCode.NOTE_INTEGRITY_FAILED;
const UNSUPPORTED = CryptoErrorCode.NOTE_FORMAT_UNSUPPORTED;

async function encrypted(
  room: TestRoomKey,
  revision = 1,
  title = 'Plan',
  body = 'Synthetic body',
): Promise<EncryptedNote> {
  return encryptNote(room.key, { noteId: randomUUID(), revision, title, body });
}

describe('encrypted notes: format against an independent implementation', () => {
  it('opens a note made by Node.js crypto from the documented contexts and document', async () => {
    const room = await roomKey();
    const note = nodeNote(room, { v: 1, title: 'Quarterly plan', body: 'Line one\nLine two' }, { revision: 7 });
    expect(await openNote(room.key, note)).toEqual({
      roomId: room.key.roomId,
      noteId: note.noteId,
      revision: 7,
      keyVersion: 1,
      title: 'Quarterly plan',
      body: 'Line one\nLine two',
    });
  });

  it('produces records that Node.js crypto decrypts with RWK_v and the documented contexts', async () => {
    const room = await roomKey(randomUUID(), 3);
    const note = await encryptNote(room.key, {
      noteId: randomUUID(),
      revision: 42,
      title: 'Café ☕',
      body: 'Ünïcode 🚀',
    });
    const { roomId, noteId } = note;
    expect(note).toMatchObject({ keyVersion: 3, revision: 42, suite: 'CM1' });
    expect(note.wrappedNek.ciphertext).toHaveLength(NOTES.wrappedNekBytes);
    const nek = gcmDecrypt(room.rwk, note.wrappedNek.iv, note.wrappedNek.ciphertext, wrapAad(roomId, 3, noteId, 42));
    expect(nek).toHaveLength(32);
    const document = gcmDecrypt(nek, note.content.iv, note.content.ciphertext, contentAad(roomId, noteId, 42));
    // The document is exactly the RFC 8785 serialization: keys sorted, no whitespace.
    expect(document.toString('utf8')).toBe('{"body":"Ünïcode 🚀","title":"Café ☕","v":1}');
  });

  it('uses a fresh NEK and fresh IVs for every revision, even for identical text', async () => {
    const room = await roomKey();
    const noteId = randomUUID();
    const seenIvs = new Set<string>();
    const neks = new Set<string>();
    for (let revision = 1; revision <= 20; revision += 1) {
      const note = await encryptNote(room.key, { noteId, revision: 1, title: 'Same', body: 'Same' });
      expect(note.revision).toBe(1);
      for (const iv of [note.wrappedNek.iv, note.content.iv]) seenIvs.add(toBase64Url(iv));
      const nek = gcmDecrypt(
        room.rwk,
        note.wrappedNek.iv,
        note.wrappedNek.ciphertext,
        wrapAad(note.roomId, 1, noteId, 1),
      );
      neks.add(nek.toString('hex'));
    }
    expect(seenIvs.size).toBe(40);
    expect(neks.size).toBe(20);
  });
});

describe('encrypted notes: round trips and limits', () => {
  it('round-trips an empty body, multi-line text and every kind of Unicode', async () => {
    const room = await roomKey();
    for (const [title, body] of [
      ['Empty', ''],
      ['Lines', 'one\r\ntwo\n\tthree'],
      ['日本語のノート', 'Ελληνικά, עברית, العربية, 😀👩‍👩‍👧'],
      ['<script>alert(1)</script>', '<img src=x onerror=alert(1)> "quotes" \\ backslash \u0000 nul'],
    ] as const) {
      const note = await encryptNote(room.key, { noteId: randomUUID(), revision: 1, title, body });
      expect(await openNote(room.key, stored(note))).toMatchObject({ title, body });
    }
  });

  it('accepts a document of exactly the D-08-01 limit and refuses one byte more', async () => {
    const room = await roomKey();
    const overhead = noteDocumentBytes({ title: 'T', body: '' });
    const fits = 'a'.repeat(NOTES.maxDocumentBytes - overhead);
    expect(noteDocumentBytes({ title: 'T', body: fits })).toBe(NOTES.maxDocumentBytes);
    const note = await encryptNote(room.key, { noteId: randomUUID(), revision: 1, title: 'T', body: fits });
    expect(note.content.ciphertext).toHaveLength(NOTES.maxDocumentBytes + 16);
    expect((await openNote(room.key, stored(note))).body).toHaveLength(fits.length);
    await rejects(
      encryptNote(room.key, { noteId: randomUUID(), revision: 1, title: 'T', body: `${fits}a` }),
      CryptoErrorCode.INVALID_INPUT,
    );
    // Escaped characters count as they are serialized: a newline is two bytes in the document.
    expect(noteDocumentBytes({ title: 'T', body: '\n' })).toBe(overhead + 2);
  });

  it('accepts titles up to 200 code units and refuses empty, longer or disguised titles', async () => {
    const room = await roomKey();
    expect(isNoteTitle('x'.repeat(NOTES.maxTitleLength))).toBe(true);
    for (const title of [
      '',
      'x'.repeat(NOTES.maxTitleLength + 1),
      'two\nlines',
      'tab\there',
      'bidi‮txt',
      'lone \ud800',
    ]) {
      expect(isNoteTitle(title), JSON.stringify(title)).toBe(false);
      await rejects(
        encryptNote(room.key, { noteId: randomUUID(), revision: 1, title, body: '' }),
        CryptoErrorCode.INVALID_INPUT,
      );
    }
    expect(noteDocumentBytes({ title: 'ok', body: 'lone \udc00' })).toBe(Number.POSITIVE_INFINITY);
    expect(noteDocumentBytes({ title: 7 as unknown as string, body: '' })).toBe(Number.POSITIVE_INFINITY);
  });

  it('accepts revisions 1 to 2^31 - 1 and refuses anything else', async () => {
    const room = await roomKey();
    const top = await encrypted(room, NOTES.maxRevision);
    expect((await openNote(room.key, stored(top))).revision).toBe(NOTES.maxRevision);
    for (const revision of [0, -1, 1.5, NOTES.maxRevision + 1, Number.NaN]) {
      await rejects(
        encryptNote(room.key, { noteId: randomUUID(), revision, title: 'T', body: '' }),
        CryptoErrorCode.INVALID_INPUT,
      );
      await rejects(openNote(room.key, { ...stored(top), revision }), INTEGRITY);
    }
  });

  it('refuses identifiers that are not UUIDv4 before any key exists', async () => {
    const room = await roomKey();
    await rejects(
      encryptNote(room.key, { noteId: 'not-a-uuid', revision: 1, title: 'T', body: '' }),
      CryptoErrorCode.INVALID_INPUT,
    );
  });
});

describe('encrypted notes: tampering and substitution fail closed', () => {
  it('refuses bit flips in the body ciphertext, its tag, its IV, the wrapped NEK and its IV', async () => {
    const room = await roomKey();
    const note = stored(await encrypted(room));
    const { content, wrappedNek } = note;
    for (const changed of [
      { ...note, content: { ...content, ciphertext: flip(content.ciphertext) } },
      { ...note, content: { ...content, ciphertext: flip(content.ciphertext, -1) } },
      { ...note, content: { ...content, iv: flip(content.iv) } },
      { ...note, wrappedNek: { ...wrappedNek, ciphertext: flip(wrappedNek.ciphertext, 5) } },
      { ...note, wrappedNek: { ...wrappedNek, ciphertext: flip(wrappedNek.ciphertext, -1) } },
      { ...note, wrappedNek: { ...wrappedNek, iv: flip(wrappedNek.iv) } },
    ]) {
      await rejects(openNote(room.key, changed), AUTH);
    }
  });

  it('refuses a title change: title and body are one authenticated message', async () => {
    // The title is the second field of the document; flipping a byte inside it fails the tag.
    const room = await roomKey();
    const note = stored(await encrypted(room, 1, 'Original title', 'body'));
    const titleOffset = '{"body":"body","title":"'.length;
    await rejects(
      openNote(room.key, {
        ...note,
        content: { ...note.content, ciphertext: flip(note.content.ciphertext, titleOffset) },
      }),
      AUTH,
    );
  });

  it('refuses truncated and extended ciphertext', async () => {
    const room = await roomKey();
    const note = stored(await encrypted(room));
    const { ciphertext } = note.content;
    await rejects(
      openNote(room.key, { ...note, content: { ...note.content, ciphertext: ciphertext.subarray(0, -1) } }),
      AUTH,
    );
    await rejects(
      openNote(room.key, { ...note, content: { ...note.content, ciphertext: new Uint8Array([...ciphertext, 0]) } }),
      AUTH,
    );
    await rejects(
      openNote(room.key, { ...note, content: { ...note.content, ciphertext: ciphertext.subarray(0, 16) } }),
      INTEGRITY,
    );
    await rejects(
      openNote(room.key, {
        ...note,
        wrappedNek: { ...note.wrappedNek, ciphertext: note.wrappedNek.ciphertext.subarray(0, 47) },
      }),
      INTEGRITY,
    );
    await rejects(
      openNote(room.key, { ...note, content: { ...note.content, iv: note.content.iv.subarray(0, 11) } }),
      INTEGRITY,
    );
    await rejects(
      openNote(room.key, { ...note, wrappedNek: { ...note.wrappedNek, iv: new Uint8Array(13) } }),
      INTEGRITY,
    );
    await rejects(
      openNote(room.key, {
        ...note,
        content: { ...note.content, ciphertext: new Uint8Array(NOTES.maxDocumentBytes + 17) },
      }),
      INTEGRITY,
    );
  });

  it('refuses another revision: ciphertext moved to revision r + 1 or replayed as r - 1 fails authentication', async () => {
    const room = await roomKey();
    const note = stored(await encrypted(room, 5));
    for (const revision of [4, 6, 1]) {
      await rejects(openNote(room.key, { ...note, revision }), AUTH);
    }
    // Even a NEK wrapped for the claimed revision cannot carry a body encrypted for another one.
    const nek = nodeRandom(32);
    const mixed = nodeNote(room, { v: 1, title: 'T', body: 'B' }, { revision: 6, nek });
    const body5 = nodeNote(room, { v: 1, title: 'T', body: 'B' }, { noteId: mixed.noteId, revision: 5, nek });
    await rejects(openNote(room.key, { ...mixed, content: body5.content }), AUTH);
  });

  it('refuses another note: a wrapped NEK or body moved between notes fails authentication', async () => {
    const room = await roomKey();
    const a = stored(await encrypted(room));
    const b = stored(await encrypted(room));
    await rejects(openNote(room.key, { ...a, noteId: b.noteId }), AUTH);
    await rejects(openNote(room.key, { ...a, content: b.content }), AUTH);
    await rejects(openNote(room.key, { ...a, wrappedNek: b.wrappedNek }), AUTH);
  });

  it('refuses another room or key version, and a key that is not the room key of that version', async () => {
    const room = await roomKey(randomUUID(), 1);
    const note = stored(await encrypted(room));
    const otherRoom = await roomKey();
    // The record claims the other room: the key matches the claim, the contexts do not.
    await rejects(openNote(otherRoom.key, { ...note, roomId: otherRoom.key.roomId }), AUTH);
    const version2 = await roomKey(room.key.roomId, 2);
    await rejects(openNote(version2.key, { ...note, keyVersion: 2 }), AUTH);
    // A key of another room or version than the record names is refused before decryption.
    await rejects(openNote(otherRoom.key, note), CryptoErrorCode.INVALID_INPUT);
    await rejects(openNote(version2.key, note), CryptoErrorCode.INVALID_INPUT);
    // Same room and version, different key material (for example a substituted envelope).
    const impostor = await roomKey(room.key.roomId, 1);
    await rejects(openNote(impostor.key, note), AUTH);
  });

  it('refuses a NEK wrapped for another item type, revision or key version (wrong wrapping context)', async () => {
    const room = await roomKey(randomUUID(), 2);
    const { roomId } = room.key;
    const noteId = randomUUID();
    const nek = nodeRandom(32);
    const good = nodeNote(room, { v: 1, title: 'T', body: 'B' }, { noteId, revision: 3, nek });
    for (const aad of [
      wrapAad(roomId, 2, noteId, 3, 'file'),
      wrapAad(roomId, 2, noteId, 0),
      wrapAad(roomId, 1, noteId, 3),
      contentAad(roomId, noteId, 3),
    ]) {
      const iv = nodeRandom(12);
      const wrappedNek = { iv: bytes(iv), ciphertext: bytes(gcmEncrypt(room.rwk, iv, nek, aad)) };
      await rejects(openNote(room.key, { ...good, wrappedNek }), AUTH);
    }
    expect((await openNote(room.key, good)).title).toBe('T');
  });

  it('refuses an unsupported suite before any decryption', async () => {
    const room = await roomKey();
    const note = stored(await encrypted(room));
    for (const suite of ['CM2', 'cm1', '']) await rejects(openNote(room.key, { ...note, suite }), UNSUPPORTED);
  });
});

describe('encrypted notes: documents from a malicious member', () => {
  // A member who holds the room key can encrypt any bytes; the document must still be a valid note.
  it('refuses a document version it does not know', async () => {
    const room = await roomKey();
    await rejects(openNote(room.key, nodeNote(room, { v: 2, title: 'T', body: 'B' })), UNSUPPORTED);
    for (const v of ['1', null, true]) {
      await rejects(openNote(room.key, nodeNote(room, { v, title: 'T', body: 'B' })), INTEGRITY);
    }
  });

  it('refuses documents that authenticate but are not canonical version-1 notes', async () => {
    const room = await roomKey();
    const text = (s: string) => new TextEncoder().encode(s);
    for (const document of [
      text('not json'),
      text('[1]'),
      text('null'),
      text('{"body":"B","title":"T","v":1,"extra":true}'),
      text('{"body":"B","v":1}'),
      text('{"body":5,"title":"T","v":1}'),
      text('{"body":"B","title":"","v":1}'),
      text('{"body":"B","title":"two\\nlines","v":1}'),
      text('{"title":"T","body":"B","v":1}'),
      text('{ "body":"B","title":"T","v":1}'),
      text('{"body":"B","body":"C","title":"T","v":1}'),
      text('{"body":"\\ud800","title":"T","v":1}'),
      new Uint8Array([0xff, 0xfe]),
    ]) {
      await rejects(openNote(room.key, nodeNote(room, document)), INTEGRITY);
    }
  });
});

describe('encrypted notes: wire format', () => {
  it('round-trips through base64url and refuses malformed values', async () => {
    const room = await roomKey();
    const note = await encrypted(room, 9, 'Wire', 'Format');
    const wire: StoredNoteWire = { ...noteCiphertextToWire(note), noteId: note.noteId, revision: 9 };
    expect(Object.keys(noteCiphertextToWire(note)).sort()).toEqual(
      ['ciphertext', 'contentIv', 'keyVersion', 'nekIv', 'suite', 'wrappedNek'].sort(),
    );
    expect(fromBase64Url(wire.ciphertext)).toEqual(note.content.ciphertext);
    expect(await openNote(room.key, storedNoteFromWire(room.key.roomId, wire))).toMatchObject({
      title: 'Wire',
      body: 'Format',
    });
    for (const broken of [
      { ...wire, wrappedNek: wire.wrappedNek.slice(1) },
      { ...wire, nekIv: 'AAAA' },
      { ...wire, contentIv: '!!!!!!!!!!!!!!!!' },
      { ...wire, ciphertext: 'not base64url+' },
      { ...wire, ciphertext: toBase64Url(new Uint8Array(NOTES.maxDocumentBytes + 17)) },
    ]) {
      expect(() => storedNoteFromWire(room.key.roomId, broken)).toThrow(expect.objectContaining({ code: INTEGRITY }));
    }
  });

  it('a record decoded for another room is refused by the room key check', async () => {
    const room = await roomKey();
    const note = await encrypted(room);
    const wire = { ...noteCiphertextToWire(note), noteId: note.noteId, revision: 1 };
    await rejects(openNote(room.key, storedNoteFromWire(randomUUID(), wire)), CryptoErrorCode.INVALID_INPUT);
  });
});
