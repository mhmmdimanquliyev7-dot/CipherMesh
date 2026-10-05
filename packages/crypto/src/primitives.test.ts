import { describe, expect, it } from 'vitest';
import { decrypt, encrypt, type Sealed } from './aead';
import { contextBytes } from './contexts';
import { fromHex, toHex } from './encoding';
import { CryptoErrorCode, isCryptoError } from './errors';
import { sha256 } from './hash';
import { deriveBits, importKeyMaterial } from './hkdf';
import { aesGcmDecryptWithIv, aesGcmEncryptWithIv, hkdfSha256Bits, importAesGcmKeyForTest } from './internal/raw';
import type { Bytes } from './types';
import { subtle } from './webcrypto';

// Known-answer tests use published vectors only (FIPS 180-2 examples, RFC 5869, the GCM
// specification of McGrew and Viega, test cases 13 to 16 for AES-256). A round trip alone is never
// accepted as evidence, because two equally wrong implementations round-trip perfectly.

const ascii = (text: string): Bytes => new Uint8Array(Buffer.from(text, 'ascii'));

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  expect(isCryptoError(caught)).toBe(true);
  expect((caught as { code: string }).code).toBe(code);
}

describe('SHA-256 (FIPS 180-2 examples)', () => {
  it('matches the published digests', async () => {
    expect(toHex(await sha256(ascii('')))).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(toHex(await sha256(ascii('abc')))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(toHex(await sha256(ascii('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')))).toBe(
      '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
    );
  });
});

describe('HKDF-SHA-256 (RFC 5869 appendix A)', () => {
  const importIkm = async (hex: string) => {
    // importKeyMaterial accepts exactly 32 bytes; the RFC inputs use other sizes, so they are
    // imported directly through the same WebCrypto call.
    return subtle().importKey('raw', fromHex(hex), 'HKDF', false, ['deriveBits']);
  };

  it('test case 1', async () => {
    const okm = await hkdfSha256Bits(
      await importIkm('0b'.repeat(22)),
      fromHex('000102030405060708090a0b0c'),
      fromHex('f0f1f2f3f4f5f6f7f8f9'),
      42,
    );
    expect(toHex(okm)).toBe('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
  });

  it('test case 2 (long inputs and output)', async () => {
    const range = (from: number, to: number) => toHex(Uint8Array.from({ length: to - from + 1 }, (_, i) => from + i));
    const okm = await hkdfSha256Bits(
      await importIkm(range(0x00, 0x4f)),
      fromHex(range(0x60, 0xaf)),
      fromHex(range(0xb0, 0xff)),
      82,
    );
    expect(toHex(okm)).toBe(
      'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09' +
        'da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87',
    );
  });

  it('test case 3: an empty salt equals the 32 zero bytes CipherMesh uses (CP-03)', async () => {
    const expected = '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8';
    const ikm = await importIkm('0b'.repeat(22));
    expect(toHex(await hkdfSha256Bits(ikm, new Uint8Array(0), new Uint8Array(0), 42))).toBe(expected);
    expect(toHex(await hkdfSha256Bits(ikm, new Uint8Array(32), new Uint8Array(0), 42))).toBe(expected);
  });

  it('production derivation = HKDF(ikm, 32 zero bytes, canonical context), and contexts separate keys', async () => {
    const ikmBytes = fromHex('11'.repeat(32));
    const ikm = await importKeyMaterial(new Uint8Array(ikmBytes));
    const info = contextBytes('cm.room.commitment', { roomId: '1d6b4f0e-2c3a-4b5d-8e9f-0a1b2c3d4e5f', keyVersion: 1 });
    const viaWrapper = await deriveBits(ikm, info);
    const reference = await hkdfSha256Bits(await importIkm(toHex(ikmBytes)), new Uint8Array(32), info, 32);
    expect(toHex(viaWrapper)).toBe(toHex(reference));
    const other = contextBytes('cm.room.safety-code', {
      roomId: '1d6b4f0e-2c3a-4b5d-8e9f-0a1b2c3d4e5f',
      keyVersion: 1,
    });
    expect(toHex(await deriveBits(ikm, other))).not.toBe(toHex(viaWrapper));
  });

  it('importKeyMaterial wipes the input buffer and accepts only 32 bytes', async () => {
    const bytes = fromHex('22'.repeat(32));
    await importKeyMaterial(bytes);
    expect(bytes.every((b) => b === 0)).toBe(true);
    await expectCode(importKeyMaterial(new Uint8Array(31)), CryptoErrorCode.INVALID_INPUT);
  });
});

describe('AES-256-GCM (GCM specification test cases 13 to 16)', () => {
  const K1 = '00'.repeat(32);
  const K2 = 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308';
  const P =
    'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525' +
    'b16aedf5aa0de657ba637b391aafd255';
  const C =
    '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838' +
    'c5f61e6393ba7a0abcc9f662898015ad';
  const cases = [
    { name: 'TC13', key: K1, iv: '00'.repeat(12), pt: '', aad: '', ct: '', tag: '530f8afbc74536b9a963b4f1c4cb738b' },
    {
      name: 'TC14',
      key: K1,
      iv: '00'.repeat(12),
      pt: '00'.repeat(16),
      aad: '',
      ct: 'cea7403d4d606b6e074ec5d3baf39d18',
      tag: 'd0d1c8a799996bf0265b98b5d48ab919',
    },
    {
      name: 'TC15',
      key: K2,
      iv: 'cafebabefacedbaddecaf888',
      pt: P,
      aad: '',
      ct: C,
      tag: 'b094dac5d93471bdec1a502270e3cc6c',
    },
    {
      name: 'TC16',
      key: K2,
      iv: 'cafebabefacedbaddecaf888',
      pt: P.slice(0, 120),
      aad: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
      ct: C.slice(0, 120),
      tag: '76fc6ece0f4e1768cddf8853bb2d551b',
    },
  ];

  for (const v of cases) {
    it(`${v.name}: encrypts and decrypts to the published values`, async () => {
      const key = await importAesGcmKeyForTest(fromHex(v.key), ['encrypt', 'decrypt']);
      const out = await aesGcmEncryptWithIv(key, fromHex(v.iv), fromHex(v.pt), fromHex(v.aad));
      expect(toHex(out)).toBe(v.ct + v.tag);
      expect(toHex(await aesGcmDecryptWithIv(key, fromHex(v.iv), fromHex(v.ct + v.tag), fromHex(v.aad)))).toBe(v.pt);
    });
  }

  it('TC16 tampering: each modified part fails authentication and returns no plaintext', async () => {
    const v = cases[3];
    if (v === undefined) throw new Error('missing vector');
    const key = await importAesGcmKeyForTest(fromHex(v.key), ['decrypt']);
    const sealed = fromHex(v.ct + v.tag);
    const flip = (bytes: Bytes, index: number): Bytes => {
      const copy = new Uint8Array(bytes);
      copy[index] = (copy[index] ?? 0) ^ 1;
      return copy;
    };
    const attempts: [Bytes, Bytes, Bytes][] = [
      [fromHex(v.iv), flip(sealed, 0), fromHex(v.aad)], // ciphertext bit
      [fromHex(v.iv), flip(sealed, sealed.length - 1), fromHex(v.aad)], // tag bit
      [flip(fromHex(v.iv), 11), sealed, fromHex(v.aad)], // IV bit
      [fromHex(v.iv), sealed, flip(fromHex(v.aad), 0)], // AAD bit
      [fromHex(v.iv), sealed, new Uint8Array(0)], // AAD removed
      [fromHex(v.iv), sealed.slice(0, sealed.length - 1), fromHex(v.aad)], // truncated
    ];
    for (const [iv, ct, aad] of attempts) {
      await expectCode(aesGcmDecryptWithIv(key, iv, ct, aad), CryptoErrorCode.AUTHENTICATION_FAILED);
    }
  });
});

describe('AES-256-GCM wrapper: internal IVs, mandatory contexts, fail closed (INV-02)', () => {
  const ROOM = '1d6b4f0e-2c3a-4b5d-8e9f-0a1b2c3d4e5f';
  const FILE = '7a8b9c0d-1e2f-4a3b-9c4d-5e6f7a8b9c0d';
  const aad = contextBytes('cm.file.content', { roomId: ROOM, fileId: FILE });

  it('accepts no IV parameter: encrypt takes exactly key, plaintext and context', () => {
    expect(encrypt.length).toBe(3);
  });

  // 10,000 sequential WebCrypto calls take about 1 s alone but can exceed the default 5 s while
  // the database suites share the CPU, so this test has its own time budget (the count is kept).
  it('generates a fresh 96-bit IV for every encryption (10,000 encryptions, no repeat)', async () => {
    const key = await importAesGcmKeyForTest(fromHex('33'.repeat(32)), ['encrypt']);
    const seen = new Set<string>();
    const plaintext = new Uint8Array(16);
    for (let i = 0; i < 10_000; i++) {
      const { iv } = await encrypt(key, plaintext, aad);
      expect(iv).toHaveLength(12);
      seen.add(toHex(iv));
    }
    expect(seen.size).toBe(10_000);
  }, 60_000);

  it('decrypts its own output only under the same context', async () => {
    const key = await importAesGcmKeyForTest(fromHex('44'.repeat(32)), ['encrypt', 'decrypt']);
    const sealed = await encrypt(key, ascii('room content'), aad);
    expect(Buffer.from(await decrypt(key, sealed, aad)).toString()).toBe('room content');
    const otherFile = contextBytes('cm.file.content', { roomId: ROOM, fileId: '2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e' });
    await expectCode(decrypt(key, sealed, otherFile), CryptoErrorCode.AUTHENTICATION_FAILED);
    const manifest = contextBytes('cm.file.manifest', { roomId: ROOM, fileId: FILE });
    await expectCode(decrypt(key, sealed, manifest), CryptoErrorCode.AUTHENTICATION_FAILED);
  });

  it('a wrapped private key opens only with the same wrapping key and the same context (AAD binding)', async () => {
    const { generateSigningKeyPair } = await import('./signing');
    const { wrapPrivateKey, unwrapPrivateKey } = await import('./aead');
    const wrappingKey = await subtle().generateKey({ name: 'AES-GCM', length: 256 }, false, ['wrapKey', 'unwrapKey']);
    const pair = await generateSigningKeyPair();
    const ids = { userId: '4b0c0b7e-6a5c-4d0e-9f3a-2b1c8d7e6f5a', keyId: '8f14e45f-ceea-467a-a5ad-6c1f0d9a2b3c' };
    const context = (fingerprint: string) =>
      contextBytes('cm.vault.private-key', { ...ids, purpose: 'signing', fingerprint, suite: 'CM1', vaultVersion: 1 });
    const target = { algorithm: { name: 'ECDSA', namedCurve: 'P-256' }, usages: ['sign'] as const };
    const sealed = await wrapPrivateKey(pair.privateKey, wrappingKey, context('a'.repeat(64)));
    await expect(unwrapPrivateKey(sealed, wrappingKey, context('a'.repeat(64)), target, false)).resolves.toBeDefined();
    await expectCode(
      unwrapPrivateKey(sealed, wrappingKey, context('b'.repeat(64)), target, false),
      CryptoErrorCode.AUTHENTICATION_FAILED,
    );
    const otherPurpose = contextBytes('cm.vault.private-key', {
      ...ids,
      purpose: 'encryption',
      fingerprint: 'a'.repeat(64),
      suite: 'CM1',
      vaultVersion: 1,
    });
    await expectCode(
      unwrapPrivateKey(sealed, wrappingKey, otherPurpose, target, false),
      CryptoErrorCode.AUTHENTICATION_FAILED,
    );
  });

  it('refuses an empty context and malformed sealed values', async () => {
    const key = await importAesGcmKeyForTest(fromHex('55'.repeat(32)), ['encrypt', 'decrypt']);
    await expectCode(encrypt(key, ascii('x'), new Uint8Array(0) as never), CryptoErrorCode.INVALID_INPUT);
    const sealed = await encrypt(key, ascii('x'), aad);
    const bad: Sealed[] = [
      { iv: sealed.iv.slice(0, 11), ciphertext: sealed.ciphertext },
      { iv: sealed.iv, ciphertext: sealed.ciphertext.slice(0, 15) },
    ];
    for (const s of bad) await expectCode(decrypt(key, s, aad), CryptoErrorCode.AUTHENTICATION_FAILED);
  });
});
