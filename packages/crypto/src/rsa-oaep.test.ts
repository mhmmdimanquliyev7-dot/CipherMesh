import {
  constants,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  privateDecrypt,
  publicEncrypt,
} from 'node:crypto';
import { describe, expect, it } from 'vitest';
import vectors from '../vectors/rsa-oaep-3072-sha256.json' with { type: 'json' };
import { contextBytes } from './contexts';
import { fromHex, toHex } from './encoding';
import { CryptoErrorCode, isCryptoError } from './errors';
import { importRsaOaepPrivateKeyForTest, rsaOaepDecryptRaw } from './internal/raw';
import { exportSpki, generateEncryptionKeyPair, importEncryptionPublicKey, unwrap32, wrap32 } from './rsa-oaep';

// RSA-OAEP-3072 / SHA-256 / MGF1-SHA-256 (CP-02). Vectors: Project Wycheproof test group 1 (all
// 37 cases, valid and invalid) and one 32-byte value encrypted by OpenSSL to the same published
// test key with the canonical pair-check label (vectors/README.md).

const PAIR_CHECK_IDS = {
  userId: '4b0c0b7e-6a5c-4d0e-9f3a-2b1c8d7e6f5a',
  keyId: '8f14e45f-ceea-467a-a5ad-6c1f0d9a2b3c',
};

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

describe('RSA-OAEP known answers (Wycheproof rsa_oaep_3072_sha256_mgf1sha256)', () => {
  it('decrypts every valid vector to its message and rejects every invalid one', async () => {
    const privateKey = await importRsaOaepPrivateKeyForTest(fromHex(vectors.pkcs8));
    let valid = 0;
    let invalid = 0;
    for (const t of vectors.tests) {
      const attempt = rsaOaepDecryptRaw(privateKey, fromHex(t.ct), fromHex(t.label));
      if (t.result === 'valid') {
        expect(toHex(await attempt), `tcId ${String(t.tcId)}`).toBe(t.msg);
        valid++;
      } else {
        await expectCode(attempt, CryptoErrorCode.AUTHENTICATION_FAILED);
        invalid++;
      }
    }
    expect([valid, invalid]).toEqual([18, 19]);
  });

  it('unwrap32 recovers the OpenSSL-encrypted 32-byte value with the canonical pair-check label', async () => {
    const label = contextBytes('cm.vault.pair-check', { ...PAIR_CHECK_IDS, suite: 'CM1' });
    // The label bytes are exactly the ones OpenSSL was given (independent check of the builder).
    expect(Buffer.from(label).toString('utf8')).toBe(vectors.wrap32.labelUtf8);
    const privateKey = await importRsaOaepPrivateKeyForTest(fromHex(vectors.pkcs8));
    expect(toHex(await unwrap32(privateKey, fromHex(vectors.wrap32.ct), label))).toBe(vectors.wrap32.plaintext);
  });
});

describe('RSA-OAEP wrapper (INV-17: 32-byte values only, label always a canonical context)', () => {
  const label = contextBytes('cm.vault.pair-check', { ...PAIR_CHECK_IDS, suite: 'CM1' });

  it('interoperates with OpenSSL in both directions', async () => {
    const publicKey = await importEncryptionPublicKey(fromHex(vectors.spki));
    const value = new Uint8Array(32).map((_, i) => 255 - i);
    const wrapped = await wrap32(publicKey, value, label);
    expect(wrapped).toHaveLength(384);
    const opened = privateDecrypt(
      {
        key: createPrivateKey({ key: Buffer.from(vectors.pkcs8, 'hex'), format: 'der', type: 'pkcs8' }),
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
        oaepLabel: Buffer.from(label),
      },
      wrapped,
    );
    expect(toHex(opened)).toBe(toHex(value));
  });

  it('refuses anything but exactly 32 bytes (no RSA encryption of content)', async () => {
    const { publicKey } = await generateEncryptionKeyPair();
    for (const size of [0, 1, 31, 33, 64, 318]) {
      await expectCode(wrap32(publicKey, new Uint8Array(size), label), CryptoErrorCode.INVALID_INPUT);
    }
  });

  it('rejects a wrong label, a modified ciphertext, a wrong size and a valid OAEP value of 31 bytes', async () => {
    const pair = await generateEncryptionKeyPair();
    const value = new Uint8Array(32).fill(9);
    const wrapped = await wrap32(pair.publicKey, value, label);
    expect(toHex(await unwrap32(pair.privateKey, wrapped, label))).toBe(toHex(value));
    const otherLabel = contextBytes('cm.vault.pair-check', {
      ...PAIR_CHECK_IDS,
      userId: '1d6b4f0e-2c3a-4b5d-8e9f-0a1b2c3d4e5f',
      suite: 'CM1',
    });
    await expectCode(unwrap32(pair.privateKey, wrapped, otherLabel), CryptoErrorCode.AUTHENTICATION_FAILED);
    const flipped = new Uint8Array(wrapped);
    flipped[100] = (flipped[100] ?? 0) ^ 0x10;
    await expectCode(unwrap32(pair.privateKey, flipped, label), CryptoErrorCode.AUTHENTICATION_FAILED);
    await expectCode(unwrap32(pair.privateKey, wrapped.slice(1), label), CryptoErrorCode.AUTHENTICATION_FAILED);
    // A correctly padded ciphertext of a 31-byte value, made by OpenSSL, is still refused.
    const spki = await exportSpki(pair.publicKey);
    const short = publicEncrypt(
      {
        key: createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' }),
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
        oaepLabel: Buffer.from(label),
      },
      Buffer.alloc(31, 1),
    );
    await expectCode(unwrap32(pair.privateKey, new Uint8Array(short), label), CryptoErrorCode.AUTHENTICATION_FAILED);
  });
});

describe('importEncryptionPublicKey: only RSA-3072 with e = 65537 in canonical DER', () => {
  const spkiOf = (modulusLength: number, publicExponent: number): Uint8Array =>
    new Uint8Array(
      generateKeyPairSync('rsa', { modulusLength, publicExponent }).publicKey.export({ type: 'spki', format: 'der' }),
    );

  it('accepts the vector key and generated keys', async () => {
    await expect(importEncryptionPublicKey(fromHex(vectors.spki))).resolves.toBeDefined();
    const pair = await generateEncryptionKeyPair();
    const spki = await exportSpki(pair.publicKey);
    expect(spki).toHaveLength(422);
    await expect(importEncryptionPublicKey(spki)).resolves.toBeDefined();
  });

  it('rejects RSA-2048, a 3072-bit key with another exponent, garbage and an EC key', async () => {
    await expectCode(importEncryptionPublicKey(new Uint8Array(spkiOf(2048, 65537))), CryptoErrorCode.IDENTITY_INVALID);
    const otherExponent = spkiOf(3072, 65539);
    expect(otherExponent).toHaveLength(422);
    await expectCode(importEncryptionPublicKey(new Uint8Array(otherExponent)), CryptoErrorCode.IDENTITY_INVALID);
    await expectCode(importEncryptionPublicKey(new Uint8Array(422).fill(0x30)), CryptoErrorCode.IDENTITY_INVALID);
    const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ type: 'spki', format: 'der' });
    await expectCode(importEncryptionPublicKey(new Uint8Array(ec)), CryptoErrorCode.IDENTITY_INVALID);
  });
});
