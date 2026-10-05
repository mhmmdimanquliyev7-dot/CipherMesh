import { generateKeyPairSync, sign as nodeSign, verify as nodeVerify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import vectors from '../vectors/ecdsa-p256-sha256-p1363.json' with { type: 'json' };
import { contextBytes } from './contexts';
import { fromHex } from './encoding';
import { CryptoErrorCode, isCryptoError } from './errors';
import { ecdsaVerifyRaw } from './internal/raw';
import { exportSpki } from './rsa-oaep';
import { generateSigningKeyPair, importSigningPublicKey, signStatement, verifyStatement } from './signing';

// ECDSA P-256 / SHA-256 with IEEE P1363 signatures (CP-26, ADR-015). Vectors: Project Wycheproof
// ecdsa_secp256r1_sha256_p1363 test group 1 (all cases) and RFC 6979 appendix A.2.5.

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

const STATEMENT = contextBytes('cm.vault.signing-check', {
  userId: '4b0c0b7e-6a5c-4d0e-9f3a-2b1c8d7e6f5a',
  keyId: '8f14e45f-ceea-467a-a5ad-6c1f0d9a2b3c',
  challenge: Buffer.alloc(32, 3).toString('base64url'),
});

describe('ECDSA known answers', () => {
  it('Wycheproof: every valid signature verifies and every invalid one is rejected', async () => {
    const publicKey = await importSigningPublicKey(fromHex(vectors.spki));
    let valid = 0;
    let invalid = 0;
    for (const t of vectors.tests) {
      const result = await ecdsaVerifyRaw(publicKey, fromHex(t.msg), fromHex(t.sig));
      expect(result, `tcId ${String(t.tcId)} ${t.comment}`).toBe(t.result === 'valid');
      if (t.result === 'valid') valid++;
      else invalid++;
    }
    expect(valid + invalid).toBe(vectors.tests.length);
    expect(valid).toBeGreaterThan(0);
    expect(invalid).toBeGreaterThan(0);
  });

  it('RFC 6979 A.2.5: the published P-256 / SHA-256 signatures verify', async () => {
    const spki = fromHex(
      '3059301306072a8648ce3d020106082a8648ce3d030107034200' +
        '04' +
        '60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6' +
        '7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299',
    );
    const publicKey = await importSigningPublicKey(spki);
    const signatures: [string, string][] = [
      [
        'sample',
        'efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716' +
          'f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8',
      ],
      [
        'test',
        'f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367' +
          '019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083',
      ],
    ];
    for (const [message, signature] of signatures) {
      const bytes = new Uint8Array(Buffer.from(message, 'ascii'));
      expect(await ecdsaVerifyRaw(publicKey, bytes, fromHex(signature))).toBe(true);
      expect(await ecdsaVerifyRaw(publicKey, new Uint8Array(Buffer.from(`${message}!`)), fromHex(signature))).toBe(
        false,
      );
    }
  });
});

describe('statement signatures', () => {
  it('sign and verify round trip; 64-byte P1363 signatures', async () => {
    const pair = await generateSigningKeyPair();
    const signature = await signStatement(pair.privateKey, STATEMENT);
    expect(signature).toHaveLength(64);
    expect(await verifyStatement(pair.publicKey, STATEMENT, signature)).toBe(true);
  });

  it('rejects a modified statement, a modified signature, another key and wrong lengths', async () => {
    const pair = await generateSigningKeyPair();
    const other = await generateSigningKeyPair();
    const signature = await signStatement(pair.privateKey, STATEMENT);
    const otherStatement = contextBytes('cm.vault.signing-check', {
      userId: '4b0c0b7e-6a5c-4d0e-9f3a-2b1c8d7e6f5a',
      keyId: '8f14e45f-ceea-467a-a5ad-6c1f0d9a2b3c',
      challenge: Buffer.alloc(32, 4).toString('base64url'),
    });
    expect(await verifyStatement(pair.publicKey, otherStatement, signature)).toBe(false);
    const flipped = new Uint8Array(signature);
    flipped[5] = (flipped[5] ?? 0) ^ 1;
    expect(await verifyStatement(pair.publicKey, STATEMENT, flipped)).toBe(false);
    expect(await verifyStatement(other.publicKey, STATEMENT, signature)).toBe(false);
    expect(await verifyStatement(pair.publicKey, STATEMENT, signature.slice(0, 63))).toBe(false);
    expect(await verifyStatement(pair.publicKey, STATEMENT, new Uint8Array(64))).toBe(false);
  });

  it('never signs, and never accepts, an empty statement', async () => {
    const pair = await generateSigningKeyPair();
    const empty = new Uint8Array(0) as unknown as typeof STATEMENT;
    await expectCode(signStatement(pair.privateKey, empty), CryptoErrorCode.INVALID_INPUT);
    expect(await verifyStatement(pair.publicKey, empty, new Uint8Array(64))).toBe(false);
  });

  it('interoperates with OpenSSL in both directions', async () => {
    const node = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const nodeSignature = nodeSign('sha256', STATEMENT, { key: node.privateKey, dsaEncoding: 'ieee-p1363' });
    const publicKey = await importSigningPublicKey(
      new Uint8Array(node.publicKey.export({ type: 'spki', format: 'der' })),
    );
    expect(await verifyStatement(publicKey, STATEMENT, new Uint8Array(nodeSignature))).toBe(true);

    const pair = await generateSigningKeyPair();
    const signature = await signStatement(pair.privateKey, STATEMENT);
    const spki = Buffer.from(await exportSpki(pair.publicKey));
    expect(
      nodeVerify('sha256', STATEMENT, { key: spki, format: 'der', type: 'spki', dsaEncoding: 'ieee-p1363' }, signature),
    ).toBe(true);
  });
});

describe('importSigningPublicKey: only uncompressed P-256 in canonical DER', () => {
  it('rejects other curves, compressed points, points off the curve, RSA keys and garbage', async () => {
    const p384 = generateKeyPairSync('ec', { namedCurve: 'P-384' }).publicKey.export({ type: 'spki', format: 'der' });
    await expectCode(importSigningPublicKey(new Uint8Array(p384)), CryptoErrorCode.IDENTITY_INVALID);
    const p256 = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey;
    const compressed = p256.export({
      type: 'spki',
      format: 'der',
      ...({ pointConversionForm: 'compressed' } as object),
    });
    if (compressed.length !== 91) {
      await expectCode(importSigningPublicKey(new Uint8Array(compressed)), CryptoErrorCode.IDENTITY_INVALID);
    }
    const offCurve = new Uint8Array(p256.export({ type: 'spki', format: 'der' }));
    offCurve[90] = (offCurve[90] ?? 0) ^ 1;
    await expectCode(importSigningPublicKey(offCurve), CryptoErrorCode.IDENTITY_INVALID);
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'der' });
    await expectCode(importSigningPublicKey(new Uint8Array(rsa)), CryptoErrorCode.IDENTITY_INVALID);
    await expectCode(importSigningPublicKey(new Uint8Array(91)), CryptoErrorCode.IDENTITY_INVALID);
  });
});
