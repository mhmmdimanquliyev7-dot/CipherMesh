import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import rsaVectors from '../vectors/rsa-oaep-3072-sha256.json' with { type: 'json' };
import { CryptoErrorCode, isCryptoError } from './errors';
import { computeFingerprint, formatFingerprint, isFingerprint } from './fingerprint';
import { generateIdentity, verifyPublicIdentity, type PublicIdentity } from './identity';
import { fromHex } from './encoding';

// The identity bundle of ADR-015: RSA-OAEP-3072 encryption key + ECDSA P-256 signing key under
// one key ID, a binding signature, and a fingerprint over both public keys (CP-17).

const USER = '4b0c0b7e-6a5c-4d0e-9f3a-2b1c8d7e6f5a';
const OTHER_USER = '1d6b4f0e-2c3a-4b5d-8e9f-0a1b2c3d4e5f';

// RFC 6979 A.2.5 public key, as SPKI (an independently published P-256 key).
const EC_SPKI_HEX =
  '3059301306072a8648ce3d020106082a8648ce3d030107034200' +
  '0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6' +
  '7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299';

async function expectInvalid(candidate: PublicIdentity): Promise<void> {
  let caught: unknown;
  try {
    await verifyPublicIdentity(candidate);
  } catch (error) {
    caught = error;
  }
  expect(isCryptoError(caught, CryptoErrorCode.IDENTITY_INVALID)).toBe(true);
}

describe('identity fingerprint (CP-17 revised by ADR-015)', () => {
  it('is SHA-256 of the canonical statement over both public keys (independent computation)', async () => {
    const encryption = fromHex(rsaVectors.spki);
    const signing = fromHex(EC_SPKI_HEX);
    // The statement written out by hand from the definition, then hashed with OpenSSL.
    const statement =
      `{"ctx":"cm.identity.fingerprint","encryptionKeySpki":"${Buffer.from(encryption).toString('base64url')}",` +
      `"signingKeySpki":"${Buffer.from(signing).toString('base64url')}","suite":"CM1","v":1}`;
    const expected = createHash('sha256').update(statement, 'utf8').digest('hex');
    expect(await computeFingerprint(encryption, signing)).toBe(expected);
  });

  it('changes when either key changes and is shown as 16 groups of 4', async () => {
    const a = await generateIdentity(USER);
    const b = await generateIdentity(USER);
    const mixed = await computeFingerprint(a.identity.encryptionKeySpki, b.identity.signingKeySpki);
    expect(new Set([a.identity.fingerprint, b.identity.fingerprint, mixed]).size).toBe(3);
    const groups = formatFingerprint(a.identity.fingerprint);
    expect(groups).toHaveLength(16);
    expect(groups.join('')).toBe(a.identity.fingerprint);
    expect(groups.every((g) => /^[0-9a-f]{4}$/.test(g))).toBe(true);
    expect(isFingerprint(a.identity.fingerprint.toUpperCase())).toBe(false);
  });
});

describe('fingerprint display', () => {
  it('formats only well-formed fingerprints', () => {
    expect(isFingerprint('a'.repeat(64))).toBe(true);
    for (const bad of ['A'.repeat(64), 'a'.repeat(63), 'g'.repeat(64), '']) {
      expect(isFingerprint(bad)).toBe(false);
      let caught: unknown;
      try {
        formatFingerprint(bad);
      } catch (error) {
        caught = error;
      }
      expect(isCryptoError(caught, CryptoErrorCode.INVALID_INPUT)).toBe(true);
    }
  });
});

describe('generateIdentity and verifyPublicIdentity', () => {
  it('produces an identity that the same verification as the API accepts', async () => {
    const { identity, encryptionPrivateKey, signingPrivateKey } = await generateIdentity(USER);
    expect(identity.userId).toBe(USER);
    expect(identity.encryptionKeySpki).toHaveLength(422);
    expect(identity.signingKeySpki).toHaveLength(91);
    expect(identity.bindingSignature).toHaveLength(64);
    expect(isFingerprint(identity.fingerprint)).toBe(true);
    // Purposes are separate: the encryption private key cannot sign, the signing key cannot decrypt.
    expect(encryptionPrivateKey.usages.sort()).toEqual(['decrypt', 'unwrapKey']);
    expect(signingPrivateKey.usages).toEqual(['sign']);
    expect(encryptionPrivateKey.algorithm.name).toBe('RSA-OAEP');
    expect(signingPrivateKey.algorithm.name).toBe('ECDSA');
    await expect(verifyPublicIdentity(identity)).resolves.toMatchObject({ keyId: identity.keyId });
  });

  it('rejects any modified field', async () => {
    const { identity } = await generateIdentity(USER);
    const flip = (bytes: Uint8Array, index: number): Uint8Array<ArrayBuffer> => {
      const copy = new Uint8Array(bytes);
      copy[index] = (copy[index] ?? 0) ^ 1;
      return copy;
    };
    await expectInvalid({ ...identity, userId: OTHER_USER });
    await expectInvalid({ ...identity, keyId: '8f14e45f-ceea-467a-a5ad-6c1f0d9a2b3c' });
    await expectInvalid({ ...identity, bindingSignature: flip(identity.bindingSignature, 10) });
    const lastHex = identity.fingerprint.endsWith('0') ? '1' : '0';
    await expectInvalid({ ...identity, fingerprint: `${identity.fingerprint.slice(0, 63)}${lastHex}` });
    await expectInvalid({ ...identity, encryptionKeySpki: flip(identity.encryptionKeySpki, 300) });
    await expectInvalid({ ...identity, signingKeySpki: flip(identity.signingKeySpki, 80) });
    await expectInvalid({ ...identity, suite: 'CM2' as 'CM1' });
  });

  it("refuses another identity's keys under a different account (key copy, ADR-015 section 2)", async () => {
    const victim = await generateIdentity(USER);
    // An attacker copies the victim's public keys and fingerprint into their own account. Without
    // the victim's signing key they cannot produce a binding over their own user ID.
    await expectInvalid({ ...victim.identity, userId: OTHER_USER });
  });

  it('refuses a substituted encryption key even with a matching recomputed fingerprint', async () => {
    const victim = await generateIdentity(USER);
    const attacker = await generateIdentity(USER);
    // A server swaps in its own encryption key and recomputes the fingerprint; the victim's
    // binding signature does not cover the attacker's key.
    const encryptionKeySpki = attacker.identity.encryptionKeySpki;
    const fingerprint = await computeFingerprint(encryptionKeySpki, victim.identity.signingKeySpki);
    await expectInvalid({ ...victim.identity, encryptionKeySpki, fingerprint });
  });
});
