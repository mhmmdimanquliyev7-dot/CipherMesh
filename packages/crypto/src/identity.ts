import { contextBytes, type CanonicalBytes } from './contexts';
import { toBase64Url } from './encoding';
import { CryptoError, CryptoErrorCode } from './errors';
import { computeFingerprint, isFingerprint } from './fingerprint';
import { SUITE, type Suite } from './params';
import { randomUuidV4 } from './random';
import { exportSpki, generateEncryptionKeyPair, importEncryptionPublicKey } from './rsa-oaep';
import { generateSigningKeyPair, importSigningPublicKey, signStatement, verifyStatement } from './signing';
import type { Bytes, Key } from './types';

/**
 * The cryptographic identity (ADR-015): two key pairs under one client-generated key ID.
 *   - encryption key: RSA-OAEP-3072, receives 32-byte values only (CP-02, INV-17);
 *   - signing key: ECDSA P-256, signs canonical statements only (CP-26).
 * The signing key signs the binding statement cm.identity.binding {userId, keyId, suite, both
 * SPKIs}. The binding proves possession of the signing key and ties both public keys to one
 * account and key ID, so a copied public key cannot be presented as someone else's identity.
 *
 * The API runs verifyPublicIdentity() on upload, and every client runs it before it uses a public
 * identity. Both use this module, so they check exactly the same bytes.
 */
export interface PublicIdentity {
  readonly userId: string;
  readonly keyId: string;
  readonly suite: Suite;
  readonly encryptionKeySpki: Bytes;
  readonly signingKeySpki: Bytes;
  readonly bindingSignature: Bytes;
  readonly fingerprint: string;
}

/** A public identity whose keys, fingerprint and binding signature were all checked. */
export interface VerifiedIdentity extends PublicIdentity {
  readonly encryptionPublicKey: Key;
  readonly signingPublicKey: Key;
}

/** A freshly generated identity. The private keys are extractable only until the vault wraps them. */
export interface GeneratedIdentity {
  readonly identity: VerifiedIdentity;
  readonly encryptionPrivateKey: Key;
  readonly signingPrivateKey: Key;
}

export function bindingStatement(fields: {
  readonly userId: string;
  readonly keyId: string;
  readonly encryptionKeySpki: Bytes;
  readonly signingKeySpki: Bytes;
}): CanonicalBytes {
  return contextBytes('cm.identity.binding', {
    userId: fields.userId,
    keyId: fields.keyId,
    suite: SUITE,
    encryptionKeySpki: toBase64Url(fields.encryptionKeySpki),
    signingKeySpki: toBase64Url(fields.signingKeySpki),
  });
}

/**
 * Validates a public identity completely: suite, identifiers, both public keys (algorithm, size,
 * canonical DER), the fingerprint recomputed from the keys, and the binding signature. Any
 * failure is IDENTITY_INVALID; the reason is not distinguished.
 */
export async function verifyPublicIdentity(candidate: PublicIdentity): Promise<VerifiedIdentity> {
  try {
    // Untrusted input may carry any suite string whatever its static type says.
    const suite: string = candidate.suite;
    if (suite !== SUITE || !isFingerprint(candidate.fingerprint)) {
      throw new CryptoError(CryptoErrorCode.IDENTITY_INVALID);
    }
    // Throws for malformed user or key IDs before any key is imported.
    const statement = bindingStatement(candidate);
    const [encryptionPublicKey, signingPublicKey] = await Promise.all([
      importEncryptionPublicKey(candidate.encryptionKeySpki),
      importSigningPublicKey(candidate.signingKeySpki),
    ]);
    const fingerprint = await computeFingerprint(candidate.encryptionKeySpki, candidate.signingKeySpki);
    const signatureValid = await verifyStatement(signingPublicKey, statement, candidate.bindingSignature);
    if (fingerprint !== candidate.fingerprint || !signatureValid) {
      throw new CryptoError(CryptoErrorCode.IDENTITY_INVALID);
    }
    return { ...candidate, encryptionPublicKey, signingPublicKey };
  } catch {
    throw new CryptoError(CryptoErrorCode.IDENTITY_INVALID);
  }
}

/**
 * Generates a new identity for `userId` in this browser. The result is checked with the same
 * verifyPublicIdentity() that the API and other clients run, so an identity that peers would
 * reject is never uploaded.
 */
export async function generateIdentity(userId: string): Promise<GeneratedIdentity> {
  const keyId = randomUuidV4();
  const [encryption, signing] = await Promise.all([generateEncryptionKeyPair(), generateSigningKeyPair()]);
  const [encryptionKeySpki, signingKeySpki] = await Promise.all([
    exportSpki(encryption.publicKey),
    exportSpki(signing.publicKey),
  ]);
  const bindingSignature = await signStatement(
    signing.privateKey,
    bindingStatement({ userId, keyId, encryptionKeySpki, signingKeySpki }),
  );
  const fingerprint = await computeFingerprint(encryptionKeySpki, signingKeySpki);
  const identity = await verifyPublicIdentity({
    userId,
    keyId,
    suite: SUITE,
    encryptionKeySpki,
    signingKeySpki,
    bindingSignature,
    fingerprint,
  });
  return { identity, encryptionPrivateKey: encryption.privateKey, signingPrivateKey: signing.privateKey };
}
