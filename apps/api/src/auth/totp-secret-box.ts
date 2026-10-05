import { contextBytes } from '@ciphermesh/crypto/contexts';
import { createCipheriv, createDecipheriv, createSecretKey, randomBytes, type KeyObject } from 'node:crypto';

/**
 * Server-side encryption of TOTP secrets at rest (CP-11, DF-02). The TOTP secret is the one user
 * secret the server must be able to read, because it verifies codes; it is therefore encrypted
 * with AES-256-GCM under TOTP_ENCRYPTION_KEY, which lives outside the database. This is a
 * server trust domain and has nothing to do with the user's Vault (key-hierarchy.md).
 *
 * Stored format (users.mfa_totp_secret_enc): IV (12 bytes, fresh from the CSPRNG) || ciphertext
 * || GCM tag (16 bytes). The key ID is stored next to it (users.mfa_totp_key_id) for rotation.
 * AAD binds the ciphertext to the user and key (canonical context `cm.srv.totp`, CP-15), so a
 * ciphertext copied to another user's row fails authentication.
 *
 * CD-22: Phase 3 built this context with a restricted local builder. Since Phase 4 it comes from
 * the general canonical context builders of packages/crypto, which produce the same bytes for
 * this context; primitives.test.ts opens a secret sealed by the Phase 3 code to prove that stored
 * MFA secrets stay readable. A user ID that is not a UUIDv4 now fails closed.
 */
const IV_BYTES = 12;
const TAG_BYTES = 16;

export class TotpSecretBox {
  private readonly key: KeyObject;

  constructor(
    keyBase64Url: string,
    readonly keyId: string,
  ) {
    this.key = createSecretKey(Buffer.from(keyBase64Url, 'base64url'));
  }

  private aad(userId: string, keyId: string): Uint8Array {
    return contextBytes('cm.srv.totp', { userId, keyId });
  }

  seal(userId: string, secret: Buffer): Buffer {
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv, { authTagLength: TAG_BYTES });
    cipher.setAAD(this.aad(userId, this.keyId));
    const ciphertext = Buffer.concat([cipher.update(secret), cipher.final()]);
    return Buffer.concat([iv, ciphertext, cipher.getAuthTag()]);
  }

  /** Fails closed: a wrong key ID, user or any modified byte throws. */
  open(userId: string, keyId: string, sealed: Uint8Array): Buffer {
    if (keyId !== this.keyId) throw new Error('TOTP secret was sealed with another key');
    const box = Buffer.from(sealed);
    if (box.length <= IV_BYTES + TAG_BYTES) throw new Error('TOTP ciphertext too short');
    const decipher = createDecipheriv('aes-256-gcm', this.key, box.subarray(0, IV_BYTES), { authTagLength: TAG_BYTES });
    decipher.setAAD(this.aad(userId, keyId));
    decipher.setAuthTag(box.subarray(box.length - TAG_BYTES));
    return Buffer.concat([decipher.update(box.subarray(IV_BYTES, box.length - TAG_BYTES)), decipher.final()]);
  }
}
