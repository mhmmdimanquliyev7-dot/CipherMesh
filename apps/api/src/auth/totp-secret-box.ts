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
 */
const IV_BYTES = 12;
const TAG_BYTES = 16;

/**
 * Canonical context for a flat object of strings and safe integers: RFC 8785 serialization of
 * this restricted subset is JSON.stringify of each value with keys in code-unit order. Anything
 * else is refused. The general RFC 8785 implementation arrives with packages/crypto in Phase 4
 * (OCD-04); its test vectors must reproduce these bytes.
 */
export function canonicalServerContext(fields: Readonly<Record<string, string | number>>): Buffer {
  const keys = Object.keys(fields).sort();
  const parts = keys.map((key) => {
    const value = fields[key];
    if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new Error('Unsafe integer in context');
    return `${JSON.stringify(key)}:${JSON.stringify(value)}`;
  });
  return Buffer.from(`{${parts.join(',')}}`, 'utf8');
}

export class TotpSecretBox {
  private readonly key: KeyObject;

  constructor(
    keyBase64Url: string,
    readonly keyId: string,
  ) {
    this.key = createSecretKey(Buffer.from(keyBase64Url, 'base64url'));
  }

  private aad(userId: string, keyId: string): Buffer {
    return canonicalServerContext({ ctx: 'cm.srv.totp', keyId, userId, v: 1 });
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
