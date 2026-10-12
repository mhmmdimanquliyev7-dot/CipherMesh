import { fromBase64Url, toBase64Url } from './encoding';
import { CryptoError, CryptoErrorCode } from './errors';
import { AES_GCM, RSA_OAEP, SECRETS } from './params';
import type { EncryptedSecret, StoredSecret } from './secrets';

/**
 * Wire format of recipient-bound secrets (Phase 9, DF-09): binary values as unpadded base64url
 * (CP-15). The creation request carries the identifiers the contexts bind, the wrapped SEK and the
 * payload; the room comes from the path. The reveal response returns the same fields once.
 */
export interface SecretCiphertextWire {
  readonly secretId: string;
  readonly recipientUserId: string;
  readonly recipientKeyId: string;
  readonly suite: string;
  readonly wrappedSek: string;
  readonly payloadIv: string;
  readonly ciphertext: string;
}

const integrity = (): CryptoError => new CryptoError(CryptoErrorCode.SECRET_INTEGRITY_FAILED);

/** The ciphertext fields of a creation request. */
export function encryptedSecretToWire(secret: EncryptedSecret): SecretCiphertextWire {
  return {
    secretId: secret.secretId,
    recipientUserId: secret.recipientUserId,
    recipientKeyId: secret.recipientKeyId,
    suite: secret.suite,
    wrappedSek: toBase64Url(secret.wrappedSek),
    payloadIv: toBase64Url(secret.payload.iv),
    ciphertext: toBase64Url(secret.payload.ciphertext),
  };
}

/**
 * Decodes a secret the API released for the room in the request path. Malformed values are an
 * integrity failure: nothing the server sends is trusted before openSecret authenticates it.
 */
export function storedSecretFromWire(roomId: string, wire: SecretCiphertextWire): StoredSecret {
  try {
    const ciphertext = fromBase64Url(wire.ciphertext);
    if (ciphertext.length > SECRETS.maxDocumentBytes + AES_GCM.tagBytes) throw integrity();
    return {
      roomId,
      secretId: wire.secretId,
      recipientUserId: wire.recipientUserId,
      recipientKeyId: wire.recipientKeyId,
      suite: wire.suite,
      wrappedSek: fromBase64Url(wire.wrappedSek, RSA_OAEP.ciphertextBytes),
      payload: { iv: fromBase64Url(wire.payloadIv, AES_GCM.ivBytes), ciphertext },
    };
  } catch {
    throw integrity();
  }
}
