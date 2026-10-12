import { decrypt, encrypt, importDataKey, type Sealed } from './aead';
import { canonicalBytes } from './canonical';
import { contextBytes, type CanonicalBytes } from './contexts';
import { bytesEqual, isWellFormedUnicode, utf8Decode, wipe } from './encoding';
import { CryptoError, CryptoErrorCode } from './errors';
import type { PublicIdentity, VerifiedIdentity } from './identity';
import { AES_GCM, RSA_OAEP, SECRETS, SUITE } from './params';
import { randomBytes } from './random';
import { authenticateRoomMember, type RoomKeyBundle } from './room-keys';
import { unwrap32, wrap32 } from './rsa-oaep';
import type { Bytes } from './types';
import type { UnlockedVault } from './vault';

/**
 * Recipient-bound secrets (Phase 9, CM-T043; cryptographic-architecture section 6.3, DF-09, CD-06).
 *
 *   SEK      = 32 fresh random bytes, one per secret (INV-03)
 *   document = RFC 8785 {text, v: 1}, at most 16 KiB (CP-29, D-09-01)
 *   payload  = AES-256-GCM(SEK, document, AAD = cm.secret.payload {roomId, secretId})
 *   wrapped  = RSA-OAEP-3072(recipient encryption key, SEK, label = cm.secret.sek-wrap
 *              {roomId, secretId, recipientUserId, recipientKeyId, suite})
 *
 * Envelope encryption, as for files and notes: the payload is never RSA-encrypted; RSA-OAEP only
 * transports the 32-byte SEK, through the single wrapper in rsa-oaep.ts (INV-17, CD-17). The SEK
 * encrypts exactly one message, so IV reuse under it is impossible by construction, and the IV is
 * generated inside the AES-GCM wrapper (INV-02). The label binds the wrapped SEK to its room,
 * secret, recipient user, recipient key and suite; the AAD binds the payload to its room and
 * secret. A wrapped SEK or payload moved to another secret, room or recipient fails.
 *
 * Only the recipient's private key can unwrap the SEK, so other members (and the server) cannot
 * decrypt the secret even with the ciphertext (DF-09). The recipient key is not taken from the
 * server on trust: authenticateSecretRecipient accepts it only when the room's verified statements
 * name that key for that member (ADR-015 section 4), and encryptSecret accepts only recipients
 * authenticated that way.
 *
 * The raw SEK exists only inside this module: on the sender's side between generation and the
 * wrap, on the recipient's side between the unwrap and the import; both buffers are overwritten.
 * The keys used for AES-GCM are non-extractable. Nothing is stored.
 *
 * What the cryptography cannot do: say who sent the secret (the sender is the server's statement,
 * L-56), stop the recipient from copying the plaintext (L-03), or make the server delete backups
 * (L-12). Burn-after-reading is a server transaction (INV-13), not a cryptographic property.
 */

/** A member identity this client authenticated for one room (authenticateSecretRecipient). */
export interface SecretRecipient {
  readonly roomId: string;
  readonly identity: VerifiedIdentity;
}

/** What the sender's browser sends to the API: identifiers, the wrapped SEK and the payload. */
export interface EncryptedSecret {
  readonly roomId: string;
  readonly secretId: string;
  readonly recipientUserId: string;
  readonly recipientKeyId: string;
  readonly suite: typeof SUITE;
  readonly wrappedSek: Bytes;
  readonly payload: Sealed;
}

/** A secret as the API released it, decoded. Every value is untrusted until openSecret checks it. */
export interface StoredSecret {
  readonly roomId: string;
  readonly secretId: string;
  readonly recipientUserId: string;
  readonly recipientKeyId: string;
  readonly suite: string;
  readonly wrappedSek: Bytes;
  readonly payload: Sealed;
}

/** A secret after authenticated decryption. Untrusted text: render as text only (T-12). */
export interface OpenedSecret {
  readonly roomId: string;
  readonly secretId: string;
  readonly text: string;
}

const integrityFailed = (): CryptoError => new CryptoError(CryptoErrorCode.SECRET_INTEGRITY_FAILED);
const invalidInput = (): CryptoError => new CryptoError(CryptoErrorCode.INVALID_INPUT);

/** Recipients authenticated in this realm; encryptSecret refuses any other object. */
const authenticated = new WeakSet<SecretRecipient>();

/** Secret text: at least one character of well-formed Unicode; the document size bounds the rest. */
export function isSecretText(text: unknown): text is string {
  return typeof text === 'string' && text.length >= 1 && isWellFormedUnicode(text);
}

function documentOf(text: string): Bytes {
  return canonicalBytes({ v: SECRETS.formatVersion, text });
}

/**
 * The size in bytes of the secret document that would be encrypted (at most
 * SECRETS.maxDocumentBytes), so a form can say "too long" before encrypting. Returns Infinity for
 * text that is not a secret.
 */
export function secretDocumentBytes(text: string): number {
  if (!isSecretText(text)) return Number.POSITIVE_INFINITY;
  const document = documentOf(text);
  wipe(document);
  return document.length;
}

function wrapLabel(roomId: string, secretId: string, userId: string, keyId: string): CanonicalBytes {
  return contextBytes('cm.secret.sek-wrap', {
    roomId,
    secretId,
    recipientUserId: userId,
    recipientKeyId: keyId,
    suite: SUITE,
  });
}

function payloadContext(roomId: string, secretId: string): CanonicalBytes {
  return contextBytes('cm.secret.payload', { roomId, secretId });
}

/**
 * Authenticates the member a secret is for (CM-T043): the candidate identity, as the API returned
 * it for the member, must be a key holder of the room by the room's verified statements
 * (authenticateRoomMember). The sender cannot be the recipient.
 */
export async function authenticateSecretRecipient(
  vault: UnlockedVault,
  bundle: RoomKeyBundle,
  candidate: PublicIdentity,
): Promise<SecretRecipient> {
  const identity = await authenticateRoomMember(vault, bundle, candidate);
  if (identity.userId === vault.identity.userId) throw invalidInput();
  const recipient: SecretRecipient = Object.freeze({ roomId: bundle.roomId, identity });
  authenticated.add(recipient);
  return recipient;
}

/**
 * Encrypts a secret in the sender's browser for an authenticated recipient. The caller chooses the
 * secret ID (UUIDv4, part of both contexts). Returns only ciphertext and the wrapped SEK.
 */
export async function encryptSecret(
  recipient: SecretRecipient,
  input: { readonly secretId: string; readonly text: string },
): Promise<EncryptedSecret> {
  if (!authenticated.has(recipient) || !isSecretText(input.text)) throw invalidInput();
  const { roomId } = recipient;
  const { userId, keyId, encryptionPublicKey } = recipient.identity;
  const { secretId } = input;
  // The contexts validate the identifiers; build them before any key exists.
  const label = wrapLabel(roomId, secretId, userId, keyId);
  const aad = payloadContext(roomId, secretId);
  const document = documentOf(input.text);
  const sek = randomBytes(SECRETS.sekBytes);
  try {
    if (document.length > SECRETS.maxDocumentBytes) throw invalidInput();
    const wrappedSek = await wrap32(encryptionPublicKey, sek, label);
    // importDataKey wipes the SEK bytes; from here on only the non-extractable key exists.
    const key = await importDataKey(sek, 'encrypt');
    const payload = await encrypt(key, document, aad);
    return { roomId, secretId, recipientUserId: userId, recipientKeyId: keyId, suite: SUITE, wrappedSek, payload };
  } finally {
    wipe(document, sek);
  }
}

const DOCUMENT_FIELDS = ['text', 'v'];

/** Parses a version-1 secret document. Anything else is refused; nothing is guessed. */
function parseDocument(bytes: Bytes): string {
  let value: unknown;
  try {
    value = JSON.parse(utf8Decode(bytes));
  } catch {
    throw integrityFailed();
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw integrityFailed();
  const record = value as Record<string, unknown>;
  if (record['v'] !== SECRETS.formatVersion) {
    throw new CryptoError(
      typeof record['v'] === 'number'
        ? CryptoErrorCode.SECRET_FORMAT_UNSUPPORTED
        : CryptoErrorCode.SECRET_INTEGRITY_FAILED,
    );
  }
  const keys = Object.keys(record).sort();
  if (keys.length !== DOCUMENT_FIELDS.length || keys.some((key, i) => key !== DOCUMENT_FIELDS[i])) {
    throw integrityFailed();
  }
  const { text } = record;
  if (!isSecretText(text)) throw integrityFailed();
  // Only the canonical serialization is a secret: no duplicate keys, whitespace or other encodings.
  const canonical = documentOf(text);
  const same = bytesEqual(canonical, bytes);
  wipe(canonical);
  if (!same) throw integrityFailed();
  return text;
}

/**
 * Opens a secret the API released to this client: the record must name this vault's identity as
 * its recipient, the SEK must unwrap under the label for this room, secret and recipient key, and
 * the payload must authenticate and be a canonical version-1 document before the text is
 * returned. A wrong key, label or modified byte fails without releasing anything (fail closed).
 */
export async function openSecret(vault: UnlockedVault, record: StoredSecret): Promise<OpenedSecret> {
  if (record.suite !== SUITE) throw new CryptoError(CryptoErrorCode.SECRET_FORMAT_UNSUPPORTED);
  if (record.recipientUserId !== vault.identity.userId || record.recipientKeyId !== vault.identity.keyId) {
    throw invalidInput();
  }
  if (
    record.wrappedSek.length !== RSA_OAEP.ciphertextBytes ||
    record.payload.iv.length !== AES_GCM.ivBytes ||
    record.payload.ciphertext.length <= AES_GCM.tagBytes ||
    record.payload.ciphertext.length > SECRETS.maxDocumentBytes + AES_GCM.tagBytes
  ) {
    throw integrityFailed();
  }
  const { roomId, secretId } = record;
  const label = wrapLabel(roomId, secretId, record.recipientUserId, record.recipientKeyId);
  const aad = payloadContext(roomId, secretId);
  const sek = await unwrap32(vault.encryptionPrivateKey, record.wrappedSek, label);
  const key = await importDataKey(sek, 'decrypt');
  const document = await decrypt(key, record.payload, aad);
  try {
    return { roomId, secretId, text: parseDocument(document) };
  } finally {
    wipe(document);
  }
}
