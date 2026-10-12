import {
  encryptedSecretToWire,
  encryptSecret,
  openSecret,
  SECRETS,
  secretDocumentBytes,
  storedSecretFromWire,
} from '@ciphermesh/crypto';
import {
  secretCreatedResponseSchema,
  secretListResponseSchema,
  secretRevealResponseSchema,
  secretRevokedResponseSchema,
  type SecretMetadataView,
} from '@ciphermesh/validation';
import { api } from '../lib/api';
import { vaultController } from '../vault/controller';
import { roomKeys } from './keys';

/**
 * Recipient-bound secrets in this tab (Phase 9, CM-T043, CM-T044; DF-09). All cryptography is done
 * by @ciphermesh/crypto; this module sequences it with the API.
 *
 * - Send: the recipient's key is accepted only after the room's verified statements name it
 *   (roomKeys.secretRecipient). The text is encrypted here under a fresh SEK and only the 32-byte
 *   SEK is wrapped to that key; the API receives ciphertext, the wrapped SEK and metadata.
 * - Reveal: an explicit POST, never on page load. The vault must be unlocked before the request
 *   is sent, because a burn-after-reading secret is destroyed on the server in the transaction
 *   that returns it: the text is decrypted with the identity key held in memory right after the
 *   response arrives. A failed check shows no text.
 * - Nothing is persisted: no text, SEK or ciphertext goes into browser storage, caches or the URL.
 *   Revealed text lives in React state and is dropped on hide, vault lock or leaving the page.
 */

/** The size the secret would have once serialized, against the 16 KiB limit (CP-29). */
export function secretFits(text: string): boolean {
  return secretDocumentBytes(text) <= SECRETS.maxDocumentBytes;
}

export const SECRET_MAX_KIB = SECRETS.maxDocumentBytes / 1024;

export class SecretTooLong extends Error {
  readonly code = 'SECRET_TOO_LONG';
  constructor() {
    super('The secret is longer than the limit');
    this.name = 'SecretTooLong';
  }
}

/** One page of the secret metadata this member may see (AZ-32). No ciphertext is listed. */
export async function listSecrets(
  roomId: string,
  cursor?: string,
): Promise<{ readonly secrets: SecretMetadataView[]; readonly nextCursor: string | null }> {
  const page = await api(
    'GET',
    `/rooms/${roomId}/secrets${cursor === undefined ? '' : `?cursor=${encodeURIComponent(cursor)}`}`,
    secretListResponseSchema,
  );
  return { secrets: page.secrets, nextCursor: page.nextCursor };
}

/** Encrypts `text` for an authenticated member and stores it (AZ-23). */
export async function sendSecret(input: {
  readonly roomId: string;
  readonly recipientUserId: string;
  readonly text: string;
  readonly expiresAt: string;
  readonly burnAfterReading: boolean;
}): Promise<SecretMetadataView> {
  if (!secretFits(input.text)) throw new SecretTooLong();
  const recipient = await roomKeys.secretRecipient(input.roomId, input.recipientUserId);
  const encrypted = await encryptSecret(recipient, { secretId: crypto.randomUUID(), text: input.text });
  const { secret } = await api('POST', `/rooms/${input.roomId}/secrets`, secretCreatedResponseSchema, {
    ...encryptedSecretToWire(encrypted),
    expiresAt: input.expiresAt,
    burnAfterReading: input.burnAfterReading,
  });
  return secret;
}

/**
 * Reveals a secret addressed to this identity (AZ-24) and decrypts it. Throws VAULT_LOCKED before
 * any request when the vault is locked, so a locked vault never burns a secret it cannot open.
 */
export async function revealSecret(
  roomId: string,
  view: SecretMetadataView,
): Promise<{ readonly secret: SecretMetadataView; readonly text: string }> {
  return vaultController.withUnlockedVault(async (vault) => {
    // A secret wrapped to an earlier identity key cannot be opened here; do not ask for it.
    if (view.recipientKeyId !== vault.identity.keyId) throw new SecretForOtherKey();
    const response = await api('POST', `/rooms/${roomId}/secrets/${view.id}/reveal`, secretRevealResponseSchema, {});
    const opened = await openSecret(
      vault,
      storedSecretFromWire(roomId, {
        ...response.ciphertext,
        secretId: response.secret.id,
        recipientUserId: response.secret.recipientUserId,
        recipientKeyId: response.secret.recipientKeyId,
      }),
    );
    return { secret: response.secret, text: opened.text };
  });
}

export class SecretForOtherKey extends Error {
  readonly code = 'SECRET_FOR_OTHER_KEY';
  constructor() {
    super('The secret was sent to an earlier identity key');
    this.name = 'SecretForOtherKey';
  }
}

/** Revokes an ACTIVE secret (AZ-25). */
export async function revokeSecret(roomId: string, secretId: string): Promise<void> {
  await api('POST', `/rooms/${roomId}/secrets/${secretId}/revoke`, secretRevokedResponseSchema, {});
}
