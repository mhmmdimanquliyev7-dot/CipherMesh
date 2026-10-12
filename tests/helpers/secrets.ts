import {
  authenticateSecretRecipient,
  encryptedSecretToWire,
  encryptSecret,
  openSecret,
  publicIdentityFromWire,
  roomKeyBundlesFromWire,
  storedSecretFromWire,
  type RoomKeyMaterialWire,
  type OpenedSecret,
  type PublicIdentityWire,
  type SecretCiphertextWire,
} from '@ciphermesh/crypto';
import { randomUUID } from 'node:crypto';
import { expect } from 'vitest';
import { fetchKeyMaterial, vaultOf, type Identified } from './room-crypto';

// Recipient-bound secrets for the API suites (Phase 9). Secrets are encrypted by packages/crypto
// for a recipient authenticated against the room's signed statements, exactly as the browser does,
// and decrypted the same way. Every text is synthetic; nothing here is a real secret.

type Response = { readonly status: number; readonly body: Record<string, unknown> };

/** A secret's metadata as the API projects it. */
export interface SecretView {
  readonly id: string;
  readonly senderId: string;
  readonly recipientUserId: string;
  readonly recipientKeyId: string;
  readonly status: 'ACTIVE' | 'REVEALED' | 'EXPIRED' | 'REVOKED';
  readonly burnAfterReading: boolean;
  readonly expiresAt: string;
  readonly createdAt: string;
  readonly revealedAt: string | null;
  readonly destroyedAt: string | null;
}

/** An expiry `ms` from the API's clock (the TestClock starts at the real time). */
export const inFromNow = (ms: number, now: Date = new Date()): string => new Date(now.getTime() + ms).toISOString();

/** The creation body for `recipient`, encrypted by the sender's browser code (fields may be overridden). */
export async function secretBody(
  sender: Identified,
  roomId: string,
  recipient: Identified,
  text: string,
  overrides: Record<string, unknown> = {},
): Promise<{ readonly body: Record<string, unknown>; readonly secretId: string }> {
  const response = await sender.browser.request('GET', `/rooms/${roomId}/members/${recipient.userId}/identity`);
  expect(response.status, JSON.stringify(response.body)).toBe(200);
  const candidate = publicIdentityFromWire(
    response.body['identity'] as PublicIdentityWire,
    response.body['userId'] as string,
  );
  // The member's own grant chain completes the room's statements, as in the browser (CM-T043).
  const authority = response.body['authority'] as Pick<RoomKeyMaterialWire, 'grants' | 'identities'>;
  const { material, envelopes } = await fetchKeyMaterial(sender, roomId);
  const vault = vaultOf(sender);
  const bundle = roomKeyBundlesFromWire(
    roomId,
    { userId: vault.identity.userId, keyId: vault.identity.keyId },
    {
      ...material,
      grants: [...material.grants, ...authority.grants],
      identities: [...material.identities, ...authority.identities],
    },
    envelopes,
  ).at(-1);
  if (bundle === undefined) throw new Error('the sender holds no key version of the room');
  const authenticated = await authenticateSecretRecipient(vault, bundle, candidate);
  const secretId = randomUUID();
  const encrypted = await encryptSecret(authenticated, { secretId, text });
  return {
    secretId,
    body: {
      ...encryptedSecretToWire(encrypted),
      expiresAt: inFromNow(3_600_000),
      burnAfterReading: true,
      ...overrides,
    },
  };
}

/** POST /rooms/{roomId}/secrets. */
export async function createSecret(
  sender: Identified,
  roomId: string,
  recipient: Identified,
  text: string,
  overrides: Record<string, unknown> = {},
): Promise<{ readonly response: Response; readonly secretId: string }> {
  const { body, secretId } = await secretBody(sender, roomId, recipient, text, overrides);
  return { response: await sender.browser.request('POST', `/rooms/${roomId}/secrets`, body), secretId };
}

/** Creates a secret and expects 201; returns its ID. */
export async function createdSecret(
  sender: Identified,
  roomId: string,
  recipient: Identified,
  text: string,
  overrides: Record<string, unknown> = {},
): Promise<string> {
  const { response, secretId } = await createSecret(sender, roomId, recipient, text, overrides);
  expect(response.status, JSON.stringify(response.body)).toBe(201);
  return secretId;
}

/** POST /rooms/{roomId}/secrets/{secretId}/reveal. */
export function reveal(who: Identified, roomId: string, secretId: string): Promise<Response> {
  return who.browser.request('POST', `/rooms/${roomId}/secrets/${secretId}/reveal`, {});
}

/** POST /rooms/{roomId}/secrets/{secretId}/revoke. */
export function revoke(who: Identified, roomId: string, secretId: string): Promise<Response> {
  return who.browser.request('POST', `/rooms/${roomId}/secrets/${secretId}/revoke`, {});
}

/** Decrypts a reveal response exactly as the recipient's browser does. */
export async function openRevealed(who: Identified, roomId: string, response: Response): Promise<OpenedSecret> {
  const secret = response.body['secret'] as SecretView;
  const ciphertext = response.body['ciphertext'] as Omit<
    SecretCiphertextWire,
    'secretId' | 'recipientUserId' | 'recipientKeyId'
  >;
  return openSecret(
    vaultOf(who),
    storedSecretFromWire(roomId, {
      ...ciphertext,
      secretId: secret.id,
      recipientUserId: secret.recipientUserId,
      recipientKeyId: secret.recipientKeyId,
    }),
  );
}

/** GET /rooms/{roomId}/secrets as `who`: the metadata entries. */
export async function listSecrets(who: Identified, roomId: string): Promise<SecretView[]> {
  const response = await who.browser.request('GET', `/rooms/${roomId}/secrets`);
  expect(response.status, JSON.stringify(response.body)).toBe(200);
  return response.body['secrets'] as SecretView[];
}
