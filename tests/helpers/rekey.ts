import {
  createInvitationKeys,
  createRekeyKeys,
  createVault,
  invitationKeysToWire,
  openRoomKeys,
  publicIdentityFromWire,
  rekeyKeysToWire,
  reviewRekeyRecipients,
  type OpenedRoomKey,
  type RoomKeyBundle,
  type UnlockedVault,
  vaultRecordToWire,
} from '@ciphermesh/crypto';
import { rekeyStartedResponseSchema, type RekeyStartedResponse } from '@ciphermesh/validation';
import { expect } from 'vitest';
import type { AuthTestApi } from './auth';
import { fetchKeyMaterial, keyBundles, vaultOf, type Identified } from './room-crypto';
import { stepUp, type Person } from './rooms';
import { newPassphrase, runner } from './vault';

// Key rotation for the API suites (Phase 11, CM-T050 to CM-T053). The starter's "browser" is the
// real packages/crypto code running in the test process: it reviews the server's recipient
// snapshot, verifies the base version, makes fresh key material, one envelope per recipient and
// the signed key-version statement. Nothing here is a fixed key; every value is synthetic.

type Response = { readonly status: number; readonly body: Record<string, unknown> };

export const startRekey = (who: Identified, roomId: string): Promise<Response> =>
  who.browser.request('POST', `/rooms/${roomId}/rekey-operations`, {});

export function startedOf(response: Response): RekeyStartedResponse {
  expect(response.status, JSON.stringify(response.body)).toBe(201);
  return rekeyStartedResponseSchema.parse(response.body);
}

/** Every version this person can open, verified and chained as the browser does. */
async function verifiedBase(who: Identified, roomId: string): Promise<RoomKeyBundle> {
  const bundles = await keyBundles(who, roomId);
  const opened = await openRoomKeys(vaultOf(who), bundles);
  const base = bundles.at(-1);
  if (base === undefined) throw new Error('no room key for this person');
  const previous = opened.find((k) => k.keyVersion === base.keyVersion.keyVersion - 1);
  return previous === undefined ? base : { ...base, verifiedPreviousCommitment: previous.commitment };
}

/** The finalize body the starter's browser makes for a started operation (ADR-013 step 2). */
export async function finalizeBody(
  who: Identified,
  roomId: string,
  started: RekeyStartedResponse,
  options: { readonly recipients?: readonly UnlockedVault['identity'][] } = {},
): Promise<{ body: ReturnType<typeof rekeyKeysToWire>; opened: OpenedRoomKey }> {
  const vault = vaultOf(who);
  const base = await verifiedBase(who, roomId);
  const withRecipientGrants: RoomKeyBundle = {
    ...base,
    grants: [...base.grants, ...recipientGrantsOf(roomId, started)],
    identities: [...base.identities, ...started.identities.map((i) => publicIdentityFromWire(i, i.userId))],
  };
  const reviewed = await reviewRekeyRecipients(
    vault,
    withRecipientGrants,
    started.recipients.map((r) => publicIdentityFromWire(r.identity, r.userId)),
  );
  const { keys, opened } = await createRekeyKeys(vault, {
    roomId,
    base,
    recipients: options.recipients ?? reviewed.map((r) => r.identity),
  });
  return { body: rekeyKeysToWire(keys), opened };
}

/** The grants of the start response, decoded for the verification rule (the package checks them). */
function recipientGrantsOf(roomId: string, started: RekeyStartedResponse) {
  return started.grants.map((g) => ({
    roomId,
    subjectUserId: g.subjectUserId,
    subjectKeyId: g.subjectKeyId,
    role: g.role,
    grantorUserId: g.grantorUserId,
    grantorKeyId: g.grantorKeyId,
    signature: new Uint8Array(Buffer.from(g.signature, 'base64url')),
  }));
}

export const finalize = (who: Identified, roomId: string, operationId: string, body: unknown): Promise<Response> =>
  who.browser.request('POST', `/rooms/${roomId}/rekey-operations/${operationId}/finalize`, body);

export const cancel = (who: Identified, roomId: string, operationId: string): Promise<Response> =>
  who.browser.request('POST', `/rooms/${roomId}/rekey-operations/${operationId}/cancel`, {});

export const keyState = async (who: Identified, roomId: string): Promise<Record<string, unknown>> => {
  const response = await who.browser.request('GET', `/rooms/${roomId}/rekey-operations/current`);
  expect(response.status, JSON.stringify(response.body)).toBe(200);
  return response.body;
};

/** A complete rekey by `who`: start, review, make and finalize. Returns the new version. */
export async function rekey(who: Identified, roomId: string): Promise<number> {
  const started = startedOf(await startRekey(who, roomId));
  const { body } = await finalizeBody(who, roomId, started);
  const done = await finalize(who, roomId, started.operation.id, body);
  expect(done.status, JSON.stringify(done.body)).toBe(200);
  return done.body['keyVersion'] as number;
}

/**
 * A vault reset through the API (strict step-up, key-lifecycle section 3): a new identity made by
 * the real vault code. Returns the person with the new identity's keys (in memory only).
 */
export async function resetVault(
  api: AuthTestApi,
  who: Person & { readonly secret?: string },
  identityCompromised?: boolean,
): Promise<Person & { readonly secret?: string }> {
  // A reset needs a strict step-up; an account with TOTP answers it with a code too.
  await stepUp(api, who, who.secret);
  const fresh = await createVault({
    userId: who.userId,
    passphrase: newPassphrase(),
    account: { email: who.email, displayName: 'Synthetic Test User' },
    runner,
  });
  const response = await who.browser.request('POST', '/vault/reset', {
    supersedesKeyId: vaultOf(who).identity.keyId,
    vault: vaultRecordToWire(fresh.record),
    ...(identityCompromised === undefined ? {} : { identityCompromised }),
  });
  expect(response.status, JSON.stringify(response.body)).toBe(201);
  return { ...who, vault: await fresh.complete(fresh.record) };
}

/** The body of POST /rooms/{roomId}/members/{userId}/reshare, made by the re-sharer's browser code. */
export async function reshareBody(
  who: Identified,
  roomId: string,
  member: Identified,
  role: 'ADMIN' | 'MEMBER' | 'VIEWER',
  options: { readonly currentOnly?: boolean; readonly confirmedFingerprint?: string | null } = {},
): Promise<Record<string, unknown>> {
  const bundles = await keyBundles(who, roomId);
  const newest = bundles.at(-1);
  if (newest === undefined) throw new Error('no room key to share');
  const keys = await createInvitationKeys(vaultOf(who), {
    roomId,
    bundles: options.currentOnly === true ? [newest] : bundles,
    invitee: vaultOf(member).identity,
    role,
  });
  const wire = invitationKeysToWire(keys);
  return {
    subjectKeyId: vaultOf(member).identity.keyId,
    confirmedFingerprint: options.confirmedFingerprint ?? null,
    grantSignature: wire.grantSignature,
    envelopes: wire.envelopes,
  };
}

export async function reshare(
  who: Identified,
  roomId: string,
  member: Identified,
  role: 'ADMIN' | 'MEMBER' | 'VIEWER',
  options: { readonly currentOnly?: boolean; readonly confirmedFingerprint?: string | null } = {},
): Promise<Response> {
  return who.browser.request(
    'POST',
    `/rooms/${roomId}/members/${member.userId}/reshare`,
    await reshareBody(who, roomId, member, role, options),
  );
}

/** The versions this person's own envelopes cover (AZ-12), oldest first. */
export async function envelopeVersions(who: Identified, roomId: string): Promise<number[]> {
  const { envelopes } = await fetchKeyMaterial(who, roomId);
  return envelopes.map((e) => e.keyVersion).sort((a, b) => a - b);
}
