import {
  constants,
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  privateDecrypt,
  publicEncrypt,
  randomBytes as nodeRandom,
  randomUUID,
} from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import { canonicalBytes } from './canonical';
import { contextBytes } from './contexts';
import { toBase64Url } from './encoding';
import { CryptoErrorCode, isCryptoError } from './errors';
import { generateIdentity, type PublicIdentity, type VerifiedIdentity } from './identity';
import type { RecipientRef } from './recipients';
import { createInitialRoomKey, signMembershipGrant, type RoomKeyBundle, type SignedMembershipGrant } from './room-keys';
import { encryptedSecretToWire, storedSecretFromWire } from './secret-format';
import {
  authenticateSecretRecipient,
  encryptSecret,
  isSecretText,
  openSecret,
  secretDocumentBytes,
  type EncryptedSecret,
  type SecretRecipient,
  type StoredSecret,
} from './secrets';
import { SECRETS } from './params';
import type { Bytes } from './types';
import type { UnlockedVault } from './vault';
import { subtle } from './webcrypto';

// Recipient-bound secrets (Phase 9, CM-T043, DF-09). Known answers come from an independent
// implementation: Node.js crypto (OpenSSL) encrypts the payload with AES-256-GCM and wraps the SEK
// with RSA-OAEP-SHA-256 under the documented label, and decrypts what the package produced. The
// tamper tests change every stored part and move parts between secrets, rooms and recipients; each
// must fail without releasing text (T-07). Recipient authentication is checked against the room's
// signed statements (ADR-015 section 4, T-25, T-36). Every text here is synthetic.

const bytes = (value: Uint8Array | Buffer): Bytes => new Uint8Array(value);
const CANARY = 'synthetic-secret-canary-7f3a';

interface Member {
  readonly vault: UnlockedVault;
  /** PKCS#8 of the encryption key, exported once here only for the independent OpenSSL check. */
  readonly pkcs8: Buffer;
}

async function member(userId: string = randomUUID()): Promise<Member> {
  const generated = await generateIdentity(userId);
  const pkcs8 = Buffer.from(await subtle().exportKey('pkcs8', generated.encryptionPrivateKey));
  return {
    vault: {
      identity: generated.identity,
      encryptionPrivateKey: generated.encryptionPrivateKey,
      signingPrivateKey: generated.signingPrivateKey,
    },
    pkcs8,
  };
}

const self = (v: UnlockedVault): RecipientRef => ({ userId: v.identity.userId, keyId: v.identity.keyId });
const publicOf = (identity: VerifiedIdentity): PublicIdentity => ({
  userId: identity.userId,
  keyId: identity.keyId,
  suite: identity.suite,
  encryptionKeySpki: identity.encryptionKeySpki,
  signingKeySpki: identity.signingKeySpki,
  bindingSignature: identity.bindingSignature,
  fingerprint: identity.fingerprint,
});

const sekLabel = (roomId: string, secretId: string, to: RecipientRef) =>
  contextBytes('cm.secret.sek-wrap', {
    roomId,
    secretId,
    recipientUserId: to.userId,
    recipientKeyId: to.keyId,
    suite: 'CM1',
  });
const payloadAad = (roomId: string, secretId: string) => contextBytes('cm.secret.payload', { roomId, secretId });

async function rejects(promise: Promise<unknown>, code: string): Promise<unknown> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  expect(isCryptoError(caught), String(caught)).toBe(true);
  expect((caught as { code: string }).code).toBe(code);
  expect((caught as Error).message).not.toContain(CANARY);
  return caught;
}

const flip = (data: Uint8Array, index = 0): Bytes => {
  const copy = new Uint8Array(data);
  const at = index < 0 ? copy.length + index : index;
  copy[at] = (copy[at] ?? 0) ^ 0x01;
  return copy;
};

/** A room as the server serves it to `to`: genesis, key version 1, grants and signer identities. */
interface Room {
  readonly roomId: string;
  readonly bundle: (to: Member, grants: SignedMembershipGrant[], identities: VerifiedIdentity[]) => RoomKeyBundle;
}

async function newRoom(owner: Member): Promise<Room> {
  const roomId = randomUUID();
  const { keys } = await createInitialRoomKey(owner.vault, roomId);
  const genesis = {
    roomId,
    creatorUserId: owner.vault.identity.userId,
    creatorKeyId: owner.vault.identity.keyId,
    signature: keys.genesisSignature,
  };
  const keyVersion = {
    roomId,
    keyVersion: 1,
    commitment: keys.commitment,
    previousCommitment: null,
    creatorUserId: owner.vault.identity.userId,
    creatorKeyId: owner.vault.identity.keyId,
    recipients: [self(owner.vault)],
    signature: keys.keyVersionSignature,
  };
  return {
    roomId,
    bundle: (_to, grants, identities) => ({
      roomId,
      genesis,
      keyVersion,
      grants,
      identities: [owner.vault.identity, ...identities].map(publicOf),
      // The statements are what recipient authentication checks; the envelope is not opened.
      envelope: new Uint8Array(384),
    }),
  };
}

async function grant(roomId: string, grantor: Member, subject: Member, role: 'MEMBER' | 'VIEWER' | 'ADMIN') {
  const signed = await signMembershipGrant(grantor.vault, { roomId, subject: subject.vault.identity, role });
  return {
    roomId,
    subjectUserId: subject.vault.identity.userId,
    subjectKeyId: subject.vault.identity.keyId,
    role,
    grantorUserId: grantor.vault.identity.userId,
    grantorKeyId: grantor.vault.identity.keyId,
    signature: signed.signature,
  } satisfies SignedMembershipGrant;
}

let owner: Member;
let alice: Member;
let bob: Member;
let outsider: Member;
let room: Room;
let grants: SignedMembershipGrant[];
/** Alice as authenticated by the owner, and the owner as authenticated by Alice. */
let toAlice: SecretRecipient;
let toOwner: SecretRecipient;

beforeAll(async () => {
  [owner, alice, bob, outsider] = await Promise.all([member(), member(), member(), member()]);
  room = await newRoom(owner);
  grants = [await grant(room.roomId, owner, alice, 'MEMBER'), await grant(room.roomId, owner, bob, 'VIEWER')];
  toAlice = await authenticateSecretRecipient(
    owner.vault,
    room.bundle(owner, grants, []),
    publicOf(alice.vault.identity),
  );
  toOwner = await authenticateSecretRecipient(
    alice.vault,
    room.bundle(alice, grants, []),
    publicOf(owner.vault.identity),
  );
}, 120_000);

const stored = (secret: EncryptedSecret): StoredSecret => ({ ...secret });

/** A stored secret built entirely with Node.js crypto from the documented format. */
function nodeSecret(
  to: Member,
  document: Record<string, unknown> | Uint8Array = { v: 1, text: `${CANARY} node` },
  options: { secretId?: string; roomId?: string } = {},
): StoredSecret {
  const roomId = options.roomId ?? room.roomId;
  const secretId = options.secretId ?? randomUUID();
  const sek = nodeRandom(32);
  const iv = nodeRandom(12);
  const plaintext = document instanceof Uint8Array ? document : canonicalBytes(document as never);
  const cipher = createCipheriv('aes-256-gcm', sek, iv);
  cipher.setAAD(payloadAad(roomId, secretId));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  const publicKey = createPublicKey({
    key: Buffer.from(to.vault.identity.encryptionKeySpki),
    format: 'der',
    type: 'spki',
  });
  const wrappedSek = publicEncrypt(
    {
      key: publicKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
      oaepLabel: Buffer.from(sekLabel(roomId, secretId, self(to.vault))),
    },
    sek,
  );
  return {
    roomId,
    secretId,
    recipientUserId: to.vault.identity.userId,
    recipientKeyId: to.vault.identity.keyId,
    suite: 'CM1',
    wrappedSek: bytes(wrappedSek),
    payload: { iv: bytes(iv), ciphertext: bytes(ciphertext) },
  };
}

// --------------------------------------------------------------------------- format and limits

describe('secret text and document size (CP-29)', () => {
  it('accepts any well-formed non-empty text and measures the canonical document', () => {
    expect(isSecretText('x')).toBe(true);
    expect(isSecretText('line 1\nline 2\ttab')).toBe(true);
    expect(isSecretText('')).toBe(false);
    expect(isSecretText('\ud800')).toBe(false);
    expect(isSecretText(42)).toBe(false);
    expect(secretDocumentBytes('x')).toBe('{"text":"x","v":1}'.length);
    expect(secretDocumentBytes('')).toBe(Number.POSITIVE_INFINITY);
    expect(SECRETS.maxDocumentBytes).toBe(16 * 1024);
  });

  it('encrypts a document of exactly 16 KiB and refuses one byte more', async () => {
    const overhead = secretDocumentBytes('x') - 1;
    const largest = 'a'.repeat(SECRETS.maxDocumentBytes - overhead);
    expect(secretDocumentBytes(largest)).toBe(SECRETS.maxDocumentBytes);
    const secret = await encryptSecret(toAlice, { secretId: randomUUID(), text: largest });
    expect(secret.payload.ciphertext.length).toBe(SECRETS.maxDocumentBytes + 16);
    expect((await openSecret(alice.vault, stored(secret))).text).toBe(largest);
    await rejects(
      encryptSecret(toAlice, { secretId: randomUUID(), text: `${largest}a` }),
      CryptoErrorCode.INVALID_INPUT,
    );
  });

  it('refuses empty and ill-formed text, and malformed identifiers, before any key exists', async () => {
    await rejects(encryptSecret(toAlice, { secretId: randomUUID(), text: '' }), CryptoErrorCode.INVALID_INPUT);
    await rejects(encryptSecret(toAlice, { secretId: randomUUID(), text: '\udfff' }), CryptoErrorCode.INVALID_INPUT);
    await rejects(encryptSecret(toAlice, { secretId: 'not-a-uuid', text: 'x' }), CryptoErrorCode.INVALID_INPUT);
  });
});

// ------------------------------------------------------------------------- round trips (DF-09)

describe('encryption and authenticated opening', () => {
  it('round-trips Unicode text for the intended recipient', async () => {
    const text = `${CANARY} Grüße 秘密 🔐\nzweite Zeile`;
    const secret = await encryptSecret(toAlice, { secretId: randomUUID(), text });
    expect(secret.recipientUserId).toBe(alice.vault.identity.userId);
    expect(secret.recipientKeyId).toBe(alice.vault.identity.keyId);
    expect(secret.suite).toBe('CM1');
    const opened = await openSecret(alice.vault, stored(secret));
    expect(opened).toEqual({ roomId: room.roomId, secretId: secret.secretId, text });
  });

  it('uses a fresh SEK and IV for every secret, and RSA-OAEP only on the 32-byte SEK (INV-02, INV-17)', async () => {
    const secretId = randomUUID();
    const a = await encryptSecret(toAlice, { secretId, text: 'same text' });
    const b = await encryptSecret(toAlice, { secretId, text: 'same text' });
    expect(toBase64Url(a.payload.iv)).not.toBe(toBase64Url(b.payload.iv));
    expect(toBase64Url(a.wrappedSek)).not.toBe(toBase64Url(b.wrappedSek));
    expect(toBase64Url(a.payload.ciphertext)).not.toBe(toBase64Url(b.payload.ciphertext));
    // The wrapped SEK is one RSA-OAEP-3072 block of a 32-byte value; the payload is AES-GCM output
    // (document plus a 16-byte tag), never an RSA block.
    expect(a.wrappedSek.length).toBe(384);
    const recovered = privateDecrypt(
      {
        key: createPrivateKey({ key: alice.pkcs8, format: 'der', type: 'pkcs8' }),
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
        oaepLabel: Buffer.from(sekLabel(room.roomId, secretId, self(alice.vault))),
      },
      Buffer.from(a.wrappedSek),
    );
    expect(recovered.length).toBe(32);
    expect(a.payload.ciphertext.length).toBe(secretDocumentBytes('same text') + 16);
    const ivs = new Set<string>();
    for (let i = 0; i < 32; i += 1) {
      ivs.add(toBase64Url((await encryptSecret(toAlice, { secretId: randomUUID(), text: 'x' })).payload.iv));
    }
    expect(ivs.size).toBe(32);
  });

  it('OpenSSL decrypts what the package produced (independent check of the documented format)', async () => {
    const secretId = randomUUID();
    const text = `${CANARY} for openssl`;
    const secret = await encryptSecret(toAlice, { secretId, text });
    const sek = privateDecrypt(
      {
        key: createPrivateKey({ key: alice.pkcs8, format: 'der', type: 'pkcs8' }),
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
        oaepLabel: Buffer.from(sekLabel(room.roomId, secretId, self(alice.vault))),
      },
      Buffer.from(secret.wrappedSek),
    );
    const sealed = Buffer.from(secret.payload.ciphertext);
    const decipher = createDecipheriv('aes-256-gcm', sek, secret.payload.iv);
    decipher.setAAD(payloadAad(room.roomId, secretId));
    decipher.setAuthTag(sealed.subarray(-16));
    const document = Buffer.concat([decipher.update(sealed.subarray(0, -16)), decipher.final()]);
    expect(document.toString('utf8')).toBe(JSON.stringify({ text, v: 1 }));
  });

  it('opens a secret that OpenSSL produced from the documented format', async () => {
    const opened = await openSecret(alice.vault, nodeSecret(alice));
    expect(opened.text).toBe(`${CANARY} node`);
  });

  it('round-trips through the wire format', async () => {
    const secret = await encryptSecret(toOwner, { secretId: randomUUID(), text: `${CANARY} wire` });
    const wire = encryptedSecretToWire(secret);
    expect(Object.keys(wire).sort()).toEqual(
      ['ciphertext', 'payloadIv', 'recipientKeyId', 'recipientUserId', 'secretId', 'suite', 'wrappedSek'].sort(),
    );
    expect(JSON.stringify(wire)).not.toContain(CANARY);
    const opened = await openSecret(owner.vault, storedSecretFromWire(room.roomId, wire));
    expect(opened.text).toBe(`${CANARY} wire`);
  });
});

// ------------------------------------------------------------- recipient authentication (T-25)

describe('recipient authentication against the room statements (ADR-015 section 4)', () => {
  it('accepts a member named by an accepted grant, and the creator named in the recipient list', async () => {
    const bobAsRecipient = await authenticateSecretRecipient(
      alice.vault,
      room.bundle(alice, grants, []),
      publicOf(bob.vault.identity),
    );
    expect(bobAsRecipient.identity.keyId).toBe(bob.vault.identity.keyId);
    expect(toOwner.identity.keyId).toBe(owner.vault.identity.keyId);
  });

  it('refuses the sender as recipient', async () => {
    await rejects(
      authenticateSecretRecipient(owner.vault, room.bundle(owner, grants, []), publicOf(owner.vault.identity)),
      CryptoErrorCode.INVALID_INPUT,
    );
  });

  it('refuses an identity the statements do not name: an outsider, or a substituted key for a member', async () => {
    await rejects(
      authenticateSecretRecipient(owner.vault, room.bundle(owner, grants, []), publicOf(outsider.vault.identity)),
      CryptoErrorCode.KEY_AUTHENTICATION_FAILED,
    );
    // The server answers Alice's user ID with a different, self-consistent key (T-25): refused.
    const substitute = await member(alice.vault.identity.userId);
    await rejects(
      authenticateSecretRecipient(owner.vault, room.bundle(owner, grants, []), publicOf(substitute.vault.identity)),
      CryptoErrorCode.KEY_AUTHENTICATION_FAILED,
    );
  });

  it('refuses a grant the authority chain does not accept, and a tampered identity', async () => {
    // A grant for the outsider signed by Bob (a VIEWER, not an ADMIN): no authority.
    const forged = await grant(room.roomId, bob, outsider, 'MEMBER');
    await rejects(
      authenticateSecretRecipient(
        owner.vault,
        room.bundle(owner, [...grants, forged], [bob.vault.identity]),
        publicOf(outsider.vault.identity),
      ),
      CryptoErrorCode.KEY_AUTHENTICATION_FAILED,
    );
    const tampered = {
      ...publicOf(alice.vault.identity),
      bindingSignature: flip(alice.vault.identity.bindingSignature),
    };
    await rejects(
      authenticateSecretRecipient(owner.vault, room.bundle(owner, grants, []), tampered),
      CryptoErrorCode.KEY_AUTHENTICATION_FAILED,
    );
  });

  it("refuses a bundle whose statements are not the room's, or that does not authorize the caller", async () => {
    const other = await newRoom(outsider);
    // The statements of another room presented for this one.
    const mixed = { ...room.bundle(owner, grants, []), genesis: other.bundle(outsider, [], []).genesis };
    await rejects(
      authenticateSecretRecipient(owner.vault, mixed, publicOf(alice.vault.identity)),
      CryptoErrorCode.KEY_AUTHENTICATION_FAILED,
    );
    // The outsider holds no grant, so the room's statements do not authorize it to act.
    await rejects(
      authenticateSecretRecipient(outsider.vault, room.bundle(outsider, grants, []), publicOf(alice.vault.identity)),
      CryptoErrorCode.KEY_AUTHENTICATION_FAILED,
    );
  });

  it('encrypts only for recipients authenticated by this module', async () => {
    const forged = { roomId: room.roomId, identity: outsider.vault.identity } as SecretRecipient;
    await rejects(encryptSecret(forged, { secretId: randomUUID(), text: 'x' }), CryptoErrorCode.INVALID_INPUT);
    await rejects(encryptSecret({ ...toAlice }, { secretId: randomUUID(), text: 'x' }), CryptoErrorCode.INVALID_INPUT);
  });
});

// --------------------------------------------------------------------------- tampering (T-07)

describe('tampering and substitution fail closed', () => {
  let secret: EncryptedSecret;

  beforeAll(async () => {
    secret = await encryptSecret(toAlice, { secretId: randomUUID(), text: `${CANARY} tamper` });
  });

  it('refuses a modified wrapped SEK, IV, ciphertext or tag', async () => {
    const base = stored(secret);
    const failed = CryptoErrorCode.AUTHENTICATION_FAILED;
    await rejects(openSecret(alice.vault, { ...base, wrappedSek: flip(base.wrappedSek, 100) }), failed);
    await rejects(
      openSecret(alice.vault, { ...base, payload: { ...base.payload, iv: flip(base.payload.iv) } }),
      failed,
    );
    await rejects(
      openSecret(alice.vault, { ...base, payload: { ...base.payload, ciphertext: flip(base.payload.ciphertext) } }),
      failed,
    );
    await rejects(
      openSecret(alice.vault, { ...base, payload: { ...base.payload, ciphertext: flip(base.payload.ciphertext, -1) } }),
      failed,
    );
  });

  it('refuses the secret under another secret ID or room (both contexts bind them)', async () => {
    const base = stored(secret);
    await rejects(openSecret(alice.vault, { ...base, secretId: randomUUID() }), CryptoErrorCode.AUTHENTICATION_FAILED);
    await rejects(openSecret(alice.vault, { ...base, roomId: randomUUID() }), CryptoErrorCode.AUTHENTICATION_FAILED);
  });

  it('refuses a payload moved under another secret’s wrapped SEK', async () => {
    const other = await encryptSecret(toAlice, { secretId: secret.secretId, text: 'other text' });
    await rejects(
      openSecret(alice.vault, { ...stored(secret), wrappedSek: other.wrappedSek }),
      CryptoErrorCode.AUTHENTICATION_FAILED,
    );
  });

  it('cannot be opened by another member, with their own key or by relabelling the record', async () => {
    // Bob is told the secret is his: the label then names Bob, but the SEK was wrapped to Alice.
    const relabelled = {
      ...stored(secret),
      recipientUserId: bob.vault.identity.userId,
      recipientKeyId: bob.vault.identity.keyId,
    };
    await rejects(openSecret(bob.vault, relabelled), CryptoErrorCode.AUTHENTICATION_FAILED);
    // The record as stored names Alice: Bob's client refuses it before any decryption.
    await rejects(openSecret(bob.vault, stored(secret)), CryptoErrorCode.INVALID_INPUT);
    // A wrapped SEK for Alice's user but another key (a reset identity) fails too.
    const resetAlice = await member(alice.vault.identity.userId);
    await rejects(
      openSecret(resetAlice.vault, { ...stored(secret), recipientKeyId: resetAlice.vault.identity.keyId }),
      CryptoErrorCode.AUTHENTICATION_FAILED,
    );
  });

  it('refuses unsupported suites and document versions, non-canonical and malformed documents', async () => {
    await rejects(
      openSecret(alice.vault, { ...stored(secret), suite: 'CM2' }),
      CryptoErrorCode.SECRET_FORMAT_UNSUPPORTED,
    );
    await rejects(
      openSecret(alice.vault, nodeSecret(alice, { v: 2, text: 'x' })),
      CryptoErrorCode.SECRET_FORMAT_UNSUPPORTED,
    );
    const integrity = CryptoErrorCode.SECRET_INTEGRITY_FAILED;
    await rejects(openSecret(alice.vault, nodeSecret(alice, Buffer.from('{"v":1,"text":"x"}'))), integrity);
    await rejects(openSecret(alice.vault, nodeSecret(alice, Buffer.from('{"text":"x", "v":1}'))), integrity);
    await rejects(openSecret(alice.vault, nodeSecret(alice, { v: 1, text: 'x', extra: true })), integrity);
    await rejects(openSecret(alice.vault, nodeSecret(alice, { v: 1, text: '' })), integrity);
    await rejects(openSecret(alice.vault, nodeSecret(alice, { v: '1', text: 'x' })), integrity);
    await rejects(openSecret(alice.vault, nodeSecret(alice, Buffer.from('not json'))), integrity);
    await rejects(openSecret(alice.vault, nodeSecret(alice, Buffer.from('[1]'))), integrity);
  });

  it('refuses records with invalid lengths before any decryption', async () => {
    const base = stored(secret);
    const integrity = CryptoErrorCode.SECRET_INTEGRITY_FAILED;
    await rejects(openSecret(alice.vault, { ...base, wrappedSek: base.wrappedSek.slice(1) }), integrity);
    await rejects(
      openSecret(alice.vault, { ...base, payload: { ...base.payload, iv: new Uint8Array(16) } }),
      integrity,
    );
    await rejects(
      openSecret(alice.vault, { ...base, payload: { ...base.payload, ciphertext: new Uint8Array(16) } }),
      integrity,
    );
    await rejects(
      openSecret(alice.vault, {
        ...base,
        payload: { ...base.payload, ciphertext: new Uint8Array(SECRETS.maxDocumentBytes + 17) },
      }),
      integrity,
    );
  });

  it('refuses malformed wire values as integrity failures', () => {
    const wire = encryptedSecretToWire(secret);
    for (const broken of [
      { ...wire, wrappedSek: wire.wrappedSek.slice(4) },
      { ...wire, payloadIv: `${wire.payloadIv}AA` },
      { ...wire, ciphertext: '***' },
      { ...wire, ciphertext: toBase64Url(new Uint8Array(SECRETS.maxDocumentBytes + 17)) },
    ]) {
      let caught: unknown;
      try {
        storedSecretFromWire(room.roomId, broken);
      } catch (error) {
        caught = error;
      }
      expect(isCryptoError(caught, CryptoErrorCode.SECRET_INTEGRITY_FAILED)).toBe(true);
    }
  });
});
