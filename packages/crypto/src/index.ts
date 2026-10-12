/**
 * @ciphermesh/crypto: client-side cryptography of CipherMesh (Phase 4, CM-T023 to CM-T028).
 *
 * NO HOMEMADE CRYPTOGRAPHY. Everything here composes WebCrypto (AES-256-GCM, RSA-OAEP, ECDSA,
 * HKDF, SHA-256) and the Argon2id library registered as LIB-03, exactly as specified in
 * docs/crypto/ and ADR-015. The export surface is deliberately narrow and is fixed by
 * boundary.test.ts: no function accepts an IV, an algorithm choice or a raw AAD, and no function
 * returns private-key bytes. Low-level seams for known-answer tests live in src/internal and are
 * not exported.
 *
 * Boundary rules (enforced by ESLint): no Node-only imports, no server code, no secrets.
 */
export { CryptoError, CryptoErrorCode, isCryptoError } from './errors';
export {
  isBelowKdfTarget,
  SUITE,
  VAULT_KDF,
  VAULT_PASSPHRASE_POLICY,
  VAULT_VERSION,
  type Argon2idParameters,
} from './params';
export { checkVaultPassphrase, normalizeVaultPassphrase, PassphraseProblem, type PassphraseCheck } from './passphrase';
export { computeFingerprint, formatFingerprint, isFingerprint } from './fingerprint';
export { verifyPublicIdentity, type PublicIdentity, type VerifiedIdentity } from './identity';
export {
  changeVaultPassphrase,
  createVault,
  unlockVault,
  upgradeVaultProtection,
  type UnlockedVault,
  type VaultRewrap,
  type VaultRewrapRequest,
  type VaultSetup,
} from './vault';
export {
  publicIdentityFromWire,
  rewrapToWire,
  vaultRecordFromWire,
  vaultRecordToWire,
  type PublicIdentityWire,
  type VaultKdf,
  type VaultRecord,
  type VaultRewrapWire,
  type VaultWire,
} from './vault-format';
export { createWorkerRunner, type KdfRunner } from './kdf/runner';
// Room keys and signed room statements (Phase 6, CM-T033 to CM-T036, CM-T085).
export {
  computeSafetyCode,
  createInitialRoomKey,
  createInvitationKeys,
  createRekeyKeys,
  openRoomKey,
  reviewRekeyRecipients,
  signMembershipGrant,
  type InvitationKeys,
  type OpenedRoomKey,
  type RecipientAuthorization,
  type RekeyKeys,
  type ReviewedRekeyRecipient,
  type RoomCreationKeys,
  type RoomKeyBundle,
  type SafetyCode,
  type SignedGenesis,
  type SignedKeyVersion,
  type SignedMembershipGrant,
} from './room-keys';
export {
  grantProofToWire,
  invitationKeysToWire,
  openRoomKeys,
  rekeyKeysToWire,
  roomCreationKeysToWire,
  roomKeyBundlesFromWire,
  type EnvelopeWire,
  type RoomKeyMaterialWire,
} from './room-format';
export { sortRecipients, type RecipientRef } from './recipients';
// Encrypted files (Phase 7, CM-T038, CM-T039).
export { encryptFile, openFile, type EncryptedFile, type OpenedFile, type StoredFile } from './files';
export { encryptedFileToWire, storedFileFromWire, type EncryptedFileWire } from './file-format';
// Encrypted notes (Phase 8, CM-T042).
export {
  encryptNote,
  isNoteTitle,
  noteDocumentBytes,
  openNote,
  type EncryptedNote,
  type NoteContent,
  type OpenedNote,
  type StoredNote,
} from './notes';
export { noteCiphertextToWire, storedNoteFromWire, type NoteCiphertextWire, type StoredNoteWire } from './note-format';
// Recipient-bound secrets (Phase 9, CM-T043, CM-T044).
export {
  authenticateSecretRecipient,
  encryptSecret,
  isSecretText,
  openSecret,
  secretDocumentBytes,
  type EncryptedSecret,
  type OpenedSecret,
  type SecretRecipient,
  type StoredSecret,
} from './secrets';
export { encryptedSecretToWire, storedSecretFromWire, type SecretCiphertextWire } from './secret-format';
export { FILES, NOTES, ROOM_KEYS, SECRETS, type RoomRole } from './params';
export { isDerivationRunning } from './kdf/derive';
export type { Key } from './types';
