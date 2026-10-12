import { isCryptoError } from '@ciphermesh/crypto';
import { ApiError, describeError } from '../lib/api';

/** Text for the stable error codes of the room routes. Never reveals more than the code. */
export function describeRoomError(error: unknown): string {
  if (isCryptoError(error)) {
    switch (error.code) {
      case 'KEY_AUTHENTICATION_FAILED':
        return KEY_REFUSED;
      case 'KEY_COMMITMENT_MISMATCH':
        return KEY_MISMATCH;
      case 'CRYPTO_UNAVAILABLE':
        return 'This browser does not provide the cryptography CipherMesh requires.';
      case 'CRYPTO_AUTHENTICATION_FAILED':
      case 'FILE_INTEGRITY_FAILED':
        return FILE_INTEGRITY_ERROR;
      case 'FILE_FORMAT_UNSUPPORTED':
        return 'This file was encrypted in a format this version of CipherMesh does not support. Nothing was opened.';
      case 'NOTE_INTEGRITY_FAILED':
        return NOTE_INTEGRITY_ERROR;
      case 'NOTE_FORMAT_UNSUPPORTED':
        return NOTE_UNSUPPORTED;
      case 'SECRET_INTEGRITY_FAILED':
        return SECRET_INTEGRITY_ERROR;
      case 'SECRET_FORMAT_UNSUPPORTED':
        return 'This secret was encrypted in a format this version of CipherMesh does not support. Nothing was shown.';
      default:
        return 'A cryptographic check failed. Nothing was used or sent.';
    }
  }
  if (typeof error === 'object' && error !== null && 'code' in error) {
    if (error.code === 'VAULT_LOCKED')
      return 'Unlock your vault first. Room keys are created and opened in this browser.';
    if (error.code === 'ROOM_KEY_MISSING') return KEY_MISSING;
    if (error.code === 'FILE_TOO_LARGE')
      return 'Files can be at most 50 MiB (they are encrypted in this browser in one piece).';
    if (error.code === 'NOTE_TOO_LONG')
      return 'This note is too long: a note can hold at most 64 KiB of text (title and body together).';
    if (error.code === 'SECRET_TOO_LONG') return 'This secret is too long: a secret can hold at most 16 KiB of text.';
    if (error.code === 'SECRET_FOR_OTHER_KEY')
      return 'This secret was sent to an earlier identity key of yours, so this vault cannot open it. Nothing was requested.';
    if (error.code === 'STORAGE_TRANSFER_FAILED')
      return 'The encrypted file could not be transferred to or from storage. Check your connection and try again.';
  }
  if (error instanceof ApiError) {
    switch (error.code) {
      case 'NOT_FOUND':
        return 'This room, member or invitation does not exist, or you cannot see it.';
      case 'FORBIDDEN':
        return 'Your role in this room does not allow this action.';
      case 'VAULT_SETUP_REQUIRED':
        return 'Set up your vault first.';
      case 'MFA_REQUIRED':
        return 'This security profile needs a session verified with an authentication code. Turn on two-step sign-in in Account, then sign in again.';
      case 'REAUTH_REQUIRED':
        return 'This security profile needs a recent sign-in. Sign in again.';
      case 'ROOM_ID_UNAVAILABLE':
        return 'That room identifier cannot be used. Please try again.';
      case 'VALIDATION_FAILED':
        return 'The request was not accepted. Check the values and try again.';
      case 'REKEY_REQUIRED':
        return 'This room is locked until its key is rotated, so no one can be invited or join now.';
      case 'ROOM_STATEMENT_INVALID':
        return 'The server could not verify the signed room statement. Nothing was changed.';
      case 'ENVELOPE_SET_INVALID':
        return 'The room keys for this invitation do not match what the room requires.';
      case 'IDENTITY_KEY_CHANGED':
        return 'That identity key is no longer current (the vault was reset). Look the person up again.';
      case 'ALREADY_MEMBER':
        return 'This person is already a member of the room.';
      case 'INVITATION_PENDING':
        return 'This person already has an open invitation to the room.';
      case 'INVITATION_NOT_OPEN':
        return 'This invitation cannot be used now. It may wait for approval, or it was closed.';
      case 'INVITATION_EXPIRED':
        return 'This invitation has expired. Ask for a new one.';
      case 'FINGERPRINT_REQUIRED':
        return 'This room requires you to compare and confirm the fingerprint first.';
      case 'FINGERPRINT_MISMATCH':
        return "The fingerprint you confirmed is not this person's current fingerprint. Do not invite them; compare again.";
      // Encrypted files (Phase 7).
      case 'KEY_VERSION_STALE':
        return 'The room key changed while you were uploading. Reload the room and try again.';
      case 'FILE_ID_UNAVAILABLE':
        return 'That file identifier cannot be used. Please try again.';
      case 'EXPIRY_NOT_ALLOWED':
        return "Choose an expiry that this room's security profile allows.";
      case 'FILE_QUOTA_EXCEEDED':
        return 'The storage quota is used up, or you have too many unfinished uploads. Delete files or wait, then try again.';
      case 'UPLOAD_INCOMPLETE':
        return 'The encrypted file has not reached storage yet. Try again.';
      case 'UPLOAD_SIZE_MISMATCH':
        return 'The stored file did not match what was announced, so the upload was cancelled.';
      case 'UPLOAD_EXPIRED':
        return 'The upload took too long and was cancelled. Try again.';
      case 'FILE_NOT_PENDING':
        return 'This upload was already completed or cancelled.';
      case 'STORAGE_UNAVAILABLE':
        return 'File storage is not available right now. Try again later.';
      // Encrypted notes (Phase 8).
      case 'REVISION_CONFLICT':
        return NOTE_CONFLICT;
      case 'NOTE_ID_UNAVAILABLE':
        return 'That note identifier cannot be used. Please try again.';
      case 'NOTE_LIMIT_REACHED':
        return 'This room holds the most notes it can (1000). Delete notes you no longer need first.';
      // Recipient-bound secrets (Phase 9).
      case 'SECRET_UNAVAILABLE':
        return SECRET_UNAVAILABLE;
      case 'SECRET_RECIPIENT_INVALID':
        return 'That person cannot receive secrets in this room right now (not an active member, or their identity key changed).';
      case 'BURN_REQUIRED':
        return 'Secrets in this room are always destroyed after they are revealed (restricted profile).';
      case 'SECRET_LIMIT_REACHED':
        return 'You have sent the most active secrets allowed (100). Revoke secrets that are no longer needed, or wait until they are revealed or expire.';
      case 'SECRET_ID_UNAVAILABLE':
        return 'That secret identifier cannot be used. Please try again.';
    }
  }
  return describeError(error);
}

/** Any failed check of an encrypted file (CM-T039, T-07): nothing was shown or saved. */
export const FILE_INTEGRITY_ERROR =
  'This file failed its integrity check: it was changed or damaged after it was encrypted. Nothing was shown or saved. Tell the room owner through another channel.';

/** Any failed check of an encrypted note (CM-T042, T-07): nothing was shown. */
export const NOTE_INTEGRITY_ERROR =
  'This note failed its integrity check: it was changed or damaged after it was encrypted. Nothing was shown. Tell the room owner through another channel.';
export const NOTE_UNSUPPORTED =
  'This note was encrypted in a format this version of CipherMesh does not support. Nothing was shown.';
/** A save refused because someone else saved first (DF-12): nothing was overwritten. */
export const NOTE_CONFLICT =
  'Someone else saved this note after you opened it, so your version was not saved and nothing was overwritten. Your text is still in the editor: copy what you need, then load the latest version.';
/** The browser saw a newer revision earlier in this tab (T-32, L-10). */
export const NOTE_ROLLBACK =
  'The server returned an older version of this note than this tab saw before. It may be restoring old content. Reload the room, and tell the owner through another channel if it persists.';

/** Encrypted notes (security-ui, L-09, L-11): what encryption does and does not cover. */
export const NOTES_EXPLANATION =
  'Notes are encrypted in your browser; the server stores only ciphertext. It sees who wrote or changed a note, when, its size and how often it changes. Anyone who can read a note can copy its text, and removing someone from the room does not take back what they already read.';

/** Any authentication failure while opening a note (the generic crypto code included). */
export function describeNoteError(error: unknown): string {
  if (
    isCryptoError(error) &&
    (error.code === 'CRYPTO_AUTHENTICATION_FAILED' || error.code === 'CRYPTO_INVALID_INPUT')
  ) {
    return NOTE_INTEGRITY_ERROR;
  }
  if (error instanceof ApiError && error.code === 'KEY_VERSION_STALE') {
    return 'The room key changed while you were editing. Reload the room and save again; your text is still in the editor.';
  }
  return describeRoomError(error);
}

/** Any failed check of a revealed secret (CM-T043, T-07): nothing was shown. */
export const SECRET_INTEGRITY_ERROR =
  'This secret failed its integrity check: it was changed or damaged after it was encrypted, or it was not encrypted for your key. Nothing was shown. Tell the sender through another channel.';
/** The server refused the reveal: already revealed, expired or revoked. */
export const SECRET_UNAVAILABLE =
  'This secret can no longer be revealed: it was already revealed, it expired, or it was revoked.';

/** Recipient-bound secrets (security-ui, L-03, L-12, L-55, L-56): what the feature does and does not do. */
export const SECRETS_EXPLANATION =
  'A secret is encrypted in your browser for one member; only their identity key can open it, and the server stores only ciphertext. The server sees who sent it to whom, when, its size and whether it was revealed. Once a secret is revealed, it cannot be retrieved again through CipherMesh, but the recipient can copy what they see, and database backups keep the ciphertext until they expire.';

/** Shown before an explicit reveal of a burn-after-reading secret (DF-09: at most once). */
export const SECRET_REVEAL_WARNING =
  'Revealing destroys this secret on the server at the moment it is sent to this browser. If this page closes or the connection drops before it is shown, it cannot be recovered. Make sure you can read it now.';

/** Any authentication failure while opening a secret (the generic crypto codes included). */
export function describeSecretError(error: unknown): string {
  if (
    isCryptoError(error) &&
    (error.code === 'CRYPTO_AUTHENTICATION_FAILED' || error.code === 'CRYPTO_INVALID_INPUT')
  ) {
    return SECRET_INTEGRITY_ERROR;
  }
  if (isCryptoError(error) && error.code === 'KEY_AUTHENTICATION_FAILED') {
    return "The recipient's identity key could not be confirmed from the room's signed records, so nothing was encrypted or sent. Ask the room owner to check the member's fingerprint.";
  }
  return describeRoomError(error);
}

/** Encrypted files (security-ui, L-11, L-14): what encryption does and does not cover. */
export const FILES_EXPLANATION =
  'Files are encrypted in your browser before upload; the server and storage hold only ciphertext. Their size and upload time are visible to the server. A file you download is saved unencrypted on your device, outside CipherMesh, and removing someone from the room does not take back files they already downloaded.';

/** Shown wherever a room name is typed (data-model 4.6, T-28). */
export const ROOM_NAME_WARNING =
  'Room names are not encrypted: the server stores them and shows them to every member. Do not put sensitive information in a room name.';

/** Shown for a room in REKEY_REQUIRED or REKEYING (ADR-013); the rekey itself arrives in a later phase. */
export const REKEY_NOTICE =
  'A member left this room. Until an owner or admin completes a key rotation, new content cannot be added and no one can be invited. Key rotation arrives in a later phase.';

/** security-ui.md 2.6: a refused key is never used, and the refusal is reported. */
export const KEY_REFUSED =
  'The room key could not be verified on this device and was not used. This can indicate tampering on the server. The event was reported; tell the room owner through another channel.';
export const KEY_MISMATCH =
  "The room key you received does not match the room's signed record. It was not used, and the event was reported.";
export const KEY_MISSING =
  'There is no room key for your current identity in this room, for example after a vault reset. An owner or admin has to share the key with you again.';

/** The Room Safety Code panel (security-ui.md 2.3, ADR-012, L-22). */
export const SAFETY_CODE_GUIDANCE =
  'Compare these words with each member in person or on a voice or video call. Do not paste them into CipherMesh or a group chat before everyone has read their own.';
export const SAFETY_CODE_EXPLANATION =
  'The Safety Code checks that you and another member hold the same room key. Comparing it over a channel you trust can reveal that members were given different keys. It does not show who else holds the key, it cannot detect a key everyone received from an attacker, and it only helps if you compare it.';
export const SAFETY_CODE_MISMATCH =
  'Your codes differ: you hold different room keys. This can indicate an attack involving the server. Stop adding content to this room and alert the owner through another channel. A mismatch report holding only the key version was sent.';

/** Fingerprint comparison while inviting (security-ui.md 2.2, PC-05, L-18, T-25, T-35). */
export const FINGERPRINT_GUIDANCE =
  'Ask the person to read their fingerprint to you (shown in their Vault page) over a channel where you recognise them, and compare all 64 characters. CipherMesh cannot check that you compared; it only checks that what you confirm is their current key.';
