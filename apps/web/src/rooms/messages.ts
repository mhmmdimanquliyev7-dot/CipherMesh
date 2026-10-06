import { ApiError, describeError } from '../lib/api';

/** Text for the stable error codes of the room routes. Never reveals more than the code. */
export function describeRoomError(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.code) {
      case 'NOT_FOUND':
        return 'This room or member does not exist, or you are not a member of the room.';
      case 'FORBIDDEN':
        return 'Your role in this room does not allow this action.';
      case 'VAULT_SETUP_REQUIRED':
        return 'Set up your vault before creating a room.';
      case 'MFA_REQUIRED':
        return 'This security profile needs a session verified with an authentication code. Turn on two-step sign-in in Account, then sign in again.';
      case 'REAUTH_REQUIRED':
        return 'Sign in again to create a room with this security profile.';
      case 'ROOM_ID_UNAVAILABLE':
        return 'That room identifier cannot be used. Please try again.';
      case 'VALIDATION_FAILED':
        return 'Use a room name of 1 to 100 characters without control characters.';
    }
  }
  return describeError(error);
}

/** Shown wherever a room name is typed (data-model 4.6, T-28). */
export const ROOM_NAME_WARNING =
  'Room names are not encrypted: the server stores them and shows them to every member. Do not put sensitive information in a room name.';

/** Shown for a room in REKEY_REQUIRED or REKEYING (ADR-013); the rekey itself arrives in a later phase. */
export const REKEY_NOTICE =
  'A member left this room. Until an owner or admin completes a key rotation, new content cannot be added. Key rotation arrives in a later phase.';
