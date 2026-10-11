/**
 * The recipients of a signed key-version statement (ADR-015 section 4): each is a user and the
 * identity key that received an envelope. The statement lists them in one canonical order, by
 * user ID and then key ID, compared as UTF-16 code units (for lower-case UUIDs that is byte order),
 * so every recipient set has exactly one signed byte form.
 */
export interface RecipientRef {
  readonly userId: string;
  readonly keyId: string;
}

export function compareRecipients(a: RecipientRef, b: RecipientRef): number {
  if (a.userId !== b.userId) return a.userId < b.userId ? -1 : 1;
  if (a.keyId !== b.keyId) return a.keyId < b.keyId ? -1 : 1;
  return 0;
}

/** A sorted copy with only the two identifiers of each entry. Duplicates are kept for the builder to refuse. */
export function sortRecipients(recipients: readonly RecipientRef[]): RecipientRef[] {
  return recipients.map((r) => ({ userId: r.userId, keyId: r.keyId })).sort(compareRecipients);
}
