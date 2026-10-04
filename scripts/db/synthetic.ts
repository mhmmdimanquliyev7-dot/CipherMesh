// Synthetic seed data (CM-T011). Clearly fake, and safe to publish:
// - Addresses use the reserved `.test` top-level domain (RFC 2606); no real names or people.
// - No credentials. The password hash is a syntactically valid Argon2id PHC string whose salt
//   and hash fields decode to the ASCII labels "SYNTHETIC-SALT" and "SYNTHETIC-NOT-A-HASH". It
//   was not produced from any password, so no password verifies against it. The accounts are
//   also DISABLED, which blocks login regardless.
// - No key material, ciphertext, rooms or envelopes. Those are created by member browsers
//   through packages/crypto from Phase 4 on; the server and its tooling never generate them
//   (data-model section 6), and fake key bytes would only blur that rule.

export const PLACEHOLDER_PHC = '$argon2id$v=19$m=19456,t=2,p=1$U1lOVEhFVElDLVNBTFQ$U1lOVEhFVElDLU5PVC1BLUhBU0g';

export const SYNTHETIC_USERS = [
  { email: 'seed-user-1@example.test', displayName: 'Synthetic User 1' },
  { email: 'seed-user-2@example.test', displayName: 'Synthetic User 2' },
  { email: 'seed-user-3@example.test', displayName: 'Synthetic User 3' },
] as const;

/** Fixed timestamp so reseeding produces identical rows. */
export const SEED_TIMESTAMP = new Date('2026-01-01T00:00:00.000Z');
