import { isWellFormedUnicode } from './encoding';
import { VAULT_PASSPHRASE_POLICY } from './params';
import { COMMON_PASSPHRASES } from './passphrase-blocklist';

/**
 * Vault Passphrase policy (CP-06). The passphrase protects the private keys against anyone who
 * obtains the encrypted vault, for example from a database copy, and who can then guess offline
 * at the Argon2id cost (T-22, L-08). It is therefore longer than the account password minimum.
 *
 *   - 16 to 256 Unicode code points after NFKC normalization (CD-15); never truncated;
 *   - no lone UTF-16 surrogates (they cannot be encoded reliably);
 *   - not in the local list of breached passwords of 16 or more characters;
 *   - not built from the account's email local part, display name or the product name;
 *   - no composition rules: length and unpredictability matter, and passphrases made of several
 *     random words are encouraged.
 * Every check runs in the browser. The passphrase is never sent for validation (INV-01).
 * Whitespace is kept exactly as typed after NFKC; trimming would make two different strings
 * derive the same key on one device and different keys on another.
 */
export const PassphraseProblem = {
  TOO_SHORT: 'passphrase_too_short',
  TOO_LONG: 'passphrase_too_long',
  MALFORMED: 'passphrase_malformed',
  COMMON: 'passphrase_common',
  CONTAINS_IDENTITY: 'passphrase_contains_identity',
} as const;
export type PassphraseProblem = (typeof PassphraseProblem)[keyof typeof PassphraseProblem];

export type PassphraseCheck =
  | { readonly ok: true; readonly normalized: string; readonly length: number }
  | { readonly ok: false; readonly problems: readonly PassphraseProblem[] };

let blocklist: ReadonlySet<string> | undefined;
const commonPassphrases = (): ReadonlySet<string> => (blocklist ??= new Set(COMMON_PASSPHRASES.split('\n')));

/** NFKC normalization for derivation (CD-15). Undefined for strings with lone surrogates. */
export function normalizeVaultPassphrase(raw: string): string | undefined {
  return isWellFormedUnicode(raw) ? raw.normalize('NFKC') : undefined;
}

/** Checks a new Vault Passphrase (setup and change only; unlock never applies the policy). */
export function checkVaultPassphrase(
  raw: string,
  identity: { readonly email: string; readonly displayName: string },
): PassphraseCheck {
  const normalized = normalizeVaultPassphrase(raw);
  if (normalized === undefined) return { ok: false, problems: [PassphraseProblem.MALFORMED] };
  const length = Array.from(normalized).length;
  if (length < VAULT_PASSPHRASE_POLICY.minLength) return { ok: false, problems: [PassphraseProblem.TOO_SHORT] };
  if (length > VAULT_PASSPHRASE_POLICY.maxLength) return { ok: false, problems: [PassphraseProblem.TOO_LONG] };
  const lower = normalized.toLowerCase();
  if (commonPassphrases().has(lower)) return { ok: false, problems: [PassphraseProblem.COMMON] };
  const localPart = identity.email.split('@')[0] ?? '';
  const parts = [localPart.toLowerCase(), identity.displayName.normalize('NFKC').toLowerCase(), 'ciphermesh'];
  if (parts.some((part) => part.length >= 4 && lower.includes(part))) {
    return { ok: false, problems: [PassphraseProblem.CONTAINS_IDENTITY] };
  }
  return { ok: true, normalized, length };
}
