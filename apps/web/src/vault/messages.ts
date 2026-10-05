import { PassphraseProblem } from '@ciphermesh/crypto';
import { describeError } from '../lib/api';
import { codeOf } from './controller';

/**
 * User-facing texts for vault errors. A wrong passphrase and a damaged vault deliberately get the
 * same message (DF-04): the browser cannot tell them apart and does not try to.
 */
const MESSAGES: Readonly<Record<string, string>> = {
  VAULT_UNLOCK_FAILED:
    'The vault could not be opened. Either the Vault Passphrase is wrong or the stored vault is damaged. Nothing was decrypted.',
  IDENTITY_INVALID:
    'The vault data from the server failed its integrity checks in this browser. It was not used. If this persists, report it.',
  INVALID_VAULT_FORMAT: 'The vault data is not in a format this browser accepts. It was not used.',
  UNSUPPORTED_VAULT_VERSION: 'The vault uses a format this version of CipherMesh does not support. It was not used.',
  KDF_PARAMETERS_OUT_OF_RANGE:
    'The vault asks for key-derivation settings outside the accepted range. It was not used.',
  CRYPTO_UNAVAILABLE:
    'This browser cannot run the cryptography CipherMesh needs (WebCrypto, WebAssembly and Web Workers in a secure context). CipherMesh does not fall back to weaker methods.',
  KDF_BUSY: 'A vault operation is already running in this tab. Wait for it to finish.',
  KDF_FAILED: 'The key derivation did not finish. Close other heavy tabs and try again.',
  PASSPHRASE_REJECTED: 'The new Vault Passphrase does not meet the policy.',
  STEP_UP_REQUIRED: 'Confirm your account first (account password, and authentication code if MFA is on).',
  VAULT_ALREADY_EXISTS: 'A vault already exists for this account. Reload the page.',
  VAULT_CONFLICT: 'The vault was changed elsewhere in the meantime. Reload and try again.',
  VAULT_SIGNATURE_INVALID: 'The server refused the change because it was not signed by your vault identity.',
  IDENTITY_REJECTED: 'The server could not verify the new identity. Nothing was stored.',
  VAULT_SETUP_REQUIRED: 'Set up your own vault before looking up other users.',
  NOT_FOUND: 'No user with a cryptographic identity was found for this exact address.',
};

export function describeVaultError(error: unknown): string {
  return MESSAGES[codeOf(error)] ?? describeError(error);
}

export const PASSPHRASE_PROBLEM_TEXT: Readonly<Record<PassphraseProblem, string>> = {
  [PassphraseProblem.TOO_SHORT]: 'Use at least 16 characters. Several random words work well.',
  [PassphraseProblem.TOO_LONG]: 'Use at most 256 characters.',
  [PassphraseProblem.MALFORMED]: 'The passphrase contains characters that cannot be processed.',
  [PassphraseProblem.COMMON]: 'This appears in lists of breached passwords. Choose another one.',
  [PassphraseProblem.CONTAINS_IDENTITY]: 'Do not build it from your email address, your name or the product name.',
};
