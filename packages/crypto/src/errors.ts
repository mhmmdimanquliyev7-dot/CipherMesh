/**
 * Typed errors of the crypto package. Every error carries a stable code and a fixed message. No
 * error ever contains key material, passphrases, plaintext, ciphertext or the text of an
 * underlying library error (INV-10), and no underlying error is attached as a cause, because
 * WebCrypto and WASM errors can describe internal state.
 */
export const CryptoErrorCode = {
  /** WebCrypto, WebAssembly or Web Workers are missing: fail closed, never fall back (INV-15). */
  UNAVAILABLE: 'CRYPTO_UNAVAILABLE',
  /** A caller passed malformed input, for example a wrong length or an invalid context field. */
  INVALID_INPUT: 'CRYPTO_INVALID_INPUT',
  /** Authenticated decryption or RSA-OAEP decryption failed. Deliberately generic. */
  AUTHENTICATION_FAILED: 'CRYPTO_AUTHENTICATION_FAILED',
  /** A public identity failed validation: key format, binding signature or fingerprint. */
  IDENTITY_INVALID: 'IDENTITY_INVALID',
  /** A vault record is structurally invalid. Detected before any key derivation. */
  INVALID_VAULT_FORMAT: 'INVALID_VAULT_FORMAT',
  /** A vault format version or algorithm suite this client does not support (no downgrade). */
  UNSUPPORTED_VAULT_VERSION: 'UNSUPPORTED_VAULT_VERSION',
  /** Argon2id parameters below the floor or above the ceiling of CP-04. */
  KDF_PARAMETERS_OUT_OF_RANGE: 'KDF_PARAMETERS_OUT_OF_RANGE',
  /** Wrong passphrase or damaged vault. The two cases are indistinguishable on purpose. */
  VAULT_UNLOCK_FAILED: 'VAULT_UNLOCK_FAILED',
  /** Another key derivation is running; derivations are never run in parallel. */
  KDF_BUSY: 'KDF_BUSY',
  /** The Argon2id worker failed, crashed or timed out. */
  KDF_FAILED: 'KDF_FAILED',
  /** The Vault Passphrase does not meet the policy (CP-06). */
  PASSPHRASE_REJECTED: 'PASSPHRASE_REJECTED',
  /**
   * A room key version failed the verification rule of ADR-015 section 4: a signature, the
   * creator's authority, this client's authorization as a recipient, or the envelope itself. The
   * key is refused; nothing derived from it is used (T-36).
   */
  KEY_AUTHENTICATION_FAILED: 'KEY_AUTHENTICATION_FAILED',
  /** The decrypted room key does not match the signed commitment (cryptographic-architecture 7.3, T-29). */
  KEY_COMMITMENT_MISMATCH: 'KEY_COMMITMENT_MISMATCH',
} as const;

export type CryptoErrorCode = (typeof CryptoErrorCode)[keyof typeof CryptoErrorCode];

const MESSAGES: Readonly<Record<CryptoErrorCode, string>> = {
  CRYPTO_UNAVAILABLE: 'This browser does not provide the cryptography CipherMesh requires',
  CRYPTO_INVALID_INPUT: 'Invalid input to a cryptographic operation',
  CRYPTO_AUTHENTICATION_FAILED: 'Authenticated decryption failed',
  IDENTITY_INVALID: 'The public identity is not valid',
  INVALID_VAULT_FORMAT: 'The vault record is not valid',
  UNSUPPORTED_VAULT_VERSION: 'The vault format is not supported',
  KDF_PARAMETERS_OUT_OF_RANGE: 'The vault key-derivation parameters are not acceptable',
  VAULT_UNLOCK_FAILED: 'The vault could not be unlocked',
  KDF_BUSY: 'A vault key derivation is already running',
  KDF_FAILED: 'The vault key derivation failed',
  PASSPHRASE_REJECTED: 'The Vault Passphrase does not meet the policy',
  KEY_AUTHENTICATION_FAILED: 'The room key could not be authenticated and was not used',
  KEY_COMMITMENT_MISMATCH: "The room key does not match the room's signed record and was not used",
};

export class CryptoError extends Error {
  readonly code: CryptoErrorCode;

  constructor(code: CryptoErrorCode) {
    super(MESSAGES[code]);
    this.name = 'CryptoError';
    this.code = code;
  }
}

export function isCryptoError(value: unknown, code?: CryptoErrorCode): value is CryptoError {
  return value instanceof CryptoError && (code === undefined || value.code === code);
}
