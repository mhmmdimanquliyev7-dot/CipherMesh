/**
 * @ciphermesh/crypto/identity: the subset the API needs to validate what browsers upload, with
 * exactly the same code the browsers use (ADR-015): public identity verification (key format,
 * fingerprint, binding signature), the vault wire format and its size checks, and the signed
 * re-wrap statement. It contains no key generation, no Argon2id and no Web Worker code, and it
 * never touches private keys: the server holds none (INV-01).
 */
export { CryptoError, CryptoErrorCode, isCryptoError } from './errors';
export { verifyPublicIdentity, type PublicIdentity, type VerifiedIdentity } from './identity';
export { computeFingerprint, isFingerprint } from './fingerprint';
export { verifyStatement } from './signing';
export { fromBase64Url, toBase64Url } from './encoding';
export { isAcceptableKdf, SUITE, VAULT_KDF, VAULT_VERSION, type Argon2idParameters } from './params';
export {
  isNotWeaker,
  kdfFromWire,
  publicIdentityFromWire,
  publicIdentityToWire,
  rewrapFromWire,
  rewrapStatement,
  vaultRecordFromWire,
  type PublicIdentityWire,
  type SealedWire,
  type VaultKdf,
  type VaultKdfWire,
  type VaultRecord,
  type VaultRewrapWire,
  type VaultWire,
} from './vault-format';
