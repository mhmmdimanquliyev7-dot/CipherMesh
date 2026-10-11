/**
 * The parameter register (docs/crypto/crypto-decisions.md) as code. Every algorithm and size used
 * by this package comes from here; changing a value requires an ADR update, the register and
 * tests (CLAUDE.md section 7). Callers can never choose a weaker algorithm: no function of this
 * package takes an algorithm or parameter set as an argument except the vault KDF parameters,
 * which are range-checked against the floor and ceiling below.
 */

/** Algorithm suite CM1 (CP-18): CP-01, CP-02, CP-03, CP-04, CP-07 and CP-26. */
export const SUITE = 'CM1';
export type Suite = typeof SUITE;

/** CP-01: AES-256-GCM with a 96-bit IV from the CSPRNG and a 128-bit tag. */
export const AES_GCM = Object.freeze({ name: 'AES-GCM', keyBits: 256, ivBytes: 12, tagBytes: 16 });

/** CP-02: RSA-OAEP-3072, e = 65537, SHA-256 for OAEP and MGF1. Only 32-byte values (INV-17). */
export const RSA_OAEP = Object.freeze({
  name: 'RSA-OAEP',
  hash: 'SHA-256',
  modulusLength: 3072,
  publicExponent: Object.freeze([1, 0, 1]),
  spkiBytes: 422,
  ciphertextBytes: 384,
  wrappedValueBytes: 32,
});

/** CP-26 (ADR-015): ECDSA on P-256 with SHA-256, IEEE P1363 signatures (r || s). */
export const ECDSA = Object.freeze({
  name: 'ECDSA',
  namedCurve: 'P-256',
  hash: 'SHA-256',
  spkiBytes: 91,
  signatureBytes: 64,
});

/** CP-03: HKDF-SHA-256 with a salt of 32 zero bytes, info = canonical context, 256-bit output. */
export const HKDF = Object.freeze({ name: 'HKDF', hash: 'SHA-256', saltBytes: 32, outputBits: 256 });

/** CP-07: SHA-256. */
export const SHA256_BYTES = 32;

/**
 * Room keys (cryptographic-architecture section 7, ADR-015 section 4, Phase 6). RKM_v is 32 random
 * bytes (CP-23) and is only an HKDF input; RKC_v is a 32-byte HKDF output (CP-03). A key-version
 * statement lists at most 100 recipients, the member bound of CP-25. The Room Safety Code shows the
 * first 66 bits of RSC_v as six 11-bit word indices or 20 decimal digits (CP-24).
 */
export const ROOM_KEYS = Object.freeze({
  materialBytes: 32,
  commitmentBytes: 32,
  maxRecipients: 100,
  envelopeAlgorithm: 'RSA-OAEP-3072-SHA256',
  safetyCodeWords: 6,
  safetyCodeBitsPerWord: 11,
  safetyCodeDigits: 20,
});

/**
 * Encrypted files (cryptographic-architecture section 6.1, Phase 7). Each file has its own random
 * 256-bit FEK; the FEK encrypts the content and the manifest (CP-16: two messages) and is wrapped
 * under RWK_v with AES-256-GCM, so a wrapped FEK is 32 key bytes plus the tag. CP-19 limits a file
 * to 50 MiB, encrypted in one AES-GCM operation; packages/shared repeats the value (FILE_LIMITS)
 * and a test compares the two. Manifest format version 1 holds the name, type, size and the
 * SHA-256 of the plaintext (CD-09).
 */
export const FILES = Object.freeze({
  fekBytes: 32,
  wrappedFekBytes: 48,
  maxPlaintextBytes: 50 * 1024 * 1024,
  manifestVersion: 1,
  maxNameLength: 255,
  maxTypeLength: 127,
});

/** Room roles as they appear in signed membership grants (authorization-model section 2.1). */
export const ROOM_ROLES = Object.freeze(['OWNER', 'ADMIN', 'MEMBER', 'VIEWER'] as const);
export type RoomRole = (typeof ROOM_ROLES)[number];

export interface Argon2idParameters {
  readonly memoryKiB: number;
  readonly iterations: number;
  readonly parallelism: number;
}

/**
 * CP-04: browser Argon2id for the Vault (RFC 9106, version 1.3), 128-bit salt, 256-bit output.
 * Final values after the Phase 4 benchmark (crypto-decisions.md section 8). New vaults always use
 * the target. Stored vaults below the floor or above the ceiling are refused by the client and
 * the API; the ceiling stops a malicious record from exhausting the browser's memory.
 */
export const VAULT_KDF = Object.freeze({
  algorithm: 'argon2id',
  version: 0x13,
  saltBytes: 16,
  outputBytes: 32,
  floor: Object.freeze({ memoryKiB: 19_456, iterations: 2, parallelism: 1 }),
  target: Object.freeze({ memoryKiB: 65_536, iterations: 3, parallelism: 1 }),
  ceiling: Object.freeze({ memoryKiB: 262_144, iterations: 10, parallelism: 4 }),
});

/** The vault format version this client writes and reads (docs/crypto/vault.md). */
export const VAULT_VERSION = 1;

/** Vault Passphrase length in Unicode code points after NFKC (CP-06). */
export const VAULT_PASSPHRASE_POLICY = Object.freeze({ minLength: 16, maxLength: 256 });

/** Accepted sizes of the wrapped private keys (AES-GCM output: PKCS#8 bytes plus the tag). */
export const WRAPPED_KEY_BYTES = Object.freeze({
  // PKCS#8 of an RSA-3072 key is 1793 to 1795 bytes depending on the engine's DER integers.
  encryption: Object.freeze({ min: 1_700, max: 2_048 }),
  // PKCS#8 of a P-256 key is 138 bytes in Chromium, Firefox and WebKit.
  signing: Object.freeze({ min: 64, max: 256 }),
});

/** True when the parameters lie within the floor and ceiling of CP-04. */
export function isAcceptableKdf(params: Argon2idParameters): boolean {
  const { floor, ceiling } = VAULT_KDF;
  const within = (value: number, min: number, max: number): boolean =>
    Number.isSafeInteger(value) && value >= min && value <= max;
  return (
    within(params.memoryKiB, floor.memoryKiB, ceiling.memoryKiB) &&
    within(params.iterations, floor.iterations, ceiling.iterations) &&
    within(params.parallelism, floor.parallelism, ceiling.parallelism) &&
    params.memoryKiB >= 8 * params.parallelism
  );
}

/** True when stored parameters are weaker than the current target and should be upgraded. */
export function isBelowKdfTarget(params: Argon2idParameters): boolean {
  return params.memoryKiB < VAULT_KDF.target.memoryKiB || params.iterations < VAULT_KDF.target.iterations;
}
