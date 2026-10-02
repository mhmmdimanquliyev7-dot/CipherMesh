/**
 * @ciphermesh/crypto: package boundary only (Phase 1).
 *
 * NO HOMEMADE CRYPTOGRAPHY. This package will wrap WebCrypto and the approved
 * Argon2id library exactly as specified in docs/crypto/. Nothing here is usable
 * cryptography yet, and nothing may be added outside the planned phases:
 *
 *   Phase 4 (CM-T023, CM-T024): AES-256-GCM wrappers with internal IVs (INV-02),
 *     RSA-OAEP wrapper for 32-byte keys only (INV-17), HKDF, SHA-256,
 *     RFC 8785 canonical context builders, Argon2id in a Web Worker.
 *   Phase 6 (CM-T085): Room Safety Code derivation (INV-18).
 *
 * Boundary rules (enforced by ESLint): no Node-only imports, no server code,
 * no secrets, browser-compatible APIs only.
 */
export const CRYPTO_PACKAGE_STATUS = 'boundary-only' as const;
