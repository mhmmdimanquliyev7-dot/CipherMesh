# ADR-002: Client-side encryption of room content

- Status: Accepted
- Date: 2026-09-28
- Related: [cryptographic-architecture.md](../../crypto/cryptographic-architecture.md), [limitations.md](../../security/limitations.md), T-01, T-02, T-19, T-24

## Context
CipherMesh must protect sensitive room content against theft of the database, object storage and backups, and against access by the cloud provider or operators of the platform. It is a web application, so the code that performs encryption is itself delivered by the server.

## Decision
All sensitive room content is encrypted **in the browser** with WebCrypto before it leaves the device: file contents, filenames and MIME types (in an encrypted manifest), note titles and bodies, and secret payloads. The server stores ciphertext, wrapped keys and the metadata needed for authentication, authorization, policy enforcement, expiry and audit. The server never receives the keys needed to decrypt room content (INV-01). The project describes this as **client-side encrypted**.

## Alternatives Considered
- **Server-side encryption with keys held by the application:** simpler, and enables search and previews, but the server and anyone who compromises it can decrypt everything.
- **Server-side encryption with a cloud key-management service:** better key custody, but the application can still request decryption at will.
- **Provider encryption at rest only:** protects disks and snapshots, not access through valid credentials.
- **Native or desktop clients:** stronger code integrity (signed binaries), but outside the scope and timeline and not a web platform.
- **Browser extension for code delivery:** could pin code, but adds a distribution channel and store review; out of scope.

## Consequences
- No server-side search, preview, content indexing or malware scanning of content (L-11).
- Key management moves into the browser: vault, envelopes, rotation driven by clients.
- A lost Vault Passphrase loses the personal key; rooms recover through re-sharing (L-17).
- Large files are limited by browser memory (CP-19).

## Security Implications
- Addresses T-01, T-02 and T-18 for content confidentiality; tampering is detected by authenticated encryption (T-07).
- Does **not** protect against a compromised client (L-01, T-23) or malicious code served after server compromise (L-02, T-24). These are documented, not hidden.
- Metadata remains visible (L-05).
- Proven by the canary-scan tests and demonstrated in the report with database rows and bucket objects that contain only ciphertext.

## Status
Accepted. Revisit only if a requirement needs server-side processing of plaintext, which would require a new ADR and threat-model update.
