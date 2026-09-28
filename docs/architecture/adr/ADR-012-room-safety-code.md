# ADR-012: Room Safety Code

- Status: Accepted (word list selected in Phase 6, LIB-08)
- Date: 2026-09-28
- Related: [crypto-decisions.md](../../crypto/crypto-decisions.md) CP-24, CD-13, CD-18; [cryptographic-architecture.md](../../crypto/cryptographic-architecture.md) section 7; [security-ui.md](../security-ui.md); T-25, T-29, T-36; L-22; CM-T085

## Context

Each room key version has a public commitment RKC_v, derived from the room key material with HKDF. The server stores one commitment per version and serves it with the envelopes. A client that decrypts an envelope recomputes the commitment and compares. That detects envelopes which do not match the stored commitment, for example a malicious member or ADMIN who wraps different key material for different members while the server behaves honestly.

The Phase 0 documentation claimed more than that. A server, or an attacker controlling API responses, can show different commitments and matching envelopes to different members. Each member's check then passes against the value it was shown. The server can even create such envelopes itself, because RSA-OAEP encryption needs only the recipient's public key. This is a **split view**: members believe they share one room key while they hold different keys. Detecting it needs a reference that members compare over a channel the server does not control.

## Decision

1. **Derivation (CP-24).** Every member's browser computes the Room Safety Code locally from the room key material it holds:

   ```
   RSC_v = HKDF-SHA-256(
     IKM  = RKM_v                                  (32 bytes, decrypted from the member's envelope)
     salt = 32 zero bytes
     info = JCS({"ctx":"cm.room.safety-code","keyVersion":v,"roomId":"<room uuid>","v":1})
     L    = 32 bytes )
   ```

2. **Display.** The first 66 bits of RSC_v are read as six 11-bit numbers, most significant first. Each number selects a word from a fixed public list of 2048 words (LIB-08). The code is always shown with its key version, for example "Key version 4: orbit velvet canyon / pilot ember sugar" (illustrative words). An accessible numeric form shows the same 66 bits as a 20-digit decimal number in groups of four. It needs no rounding, because 2^66 is smaller than 10^20.
3. **Local only.** The code is computed only after the envelope is decrypted and the commitment check has passed. It is never sent to the server, stored, logged or put in analytics (INV-18).
4. **Comparison.** Members compare the code for the current key version over an independent channel: in person, or by voice or video with someone they recognise. They do not compare through CipherMesh. Nobody posts a code in a shared channel before everyone has read their own.
5. **Optional record.** After comparing, a member may record "compared key version v" (AZ-30). The API stores an audit event containing the key version only. It is the member's statement, not a verification by the system.
6. **Prompts are advisory.** The code is available in every room. CONFIDENTIAL rooms show a reminder, and RESTRICTED rooms prompt after every new key version ([security-ui.md](../security-ui.md)). These prompts are not policy controls, because the system cannot verify that people compared.
7. **Mismatch handling.** Different codes mean the members hold different keys. The UI tells them to stop adding content, alert the OWNER through the independent channel and report the mismatch (`SAFETY_CODE_MISMATCH_REPORTED`). A rekey through the same server does not repair a split view the server created, so the event is handled as a suspected server compromise.

## Properties

| Required property | How it is met |
|---|---|
| Calculated locally | Derived in the browser from the key material that browser decrypted |
| Server cannot dictate the displayed code | A given code follows from the key the client actually holds. To make two members with different keys see the same code, an attacker must find a colliding key (see below) |
| Does not reveal the room key | HKDF is one-way. Only 66 of 256 output bits are shown. The context differs from the wrapping key and the commitment (key separation) |
| Changes when the key or version changes | Key material, room ID and key version are all HKDF inputs |
| Comparable out of band | Six words can be read aloud or shown in person |
| Optional manual check | Nothing in the system depends on it. Prompts are advisory |

## Why 66 bits

- **Attacker without the honest code.** To make two members with different keys see matching codes, the attacker needs a key whose code equals the honest code. Without knowing that code, it can only guess, and each attempt succeeds with probability 2^-66.
- **Attacker who learns one code early.** Suppose the attacker reads one member's code before it fixes another member's key, for example because the code was posted in a readable channel. It must then search for a matching key, which takes about 2^66 HKDF evaluations on average. That is far beyond this project's threat model.
- **Short formats are unsafe.** A short format of 20 to 30 bits, such as the "WORD-NN" example in the project brief, is easy to read but can be matched by brute force in seconds to hours. The example is therefore not used literally.

## Alternatives Considered

- **Commitment only (Phase 0 design):** detects inconsistency only while the server is honest. The Phase 0 claim was too strong and has been corrected.
- **Comparing the full commitment in hex:** equally strong, but 64 hex characters are impractical, and a hex prefix of equal strength is harder to read aloud than words.
- **Codes provided by the server:** the server could show matching codes to everyone, so they prove nothing about the server.
- **Per-user signatures on key versions (OCD-12):** authenticate who created a version. They complement the Safety Code but do not replace it.
- **Key transparency log:** strong, but a large system that is out of scope.
- **Including the member list in the code:** the member list comes from the server and is not authenticated, so it would not reliably reveal hidden recipients. Rejected for the baseline and revisited with OCD-12.

## Consequences

- One new HKDF context and parameter entry, plus a public word-list data file in `packages/crypto`.
- A Safety Code panel, prompts, an optional audit event and tests.
- Many users will not compare codes. The documentation and UI say so plainly.

## Security Implications

- **Detects:** split views (T-29) and version rollback between members, because the version is an input, but only when members actually compare.
- **Does not detect:**
  - a key version that every member received consistently from an attacker (T-36);
  - hidden recipients, or key substitution where the attacker re-wraps the real key (T-25), which fingerprints address;
  - fake codes shown by malicious JavaScript (L-02);
  - anything at all when members never compare (L-22).
- The UI never presents the code as automatic protection.
- **Tests:**
  - known-answer vectors for the derivation and the word mapping;
  - two test browsers given different keys by a test harness show different codes;
  - a network capture shows the code never leaves the browser.

## Status

Accepted. Implementation in Phase 6 (CM-T085). Review when OCD-12 is decided.
