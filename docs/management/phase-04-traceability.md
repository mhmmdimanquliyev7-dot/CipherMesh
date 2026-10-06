# Phase 4 Traceability

Status: Phase 4 implemented on 2026-10-05, approved by the project owner and merged into `main` through pull request #10 (merge commit `9e13259`). Covers CM-T086 and CM-T023 to CM-T028 in [jira-backlog.md](jira-backlog.md) (checked against the current backlog before the work started). No item is DONE: DONE requires SECURITY REVIEW and TESTING in Jira and the full Definition of Done (CLAUDE.md section 14), including CI on the pull request.

Branch: `feature/CM-T023-cryptographic-vault`, created from the updated `main` (`f86a2ce`, which contains Phases 1 to 3 through pull requests #1, #7, #8 and #9). Pull request #10; CI run 37347479619 passed every job (EV-04-13).

Order of work: CM-T086 first. ADR-015 was written and accepted by the project owner on 2026-10-05 before any identity or vault code existed. Specifications: [../crypto/vault.md](../crypto/vault.md), [../crypto/cryptographic-architecture.md](../crypto/cryptographic-architecture.md) section 5, [ADR-010](../architecture/adr/ADR-010-browser-argon2id.md), [ADR-015](../architecture/adr/ADR-015-identity-signing-keys.md).

## 1. Work items

Each row reads: requirement, then implementation, then test, then evidence.

| Item | Requirement (acceptance criterion) | Implementation | Tests | Evidence | Result |
|---|---|---|---|---|---|
| CM-T086 OCD-12 | An ADR with the options, the chosen design, its limits and its effect on the vault, fingerprints, envelopes and rekey finalize | ADR-015 (ten alternatives, including Ed25519, RSA-PSS, HPKE, MLS and key transparency) | Browser probe of the candidate primitives in three engines | EV-04-06 | Met; accepted 2026-10-05 |
| | Parameter register, data model, data flows and threat model (T-36, L-23) updated | CP-17, CP-18, CP-26, CP-27, CD-11, CD-23 to CD-27; data-model 4.5 and 8; DF-03, DF-04, DF-04a, DF-04b; T-36, T-40, L-23 | | | Met |
| | CM-T025 and later items updated to match | CM-T023, CM-T025 to CM-T028, CM-T033, CM-T034, CM-T036, CM-T050, CM-T053 (markdown and CSV) | | | Met |
| CM-T023 `packages/crypto` | Known-answer tests for AES-GCM, HKDF, SHA-256, RSA-OAEP and RFC 8785 (and ECDSA, ADR-015) | `aead.ts`, `hkdf.ts`, `hash.ts`, `rsa-oaep.ts`, `signing.ts`, `canonical.ts`; vectors from FIPS 180-2, RFC 5869, the GCM specification, Wycheproof (37 RSA-OAEP, 114 ECDSA cases), RFC 6979, RFC 8785 | `primitives`, `rsa-oaep`, `signing`, `canonical` suites | EV-04-07 | Met |
| | Tamper tests for every decrypt function; no production function accepts an IV | IVs generated inside `aead.ts`; the test-only seam `internal/raw.ts` is not exported | `primitives`, `vault`, `boundary`; NC-04-01, NC-04-02 | EV-04-07, EV-04-09 | Met |
| | Different contexts produce different bytes; decryption under a wrong context fails | `contexts.ts`: fixed field sets, per-field validation, branded result type | `contexts`, `primitives` | EV-04-07 | Met |
| | Runs in browsers and Node.js; coverage at least 90% | Same code in the web client (three engines) and in Node.js tests; `pnpm test:coverage:crypto` in CI | Coverage 99.5% statements, 91.8% branches, 100% functions | EV-04-07, EV-04-10 | Met. The known-answer suites run in Node.js; in browsers the package is exercised by the vault E2E tests and `pnpm bench:vault` |
| CM-T024 Browser Argon2id | Comparison of candidates recorded; RFC 9106 vectors pass in CI | LIB-03 `argon2id` 1.0.1; comparison with `hash-wasm`, `@noble/hashes`, `argon2-browser` (crypto-decisions LIB-03 and section 8) | `argon2id`, `argon2id-no-simd` (both WebAssembly builds), OpenSSL differential | EV-04-03, EV-04-07 | Met |
| | Final parameters recorded; ADR-010 accepted | CP-04: target m = 65536 KiB, t = 3, p = 1 (unchanged), ceiling added | `pnpm bench:vault` | EV-04-03 | Met. **Deviation:** no phone was measured (L-37) |
| | CSP relaxed only by `'wasm-unsafe-eval'`; failure to load WASM fails closed | `csp-lib.mjs`; `kdf/argon2id.ts` fails with CRYPTO_UNAVAILABLE | `csp-lib.test.ts`, `web-shell.spec.ts`, `fail-closed.test.ts`, vault E2E without violations | EV-04-10 | Met |
| | Web Worker integration | Fresh module worker per derivation, one derivation per page, 120 s timeout (CD-27) | `kdf-worker.test.ts`, `fail-closed.test.ts`, E2E, benchmark (main-thread gaps under 20 ms) | EV-04-03 | Met |
| CM-T025 Vault setup | A Playwright test inspects network traffic and finds neither the passphrase nor any PKCS#8 private key | Browser-only key generation and wrapping; strict request schema | `vault.spec.ts`; NC-04-13 | EV-04-01, EV-04-09 | Met |
| | Parameters below the floor are rejected by the client and the API | `params.ts` floor and ceiling; validation schema; database CHECK | `vault.test.ts`, `argon2id.test.ts`, `tests/vault/setup.test.ts`; NC-04-08 | EV-04-08 | Met |
| | The API refuses an identity whose binding signature or fingerprint does not verify (ADR-015) | `vault/service.ts` with `@ciphermesh/crypto/identity` | `setup.test.ts` | EV-04-08 | Met |
| | Passphrase policy with feedback; `VAULT_CREATED` | CP-06 checks in the browser with explanations per problem; security event | `passphrase.test.ts`, `setup.test.ts` | EV-04-02 | Met with policy feedback; no strength meter (LIB-07 not adopted). The event goes to the log until Phase 12 (L-33) |
| CM-T026 Unlock and auto-lock | No key material or plaintext in localStorage, sessionStorage, IndexedDB or cookies | Memory-only `VaultController` | `vault.spec.ts` (also the Cache API); NC-04-12 | EV-04-04 | Met |
| | The private key cannot be exported | Non-extractable unwrapping of both keys | `vault.test.ts`; NC-04-09 | EV-04-07 | Met |
| | Auto-lock clears keys and decrypted views | 15 minutes without trusted input; Lock now; sign-out; `pagehide`; session end; keys exist only while the view is unlocked | `vault.spec.ts` (controlled clock, sign-out and session-end tests, failed background refresh); NC-04-14, NC-04-17 | EV-04-10 | Met. No decrypted content exists yet beyond the vault itself |
| | Generic error for a wrong passphrase; pair checks | One `VAULT_UNLOCK_FAILED`; RSA and ECDSA pair checks | `vault.test.ts`, `vault.spec.ts` | EV-04-10 | Met |
| CM-T027 Directory and fingerprints | Lookup returns no other fields and is rate-limited | `POST /api/directory/lookup`, projection, 20 per 10 minutes, own vault required, one 404 | `reset-and-directory.test.ts`; NC-04-03 | EV-04-08 | Met |
| | Users can view their own fingerprint for out-of-band comparison | Vault page, 16 groups of 4, computed by the browser | `vault.spec.ts` (independent recomputation) | EV-04-05 | Met |
| | Audit events and notices for key changes | `VAULT_RESET` event; new fingerprint after a reset | `reset-and-directory.test.ts` | | Partly: notices to room administrators need rooms (Phase 6) |
| CM-T028 Passphrase change | Same key pair after the change; the old record is replaced | Signed re-wrap with compare-and-swap (ADR-015 section 3) | `vault.test.ts`, `rewrap.test.ts` | EV-04-08, EV-04-10 | Met |
| | The old passphrase no longer unlocks the stored record | New salt and wrapping keys | `rewrap.test.ts`, `vault.spec.ts` | EV-04-10 | Met |
| | An unsigned, wrongly signed, replayed or stale re-wrap is refused | Signature verification under the stored signing key; previous-salt check | `rewrap.test.ts`; NC-04-07 | EV-04-06, EV-04-09 | Met |
| | Re-wrap when stored parameters are below the target | Offered after unlock (needs a step-up) | `vault.test.ts` (upgrade), `rewrap.test.ts` | | **Changed:** offered, not automatic (ADR-010) |

## 2. Decisions taken in this phase

| Decision | Record |
|---|---|
| Per-user ECDSA P-256 signing key in every identity; signed room statements from Phase 6 (OCD-12) | ADR-015, CD-23, CD-24, CP-26 |
| Fingerprint over both public keys | CP-17 revised |
| Vault format version 1: one wrapping key per private key, AAD with purpose and fingerprint, pair checks | CP-27, CD-25, [../crypto/vault.md](../crypto/vault.md) |
| Signed, compare-and-swap re-wraps; reset creates a new identity and ends other sessions | CD-26, key-lifecycle section 3 |
| LIB-03 `argon2id` 1.0.1; CP-04 target kept, ceiling added; ADR-010 accepted | LIB-03, CP-04, crypto-decisions section 8 |
| Worker design: fresh worker per derivation, one at a time, timeout; WebAssembly embedded | CD-27 |
| RFC 8785 in the repository for the CP-15 subset (OCD-04) | LIB-05 |
| The server's TOTP context uses the shared builder; old ciphertexts still open | CD-22 |
| Parameter upgrade offered after unlock instead of automatic | ADR-010 Phase 4 outcome |
| Coverage gate for `packages/crypto` in CI with `@vitest/coverage-v8` (development dependency) | engineering-baseline.md, security-testing-plan.md section 3.3 |
| CSP `form-action 'none'` and hydration-gated buttons (SF-04-01) | engineering-baseline.md section 6, authentication-security.md section 16 |

## 3. Security checkpoint (roadmap Phase 4)

| Check | Result |
|---|---|
| Known-answer tests pass | Yes (EV-04-07) |
| No public function accepts an IV | Yes: `encrypt` takes key, plaintext and context only; the boundary test fixes the exports (EV-04-07) |
| Final CP-04 parameters recorded and ADR-010 accepted | Yes; laptop measurements only (L-37) |
| Network inspection shows no passphrase or private key leaving the browser | Yes, in three engines, with a negative control (EV-04-01, EV-04-10) |
| No keys in browser storage | Yes, in three engines, including the Cache API (EV-04-04) |
| OCD-12 decided before the identity format | Yes, ADR-015 accepted before implementation (EV-04-06) |
| Negative controls | 27 of 27 defects caught, sources restored byte for byte (EV-04-09) |

## 4. Review findings recorded during the phase

- **Security finding SF-04-01 (High, fixed in this phase; introduced in Phase 3).** `/login` and `/register` are prerendered with their forms, and no form declared a method. If the user submitted before the client bundle had run (slow network, blocked or failed script), the browser performed a native GET that put every field, including the account password, into the URL, from where it reaches server access logs and the browser history (CLAUDE.md section 8, INV-10). Found while capturing evidence: a scripted click before hydration produced `GET /login?email=…&password=…`. Fix: the CSP sets `form-action 'none'`, so browsers refuse any native submission (the client sends every form with `fetch()`), and the shared buttons stay disabled until the page has hydrated. Regression test: `tests/e2e/web-shell.spec.ts` "a form submitted before the client runs sends no typed value anywhere" (blocks every client script, checks the disabled button, forces a submission and requires a `form-action` violation and no request or URL carrying the typed value). It failed before the fix and passes after it in all three engines. Negative controls NC-04-15 (CSP back to `'self'`) and NC-04-16 (buttons enabled before hydration). The vault forms render only after client state loads, so the Vault Passphrase was never exposed this way. To be recorded in Jira with the `security-finding` label.
- **Review finding R-04-01 (Medium, Phase 4 code, fixed before merge).** A background refresh of the vault state that failed (network error, rate limit) replaced the unlocked view by an error view while the private keys stayed in memory. In that state the inactivity auto-lock did not run (CP-22), and the next successful refresh locked the vault with the false message that a different identity had been found on the server. Fix in `apps/web/src/vault/controller.ts`: every view other than unlocked drops the keys, a transient failure leaves an unlocked vault unchanged, and a locked vault keeps its lock reason across refreshes. Regression test: `tests/e2e/vault.spec.ts` "a failed background refresh keeps the vault under the auto-lock and reports no identity change"; it failed before the fix (the page showed the false message) and passes after it in three engines. Negative control NC-04-17.
- **Library input checks (LIB-03).** The `argon2id` library compares the password and salt arrays themselves, not their lengths, with its limits, so those checks never fire for multi-byte input. CipherMesh validates every length before calling it, and a test pins the library behaviour.
- **Phantom dependency.** `apps/web` imported `@ciphermesh/crypto` without declaring it and resolved it only through the root development dependency; the dependency is now declared.
- **Unused worker copy.** Turbopack emits the raw worker source next to the bundled worker; it is never loaded (engineering-baseline section 6.1).
- **Test timing.** Two tests failed only on time while the whole suite ran in parallel: the 10,000-IV test and the first ESLint guard (which builds the type-aware program). Both now have their own time budget or a warm-up; no assertion changed.
- **Known intermittent failure, fixed.** `tests/database/deletion.test.ts` raced with `tests/database/retention.test.ts` in the shared test database (recorded in the Phase 3 handoff) and failed in two of three full local runs in this phase. Its session now ended inside the 30-day retention window, so the retention suite can no longer delete it first; the privilege assertions are unchanged. The fix is a separate commit in this pull request.

## 5. Pending outside the repository

- Jira: status changes for CM-T086 and CM-T023 to CM-T028 through SECURITY REVIEW and TESTING; the benchmark table and the issue history as roadmap evidence.
- GitGuardian incident 37892113 on pull request #10 is a reviewed false positive (the first 12 bytes of a test ciphertext in EV-04-02, removed in `dbe943d`); the project owner marks it in the GitGuardian dashboard.
- A phone benchmark (L-37).
