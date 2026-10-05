# Test vectors

Published test data used by the known-answer tests of `packages/crypto`. Every key in these files is public test material from the cited source and belongs to no system. Nothing here is a CipherMesh secret.

| File | Content | Source | Licence | SHA-256 of the source file |
|---|---|---|---|---|
| `rsa-oaep-3072-sha256.json` | RSA-OAEP-3072, SHA-256 and MGF1-SHA-256: Wycheproof test group 1 (all 37 tests, 8 with labels), the group's published test key, and one 32-byte vector encrypted by OpenSSL 3.5.6 (`pkeyutl -encrypt`, OAEP with SHA-256, label = the canonical `cm.vault.pair-check` context) with the same key | [C2SP/wycheproof `rsa_oaep_3072_sha256_mgf1sha256_test.json`](https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/rsa_oaep_3072_sha256_mgf1sha256_test.json) | Apache-2.0 (Project Wycheproof) | `c8122302f522bfd539650c71c4aa966bd1f89acb50c6f4c190030fdb9b2684a4` |
| `ecdsa-p256-sha256-p1363.json` | ECDSA P-256 with SHA-256 and IEEE P1363 signatures: Wycheproof test group 1 (all 114 tests) and its public key | [C2SP/wycheproof `ecdsa_secp256r1_sha256_p1363_test.json`](https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json) | Apache-2.0 (Project Wycheproof) | `c60de693930e386c3a5472d08081623ef8504decc54b38ac01ec6b2a2575c986` |

Each JSON file repeats its source, source checksum and licence. The files themselves (as committed) have these SHA-256 values:

```
c8f60a3d1e1c849cba3edd964317e4a82086d7f0957322b2835d816c0eff07ff  rsa-oaep-3072-sha256.json
253a08851a4e457e504868727bc7c51cb8c7e8de5cfaa08a03a44fa3c8cc3ba5  ecdsa-p256-sha256-p1363.json
```

Vectors that are short enough live in the test files themselves, with their source named next to them: SHA-256 (FIPS 180-2 examples), HKDF-SHA-256 (RFC 5869 appendix A, cases 1 to 3), AES-256-GCM (GCM specification test cases 13 to 16), ECDSA (RFC 6979 appendix A.2.5), RFC 8785 (the section 3.2.3 sorting example, the section 3.2.4 byte dump and the safe-integer values of appendix B) and Argon2id (RFC 9106 section 5.3).

To update a file, download the source, check its SHA-256 against the value above (or record the new one in the same pull request), convert it with the same field names, and keep every test case: a vector set may never be shortened to make a test pass.
