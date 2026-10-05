import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import * as contexts from './contexts';
import * as cryptoPackage from './index';
import * as serverSubset from './identity-server';

// The export surface is part of the security design (CM-T023): it must change only together with
// docs/crypto and a reviewed work item. No export may accept an IV, choose an algorithm, take a
// raw AAD or return private-key bytes.

describe('@ciphermesh/crypto export surface', () => {
  it('exports exactly the reviewed browser API', () => {
    expect(Object.keys(cryptoPackage).sort()).toEqual(
      [
        'CryptoError',
        'CryptoErrorCode',
        'PassphraseProblem',
        'SUITE',
        'VAULT_KDF',
        'VAULT_PASSPHRASE_POLICY',
        'VAULT_VERSION',
        'changeVaultPassphrase',
        'checkVaultPassphrase',
        'computeFingerprint',
        'createVault',
        'createWorkerRunner',
        'formatFingerprint',
        'isBelowKdfTarget',
        'isCryptoError',
        'isDerivationRunning',
        'isFingerprint',
        'normalizeVaultPassphrase',
        'publicIdentityFromWire',
        'rewrapToWire',
        'unlockVault',
        'upgradeVaultProtection',
        'vaultRecordFromWire',
        'vaultRecordToWire',
        'verifyPublicIdentity',
      ].sort(),
    );
  });

  it('the server subset has no key generation, KDF or worker code', () => {
    const names = Object.keys(serverSubset);
    expect(names).toContain('verifyPublicIdentity');
    expect(names).toContain('rewrapStatement');
    for (const forbidden of ['createVault', 'unlockVault', 'createWorkerRunner', 'generateIdentity']) {
      expect(names).not.toContain(forbidden);
    }
  });

  it('contexts are reachable only through the builder', () => {
    expect(Object.keys(contexts).sort()).toEqual(['CONTEXT_NAMES', 'contextBytes']);
  });

  it('never exports the known-answer-test seam', () => {
    const exported = [...Object.keys(cryptoPackage), ...Object.keys(serverSubset)];
    for (const seam of [
      'aesGcmEncryptWithIv',
      'aesGcmDecryptWithIv',
      'hkdfSha256Bits',
      'rsaOaepDecryptRaw',
      'ecdsaVerifyRaw',
      'importAesGcmKeyForTest',
      'importRsaOaepPrivateKeyForTest',
    ]) {
      expect(exported).not.toContain(seam);
    }
  });

  it('only the reviewed modules use the low-level seam, and only with the reviewed functions', () => {
    // A fixed-IV encryption is reachable only through aead.ts, which generates the IV itself
    // (INV-02). Test-only helpers are never imported by production code.
    const allowed: Readonly<Record<string, readonly string[]>> = {
      'aead.ts': ['aesGcmDecryptWithIv', 'aesGcmEncryptWithIv'],
      'rsa-oaep.ts': ['rsaOaepDecryptRaw'],
      'signing.ts': ['ecdsaVerifyRaw'],
    };
    const root = join(__dirname);
    const files = readdirSync(root, { recursive: true, encoding: 'utf8' })
      .filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts') && !f.startsWith('internal'))
      .map((f) => f.replaceAll('\\', '/'));
    const seen: Record<string, string[]> = {};
    for (const file of files) {
      const source = readFileSync(join(root, file), 'utf8');
      for (const match of source.matchAll(/import\s*\{([^}]*)\}\s*from\s*'[./]*internal\/raw'/g)) {
        seen[file] = (match[1] ?? '')
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean)
          .sort();
      }
    }
    expect(seen).toEqual(allowed);
  });
});
