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
        'ROOM_KEYS',
        'SUITE',
        'VAULT_KDF',
        'VAULT_PASSPHRASE_POLICY',
        'VAULT_VERSION',
        'changeVaultPassphrase',
        'checkVaultPassphrase',
        'computeFingerprint',
        'computeSafetyCode',
        'createInitialRoomKey',
        'createInvitationKeys',
        'createVault',
        'createWorkerRunner',
        'formatFingerprint',
        'grantProofToWire',
        'invitationKeysToWire',
        'isBelowKdfTarget',
        'isCryptoError',
        'isDerivationRunning',
        'isFingerprint',
        'normalizeVaultPassphrase',
        'openRoomKey',
        'openRoomKeys',
        'publicIdentityFromWire',
        'rewrapToWire',
        'roomCreationKeysToWire',
        'roomKeyBundlesFromWire',
        'signMembershipGrant',
        'sortRecipients',
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
    // Phase 6: the API rebuilds and verifies the signed room statements, but never opens,
    // creates or shares room keys and has no Safety Code (INV-01, INV-18).
    for (const builder of [
      'genesisStatement',
      'keyVersionStatement',
      'membershipGrantStatement',
      'verifyStatementBy',
    ]) {
      expect(names).toContain(builder);
    }
    for (const forbidden of [
      'createVault',
      'unlockVault',
      'createWorkerRunner',
      'generateIdentity',
      'createInitialRoomKey',
      'createInvitationKeys',
      'openRoomKey',
      'computeSafetyCode',
      'signMembershipGrant',
    ]) {
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
      // The Safety Code display mapping is a known-answer seam, not an API: codes come only from
      // computeSafetyCode over an opened key.
      'safetyCodeFromBits',
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
