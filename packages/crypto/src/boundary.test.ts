import { describe, expect, it } from 'vitest';
import * as cryptoPackage from './index';

describe('@ciphermesh/crypto boundary', () => {
  it('exports no cryptographic functions before Phase 4', () => {
    // Guards against premature or ad-hoc cryptography: the export surface must change
    // together with docs/crypto and a reviewed Phase 4 work item.
    expect(Object.keys(cryptoPackage)).toEqual(['CRYPTO_PACKAGE_STATUS']);
    expect(cryptoPackage.CRYPTO_PACKAGE_STATUS).toBe('boundary-only');
  });
});
