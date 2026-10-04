import { describe, expect, it } from 'vitest';
import { ErrorCode, isErrorCode, isUuidV4 } from './index';

describe('isUuidV4', () => {
  it('accepts a canonical version 4 UUID', () => {
    expect(isUuidV4('0b2f6c1e-8d3a-4f5b-9c7d-2e1f0a9b8c7d')).toBe(true);
  });

  it.each([
    ['uppercase', '0B2F6C1E-8D3A-4F5B-9C7D-2E1F0A9B8C7D'],
    ['version 1', '0b2f6c1e-8d3a-1f5b-9c7d-2e1f0a9b8c7d'],
    ['wrong variant', '0b2f6c1e-8d3a-4f5b-7c7d-2e1f0a9b8c7d'],
    ['surrounding text', ' 0b2f6c1e-8d3a-4f5b-9c7d-2e1f0a9b8c7d'],
    ['not a string', 42],
  ])('rejects %s', (_label, value) => {
    expect(isUuidV4(value)).toBe(false);
  });
});

describe('isErrorCode', () => {
  it('accepts every declared code and nothing else', () => {
    for (const code of Object.values(ErrorCode)) expect(isErrorCode(code)).toBe(true);
    expect(isErrorCode('not_found')).toBe(false);
    expect(isErrorCode(undefined)).toBe(false);
  });
});
