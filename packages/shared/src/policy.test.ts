import { describe, expect, it } from 'vitest';
import {
  auditLevelIncludes,
  clampedExpiry,
  currentPolicy,
  decideProfileChange,
  decideRoomAccess,
  decideSensitiveOperation,
  isSecurityProfile,
  profileChangeDirection,
  resolveRoomPolicy,
  SECURITY_PROFILES,
  stepUpIsRecent,
  type PolicySessionFacts,
} from './policy';

// Unit tests of the pure policy decisions (CM-T047, CM-T048). The values themselves are compared
// with the profile table by tests/security/policy-catalogue.test.ts; the API integration matrix is
// tests/policy. These tests fix the boundaries: exactly at a window is allowed, one millisecond
// past it is not, and a timestamp in the future never counts.
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const NOW = new Date('2026-10-12T12:00:00.000Z');
const ago = (ms: number): Date => new Date(NOW.getTime() - ms);

const STANDARD = currentPolicy('STANDARD');
const CONFIDENTIAL = currentPolicy('CONFIDENTIAL');
const RESTRICTED = currentPolicy('RESTRICTED');

const session = (overrides: Partial<PolicySessionFacts> = {}): PolicySessionFacts => ({
  authenticatedAt: ago(5 * MINUTE),
  mfaVerifiedAt: ago(5 * MINUTE),
  stepUpAt: null,
  ...overrides,
});

describe('decideRoomAccess (PC-01, PC-02)', () => {
  it('refuses an unsupported policy before anything else', () => {
    expect(decideRoomAccess(undefined, session(), NOW)).toEqual({ allowed: false, reason: 'POLICY_UNSUPPORTED' });
  });

  it('requires an MFA-verified session in CONFIDENTIAL and RESTRICTED only', () => {
    const noMfa = session({ mfaVerifiedAt: null });
    expect(decideRoomAccess(STANDARD, noMfa, NOW)).toEqual({ allowed: true });
    expect(decideRoomAccess(CONFIDENTIAL, noMfa, NOW)).toEqual({ allowed: false, reason: 'PROFILE_PC_01' });
    expect(decideRoomAccess(RESTRICTED, noMfa, NOW)).toEqual({ allowed: false, reason: 'PROFILE_PC_01' });
    expect(decideRoomAccess(RESTRICTED, session(), NOW)).toEqual({ allowed: true });
  });

  it.each([
    ['STANDARD', 12 * HOUR],
    ['CONFIDENTIAL', 4 * HOUR],
    ['RESTRICTED', 1 * HOUR],
  ] as const)('%s allows a password sign-in exactly %i ms old and refuses one older', (profile, maxAge) => {
    const policy = currentPolicy(profile);
    expect(decideRoomAccess(policy, session({ authenticatedAt: ago(maxAge) }), NOW)).toEqual({ allowed: true });
    expect(decideRoomAccess(policy, session({ authenticatedAt: ago(maxAge + 1) }), NOW)).toEqual({
      allowed: false,
      reason: 'PROFILE_PC_02',
    });
  });

  it('checks MFA before the sign-in age', () => {
    const both = session({ mfaVerifiedAt: null, authenticatedAt: ago(2 * HOUR) });
    expect(decideRoomAccess(RESTRICTED, both, NOW)).toEqual({ allowed: false, reason: 'PROFILE_PC_01' });
  });

  it('refuses an unparseable sign-in time (fail closed)', () => {
    expect(decideRoomAccess(STANDARD, session({ authenticatedAt: new Date(Number.NaN) }), NOW)).toEqual({
      allowed: false,
      reason: 'PROFILE_PC_02',
    });
  });
});

describe('stepUpIsRecent and decideSensitiveOperation (PC-03)', () => {
  it('accepts a step-up at the window boundary and refuses missing, older and future ones', () => {
    expect(stepUpIsRecent(ago(15 * MINUTE), 15 * MINUTE, NOW)).toBe(true);
    expect(stepUpIsRecent(ago(15 * MINUTE + 1), 15 * MINUTE, NOW)).toBe(false);
    expect(stepUpIsRecent(null, 15 * MINUTE, NOW)).toBe(false);
    expect(stepUpIsRecent(new Date(NOW.getTime() + 1), 15 * MINUTE, NOW)).toBe(false);
    expect(stepUpIsRecent(NOW, 15 * MINUTE, NOW)).toBe(true);
  });

  it('needs a step-up only in RESTRICTED', () => {
    expect(decideSensitiveOperation(STANDARD, session(), NOW)).toEqual({ allowed: true });
    expect(decideSensitiveOperation(CONFIDENTIAL, session(), NOW)).toEqual({ allowed: true });
    expect(decideSensitiveOperation(RESTRICTED, session(), NOW)).toEqual({ allowed: false, reason: 'PROFILE_PC_03' });
    expect(decideSensitiveOperation(RESTRICTED, session({ stepUpAt: ago(15 * MINUTE + 1) }), NOW)).toEqual({
      allowed: false,
      reason: 'PROFILE_PC_03',
    });
    expect(decideSensitiveOperation(RESTRICTED, session({ stepUpAt: ago(MINUTE) }), NOW)).toEqual({ allowed: true });
    expect(decideSensitiveOperation(undefined, session(), NOW)).toEqual({
      allowed: false,
      reason: 'POLICY_UNSUPPORTED',
    });
  });
});

describe('profile changes (CM-T048)', () => {
  it('orders the profiles by strictness', () => {
    expect(profileChangeDirection(STANDARD, RESTRICTED)).toBe('UPGRADE');
    expect(profileChangeDirection(CONFIDENTIAL, RESTRICTED)).toBe('UPGRADE');
    expect(profileChangeDirection(RESTRICTED, STANDARD)).toBe('DOWNGRADE');
    expect(profileChangeDirection(CONFIDENTIAL, STANDARD)).toBe('DOWNGRADE');
    expect(profileChangeDirection(CONFIDENTIAL, CONFIDENTIAL)).toBe('UNCHANGED');
  });

  it('an upgrade needs the new profile access requirements', () => {
    expect(decideProfileChange(STANDARD, CONFIDENTIAL, session({ mfaVerifiedAt: null }), NOW)).toEqual({
      allowed: false,
      reason: 'PROFILE_PC_01',
    });
    expect(decideProfileChange(STANDARD, CONFIDENTIAL, session({ authenticatedAt: ago(5 * HOUR) }), NOW)).toEqual({
      allowed: false,
      reason: 'PROFILE_PC_02',
    });
    expect(decideProfileChange(STANDARD, CONFIDENTIAL, session(), NOW)).toEqual({ allowed: true });
  });

  it('an upgrade to RESTRICTED also needs its PC-03 step-up (D-10-03)', () => {
    expect(decideProfileChange(STANDARD, RESTRICTED, session(), NOW)).toEqual({
      allowed: false,
      reason: 'PROFILE_PC_03',
    });
    expect(decideProfileChange(CONFIDENTIAL, RESTRICTED, session({ stepUpAt: ago(14 * MINUTE) }), NOW)).toEqual({
      allowed: true,
    });
  });

  it('a downgrade needs a step-up within 5 minutes in every profile, and nothing else', () => {
    for (const [from, to] of [
      [RESTRICTED, STANDARD],
      [RESTRICTED, CONFIDENTIAL],
      [CONFIDENTIAL, STANDARD],
    ] as const) {
      expect(decideProfileChange(from, to, session(), NOW)).toEqual({
        allowed: false,
        reason: 'PROFILE_DOWNGRADE_STEP_UP',
      });
      expect(decideProfileChange(from, to, session({ stepUpAt: ago(5 * MINUTE + 1) }), NOW)).toEqual({
        allowed: false,
        reason: 'PROFILE_DOWNGRADE_STEP_UP',
      });
      expect(decideProfileChange(from, to, session({ stepUpAt: ago(5 * MINUTE) }), NOW)).toEqual({ allowed: true });
    }
  });

  it('an unchanged profile adds no requirement', () => {
    expect(decideProfileChange(RESTRICTED, RESTRICTED, session(), NOW)).toEqual({ allowed: true });
  });
});

describe('clampedExpiry', () => {
  const max = 30 * 24 * HOUR;
  it('shortens a later expiry and fills a missing one, never extends', () => {
    const cap = new Date(NOW.getTime() + max);
    expect(clampedExpiry(null, NOW, max)).toEqual(cap);
    expect(clampedExpiry(new Date(cap.getTime() + 1), NOW, max)).toEqual(cap);
    const earlier = new Date(cap.getTime() - 1);
    expect(clampedExpiry(earlier, NOW, max)).toBe(earlier);
    expect(clampedExpiry(cap, NOW, max)).toBe(cap);
  });

  it('leaves the expiry alone without a maximum', () => {
    expect(clampedExpiry(null, NOW, null)).toBeNull();
    const later = new Date(NOW.getTime() + 400 * 24 * HOUR);
    expect(clampedExpiry(later, NOW, null)).toBe(later);
  });
});

describe('catalogue helpers', () => {
  it('orders audit levels', () => {
    expect(auditLevelIncludes('BASELINE', 'EXTENDED')).toBe(false);
    expect(auditLevelIncludes('EXTENDED', 'EXTENDED')).toBe(true);
    expect(auditLevelIncludes('FULL', 'EXTENDED')).toBe(true);
    expect(auditLevelIncludes('EXTENDED', 'FULL')).toBe(false);
    expect(auditLevelIncludes('FULL', 'BASELINE')).toBe(true);
  });

  it('recognises only the three profiles', () => {
    for (const profile of SECURITY_PROFILES) expect(isSecurityProfile(profile)).toBe(true);
    for (const value of ['restricted', 'SECRET', '', null, 3, 'toString']) expect(isSecurityProfile(value)).toBe(false);
  });

  it('resolves the stored pair exactly', () => {
    expect(resolveRoomPolicy('RESTRICTED', 1)).toBe(RESTRICTED);
    expect(resolveRoomPolicy('RESTRICTED', 2)).toBeUndefined();
  });
});
