import { PROFILE_ACCESS_REQUIREMENTS, SECURITY_PROFILES } from '@ciphermesh/shared';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

// security-policy-profiles.md is the single source of truth for profile values. Room creation
// (SS-04, Phase 5) applies PC-01 and PC-02 to the creator, from constants in packages/shared;
// this test compares them with the table so the two cannot drift apart before the versioned
// policy catalogue (CM-T046) takes over.
const PROFILES_DOC = readFileSync(new URL('../../docs/security/security-policy-profiles.md', import.meta.url), 'utf8');

function controlRow(id: string): string[] {
  const line = PROFILES_DOC.split('\n').find((l) => l.startsWith(`| ${id} |`));
  if (line === undefined) throw new Error(`${id} is missing from security-policy-profiles.md`);
  return line
    .split('|')
    .slice(1, -1)
    .map((cell) => cell.trim());
}

describe('profile access requirements used by room creation', () => {
  it('lists the three profiles of the document', () => {
    expect([...SECURITY_PROFILES]).toEqual(['STANDARD', 'CONFIDENTIAL', 'RESTRICTED']);
  });

  it('match PC-01, an MFA-verified session', () => {
    const [, , ...cells] = controlRow('PC-01');
    SECURITY_PROFILES.forEach((profile, column) => {
      expect(PROFILE_ACCESS_REQUIREMENTS[profile].mfaVerifiedSession, profile).toBe(cells[column] === 'Yes');
      expect(['Yes', 'No']).toContain(cells[column]);
    });
  });

  it('match PC-02, the maximum time since the last password authentication', () => {
    const [, , ...cells] = controlRow('PC-02');
    SECURITY_PROFILES.forEach((profile, column) => {
      const hours = /^(\d+) hours?$/.exec(cells[column] ?? '')?.[1];
      expect(hours, `${profile}: "${String(cells[column])}"`).toBeDefined();
      expect(PROFILE_ACCESS_REQUIREMENTS[profile].maxAuthenticationAgeMs).toBe(Number(hours) * 60 * 60_000);
    });
  });

  it('are frozen', () => {
    expect(Object.isFrozen(PROFILE_ACCESS_REQUIREMENTS)).toBe(true);
    expect(Object.isFrozen(PROFILE_ACCESS_REQUIREMENTS.RESTRICTED)).toBe(true);
  });
});
