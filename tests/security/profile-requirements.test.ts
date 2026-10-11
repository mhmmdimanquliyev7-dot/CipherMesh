import { FILES } from '@ciphermesh/crypto/params';
import {
  FILE_LIMITS,
  FILE_QUOTAS,
  FILE_RULES,
  FILE_TAG_BYTES,
  INVITATION_RULES,
  PROFILE_ACCESS_REQUIREMENTS,
  SECURITY_PROFILES,
} from '@ciphermesh/shared';
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

// Phase 6 (CM-T034, CM-T035): the invitation rules the API enforces, against the same table.
describe('invitation rules used by the invitation routes', () => {
  const cellsOf = (id: string): string[] => controlRow(id).slice(2);

  it('match PC-04, OWNER approval of invitations created by an ADMIN', () => {
    SECURITY_PROFILES.forEach((profile, column) => {
      expect(['Yes', 'No']).toContain(cellsOf('PC-04')[column]);
      expect(INVITATION_RULES[profile].adminInvitationNeedsApproval, profile).toBe(cellsOf('PC-04')[column] === 'Yes');
    });
  });

  it('match PC-05, the fingerprint confirmation', () => {
    const expected: Record<string, string> = {
      Optional: 'optional',
      'Optional, prompted': 'prompted',
      Required: 'required',
    };
    SECURITY_PROFILES.forEach((profile, column) => {
      expect(INVITATION_RULES[profile].fingerprintConfirmation, profile).toBe(expected[cellsOf('PC-05')[column] ?? '']);
    });
  });

  it('match PC-06, the invitation validity set by the server', () => {
    SECURITY_PROFILES.forEach((profile, column) => {
      const match = /^(\d+) (days|hours)$/.exec(cellsOf('PC-06')[column] ?? '');
      expect(match, profile).not.toBeNull();
      const hours = Number(match?.[1]) * (match?.[2] === 'days' ? 24 : 1);
      expect(INVITATION_RULES[profile].validityMs, profile).toBe(hours * 60 * 60_000);
    });
  });

  it('match PC-07, the key history given to new members', () => {
    const expected: Record<string, string> = {
      'All retained versions': 'all-retained',
      'Current version only': 'current-only',
    };
    SECURITY_PROFILES.forEach((profile, column) => {
      expect(INVITATION_RULES[profile].keyHistory, profile).toBe(expected[cellsOf('PC-07')[column] ?? '']);
    });
  });

  it('are frozen', () => {
    expect(Object.isFrozen(INVITATION_RULES)).toBe(true);
    expect(Object.isFrozen(INVITATION_RULES.RESTRICTED)).toBe(true);
  });
});

// Phase 7 (CM-T038 to CM-T041): the file rules the API enforces, against the same table, and the
// file limits against the parameter register (CP-19, CP-20) and the crypto package.
describe('file rules used by the file routes', () => {
  const cellsOf = (id: string): string[] => controlRow(id).slice(2);
  const DAY = 24 * 60 * 60_000;

  it('match PC-08, the expiry of files', () => {
    SECURITY_PROFILES.forEach((profile, column) => {
      const cell = cellsOf('PC-08')[column] ?? '';
      const rules = FILE_RULES[profile];
      if (cell === 'Optional, no maximum') {
        expect([rules.expiryRequired, rules.maxExpiryMs, rules.defaultExpiryMs], profile).toEqual([false, null, null]);
        return;
      }
      const match = /^Required, maximum (\d+) days, default (\d+) days$/.exec(cell);
      expect(match, `${profile}: "${cell}"`).not.toBeNull();
      expect(rules.expiryRequired, profile).toBe(true);
      expect(rules.maxExpiryMs, profile).toBe(Number(match?.[1]) * DAY);
      expect(rules.defaultExpiryMs, profile).toBe(Number(match?.[2]) * DAY);
    });
  });

  it('match PC-12, whether a VIEWER may obtain file key material and ciphertext', () => {
    SECURITY_PROFILES.forEach((profile, column) => {
      expect(['Yes', 'No']).toContain(cellsOf('PC-12')[column]);
      expect(FILE_RULES[profile].viewerMayDownload, profile).toBe(cellsOf('PC-12')[column] === 'Yes');
    });
  });

  it('match PC-13: download-URL issuance is audited at the EXTENDED and FULL levels', () => {
    SECURITY_PROFILES.forEach((profile, column) => {
      const level = cellsOf('PC-13')[column];
      expect(FILE_RULES[profile].auditDownloadUrls, profile).toBe(level === 'EXTENDED' || level === 'FULL');
    });
  });

  it('match CP-19 and CP-20 of the parameter register and the crypto package', () => {
    const register = readFileSync(new URL('../../docs/crypto/crypto-decisions.md', import.meta.url), 'utf8');
    const row = (id: string): string => register.split('\n').find((l) => l.startsWith(`| ${id} |`)) ?? '';
    expect(row('CP-19')).toContain('50 MiB');
    expect(FILE_LIMITS.maxPlaintextBytes).toBe(50 * 1024 * 1024);
    expect(FILES.maxPlaintextBytes).toBe(FILE_LIMITS.maxPlaintextBytes);
    expect(FILE_LIMITS.maxCiphertextBytes).toBe(FILE_LIMITS.maxPlaintextBytes + FILE_TAG_BYTES);
    expect(row('CP-20')).toContain('Upload (PUT) at most 5 minutes, download (GET) at most 60 seconds');
    expect([FILE_LIMITS.uploadUrlSeconds, FILE_LIMITS.downloadUrlSeconds]).toEqual([300, 60]);
    expect([FILES.maxNameLength, FILES.maxTypeLength]).toEqual([FILE_LIMITS.maxNameLength, FILE_LIMITS.maxTypeLength]);
  });

  it('are frozen', () => {
    for (const value of [FILE_RULES, FILE_RULES.RESTRICTED, FILE_LIMITS, FILE_QUOTAS])
      expect(Object.isFrozen(value)).toBe(true);
  });
});
