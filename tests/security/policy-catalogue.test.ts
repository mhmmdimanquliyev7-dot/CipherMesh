import { FILES, NOTES } from '@ciphermesh/crypto/params';
import {
  AUDIT_LEVELS,
  currentPolicy,
  FILE_LIMITS,
  FILE_QUOTAS,
  FILE_TAG_BYTES,
  NOTE_LIMITS,
  NOTE_LIST_PAGE_SIZE,
  NOTE_TAG_BYTES,
  POLICY_CATALOGUE_VERSION,
  PROFILE_CHANGE_RULES,
  resolveRoomPolicy,
  SECRET_LIMITS,
  SECRET_MAX_LIFETIME_MS,
  SECURITY_PROFILES,
  SENSITIVE_OPERATIONS,
  SUPPORTED_POLICY_VERSIONS,
  type ProfilePolicy,
} from '@ciphermesh/shared';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { SESSION_POLICY } from '../../apps/api/src/auth/sessions';

// CM-T046: the versioned policy catalogue (packages/shared/src/policy.ts) against the table of
// security-policy-profiles.md, the single source of truth for profile values. Every PC row is
// parsed from the document into a fixture and compared with catalogue version 1, so a change on
// either side alone fails here. (Replaces profile-requirements.test.ts of Phases 5 to 9, which
// compared the per-feature constants this catalogue absorbed.)
const PROFILES_DOC = readFileSync(new URL('../../docs/security/security-policy-profiles.md', import.meta.url), 'utf8');
const HOUR = 60 * 60_000;
const DAY = 24 * HOUR;

function controlRow(id: string): string[] {
  const line = PROFILES_DOC.split('\n').find((l) => l.startsWith(`| ${id} |`));
  if (line === undefined) throw new Error(`${id} is missing from security-policy-profiles.md`);
  return line
    .split('|')
    .slice(1, -1)
    .map((cell) => cell.trim());
}
/** The three profile cells of a control row, in the order STANDARD, CONFIDENTIAL, RESTRICTED. */
const cellsOf = (id: string): string[] => controlRow(id).slice(2, 5);

function durationMs(text: string): number {
  const match = /^(\d+) (day|days|hour|hours)$/.exec(text.trim());
  if (match === null) throw new Error(`not a duration: "${text}"`);
  return Number(match[1]) * (match[2]?.startsWith('day') === true ? DAY : HOUR);
}
const yesNo = (cell: string | undefined): boolean => {
  expect(['Yes', 'No']).toContain(cell);
  return cell === 'Yes';
};

const V1: readonly ProfilePolicy[] = SECURITY_PROFILES.map((profile) => {
  const policy = resolveRoomPolicy(profile, 1);
  if (policy === undefined) throw new Error(`catalogue version 1 has no ${profile}`);
  return policy;
});

/** Runs `check` once per profile with that profile's cell of the control and its v1 policy. */
function eachProfile(id: string, check: (cell: string, policy: ProfilePolicy) => void): void {
  const cells = cellsOf(id);
  expect(cells, id).toHaveLength(3);
  V1.forEach((policy, column) => {
    check(cells[column] ?? '', policy);
  });
}

describe('policy catalogue version 1 against the profile table (CM-T046)', () => {
  it('has the three profiles of the document, in strictness order', () => {
    expect([...SECURITY_PROFILES]).toEqual(['STANDARD', 'CONFIDENTIAL', 'RESTRICTED']);
    expect(V1.map((p) => [p.profile, p.version, p.rank])).toEqual([
      ['STANDARD', 1, 0],
      ['CONFIDENTIAL', 1, 1],
      ['RESTRICTED', 1, 2],
    ]);
  });

  it('documents exactly PC-01 to PC-16', () => {
    const ids = PROFILES_DOC.split('\n')
      .map((line) => /^\| (PC-\d\d) \|/.exec(line)?.[1])
      .filter((id): id is string => id !== undefined);
    expect(ids).toEqual(Array.from({ length: 16 }, (_, i) => `PC-${String(i + 1).padStart(2, '0')}`));
  });

  it('PC-01: an MFA-verified session', () => {
    eachProfile('PC-01', (cell, p) => {
      expect(p.access.mfaVerifiedSession, p.profile).toBe(yesNo(cell));
    });
  });

  it('PC-02: the maximum time since the last password authentication', () => {
    eachProfile('PC-02', (cell, p) => {
      expect(p.access.maxAuthenticationAgeMs, p.profile).toBe(durationMs(cell));
    });
  });

  it('PC-03: step-up for sensitive actions, its window and the operations it covers', () => {
    expect(controlRow('PC-03')[1]).toContain('within the last 15 minutes');
    eachProfile('PC-03', (cell, p) => {
      expect(p.sensitiveStepUp.required, p.profile).toBe(yesNo(cell));
      expect(p.sensitiveStepUp.windowMs, p.profile).toBe(15 * 60_000);
    });
    // The operations listed in the control's text, in order.
    const listed = /sensitive actions: (.+)$/.exec(controlRow('PC-03')[1] ?? '')?.[1] ?? '';
    expect(listed.split(', ').map((s) => s.trim())).toEqual([
      'reveal secret',
      'file download URL',
      'invite',
      'approve',
      'remove member',
      'start a rekey',
      'change profile',
      'delete room',
    ]);
    expect([...SENSITIVE_OPERATIONS]).toEqual([
      'SECRET_REVEAL',
      'FILE_DOWNLOAD_URL',
      'INVITE',
      'APPROVE_INVITATION',
      'REMOVE_MEMBER',
      'START_REKEY',
      'CHANGE_PROFILE',
      'DELETE_ROOM',
    ]);
  });

  it('PC-04: OWNER approval of invitations created by an ADMIN', () => {
    eachProfile('PC-04', (cell, p) => {
      expect(p.invitations.adminInvitationNeedsApproval, p.profile).toBe(yesNo(cell));
    });
  });

  it('PC-05: the inviter confirms the invitee key fingerprint', () => {
    const expected: Record<string, string> = {
      Optional: 'optional',
      'Optional, prompted': 'prompted',
      Required: 'required',
    };
    eachProfile('PC-05', (cell, p) => {
      expect(p.invitations.fingerprintConfirmation, p.profile).toBe(expected[cell]);
    });
  });

  it('PC-06: the invitation validity set by the server', () => {
    eachProfile('PC-06', (cell, p) => {
      expect(p.invitations.validityMs, p.profile).toBe(durationMs(cell));
    });
  });

  it('PC-07: the key history given to new members', () => {
    const expected: Record<string, string> = {
      'All retained versions': 'all-retained',
      'Current version only': 'current-only',
    };
    eachProfile('PC-07', (cell, p) => {
      expect(p.invitations.keyHistory, p.profile).toBe(expected[cell]);
    });
  });

  it('PC-08: expiry of files and notes', () => {
    eachProfile('PC-08', (cell, p) => {
      if (cell === 'Optional, no maximum') {
        expect(p.contentExpiry, p.profile).toEqual({ required: false, maxMs: null, defaultMs: null });
        return;
      }
      const match = /^Required, maximum (\d+) days, default (\d+) days$/.exec(cell);
      expect(match, `${p.profile}: "${cell}"`).not.toBeNull();
      expect(p.contentExpiry, p.profile).toEqual({
        required: true,
        maxMs: Number(match?.[1]) * DAY,
        defaultMs: Number(match?.[2]) * DAY,
      });
    });
  });

  it('PC-09: the secret lifetime and its default', () => {
    eachProfile('PC-09', (cell, p) => {
      const match = /^Maximum (.+) \((.+)\)$/.exec(cell);
      expect(match, `${p.profile}: "${cell}"`).not.toBeNull();
      expect(p.secrets.maxLifetimeMs, p.profile).toBe(durationMs(match?.[1] ?? ''));
      expect(p.secrets.defaultLifetimeMs, p.profile).toBe(durationMs(match?.[2] ?? ''));
    });
    // The database bound of 20261009000000_burn_secrets is the longest lifetime of any profile.
    expect(Math.max(...V1.map((p) => p.secrets.maxLifetimeMs))).toBe(SECRET_MAX_LIFETIME_MS);
  });

  it('PC-10: burn-after-reading', () => {
    const expected: Record<string, boolean> = { 'Optional, on by default': false, Mandatory: true };
    eachProfile('PC-10', (cell, p) => {
      expect(p.secrets.burnMandatory, p.profile).toBe(expected[cell]);
    });
  });

  it('PC-11: external one-time links (stretch, not built)', () => {
    eachProfile('PC-11', (cell, p) => {
      if (cell === 'Not allowed') {
        expect(p.externalLinks, p.profile).toEqual({ allowed: false, maxLifetimeMs: null });
        return;
      }
      expect(cell).toBe('Allowed, burn mandatory, maximum 24 hours');
      expect(p.externalLinks, p.profile).toEqual({ allowed: true, maxLifetimeMs: 24 * HOUR });
    });
  });

  it('PC-12: whether a VIEWER may obtain file key material and ciphertext', () => {
    eachProfile('PC-12', (cell, p) => {
      expect(p.viewerMayObtainFileKeys, p.profile).toBe(yesNo(cell));
    });
  });

  it('PC-13: the audit level, and what each level adds (section 3)', () => {
    eachProfile('PC-13', (cell, p) => {
      expect(p.auditLevel, p.profile).toBe(cell);
    });
    expect([...AUDIT_LEVELS]).toEqual(['BASELINE', 'EXTENDED', 'FULL']);
    expect(PROFILES_DOC).toContain('| EXTENDED | BASELINE plus file download-URL issuance and note reads |');
    expect(PROFILES_DOC).toContain(
      '| FULL | EXTENDED plus envelope fetches, member-list views and every denied request in the room |',
    );
  });

  it('PC-14: the room-key cryptoperiod', () => {
    eachProfile('PC-14', (cell, p) => {
      expect(p.cryptoperiodMs, p.profile).toBe(cell === 'Event-driven only' ? null : durationMs(cell));
    });
  });

  it('PC-15 and PC-16: mandatory in every profile', () => {
    expect(cellsOf('PC-15')).toEqual(['Mandatory', 'Mandatory', 'Mandatory']);
    expect(cellsOf('PC-16')).toEqual(['Blocked', 'Blocked', 'Blocked']);
    for (const p of V1) expect([p.rekeyAfterMemberLoss, p.writesBlockedWhileRekeying], p.profile).toEqual([true, true]);
  });

  it('the global step-up windows: 15 minutes, and 5 minutes for a profile downgrade', () => {
    expect(PROFILES_DOC).toContain(
      'A step-up (password and TOTP) is valid for 15 minutes, except for a profile downgrade, which needs a step-up within the last 5 minutes.',
    );
    expect(PROFILE_CHANGE_RULES.downgradeStepUpMs).toBe(5 * 60_000);
    // The same windows the session layer uses for its own step-up routes (CM-T021).
    expect(SESSION_POLICY.stepUpMs).toBe(V1[2]?.sensitiveStepUp.windowMs);
    expect(SESSION_POLICY.stepUpStrictMs).toBe(PROFILE_CHANGE_RULES.downgradeStepUpMs);
  });
});

describe('catalogue versioning and immutability (CM-T046)', () => {
  it('knows version 1 only, and new rooms get it', () => {
    expect([...SUPPORTED_POLICY_VERSIONS]).toEqual([1]);
    expect(POLICY_CATALOGUE_VERSION).toBe(1);
    for (const profile of SECURITY_PROFILES) expect(currentPolicy(profile)).toBe(resolveRoomPolicy(profile, 1));
  });

  it('resolves nothing for an unknown, malformed or forged version or profile (no fallback)', () => {
    for (const version of [0, 2, -1, 1.5, Number.NaN, Infinity, '1', null, undefined, {}, [1], '__proto__']) {
      for (const profile of SECURITY_PROFILES)
        expect(resolveRoomPolicy(profile, version), `version ${JSON.stringify(version)}`).toBeUndefined();
    }
    for (const profile of ['standard', 'TOP_SECRET', '', '__proto__', 'constructor', null, 1]) {
      expect(resolveRoomPolicy(profile, 1), String(profile)).toBeUndefined();
    }
  });

  it('is deeply frozen, so no code path can widen a value at runtime', () => {
    for (const p of V1) {
      for (const value of [
        p,
        p.access,
        p.sensitiveStepUp,
        p.invitations,
        p.contentExpiry,
        p.secrets,
        p.externalLinks,
      ]) {
        expect(Object.isFrozen(value)).toBe(true);
      }
      expect(() => {
        (p.access as { mfaVerifiedSession: boolean }).mfaVerifiedSession = false;
      }).toThrow(TypeError);
    }
    expect(Object.isFrozen(SUPPORTED_POLICY_VERSIONS)).toBe(true);
    expect(Object.isFrozen(PROFILE_CHANGE_RULES)).toBe(true);
    expect(currentPolicy('RESTRICTED').access.mfaVerifiedSession).toBe(true);
  });

  it('has no database table that could change policy values (data-model 4.16)', () => {
    const schema = readFileSync(new URL('../../prisma/schema.prisma', import.meta.url), 'utf8');
    const models = [...schema.matchAll(/^model (\w+) \{/gm)].map((m) => m[1] ?? '');
    expect(models.filter((name) => /polic|profile|rule/i.test(name))).toEqual([]);
    // Rooms store only the profile and the catalogue version that governs them.
    expect(schema).toMatch(/securityProfile\s+SecurityProfile\s+@map\("security_profile"\)/);
    expect(schema).toMatch(/policyVersion\s+Int\s+@map\("policy_version"\)/);
  });
});

// Limits that are not profile rules, against the parameter register and the crypto package
// (Phases 7 and 8; moved here from profile-requirements.test.ts unchanged).
describe('file and note limits', () => {
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

  it('match CP-28 of the parameter register and the crypto package', () => {
    const register = readFileSync(new URL('../../docs/crypto/crypto-decisions.md', import.meta.url), 'utf8');
    const row = register.split('\n').find((l) => l.startsWith('| CP-28 |')) ?? '';
    expect(row).toContain('64 KiB');
    expect(row).toContain('200');
    expect(NOTE_LIMITS.maxDocumentBytes).toBe(64 * 1024);
    expect(NOTES.maxDocumentBytes).toBe(NOTE_LIMITS.maxDocumentBytes);
    expect(NOTE_LIMITS.maxCiphertextBytes).toBe(NOTE_LIMITS.maxDocumentBytes + NOTE_TAG_BYTES);
    expect([NOTES.maxTitleLength, NOTES.maxRevision]).toEqual([NOTE_LIMITS.maxTitleLength, NOTE_LIMITS.maxRevision]);
    expect(NOTE_LIMITS.maxRevision).toBe(2 ** 31 - 1);
    // The largest update request (ciphertext as base64url plus the other fields) fits the 128 KiB body limit.
    expect(Math.ceil((NOTE_LIMITS.maxCiphertextBytes * 4) / 3) + 1024).toBeLessThan(128 * 1024);
    expect(NOTE_LIST_PAGE_SIZE).toBeLessThanOrEqual(20);
  });

  it('are frozen', () => {
    for (const value of [FILE_LIMITS, FILE_QUOTAS, NOTE_LIMITS, SECRET_LIMITS])
      expect(Object.isFrozen(value)).toBe(true);
  });
});
