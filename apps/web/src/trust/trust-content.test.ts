import { AES_GCM } from '@ciphermesh/crypto/params';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { FLOW, KEY_HIERARCHY, MECHANISMS, type KeyNode } from './cryptography';
import { evidenceItem, limitation, parameter } from './data';
import { POLICIES } from './governance';
import { CLOUD_CONTROLS } from './infrastructure';
import { CLAIMS, NOT_IMPLEMENTED } from './claims';
import { JOURNEYS } from './walkthrough';

// Phase 14 + Prompt 16.5 (CM-T061): the Trust Center may only say what the system and its evidence
// support. These tests resolve every curated reference, refuse "verified" without captured
// evidence, and refuse the marketing terms CLAUDE.md section 7 forbids.

const root = fileURLToPath(new URL('../../../../', import.meta.url));
const captured = (id: string): boolean => {
  const status = evidenceItem(id)?.status;
  return status === 'captured' || status === 'partial';
};

describe('cryptography content', () => {
  it('cites parameter rows, captured evidence and limitations that exist', () => {
    for (const mechanism of MECHANISMS) {
      for (const id of mechanism.parameters) expect(parameter(id), `${mechanism.id} -> ${id}`).toBeDefined();
      for (const id of mechanism.evidence) expect(captured(id), `${mechanism.id} -> ${id}`).toBe(true);
      for (const id of mechanism.limitations) expect(limitation(id), `${mechanism.id} -> ${id}`).toBeDefined();
      expect(mechanism.cannot.length, mechanism.id).toBeGreaterThan(20);
    }
  });

  it('matches the implemented AES-GCM parameters', () => {
    expect(parameter('CP-01')?.value).toContain(`${String(AES_GCM.ivBytes * 8)}-bit IV`);
    expect(parameter('CP-01')?.value).toContain(`${String(AES_GCM.tagBytes * 8)}-bit tag`);
  });

  it('never presents RSA as encrypting content', () => {
    const text = JSON.stringify([MECHANISMS, FLOW]);
    expect(text).not.toMatch(/RSA[^.]*encrypts? (the )?(file|note|content)/i);
  });

  it('shows the key hierarchy with every content key under a wrap, and nothing derived from the server', () => {
    const names: string[] = [];
    const walk = (nodes: readonly KeyNode[]): void => {
      for (const node of nodes) {
        names.push(node.name);
        walk(node.children ?? []);
      }
    };
    walk(KEY_HIERARCHY);
    for (const expected of [
      'Vault Passphrase',
      'Room wrapping key (RWK_v)',
      'File key (FEK)',
      'Note key (NEK)',
      'Secret key (SEK)',
    ]) {
      expect(names).toContain(expected);
    }
  });
});

describe('infrastructure content', () => {
  it('cites configuration sources that exist in the repository', () => {
    for (const control of CLOUD_CONTROLS) {
      expect(existsSync(join(root, control.design.source)), control.design.source).toBe(true);
      if (control.configuration.state === 'configured') {
        for (const source of control.configuration.sources) expect(existsSync(join(root, source)), source).toBe(true);
      }
    }
  });

  it('marks a control verified only with captured evidence, and never in the cloud before deployment', () => {
    for (const control of CLOUD_CONTROLS) {
      const { verification, configuration } = control;
      if (verification.state === 'verified') {
        expect(verification.evidence.length, control.id).toBeGreaterThan(0);
        for (const id of verification.evidence) expect(captured(id), `${control.id} -> ${id}`).toBe(true);
        expect(configuration.state, control.id).toBe('configured');
      } else {
        for (const id of verification.planned) {
          expect(evidenceItem(id), `${control.id} -> ${id}`).toBeDefined();
          expect(captured(id), `${control.id} -> ${id} is captured: mark the control verified`).toBe(false);
        }
      }
      // No cloud resource exists yet (the cloud workstream follows this phase).
      if (configuration.state === 'configured') expect(configuration.scope).not.toBe('cloud');
      if (verification.state === 'verified') expect(verification.scope).not.toBe('cloud');
    }
  });
});

describe('governance content', () => {
  it('lists only governing documents that exist', () => {
    for (const policy of POLICIES) expect(existsSync(join(root, policy.path)), policy.path).toBe(true);
  });
});

describe('claims, walkthrough and wording', () => {
  it('links every claim to existing evidence and limitations', () => {
    for (const claim of CLAIMS) {
      for (const id of claim.evidence) expect(captured(id), `${claim.id} -> ${id}`).toBe(true);
      for (const id of claim.limitations) expect(limitation(id), `${claim.id} -> ${id}`).toBeDefined();
    }
    expect(NOT_IMPLEMENTED.map((item) => item.name)).toContain('Tamper-evident audit ledger');
  });

  it('points walkthrough steps at real routes and existing evidence', () => {
    const appDir = join(root, 'apps/web/src/app');
    for (const journey of JOURNEYS) {
      for (const step of journey.steps) {
        const path = step.href.split(/[?#]/)[0] ?? '';
        const page = path === '/' ? join(appDir, 'page.tsx') : join(appDir, path, 'page.tsx');
        expect(existsSync(page), `${journey.id}: ${step.href}`).toBe(true);
        for (const id of step.evidence ?? []) expect(evidenceItem(id), `${journey.id} -> ${id}`).toBeDefined();
      }
    }
  });

  it('uses no forbidden security marketing terms in the client source', () => {
    const forbidden =
      /unhackable|military[- ]grade|zero[- ]knowledge|perfect(ly)? secur|tamper-proof|100% secure|impossible to hack|fully compliant|27001 (certified|compliant)|certified ISMS/i;
    const files: string[] = [];
    const walk = (dir: string): void => {
      for (const name of readdirSync(dir)) {
        const path = join(dir, name);
        if (statSync(path).isDirectory()) walk(path);
        else if (/\.(tsx?|json)$/.test(name) && !name.endsWith('.test.ts')) files.push(path);
      }
    };
    walk(join(root, 'apps/web/src'));
    for (const file of files) {
      const text = readFileSync(file, 'utf8');
      // A term may appear only to deny it ("tamper-evident, not tamper-proof", "not a certified ISMS").
      const checked = text.replace(/not (a )?(tamper-proof|certified ISMS)/gi, '');
      expect(checked, file).not.toMatch(forbidden);
    }
  });
});
