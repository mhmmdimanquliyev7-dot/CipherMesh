import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  buildTrustData,
  evidenceIds,
  evidenceIdsOfFile,
  evidenceStatus,
  parseEvidenceIndex,
  plain,
  serialize,
} from './trust-data-lib.mjs';

// Phase 14 + Prompt 16.5 (CM-T061): the Trust Center shows the normative documents, never a copy
// typed by hand. These tests fail when the committed data drifts from the documents, when a
// reference does not resolve, or when an evidence status would claim more than the files show.

const root = fileURLToPath(new URL('../../../', import.meta.url));
const read = (path: string): string => readFileSync(join(root, path), 'utf8');
const evidenceDir = join(root, 'docs', 'report', 'evidence');
const evidenceFiles = readdirSync(evidenceDir, { withFileTypes: true })
  .filter((entry) => entry.isDirectory() && /^phase-\d{2}$/.test(entry.name))
  .flatMap((dir) => readdirSync(join(evidenceDir, dir.name)).map((name) => `docs/report/evidence/${dir.name}/${name}`))
  .sort();

const docs = {
  threatModel: read('docs/threat-model/threat-model.md'),
  limitations: read('docs/security/limitations.md'),
  isms: read('docs/security/isms-control-mapping.md'),
  evidencePlan: read('docs/report/evidence-plan.md'),
  evidenceIndex: read('docs/report/evidence/index.md'),
  cryptoDecisions: read('docs/crypto/crypto-decisions.md'),
  responsibility: read('docs/cloud/shared-responsibility.md'),
  deployment: read('docs/cloud/deployment-architecture.md'),
};
const data = buildTrustData(docs, evidenceFiles);

interface Risk {
  id: string;
  limitations: string[];
  residual: string;
  fields: { label: string }[];
}
interface Control {
  control: string;
  status: string;
  evidence: string[];
}
interface Evidence {
  id: string;
  phase: number;
  status: string;
  tags: string[];
  files: { path: string }[];
}
const risks = (data['risks.json'] as { risks: Risk[] }).risks;
const controls = (data['isms.json'] as { controls: Control[] }).controls;
const evidence = (data['evidence.json'] as { evidence: Evidence[] }).evidence;
const limitations = (data['limitations.json'] as { limitations: { id: string }[] }).limitations;
const parameters = (data['parameters.json'] as { parameters: { id: string; value: string }[] }).parameters;

describe('Trust Center data', () => {
  it('matches the committed files exactly (regenerate with node apps/web/scripts/generate-trust-data.mjs)', () => {
    for (const [name, value] of Object.entries(data)) {
      const committed = read(`apps/web/src/trust/generated/${name}`).replace(/\r\n/g, '\n');
      expect(committed, name).toBe(serialize(value));
    }
  });

  it('carries every risk of the register with its threat description and existing limitations', () => {
    const register = docs.threatModel.match(/^\| T-\d+ \|/gm) ?? [];
    expect(risks).toHaveLength(register.length);
    expect(risks.length).toBeGreaterThanOrEqual(40);
    const known = new Set(limitations.map((l) => l.id));
    for (const risk of risks) {
      expect(
        risk.fields.some((f) => f.label.startsWith('Security controls')),
        risk.id,
      ).toBe(true);
      expect(risk.residual, risk.id).not.toBe('');
      for (const id of risk.limitations) expect(known.has(id), `${risk.id} -> ${id}`).toBe(true);
    }
  });

  it('keeps the documented control statuses and resolves every evidence reference to the plan', () => {
    const allowed = new Set(['Implemented by design', 'Partial', 'Provider', 'Provider and team', 'Not applicable']);
    const planned = new Set(evidence.map((item) => item.id));
    expect(controls.length).toBeGreaterThanOrEqual(40);
    for (const control of controls) {
      expect(allowed.has(control.status), `${control.control}: ${control.status}`).toBe(true);
      for (const id of control.evidence) expect(planned.has(id), `${control.control} -> ${id}`).toBe(true);
    }
  });

  it('never marks evidence captured without a committed file or a recorded location', () => {
    const files = new Set(evidenceFiles);
    for (const item of evidence) {
      for (const file of item.files) {
        if (file.path.startsWith('docs/report/evidence/phase-')) expect(files.has(file.path), file.path).toBe(true);
      }
    }
    // The audit hash chain (Phase 12) is deferred: none of its evidence may appear as captured.
    const audit = evidence.filter((item) => item.phase === 12);
    expect(audit.length).toBeGreaterThan(0);
    for (const item of audit) expect(item.status, item.id).toBe('deferred');
    // Cloud evidence belongs to the later workstream and is not captured yet.
    for (const item of evidence.filter((e) => e.phase >= 17 && e.phase <= 19)) expect(item.status).toBe('planned');
  });

  it('tags evidence with the three subjects and the application tag only', () => {
    for (const item of evidence) {
      expect(item.tags.length, item.id).toBeGreaterThan(0);
      for (const tag of item.tags) expect(['CRY', 'CLD', 'ISMS', 'APP']).toContain(tag);
    }
  });

  it('reads the parameter register verbatim', () => {
    const aead = parameters.find((p) => p.id === 'CP-01');
    expect(aead?.value).toBe('AES-256-GCM, 256-bit keys, 96-bit IV, 128-bit tag');
    expect(parameters.find((p) => p.id === 'CP-18')?.value).toContain('CP-01');
  });
});

describe('Trust Center parsing rules', () => {
  it('reduces Markdown to plain text', () => {
    expect(plain('**Bold** with [a link](../x.md), `code` and *emphasis*<br/>end')).toBe(
      'Bold with a link, code and emphasis end',
    );
  });

  it('expands evidence ranges and lists', () => {
    expect(evidenceIds('EV-03-03 to EV-03-05, EV-04-08')).toEqual(['EV-03-03', 'EV-03-04', 'EV-03-05', 'EV-04-08']);
    expect(evidenceIdsOfFile('docs/report/evidence/phase-11/EV-11-06-07_recovery.txt')).toEqual([
      'EV-11-06',
      'EV-11-07',
    ]);
    expect(evidenceIdsOfFile('docs/report/evidence/phase-01/EV-01-06a_build.txt')).toEqual(['EV-01-06']);
    expect(evidenceIdsOfFile('docs/report/evidence/README.md')).toEqual([]);
  });

  it('derives the status from files, pending rows and the phase plan', () => {
    const index = parseEvidenceIndex(
      [
        '| ID | File | Date | Jira | Caption |',
        '|---|---|---|---|---|',
        '| EV-01-01 (local part) | [a.txt](phase-01/a.txt) | 2026-10-02 | CM-T006 | Local |',
        '| EV-01-01 (CI run) | Pending | | CM-T012 | CI |',
        '| EV-02-01 | Pending | | CM-T013 | Not yet |',
      ].join('\n'),
    );
    expect(evidenceStatus({ id: 'EV-01-01', phase: 1 }, index)).toBe('partial');
    expect(evidenceStatus({ id: 'EV-02-01', phase: 2 }, index)).toBe('pending');
    expect(evidenceStatus({ id: 'EV-02-01', phase: 2 }, index, ['docs/report/evidence/phase-02/EV-02-01_x.txt'])).toBe(
      'partial',
    );
    expect(evidenceStatus({ id: 'EV-03-01', phase: 3 }, [], ['docs/report/evidence/phase-03/EV-03-01_x.txt'])).toBe(
      'captured',
    );
    expect(evidenceStatus({ id: 'EV-12-01', phase: 12 }, [])).toBe('deferred');
    expect(evidenceStatus({ id: 'EV-17-01', phase: 17 }, [])).toBe('planned');
    expect(evidenceStatus({ id: 'EV-14-01', phase: 14 }, [])).toBe('pending');
  });
});
