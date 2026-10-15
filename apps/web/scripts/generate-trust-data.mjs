// Writes the Trust Center data files from the normative documents (trust-data-lib.mjs).
//   node apps/web/scripts/generate-trust-data.mjs          regenerate after a document change
//   node apps/web/scripts/generate-trust-data.mjs --check  fail if the committed files are stale
// The web build runs --check, so a build can never ship data that differs from the documents.
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  buildIsmsCatalogue,
  buildTrustData,
  parseIsmsOperations,
  renderIsmsCatalogue,
  serialize,
} from './trust-data-lib.mjs';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const outDir = join(root, 'apps', 'web', 'src', 'trust', 'generated');
/** @param {string} path */
const read = (path) => readFileSync(join(root, path), 'utf8');

/** Committed evidence files, repository-relative with forward slashes, in a stable order. */
const evidenceFiles = readdirSync(join(root, 'docs', 'report', 'evidence'), { withFileTypes: true })
  .filter((entry) => entry.isDirectory() && /^phase-\d{2}$/.test(entry.name))
  .flatMap((dir) =>
    readdirSync(join(root, 'docs', 'report', 'evidence', dir.name)).map(
      (name) => `docs/report/evidence/${dir.name}/${name}`,
    ),
  )
  .sort();

const files = buildTrustData(
  {
    threatModel: read('docs/threat-model/threat-model.md'),
    limitations: read('docs/security/limitations.md'),
    isms: read('docs/security/isms-control-mapping.md'),
    evidencePlan: read('docs/report/evidence-plan.md'),
    evidenceIndex: read('docs/report/evidence/index.md'),
    cryptoDecisions: read('docs/crypto/crypto-decisions.md'),
    responsibility: read('docs/cloud/shared-responsibility.md'),
    deployment: read('docs/cloud/deployment-architecture.md'),
  },
  evidenceFiles,
);

// The operational ISMS catalogue (ADR-016) for the API and the web client: written into the
// shared package, checked byte for byte like the Trust Center data.
const ismsOperations = read('docs/security/isms-operations.md');
const catalogue = buildIsmsCatalogue(
  {
    threatModel: read('docs/threat-model/threat-model.md'),
    isms: read('docs/security/isms-control-mapping.md'),
    ismsOperations,
    systemOverview: read('docs/architecture/system-overview.md'),
    evidencePlan: read('docs/report/evidence-plan.md'),
    evidenceIndex: read('docs/report/evidence/index.md'),
    policyDocuments: Object.fromEntries(
      parseIsmsOperations(ismsOperations).policies.map((p) => [p.path, read(p.path)]),
    ),
  },
  evidenceFiles,
);
/** Output path to text: the Trust Center JSON files and the shared catalogue module. */
const outputs = new Map(Object.entries(files).map(([name, value]) => [join(outDir, name), serialize(value)]));
outputs.set(join(root, 'packages', 'shared', 'src', 'isms-catalogue.ts'), renderIsmsCatalogue(catalogue));

const check = process.argv.includes('--check');
const stale = [];
if (!check) mkdirSync(outDir, { recursive: true });
for (const [path, text] of outputs) {
  if (check) {
    const current = existsSync(path) ? readFileSync(path, 'utf8').replace(/\r\n/g, '\n') : undefined;
    if (current !== text) stale.push(relative(root, path).replace(/\\/g, '/'));
  } else {
    writeFileSync(path, text);
  }
}
if (stale.length > 0) {
  console.error(
    `Trust Center data is out of date with the documents: ${stale.join(', ')}. Run: node apps/web/scripts/generate-trust-data.mjs`,
  );
  process.exit(1);
}
console.log(check ? 'Trust Center data matches the documents.' : `Trust Center data written to ${outDir}.`);
