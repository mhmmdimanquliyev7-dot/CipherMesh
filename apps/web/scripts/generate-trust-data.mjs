// Writes the Trust Center data files from the normative documents (trust-data-lib.mjs).
//   node apps/web/scripts/generate-trust-data.mjs          regenerate after a document change
//   node apps/web/scripts/generate-trust-data.mjs --check  fail if the committed files are stale
// The web build runs --check, so a build can never ship data that differs from the documents.
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildTrustData, serialize } from './trust-data-lib.mjs';

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

const check = process.argv.includes('--check');
const stale = [];
if (!check) mkdirSync(outDir, { recursive: true });
for (const [name, value] of Object.entries(files)) {
  const path = join(outDir, name);
  const text = serialize(value);
  if (check) {
    if (!existsSync(path) || readFileSync(path, 'utf8').replace(/\r\n/g, '\n') !== text) stale.push(name);
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
