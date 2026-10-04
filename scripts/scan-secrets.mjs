// Secret scanning with gitleaks (threat T-16), run from a container pinned by digest.
//   pnpm scan:secrets            scans the full git history
//   pnpm scan:secrets --staged   also scans staged changes before a commit
// Findings are redacted in the output. Exits non-zero when anything is found.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const IMAGE = 'zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f';
const repo = fileURLToPath(new URL('..', import.meta.url));

/** @param {string[]} args */
function gitleaks(args) {
  const result = spawnSync(
    'docker',
    ['run', '--rm', '--volume', `${repo}:/repo:ro`, IMAGE, ...args, '--redact', '--no-banner', '--verbose'],
    { stdio: 'inherit' },
  );
  if (result.error) throw result.error;
  return result.status ?? 1;
}

const scans = [['git', '/repo']];
if (process.argv.includes('--staged')) scans.push(['git', '/repo', '--pre-commit', '--staged']);

let status = 0;
for (const args of scans) {
  console.log(`\n== gitleaks ${args.join(' ')}`);
  status = Math.max(status, gitleaks(args));
}
process.exit(status);
