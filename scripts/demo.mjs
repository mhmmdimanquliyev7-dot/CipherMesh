// Local Docker demonstration launcher (pnpm demo:*). Runs the operator scripts of the cloud stack
// in Bash: Git Bash on Windows (not the WSL launcher that `bash` may resolve to from cmd.exe),
// the system Bash elsewhere. It adds nothing of its own: see infrastructure/deployment/bin/cm-rehearsal
// and docs/deployment/local-docker-demo.md. This is a local demonstration, not a cloud deployment.
//
//   pnpm demo:up | demo:down | demo:health | demo:status | demo:backup | demo:drill | demo:build
//   pnpm demo:admin <email>      grant PLATFORM_ADMIN to a registered account with MFA
//   pnpm demo:verify [dir]       full local verification with evidence (stack-check.sh, no rebuild)
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const [command = 'up', ...rest] = process.argv.slice(2);

function bash() {
  if (process.platform !== 'win32') return 'bash';
  for (const candidate of ['C:/Program Files/Git/bin/bash.exe', 'C:/Program Files (x86)/Git/bin/bash.exe']) {
    if (existsSync(candidate)) return candidate;
  }
  console.error('Git Bash is required on Windows (https://git-scm.com/download/win).');
  process.exit(2);
}

const script =
  command === 'verify'
    ? ['infrastructure/deployment/ci/stack-check.sh', rest[0] ?? 'test-results/local-demo-evidence']
    : ['infrastructure/deployment/bin/cm-rehearsal', command, ...rest];
const result = spawnSync(bash(), script, {
  cwd: root,
  stdio: 'inherit',
  env: { ...process.env, ...(command === 'verify' ? { CM_SKIP_BUILD: '1' } : {}) },
});
process.exit(result.status ?? 1);
