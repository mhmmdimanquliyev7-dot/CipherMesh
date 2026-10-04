// Runs the Prisma CLI with a fixed allowlist of subcommands (CM-T013).
//
// - Telemetry and update checks are switched off, so the CLI does not contact Prisma services
//   during builds, tests or CI (the schema engine download on first use is checksum-verified).
// - Commands that bypass reviewed migrations or destroy data (`migrate dev`, `migrate reset`,
//   `db push`, `db execute`) are refused. Schema changes arrive only as reviewed migration files
//   applied by `migrate deploy` (change control, ISO/IEC 27001 control 8.32).
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';

const ALLOWED = new Set([
  'generate',
  'validate',
  'format',
  'version',
  'migrate deploy',
  'migrate status',
  'migrate diff',
]);

const args = process.argv.slice(2);
const command = args[0] === 'migrate' ? `migrate ${args[1] ?? ''}` : (args[0] ?? '');
if (!ALLOWED.has(command)) {
  console.error(`prisma ${command || '(none)'} is not allowed here. Allowed: ${[...ALLOWED].join(', ')}`);
  process.exit(1);
}

const cli = createRequire(import.meta.url).resolve('prisma/build/index.js');
const child = spawn(process.execPath, [cli, ...args], {
  stdio: 'inherit',
  env: { ...process.env, CHECKPOINT_DISABLE: '1', PRISMA_HIDE_UPDATE_MESSAGE: '1' },
});
child.on('exit', (code, signal) => {
  process.exitCode = code ?? (signal ? 1 : 0);
});
