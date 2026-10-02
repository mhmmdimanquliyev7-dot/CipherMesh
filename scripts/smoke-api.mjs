// Starts the built API bundle (apps/api/dist/server.js) as a real process and probes it.
// Used by CI after `pnpm build` and to capture Phase 1 evidence. Exits non-zero on failure.
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';

const apiDir = fileURLToPath(new URL('../apps/api/', import.meta.url));

/** @returns {Promise<number>} */
const freePort = () =>
  new Promise((resolve) => {
    const probe = createServer().listen(0, '127.0.0.1', () => {
      const address = probe.address();
      probe.close(() => resolve(typeof address === 'object' && address ? address.port : 0));
    });
  });

const port = await freePort();
const child = spawn(process.execPath, ['dist/server.js'], {
  cwd: apiDir,
  env: {
    PATH: process.env.PATH,
    NODE_ENV: 'production',
    APP_ORIGIN: 'https://ciphermesh.example',
    API_PORT: String(port),
  },
  stdio: ['ignore', 'pipe', 'inherit'],
});

let output = '';
const listening = new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error('API did not start within 15 seconds')), 15_000);
  child.stdout.on('data', (chunk) => {
    output += String(chunk);
    if (output.includes('"api listening"')) {
      clearTimeout(timer);
      resolve(undefined);
    }
  });
  child.on('exit', (code) => reject(new Error(`API exited early with code ${code}`)));
});

const failures = [];
try {
  await listening;
  for (const [path, status, body] of [
    ['/api/health', 200, '{"status":"ok"}'],
    ['/api/ready', 200, '{"status":"ready"}'],
    ['/api/nothing-here', 404, null],
  ]) {
    const response = await fetch(`http://127.0.0.1:${port}${path}`);
    const text = await response.text();
    const ok = response.status === status && (body === null || text === body) && !response.headers.has('x-powered-by');
    console.log(`${ok ? 'PASS' : 'FAIL'} GET ${path} -> ${response.status} ${text}`);
    if (!ok) failures.push(path);
  }
} finally {
  if (process.platform === 'win32') {
    // Windows has no SIGTERM delivery to child processes; graceful shutdown is verified in CI (Linux).
    child.kill();
    console.log('SKIP graceful shutdown check: not observable on Windows');
  } else {
    const exited = new Promise((resolve) => child.once('exit', (code) => resolve(code)));
    child.kill('SIGTERM');
    const code = await exited;
    const graceful = code === 0 && output.includes('"shutdown complete"');
    console.log(`${graceful ? 'PASS' : 'FAIL'} SIGTERM -> exit code ${code}`);
    if (!graceful) failures.push('graceful shutdown');
  }
}
if (failures.length > 0) process.exit(1);
console.log('Smoke test passed against the built API bundle.');
