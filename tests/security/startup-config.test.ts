import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

// Fail-closed startup (principle 10): the real server process refuses invalid
// configuration, exits non-zero, and does not echo configuration values.
const apiDir = fileURLToPath(new URL('../../apps/api/', import.meta.url));

function runServer(env: Record<string, string>): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    // A minimal environment: nothing from the developer's shell leaks into the test.
    const child = spawn(process.execPath, ['--import', 'tsx', 'src/server.ts'], {
      cwd: apiDir,
      env: { PATH: process.env['PATH'] ?? '', SystemRoot: process.env['SystemRoot'] ?? '', ...env },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString()));
    child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error('server did not exit on invalid configuration'));
    }, 15_000);
    child.on('exit', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

describe('API startup with invalid configuration', () => {
  it('exits with code 1 and names the variable without its value', async () => {
    const result = await runServer({
      NODE_ENV: 'production',
      APP_ORIGIN: 'http://canary-insecure.example',
      API_PORT: 'canary-port',
    });
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('APP_ORIGIN');
    expect(result.stderr).toContain('API_PORT');
    expect(`${result.stdout}${result.stderr}`).not.toContain('canary');
    expect(result.stdout).not.toContain('api listening');
  }, 20_000);
});
