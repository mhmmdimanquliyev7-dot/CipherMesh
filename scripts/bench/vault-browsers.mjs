// `pnpm bench:vault`: browser benchmark of the Vault for ADR-010 and CP-04 (CM-T024).
//
// Bundles scripts/bench/vault-page (the real @ciphermesh/crypto code and its Argon2id Web Worker)
// with Vite, serves it on 127.0.0.1 with the production security headers and Content-Security-
// Policy (script-src 'self' 'wasm-unsafe-eval', nothing else relaxed), and runs it in Chromium,
// Firefox and WebKit through Playwright. Prints a Markdown table with the median, minimum and
// maximum of each operation, the main-thread responsiveness while a derivation runs, and two
// refusal checks. Exits non-zero on a CSP violation, a page error or a failed check.
//
// Numbers depend heavily on the device. Run it on the hardware you report, and never present a
// desktop result as a phone result (docs/security/limitations.md). Needs the Playwright browsers.
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { availableParallelism, cpus, platform, release, tmpdir, totalmem } from 'node:os';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { chromium, firefox, webkit } from '@playwright/test';
import { build } from 'vite';
import { buildCsp, STATIC_SECURITY_HEADERS } from '../../apps/web/scripts/csp-lib.mjs';

/** @typedef {import('./vault-page/bench').BenchResult} BenchResult */

/** @type {Record<string, string>} */
const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.wasm': 'application/wasm',
};
const headers = { ...STATIC_SECURITY_HEADERS, 'Content-Security-Policy': buildCsp([]) };

const outDir = await mkdtemp(join(tmpdir(), 'cm-vault-bench-'));
/** @type {{ engine: string, version: string, result: BenchResult, problems: string[] }[]} */
const runs = [];
try {
  await build({
    root: resolve('scripts/bench/vault-page'),
    configFile: false,
    logLevel: 'warn',
    base: './',
    build: { outDir, emptyOutDir: true, target: 'es2022', modulePreload: false },
    worker: { format: 'es' },
  });

  const server = createServer((req, res) => {
    void (async () => {
      const path = new URL(req.url ?? '/', 'http://127.0.0.1').pathname;
      const file = normalize(join(outDir, path === '/' ? 'index.html' : decodeURIComponent(path)));
      if (!file.startsWith(outDir + sep)) {
        res.writeHead(404, headers).end();
        return;
      }
      try {
        const body = await readFile(file);
        res.writeHead(200, { ...headers, 'Content-Type': TYPES[extname(file)] ?? 'application/octet-stream' });
        res.end(body);
      } catch {
        res.writeHead(404, headers).end();
      }
    })();
  }).listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  const url = `http://127.0.0.1:${String(typeof address === 'object' && address !== null ? address.port : 0)}/`;

  try {
    for (const [engine, type] of Object.entries({ chromium, firefox, webkit })) {
      const browser = await type.launch();
      try {
        const page = await browser.newPage();
        /** @type {string[]} */
        const problems = [];
        page.on('console', (message) => {
          if (/content.security.policy/i.test(message.text())) problems.push(`CSP: ${message.text()}`);
        });
        page.on('pageerror', (error) => problems.push(`page error: ${error.message}`));
        await page.goto(url);
        await page.waitForFunction('typeof window.runVaultBench === "function"');
        const result = /** @type {BenchResult} */ (await page.evaluate('window.runVaultBench()'));
        runs.push({ engine, version: browser.version(), result, problems });
      } finally {
        await browser.close();
      }
    }
  } finally {
    server.close();
  }
} finally {
  await rm(outDir, { recursive: true, force: true });
}

/** @param {number[]} times */
const summary = (times) => {
  const sorted = [...times].sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)] ?? Number.NaN;
  const low = sorted[0] ?? Number.NaN;
  const high = sorted.at(-1) ?? Number.NaN;
  return `${String(Math.round(median))} ms (${String(Math.round(low))} to ${String(Math.round(high))}, n = ${String(times.length)})`;
};
/** @param {boolean} value */
const yesNo = (value) => (value ? 'yes' : '**NO**');

const cpu = cpus()[0]?.model.trim() ?? 'unknown CPU';
const gib = (totalmem() / 2 ** 30).toFixed(1);
console.log(`Vault benchmark, ${new Date().toISOString()}`);
console.log(
  `Host: ${cpu}, ${String(availableParallelism())} logical CPUs, ${gib} GiB RAM, ${platform()} ${release()}, Node.js ${process.version}\n`,
);
console.log(`| Operation | ${runs.map((r) => `${r.engine} ${r.version}`).join(' | ')} |`);
console.log(`|---|${runs.map(() => '---').join('|')}|`);
const first = runs[0];
if (first !== undefined) {
  first.result.rows.forEach((row, index) => {
    console.log(`| ${row.name} | ${runs.map((r) => summary(r.result.rows[index]?.times ?? [])).join(' | ')} |`);
  });
}
const line = (/** @type {string} */ label, /** @type {(r: (typeof runs)[number]) => string} */ cell) => {
  console.log(`| ${label} | ${runs.map(cell).join(' | ')} |`);
};
line(
  'Longest main-thread timer gap (10 ms timer) during a target derivation',
  (r) => `${String(Math.round(r.result.maxMainThreadGapMs))} ms`,
);
line('Second concurrent derivation refused with KDF_BUSY', (r) => yesNo(r.result.concurrentDerivationRefused));
line('Wrong passphrase refused with VAULT_UNLOCK_FAILED', (r) => yesNo(r.result.wrongPassphraseRefused));
line('Logical CPUs reported to the page', (r) => String(r.result.hardwareConcurrency));
line('CSP violations or page errors', (r) => (r.problems.length === 0 ? 'none' : `**${r.problems.join('; ')}**`));

const failed = runs.some(
  (r) => r.problems.length > 0 || !r.result.concurrentDerivationRefused || !r.result.wrongPassphraseRefused,
);
if (failed || runs.length !== 3) process.exitCode = 1;
