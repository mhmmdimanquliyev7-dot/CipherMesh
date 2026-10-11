// `pnpm bench:files`: browser benchmark of single-shot file encryption for CP-19 (Phase 7,
// CM-T038). Bundles scripts/bench/files-page (the real @ciphermesh/crypto file code) with Vite,
// serves it on 127.0.0.1 with the production security headers and Content-Security-Policy, and
// runs it in Chromium, Firefox and WebKit through Playwright: encryption and authenticated
// decryption of 1, 10 and 50 MiB, a byte-exact round trip, the refusal of 50 MiB plus one byte, and
// the page's memory where the engine reports it (the bench page is cross-origin isolated for that,
// which only adds isolation). Exits non-zero on a CSP violation, a page error or a failed check.
//
// Numbers depend on the device. Run it on the hardware you report, and never present a desktop
// result as a phone result (docs/security/limitations.md). Needs the Playwright browsers.
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { availableParallelism, cpus, platform, release, tmpdir, totalmem } from 'node:os';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { chromium, firefox, webkit } from '@playwright/test';
import { build } from 'vite';
import { DEFAULT_STORAGE_ORIGIN, STATIC_SECURITY_HEADERS, buildCsp } from '../../apps/web/scripts/csp-lib.mjs';

/** @typedef {import('./files-page/bench').FilesBenchResult} FilesBenchResult */

/** @type {Record<string, string>} */
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };
const headers = {
  ...STATIC_SECURITY_HEADERS,
  'Content-Security-Policy': buildCsp([], DEFAULT_STORAGE_ORIGIN),
  // Cross-origin isolation enables performance.measureUserAgentSpecificMemory (Chromium).
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
};

const outDir = await mkdtemp(join(tmpdir(), 'cm-files-bench-'));
/** @type {{ engine: string, version: string, result: FilesBenchResult, problems: string[] }[]} */
const runs = [];
try {
  await build({
    root: resolve('scripts/bench/files-page'),
    configFile: false,
    logLevel: 'warn',
    base: './',
    build: { outDir, emptyOutDir: true, target: 'es2022', modulePreload: false },
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
        await page.waitForFunction('typeof window.runFilesBench === "function"');
        const result = /** @type {FilesBenchResult} */ (await page.evaluate('window.runFilesBench()'));
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

const cpu = cpus()[0]?.model.trim() ?? 'unknown CPU';
const gib = (totalmem() / 2 ** 30).toFixed(1);
console.log(`File encryption benchmark (CP-19), ${new Date().toISOString()}`);
console.log(
  `Host: ${cpu}, ${String(availableParallelism())} logical CPUs, ${gib} GiB RAM, ${platform()} ${release()}, Node.js ${process.version}\n`,
);
console.log(`| Measurement | ${runs.map((r) => `${r.engine} ${r.version}`).join(' | ')} |`);
console.log(`|---|${runs.map(() => '---').join('|')}|`);
const line = (/** @type {string} */ label, /** @type {(r: (typeof runs)[number]) => string} */ cell) => {
  console.log(`| ${label} | ${runs.map(cell).join(' | ')} |`);
};
for (const [index, sizeMiB] of [1, 10, 50].entries()) {
  line(`${String(sizeMiB)} MiB: encrypt / decrypt and verify`, (r) => {
    const row = r.result.rows[index];
    return row === undefined
      ? 'missing'
      : `${String(Math.round(row.encryptMs))} ms / ${String(Math.round(row.decryptMs))} ms${row.roundTripOk ? '' : ' **MISMATCH**'}`;
  });
}
line('Page memory after the 50 MiB round trip (measureUserAgentSpecificMemory)', (r) => {
  const value = r.result.rows[2]?.pageMemoryMiB;
  return value === null || value === undefined ? 'not reported by the engine' : `${String(value)} MiB`;
});
line('50 MiB + 1 byte refused before encryption', (r) => (r.result.oversizeRefused ? 'yes' : '**NO**'));
line('CSP violations or page errors', (r) => (r.problems.length === 0 ? 'none' : `**${r.problems.join('; ')}**`));

const failed = runs.some(
  (r) => r.problems.length > 0 || !r.result.oversizeRefused || r.result.rows.some((row) => !row.roundTripOk),
);
if (failed || runs.length !== 3) process.exitCode = 1;
