// Serves the web static export (apps/web/out) with the generated security headers
// (apps/web/out-meta/security-headers.json), the way Nginx will in Phase 17.
// Test infrastructure only: not a production server. Binds to loopback.
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { extname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const webDir = fileURLToPath(new URL('../../apps/web/', import.meta.url));
const outDir = join(webDir, 'out');
const port = Number(process.env.E2E_PORT ?? 4173);
/** @type {Record<string, string>} */
const headers = JSON.parse(await readFile(join(webDir, 'out-meta', 'security-headers.json'), 'utf8'));

/** @type {Record<string, string>} */
const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

/** @param {string} urlPath */
async function resolveFile(urlPath) {
  const candidates = urlPath.endsWith('/') ? [`${urlPath}index.html`] : [urlPath, `${urlPath}.html`];
  for (const candidate of candidates) {
    const file = normalize(join(outDir, decodeURIComponent(candidate)));
    if (!file.startsWith(outDir + sep)) return undefined; // path traversal
    try {
      return { file, body: await readFile(file) };
    } catch {
      // try the next candidate
    }
  }
  return undefined;
}

createServer((req, res) => {
  void (async () => {
    const urlPath = new URL(req.url ?? '/', 'http://localhost').pathname;
    const found = await resolveFile(urlPath);
    const status = found ? 200 : 404;
    const file = found?.file ?? join(outDir, '404.html');
    const body = found?.body ?? (await readFile(file));
    res.writeHead(status, { ...headers, 'Content-Type': TYPES[extname(file)] ?? 'application/octet-stream' });
    res.end(body);
  })();
}).listen(port, '127.0.0.1', () => {
  console.log(`Static export served at http://127.0.0.1:${port}`);
});
