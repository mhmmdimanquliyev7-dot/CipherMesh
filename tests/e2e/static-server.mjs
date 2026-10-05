// E2E test server, standing in for the Nginx of Phase 17. Test infrastructure only; binds to
// loopback. It provides what the session design requires in every environment
// (session-and-csrf.md section 2): HTTPS, the static export with its generated security headers
// (apps/web/out-meta/security-headers.json), and the API behind a /api reverse proxy on the same
// origin, with exactly one forwarding hop (TRUST_PROXY_HOPS=1).
//
// The TLS certificate is self-signed for 127.0.0.1, generated with OpenSSL at startup, valid for
// one day and kept only in memory: the key file is deleted immediately. Playwright accepts it via
// ignoreHTTPSErrors. The API is the built bundle (run `pnpm build` first) using DATABASE_URL from
// the environment or .env, with random authentication keys for this run.
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { createServer } from 'node:https';
import { createServer as createNetServer } from 'node:net';
import { tmpdir } from 'node:os';
import { extname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));
const webDir = join(root, 'apps', 'web');
const outDir = join(webDir, 'out');
const port = Number(process.env.E2E_PORT ?? 4173);
const origin = `https://127.0.0.1:${String(port)}`;
if (existsSync(join(root, '.env'))) process.loadEnvFile(join(root, '.env'));

/** @type {Record<string, string>} */
const headers = JSON.parse(await readFile(join(webDir, 'out-meta', 'security-headers.json'), 'utf8'));

// ---------------------------------------------------------------- throwaway TLS certificate
function opensslBinary() {
  if (process.env.OPENSSL) return process.env.OPENSSL;
  const probe = spawnSync('openssl', ['version']);
  if (!probe.error) return 'openssl';
  const gitOpenssl = 'C:/Program Files/Git/usr/bin/openssl.exe';
  if (process.platform === 'win32' && existsSync(gitOpenssl)) return gitOpenssl;
  throw new Error('OpenSSL is required for the E2E HTTPS server (set OPENSSL to its path)');
}
const certDir = mkdtempSync(join(tmpdir(), 'cm-e2e-tls-'));
const generated = spawnSync(opensslBinary(), [
  'req',
  '-x509',
  '-newkey',
  'ec',
  '-pkeyopt',
  'ec_paramgen_curve:P-256',
  '-nodes',
  '-days',
  '1',
  '-subj',
  '/CN=127.0.0.1',
  '-addext',
  'subjectAltName=IP:127.0.0.1',
  '-keyout',
  join(certDir, 'key.pem'),
  '-out',
  join(certDir, 'cert.pem'),
]);
if (generated.status !== 0) throw new Error('OpenSSL could not create the test certificate');
const tls = { key: readFileSync(join(certDir, 'key.pem')), cert: readFileSync(join(certDir, 'cert.pem')) };
rmSync(certDir, { recursive: true, force: true });

// ------------------------------------------------------------------------------- the API
/** @returns {Promise<number>} */
const freePort = () =>
  new Promise((resolve) => {
    const probe = createNetServer().listen(0, '127.0.0.1', () => {
      const address = probe.address();
      probe.close(() => resolve(typeof address === 'object' && address ? address.port : 0));
    });
  });
const apiPort = await freePort();
const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error('DATABASE_URL is required for the E2E API (see .env.example)');
const api = spawn(process.execPath, ['dist/server.js'], {
  cwd: join(root, 'apps', 'api'),
  env: {
    PATH: process.env.PATH ?? '',
    SystemRoot: process.env.SystemRoot ?? '',
    NODE_ENV: 'development',
    APP_ORIGIN: origin,
    API_HOST: '127.0.0.1',
    API_PORT: String(apiPort),
    LOG_LEVEL: 'warn',
    DATABASE_URL: databaseUrl,
    TOTP_ENCRYPTION_KEY: randomBytes(32).toString('base64url'),
    TOTP_ENCRYPTION_KEY_ID: 'e2e',
    IDENTIFIER_HMAC_KEY: randomBytes(32).toString('base64url'),
    TRUST_PROXY_HOPS: '1',
  },
  stdio: ['ignore', 'inherit', 'inherit'],
});
const stopApi = () => api.kill();
process.on('exit', stopApi);
process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));

// ------------------------------------------------------------------------- static files
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

const CLIENT_HEADER = 'x-e2e-client-address';

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'transfer-encoding',
  'upgrade',
  'proxy-connection',
  'te',
  'trailer',
]);

createServer(tls, (req, res) => {
  const urlPath = new URL(req.url ?? '/', origin).pathname;
  if (urlPath === '/api' || urlPath.startsWith('/api/')) {
    // Reverse proxy: forward everything except hop-by-hop headers, append the client address.
    /** @type {Record<string, string | string[]>} */
    const forward = {};
    for (const [name, value] of Object.entries(req.headers)) {
      if (value !== undefined && !HOP_BY_HOP.has(name) && name !== 'x-forwarded-for' && name !== CLIENT_HEADER) {
        forward[name] = value;
      }
    }
    // Test-only: a test may name its client address from the IPv6 documentation range (RFC 3849),
    // so per-address limits do not couple unrelated tests that all connect from 127.0.0.1. The
    // Vitest suites do the same through X-Forwarded-For. Production Nginx has no such header.
    const requested = req.headers[CLIENT_HEADER];
    forward['x-forwarded-for'] =
      typeof requested === 'string' && /^2001:db8:[0-9a-f:]{1,30}$/i.test(requested)
        ? requested
        : (req.socket.remoteAddress ?? '127.0.0.1');
    const upstream = httpRequest(
      { host: '127.0.0.1', port: apiPort, path: req.url, method: req.method, headers: forward },
      (answer) => {
        res.writeHead(answer.statusCode ?? 502, answer.headers);
        answer.pipe(res);
      },
    );
    upstream.on('error', () => {
      res.writeHead(502).end();
    });
    req.pipe(upstream);
    return;
  }
  void (async () => {
    const found = await resolveFile(urlPath);
    const status = found ? 200 : 404;
    const file = found?.file ?? join(outDir, '404.html');
    const body = found?.body ?? (await readFile(file));
    res.writeHead(status, { ...headers, 'Content-Type': TYPES[extname(file)] ?? 'application/octet-stream' });
    res.end(body);
  })();
}).listen(port, '127.0.0.1', () => {
  console.log(`E2E server at ${origin} (static export and /api proxy)`);
});
