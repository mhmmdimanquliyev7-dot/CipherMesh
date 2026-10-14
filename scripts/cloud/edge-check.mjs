// External checks of a CipherMesh deployment's public edge (ADR-014; evidence EV-17-04, EV-19-05,
// EV-18-04). Run from the operator's workstation or CI against the live cloud, or against the
// local rehearsal. Read-only: GET, HEAD and requests that must be refused; it creates nothing.
//
//   node scripts/cloud/edge-check.mjs --app https://app.example --files https://files.example
//   node scripts/cloud/edge-check.mjs --app https://app.localhost:8443 --files https://files.localhost:8443 \
//     --connect 127.0.0.1 --ca ~/.ciphermesh-rehearsal/rehearsal-ca.crt --http-port 8080 --ports none
//
// --connect   connect to this address instead of resolving the host names (rehearsal)
// --ca        trust this CA certificate in addition to the system store (rehearsal only)
// --ports     comma list of TCP ports that must NOT accept connections from here (default: the
//             database, storage, API, Docker and debug ports); "none" skips the check
// --json      write the JSON report to this file
// Prints one line per check and exits 1 if any check failed. Prints no cookies, keys or URLs
// with signatures; response bodies are not printed.
import { readFileSync, writeFileSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { connect as netConnect } from 'node:net';
import { connect as tlsConnect, rootCertificates } from 'node:tls';

const args = process.argv.slice(2);
/** @param {string} name @returns {string | undefined} */
const option = (name) => {
  const index = args.indexOf(`--${name}`);
  return index === -1 ? undefined : args[index + 1];
};
/** @param {string | undefined} value */
const urlOf = (value) => {
  try {
    return new URL(value ?? '');
  } catch {
    return new URL('invalid:');
  }
};
const app = urlOf(option('app'));
const files = urlOf(option('files'));
if (app.protocol !== 'https:' || files.protocol !== 'https:') {
  console.error('usage: edge-check.mjs --app https://<app host> --files https://<storage host> [options]');
  process.exit(2);
}
const connectAddress = option('connect');
const caFile = option('ca');
const ca = caFile === undefined ? undefined : [...rootCertificates, readFileSync(caFile, 'utf8')];
const httpPort = Number(option('http-port') ?? '80');
const bucket = option('bucket') ?? 'cm-files';
const portsOption = option('ports') ?? '5432,8333,9333,8888,8080,18080,4100,2375,2376,9090,3000';
const ports = portsOption === 'none' ? [] : portsOption.split(',').map(Number);
const jsonFile = option('json');

/** @type {{ id: string, name: string, result: 'PASS' | 'FAIL', detail: string | undefined }[]} */
const results = [];
/** @param {string} id @param {string} name @param {boolean} pass @param {string} [detail] */
function record(id, name, pass, detail) {
  results.push({ id, name, result: pass ? 'PASS' : 'FAIL', detail });
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${id.padEnd(22)} ${name}${detail ? `  (${detail})` : ''}`);
}

/** @type {import('node:net').LookupFunction | undefined} */
const lookup =
  connectAddress === undefined
    ? undefined
    : (_host, options, callback) => {
        if (options.all) callback(null, [{ address: connectAddress, family: 4 }]);
        else callback(null, connectAddress, 4);
      };

/** @param {unknown} error */
const errorCode = (error) => {
  if (!(error instanceof Error)) return 'error';
  return 'code' in error && typeof error.code === 'string' ? error.code : error.message;
};

/**
 * One HTTP(S) request; resolves with status and headers, body discarded.
 * @param {string} url
 * @param {{ method?: string, headers?: Record<string, string>, servername?: string }} [options]
 * @returns {Promise<{ status: number, headers: import('node:http').IncomingHttpHeaders, error?: string }>}
 */
function call(url, { method = 'GET', headers = {}, servername } = {}) {
  const target = new URL(url);
  const isHttps = target.protocol === 'https:';
  const send = isHttps ? httpsRequest : httpRequest;
  return new Promise((resolve) => {
    const req = send(
      target,
      {
        method,
        headers: { 'user-agent': 'ciphermesh-edge-check', ...headers },
        lookup,
        ...(isHttps ? { ca, servername: servername ?? target.hostname } : {}),
        timeout: 15_000,
      },
      (res) => {
        res.resume();
        res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers }));
      },
    );
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (error) => resolve({ status: 0, error: errorCode(error), headers: {} }));
    req.end();
  });
}

/**
 * @typedef {{ ok: true, protocol: string | null, cipher: string | undefined, authorized: boolean,
 *   subject: string | undefined, issuer: string, validTo: string | undefined } | { ok: false, error: string }} TlsResult
 */
/**
 * @param {string} url
 * @param {{ minVersion?: import('node:tls').SecureVersion, maxVersion?: import('node:tls').SecureVersion, servername?: string }} [options]
 * @returns {Promise<TlsResult>}
 */
function tlsProbe(url, { minVersion, maxVersion, servername } = {}) {
  const target = new URL(url);
  return new Promise((resolve) => {
    const socket = tlsConnect({
      host: connectAddress ?? target.hostname,
      port: Number(target.port || 443),
      servername: servername ?? target.hostname,
      ca,
      minVersion,
      maxVersion,
      rejectUnauthorized: true,
      timeout: 10_000,
    });
    socket.on('secureConnect', () => {
      const cert = socket.getPeerCertificate();
      resolve({
        ok: true,
        protocol: socket.getProtocol(),
        cipher: socket.getCipher()?.name,
        authorized: socket.authorized,
        subject: String(cert?.subject?.CN ?? ''),
        issuer: [cert?.issuer?.O, cert?.issuer?.CN].filter(Boolean).join(' / '),
        validTo: cert?.valid_to,
      });
      socket.end();
    });
    socket.on('timeout', () => socket.destroy(new Error('timeout')));
    socket.on('error', (error) => resolve({ ok: false, error: errorCode(error) }));
  });
}

/** @param {string} host @param {number} port @returns {Promise<'open' | 'refused' | 'filtered'>} */
function tcpOpen(host, port) {
  return new Promise((resolve) => {
    const socket = netConnect({ host, port, timeout: 3_000 });
    socket.on('connect', () => {
      socket.destroy();
      resolve('open');
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve('filtered');
    });
    socket.on('error', (error) => resolve(errorCode(error) === 'ECONNREFUSED' ? 'refused' : 'filtered'));
  });
}

const fakeKey = `f/${'A'.repeat(43)}`;
const zeros = '0'.repeat(64);
const forged =
  `X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=cmrt0000000000000000%2F20261014%2Fus-east-1%2Fs3%2Faws4_request` +
  `&X-Amz-Date=20261014T000000Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host&X-Amz-Signature=${zeros}`;

// ------------------------------------------------------------------------------ transport
/** @type {[string, URL][]} */
const origins = [
  ['app', app],
  ['files', files],
];
for (const [label, origin] of origins) {
  const tls = await tlsProbe(origin.href);
  record(
    `TLS-${label}-trusted`,
    `${label} host: certificate chain trusted, host name matches`,
    tls.ok && tls.authorized,
    tls.ok ? `${tls.protocol}, ${tls.cipher}, issuer ${tls.issuer}, valid to ${tls.validTo}` : tls.error,
  );
  const old = await tlsProbe(origin.href, { minVersion: 'TLSv1', maxVersion: 'TLSv1.1' });
  record(
    `TLS-${label}-no-legacy`,
    `${label} host: TLS 1.0 and 1.1 refused`,
    !old.ok,
    old.ok ? String(old.protocol) : 'refused',
  );
  const v12 = await tlsProbe(origin.href, { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' });
  record(
    `TLS-${label}-1.2`,
    `${label} host: TLS 1.2 available (Mozilla intermediate)`,
    v12.ok,
    v12.ok ? v12.cipher : v12.error,
  );
}
const unknown = await tlsProbe(app.href, { servername: 'unknown-name.invalid' });
record('TLS-unknown-sni', 'unknown server name: handshake refused', !unknown.ok, unknown.ok ? 'accepted' : 'refused');

const redirect = await call(`http://${app.hostname}:${httpPort}/rooms`);
record(
  'HTTP-redirect',
  'HTTP redirects to HTTPS',
  redirect.status === 301 && String(redirect.headers.location ?? '').startsWith(`${app.origin}/`),
  `${redirect.status} ${redirect.headers.location ?? ''}`,
);

// ------------------------------------------------------------------------------ app headers
const page = await call(`${app.origin}/`);
const h = page.headers;
const csp = String(h['content-security-policy'] ?? '');
record('APP-page', 'application page served', page.status === 200, String(page.status));
record(
  'HDR-csp',
  "CSP: default-src 'none', no unsafe-inline or unsafe-eval, storage origin in connect-src",
  csp.includes("default-src 'none'") && !/'unsafe-inline'|'unsafe-eval'/.test(csp) && csp.includes(files.origin),
  `${csp.length} characters`,
);
/** @type {Record<string, (value: string) => boolean>} */
const expect = {
  'x-content-type-options': (v) => v === 'nosniff',
  'x-frame-options': (v) => v === 'DENY',
  'referrer-policy': (v) => v === 'no-referrer',
  'cross-origin-opener-policy': (v) => v === 'same-origin',
  'permissions-policy': (v) => v.includes('camera=()'),
  'strict-transport-security': (v) => /^max-age=\d+$/.test(v),
};
for (const [name, ok] of Object.entries(expect)) {
  const value = String(h[name] ?? '');
  record(`HDR-${name}`, `${name} present and correct`, value !== '' && ok(value), value || 'missing');
}
record('HDR-server', 'Server header without version', !/\d/.test(String(h.server ?? '')), String(h.server ?? 'none'));
record('HDR-cors', 'no Access-Control-Allow-Origin on the application', h['access-control-allow-origin'] === undefined);

// ------------------------------------------------------------------------------ app behaviour
const health = await call(`${app.origin}/api/health`);
record('API-health', 'GET /api/health answers 200', health.status === 200, String(health.status));
const ready = await call(`${app.origin}/api/ready`);
record('API-ready', 'GET /api/ready answers 200 (database reachable)', ready.status === 200, String(ready.status));
record(
  'API-no-store',
  'API responses are not cached',
  String(ready.headers['cache-control'] ?? '').includes('no-store'),
);
for (const path of ['/.env', '/.git/config', '/_next/static/x.js.map']) {
  const r = await call(`${app.origin}${path}`);
  record(`APP-deny-${path}`, `${path} not served`, r.status === 404, String(r.status));
}
const post = await call(`${app.origin}/`, { method: 'POST' });
record(
  'APP-static-post',
  'POST to a static page refused',
  post.status === 403 || post.status === 405,
  String(post.status),
);
const crossSite = await call(`${app.origin}/api/auth/login`, {
  method: 'POST',
  headers: {
    origin: 'https://attacker.invalid',
    'sec-fetch-site': 'cross-site',
    'content-type': 'application/json',
    'x-ciphermesh-request': '1',
  },
});
record(
  'CSRF-cross-site',
  'cross-site state-changing request refused through the proxy (INV-19)',
  crossSite.status === 403,
  String(crossSite.status),
);

// ------------------------------------------------------------------------------ storage host
/** @type {[string, string, string, { method?: string, headers?: Record<string, string> }, number[]][]} */
const storage = [
  ['STO-unsigned', 'unsigned object request refused', `/${bucket}/${fakeKey}`, {}, [403]],
  ['STO-list', 'bucket listing refused', `/${bucket}/?list-type=2`, {}, [403]],
  ['STO-root', 'service root and IAM API refused', `/?Action=ListUsers`, { method: 'POST' }, [403]],
  ['STO-master', 'SeaweedFS master and filer paths refused', `/dir/status`, {}, [403]],
  ['STO-other-bucket', 'other buckets refused', `/other-bucket/${fakeKey}`, {}, [403]],
  [
    'STO-cookie',
    'any request with a cookie refused (SF-07-01)',
    `/${bucket}/${fakeKey}?${forged}`,
    { headers: { cookie: 'a=b' } },
    [400],
  ],
  ['STO-forged', 'forged presigned signature refused by storage', `/${bucket}/${fakeKey}?${forged}`, {}, [403]],
];
for (const [id, name, path, options, statuses] of storage) {
  const r = await call(`${files.origin}${path}`, options);
  record(id, name, statuses.includes(r.status), String(r.status));
}

// ------------------------------------------------------------------------------ exposure
if (ports.length > 0) {
  const host = connectAddress ?? app.hostname;
  for (const port of ports) {
    const state = await tcpOpen(host, port);
    record(`PORT-${port}`, `TCP ${port} not reachable from here`, state !== 'open', state);
  }
}

const failed = results.filter((r) => r.result === 'FAIL').length;
const report = {
  check: 'ciphermesh-edge',
  at: new Date().toISOString(),
  app: app.origin,
  files: files.origin,
  passed: results.length - failed,
  failed,
  results,
};
if (jsonFile) writeFileSync(jsonFile, `${JSON.stringify(report, null, 2)}\n`);
console.log(`\n${results.length - failed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
