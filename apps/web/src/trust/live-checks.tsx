'use client';

import { healthResponseSchema } from '@ciphermesh/validation';
import { useCallback, useEffect, useState } from 'react';
import { Icon, type IconName } from '../components/icons';
import { Badge, SecondaryButton } from '../components/ui';
import { publicEnv } from '../config/public-env';
import { api, ApiError } from '../lib/api';

/**
 * Live checks run by this browser against the deployment that served it (Phase 14 + Prompt 16.5,
 * CM-T061). They use only what any visitor can observe: the page's protocol, the headers of a
 * same-origin response, and the public liveness and readiness probes, which return a status word.
 * No credentials, no internal endpoint, no polling: the checks run once and on request. A missing
 * header is reported as missing; nothing is assumed from configuration files.
 */

type Outcome = 'pass' | 'fail' | 'absent' | 'unavailable';
interface Result {
  readonly id: string;
  readonly name: string;
  readonly icon: IconName;
  readonly outcome: Outcome;
  readonly detail: string;
}

const OUTCOME = {
  pass: { tone: 'success', label: 'Observed', icon: 'checkCircle' },
  fail: { tone: 'danger', label: 'Failed', icon: 'xCircle' },
  absent: { tone: 'warning', label: 'Not configured here', icon: 'minusCircle' },
  unavailable: { tone: 'neutral', label: 'Unavailable', icon: 'dashedCircle' },
} as const;

const HEADER_CHECKS: readonly { name: string; header: string; ok: (value: string) => boolean; expect: string }[] = [
  {
    name: 'Content-Security-Policy',
    header: 'content-security-policy',
    ok: (v) => v.includes("default-src 'none'") && !/'unsafe-inline'|'unsafe-eval'/.test(v),
    expect: "default-src 'none', no unsafe-inline or unsafe-eval",
  },
  { name: 'X-Content-Type-Options', header: 'x-content-type-options', ok: (v) => v === 'nosniff', expect: 'nosniff' },
  { name: 'X-Frame-Options', header: 'x-frame-options', ok: (v) => v.toUpperCase() === 'DENY', expect: 'DENY' },
  { name: 'Referrer-Policy', header: 'referrer-policy', ok: (v) => v === 'no-referrer', expect: 'no-referrer' },
  {
    name: 'Cross-Origin-Opener-Policy',
    header: 'cross-origin-opener-policy',
    ok: (v) => v === 'same-origin',
    expect: 'same-origin',
  },
  {
    name: 'Permissions-Policy',
    header: 'permissions-policy',
    ok: (v) => v.includes('camera=()'),
    expect: 'camera=() and others',
  },
];

async function pageHeaders(): Promise<Headers | undefined> {
  try {
    const response = await fetch(window.location.pathname, { method: 'HEAD', cache: 'no-store', credentials: 'omit' });
    return response.ok ? response.headers : undefined;
  } catch {
    return undefined;
  }
}

async function probe(path: '/ready'): Promise<'ready' | 'not-ready' | 'unreachable'> {
  try {
    const response = await fetch(`${publicEnv.apiBasePath}${path}`, { cache: 'no-store', credentials: 'omit' });
    // Drain the body (a status word): an unread body keeps the request open.
    await response.text().catch(() => '');
    if (response.status === 200) return 'ready';
    return response.status === 503 ? 'not-ready' : 'unreachable';
  } catch {
    return 'unreachable';
  }
}

async function runChecks(): Promise<readonly Result[]> {
  const results: Result[] = [];
  const https = window.location.protocol === 'https:';
  results.push({
    id: 'https',
    name: 'HTTPS for this page',
    icon: 'lock',
    outcome: https && window.isSecureContext ? 'pass' : 'fail',
    detail: https ? `Served over HTTPS from ${window.location.host}.` : 'This page was not served over HTTPS.',
  });

  let alive: Outcome = 'unavailable';
  let aliveDetail = 'The API did not answer.';
  try {
    await api('GET', '/health', healthResponseSchema);
    alive = 'pass';
    aliveDetail = 'GET /health answered “ok”.';
  } catch (error) {
    if (error instanceof ApiError) aliveDetail = `GET /health answered ${String(error.status)}.`;
  }
  results.push({ id: 'health', name: 'API liveness', icon: 'server', outcome: alive, detail: aliveDetail });

  const ready = await probe('/ready');
  results.push({
    id: 'ready',
    name: 'API readiness (includes PostgreSQL)',
    icon: 'database',
    outcome: ready === 'ready' ? 'pass' : ready === 'not-ready' ? 'fail' : 'unavailable',
    detail:
      ready === 'ready'
        ? 'GET /ready answered “ready”: the API reached the database.'
        : ready === 'not-ready'
          ? 'GET /ready answered “not-ready”.'
          : 'GET /ready did not answer.',
  });

  const headers = await pageHeaders();
  for (const check of HEADER_CHECKS) {
    const value = headers?.get(check.header) ?? null;
    results.push({
      id: check.header,
      name: check.name,
      icon: 'browser',
      outcome: headers === undefined ? 'unavailable' : value === null ? 'absent' : check.ok(value) ? 'pass' : 'fail',
      detail:
        headers === undefined
          ? 'The response headers could not be read.'
          : value === null
            ? `Not sent by this server. Expected: ${check.expect}.`
            : check.ok(value)
              ? `Sent as expected (${check.expect}).`
              : `Sent, but not as expected (${check.expect}).`,
    });
  }
  const hsts = headers?.get('strict-transport-security') ?? null;
  results.push({
    id: 'hsts',
    name: 'Strict-Transport-Security',
    icon: 'lock',
    outcome: headers === undefined ? 'unavailable' : hsts === null ? 'absent' : 'pass',
    detail:
      hsts === null
        ? 'Not sent. HSTS is added at the TLS edge after a staged rollout (CP-21, cloud workstream).'
        : 'Sent by this server.',
  });
  return results;
}

export function LiveChecks() {
  const [results, setResults] = useState<readonly Result[] | undefined>();
  const [at, setAt] = useState<string | undefined>();
  const [running, setRunning] = useState(false);

  const run = useCallback(async () => {
    setRunning(true);
    try {
      setResults(await runChecks());
      setAt(new Date().toLocaleString());
    } finally {
      setRunning(false);
    }
  }, []);

  useEffect(() => {
    void run();
  }, [run]);

  return (
    <div className="space-y-4" data-testid="live-checks">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-slate-400">
          {at === undefined ? 'Running…' : `Measured by this browser at ${at}.`} These are observations of the server
          that served this page, not monitoring of other environments.
        </p>
        <SecondaryButton type="button" disabled={running} onClick={() => void run()}>
          <Icon name="rotate" className="size-4" />
          {running ? 'Checking…' : 'Run the checks again'}
        </SecondaryButton>
      </div>
      {results === undefined ? null : (
        <ul className="grid gap-2 md:grid-cols-2" aria-label="Live check results">
          {results.map((result) => {
            const outcome = OUTCOME[result.outcome];
            return (
              <li
                key={result.id}
                className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/50 px-3 py-2.5"
                data-testid={`live-check-${result.id}`}
                data-outcome={result.outcome}
              >
                <Icon name={result.icon} className="mt-0.5 size-4 text-slate-400" />
                <span className="min-w-0 flex-1 space-y-0.5">
                  <span className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-sm font-medium text-white">{result.name}</span>
                    <Badge tone={outcome.tone} icon={outcome.icon}>
                      {outcome.label}
                    </Badge>
                  </span>
                  <span className="block text-xs text-slate-400">{result.detail}</span>
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
