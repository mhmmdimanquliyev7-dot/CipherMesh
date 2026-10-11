import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  buildCsp,
  checkStorageOrigin,
  DEFAULT_STORAGE_ORIGIN,
  extractInlineScripts,
  findInlineStyles,
  sha256Source,
} from './csp-lib.mjs';

describe('extractInlineScripts', () => {
  it('returns executable inline scripts and skips external, JSON and empty scripts', () => {
    const html = [
      '<script>self.__next_f.push([1,"a"])</script>',
      '<script type="module">import "x";</script>',
      '<script src="/_next/static/chunk.js"></script>',
      '<script type="application/json">{"data":1}</script>',
      '<script async=""></script>',
    ].join('');
    expect(extractInlineScripts(html)).toEqual(['self.__next_f.push([1,"a"])', 'import "x";']);
  });
});

describe('findInlineStyles', () => {
  it('counts style elements and style attributes outside scripts', () => {
    const html = '<style>p{}</style><div style="color:red"></div><script>var s="<style>"</script>';
    expect(findInlineStyles(html)).toEqual({ styleElements: 1, styleAttributes: 1 });
  });
});

describe('sha256Source', () => {
  it('produces the CSP hash source for the exact script text', () => {
    const expected = createHash('sha256').update('alert(1)').digest('base64');
    expect(sha256Source('alert(1)')).toBe(`'sha256-${expected}'`);
  });
});

describe('buildCsp', () => {
  const csp = buildCsp(["'sha256-b'", "'sha256-a'", "'sha256-a'"], 'https://storage.example');

  it('never allows unsafe-inline or unsafe-eval; WebAssembly compilation is the only relaxation (ADR-010)', () => {
    expect(csp).not.toMatch(/'unsafe-inline'|'unsafe-eval'/);
    // 'wasm-unsafe-eval' appears exactly once, in script-src, and in no other directive.
    expect(csp.match(/wasm-unsafe-eval/g)).toHaveLength(1);
    expect(csp).toMatch(/script-src 'self' 'wasm-unsafe-eval' /);
  });

  it('lists each script hash once, sorted, after self', () => {
    expect(csp).toContain("script-src 'self' 'wasm-unsafe-eval' 'sha256-a' 'sha256-b';");
  });

  it('denies by default and forbids framing, plugins, base changes and native form submission', () => {
    for (const directive of [
      "default-src 'none'",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "base-uri 'none'",
      // SF-04-01: forms are only ever sent by JavaScript; a native submission would put values in the URL.
      "form-action 'none'",
    ]) {
      expect(csp).toContain(directive);
    }
  });

  it('connects only to the API origin and the one object-storage origin; images also from blob: (Phase 7)', () => {
    expect(csp).toContain("connect-src 'self' https://storage.example;");
    expect(csp).toContain("img-src 'self' blob:;");
    expect(csp.match(/blob:/g)).toHaveLength(1);
    expect(() => buildCsp([], "https://storage.example 'unsafe-inline'")).toThrow();
  });
});

describe('checkStorageOrigin', () => {
  it('accepts bare https origins and loopback http, defaulting to the local storage proxy', () => {
    expect(checkStorageOrigin(undefined)).toBe(DEFAULT_STORAGE_ORIGIN);
    expect(checkStorageOrigin('')).toBe(DEFAULT_STORAGE_ORIGIN);
    expect(checkStorageOrigin('https://storage.example')).toBe('https://storage.example');
    expect(checkStorageOrigin('http://127.0.0.1:8333')).toBe('http://127.0.0.1:8333');
  });

  it.each([
    'http://storage.example',
    'https://storage.example/bucket',
    'https://storage.example/',
    '*',
    'https://*.example',
    "https://storage.example 'unsafe-eval'",
    'data:',
    'storage.example',
  ])('refuses %s', (value) => {
    expect(() => checkStorageOrigin(value)).toThrow(/CM_STORAGE_ORIGIN/);
  });
});
