import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { buildCsp, extractInlineScripts, findInlineStyles, sha256Source } from './csp-lib.mjs';

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
  const csp = buildCsp(["'sha256-b'", "'sha256-a'", "'sha256-a'"]);

  it('never allows unsafe-inline or unsafe-eval', () => {
    expect(csp).not.toMatch(/unsafe-inline|unsafe-eval/);
  });

  it('lists each script hash once, sorted, after self', () => {
    expect(csp).toContain("script-src 'self' 'sha256-a' 'sha256-b';");
  });

  it('denies by default and forbids framing, plugins and base changes', () => {
    for (const directive of ["default-src 'none'", "frame-ancestors 'none'", "object-src 'none'", "base-uri 'none'"]) {
      expect(csp).toContain(directive);
    }
  });
});
