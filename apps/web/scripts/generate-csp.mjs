// Runs after `next build`. Hashes every executable inline script in the static export,
// writes the response headers Nginx (and the E2E test server) will use, and fails the
// build if the output needs a weaker policy.
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { STATIC_SECURITY_HEADERS, buildCsp, extractInlineScripts, findInlineStyles, sha256Source } from './csp-lib.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const outDir = join(root, 'out');
// Written next to, not inside, the export: the policy file is never served to browsers.
const metaDir = join(root, 'out-meta');

/** @param {string} dir @returns {Promise<string[]>} */
async function htmlFiles(dir) {
  const entries = await readdir(dir, { withFileTypes: true, recursive: true });
  return entries.filter((e) => e.isFile() && e.name.endsWith('.html')).map((e) => join(e.parentPath, e.name));
}

const files = await htmlFiles(outDir);
if (files.length === 0) throw new Error('No HTML files found in out/. Run next build first.');

const hashes = new Set();
const problems = [];
for (const file of files) {
  const html = await readFile(file, 'utf8');
  for (const body of extractInlineScripts(html)) hashes.add(sha256Source(body));
  const styles = findInlineStyles(html);
  if (styles.styleElements > 0 || styles.styleAttributes > 0) {
    problems.push(
      `${relative(root, file)}: ${styles.styleElements} style elements, ${styles.styleAttributes} style attributes`,
    );
  }
}
if (problems.length > 0) {
  throw new Error(`Inline styles would require 'unsafe-inline' in style-src:\n${problems.join('\n')}`);
}

const headers = { 'Content-Security-Policy': buildCsp([...hashes]), ...STATIC_SECURITY_HEADERS };
await mkdir(metaDir, { recursive: true });
await writeFile(join(metaDir, 'security-headers.json'), `${JSON.stringify(headers, null, 2)}\n`);
console.log(`CSP generated for ${files.length} HTML files with ${hashes.size} inline script hashes.`);
