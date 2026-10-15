// Bundles the API with esbuild. Workspace packages (TypeScript sources) are bundled;
// third-party runtime dependencies stay external and come from node_modules.
// Three entry points share the image (infrastructure/docker/Dockerfile): the API server, the
// one-shot worker job and the operator's platform-role CLI, so production needs no tsx.
import { readFile } from 'node:fs/promises';
import { build } from 'esbuild';

const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
const external = Object.entries(manifest.dependencies ?? {})
  .filter(([, range]) => !String(range).startsWith('workspace:'))
  .map(([name]) => name);

await build({
  entryPoints: {
    server: 'src/server.ts',
    'worker-retention': 'src/worker/retention.ts',
    'platform-admin': 'src/cli/platform-admin.ts',
  },
  outdir: 'dist',
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node24',
  external,
  sourcemap: 'linked',
  legalComments: 'none',
  logLevel: 'info',
});
