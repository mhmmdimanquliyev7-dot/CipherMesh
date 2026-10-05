import type { NextConfig } from 'next';

// ADR-011: static export only. No server-side rendering at runtime, no middleware,
// no API routes and no server actions. Nginx serves the files from `out/`.
const nextConfig: NextConfig = {
  output: 'export',
  reactStrictMode: true,
  poweredByHeader: false,
  productionBrowserSourceMaps: false,
  // Workspace packages ship TypeScript sources.
  transpilePackages: ['@ciphermesh/shared', '@ciphermesh/validation', '@ciphermesh/crypto'],
  images: { unoptimized: true },
};

export default nextConfig;
