/**
 * The web client's only configuration. Everything here is compiled into the public
 * JavaScript bundle, so only NEXT_PUBLIC_ values may be read and none may be secret.
 * This is the only web module allowed to read process.env (ESLint enforces this).
 */
function readApiBasePath(): string {
  const value = process.env['NEXT_PUBLIC_API_BASE_PATH'] ?? '/api';
  // Same-origin API only (ADR-011, INV-19): a relative path, never a full URL.
  if (!/^\/[a-z0-9/-]*$/.test(value) || value.startsWith('//')) {
    throw new Error('NEXT_PUBLIC_API_BASE_PATH must be a same-origin path such as /api');
  }
  return value;
}

/**
 * Which environment this build was made for (Phase 14, CM-T061). A build-time label only: it is
 * shown so nobody mistakes a development build for the cloud deployment, and it is never
 * presented as a verification of anything. Unknown values fail the build.
 */
export const DEPLOYMENT_ENVIRONMENTS = ['development', 'local-docker', 'cloud-demonstration'] as const;
export type DeploymentEnvironment = (typeof DEPLOYMENT_ENVIRONMENTS)[number];

function readDeploymentEnvironment(): DeploymentEnvironment {
  const value = process.env['NEXT_PUBLIC_CM_ENVIRONMENT'] ?? 'development';
  const known = DEPLOYMENT_ENVIRONMENTS.find((environment) => environment === value);
  if (known === undefined) {
    throw new Error(`NEXT_PUBLIC_CM_ENVIRONMENT must be one of ${DEPLOYMENT_ENVIRONMENTS.join(', ')}`);
  }
  return known;
}

export const publicEnv = Object.freeze({
  apiBasePath: readApiBasePath(),
  deploymentEnvironment: readDeploymentEnvironment(),
});
