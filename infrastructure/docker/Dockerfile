# CipherMesh production images (CM-T065, ADR-014). One multi-stage build, three targets:
#   api   the Express API; the same image runs the one-shot worker job and the platform-role CLI
#   web   Nginx with the static export and the generated security headers (ADR-011)
#   ops   operator tasks only (role bootstrap, migrations, storage bootstrap); never long-running
#
# Built natively for linux/arm64 on the Oracle A1 VM or the arm64 CI runner, and for amd64 locally.
# Base images are pinned by digest (T-27). Nothing secret is a build argument: the two build
# arguments are the public storage origin (CSP connect-src) and the environment label.
#
#   docker build -f infrastructure/docker/Dockerfile --target api .
#   docker build -f infrastructure/docker/Dockerfile --target web \
#     --build-arg CM_STORAGE_ORIGIN=https://files.example --build-arg NEXT_PUBLIC_CM_ENVIRONMENT=cloud-demonstration .

ARG NODE_IMAGE=node:24.19.0-alpine3.23@sha256:244cc2b53f46f9e876304391d17682b0ddae9ac33491f4857e25e35a36ba7995
ARG NGINX_IMAGE=nginxinc/nginx-unprivileged:1.30.0-alpine3.23@sha256:808f7846d21a9c94cf53833e8807a00a33fd0b65cc47fb05b79efe366c2d201f

# ------------------------------------------------------------------------------------ build
FROM ${NODE_IMAGE} AS build
# pnpm at the exact version of package.json "packageManager"; npm verifies the registry integrity.
RUN npm install --global --ignore-scripts pnpm@12.6.0 && npm cache clean --force
WORKDIR /src
ENV CHECKPOINT_DISABLE=1 PRISMA_HIDE_UPDATE_MESSAGE=1 NEXT_TELEMETRY_DISABLED=1
# Dependencies first (manifests, lockfile and what the postinstall Prisma generate reads), so a
# source change does not repeat the install.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml prisma.config.ts ./
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
COPY packages/crypto/package.json packages/crypto/
COPY packages/shared/package.json packages/shared/
COPY packages/validation/package.json packages/validation/
COPY scripts/db/prisma.mjs scripts/db/
COPY prisma/schema.prisma prisma/
RUN pnpm install --frozen-lockfile
COPY . .
ARG CM_STORAGE_ORIGIN=
ARG NEXT_PUBLIC_CM_ENVIRONMENT=cloud-demonstration
RUN pnpm --filter @ciphermesh/api build \
 && CM_STORAGE_ORIGIN="${CM_STORAGE_ORIGIN}" NEXT_PUBLIC_CM_ENVIRONMENT="${NEXT_PUBLIC_CM_ENVIRONMENT}" \
    pnpm --filter @ciphermesh/web build \
 && node infrastructure/nginx/render-security-headers.mjs apps/web/out-meta/security-headers.json /src/nginx-security-headers.conf
# Production dependencies of the API only, resolved from the lockfile. pnpm also links the
# optional peers of @prisma/client (the Prisma CLI with Studio, PGlite, TypeScript, React, d3,
# mysql2 and others); the bundle imports only @prisma/client's runtime and the pg adapter, so this
# development tooling is removed from the runtime image. The CI stack check
# runs the API, the worker and the smoke tests against the pruned image.
RUN pnpm --filter @ciphermesh/api deploy --legacy --prod /out/api \
 && cp -r apps/api/dist /out/api/dist \
 && cd /out/api/node_modules/.pnpm \
 && rm -rf prisma@* @prisma+studio-core@* @prisma+dev@* @prisma+config@* @prisma+engines@* \
      @prisma+fetch-engine@* @prisma+get-platform@* @prisma+streams-local@* @prisma+query-plan-executor@* \
      @electric-sql+* typescript@* react@* react-dom@* scheduler@* @radix-ui+* @visx+* d3-* @types+* \
      effect@* fast-check@* pure-rand@* mysql2@* elkjs@* @babel+* lodash@* c12@* jiti@* giget@* \
      chokidar@* readdirp@* valibot@* better-result@* magicast@* \
 && test -d @prisma+client@* && test -d @prisma+adapter-pg@* && test -d express@*
# The Prisma CLI fetches its schema engine on first use; fetch it now, because the ops container
# runs on an internal network without egress.
RUN node scripts/db/prisma.mjs version > /dev/null

# -------------------------------------------------------------------------------------- api
FROM ${NODE_IMAGE} AS api
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build --chown=root:root /out/api/package.json ./package.json
COPY --from=build --chown=root:root /out/api/node_modules ./node_modules
COPY --from=build --chown=root:root /out/api/dist ./dist
# Code is owned by root and read-only to the runtime user (the root filesystem is read-only too).
USER node
EXPOSE 4100
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:4100/api/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
ENTRYPOINT ["node", "--enable-source-maps"]
CMD ["dist/server.js"]

# -------------------------------------------------------------------------------------- ops
FROM build AS ops
# age (LIB-10) for the backup tools on hosts without it (Docker Desktop on Windows); from the
# Alpine repository, signature-checked by apk. Never part of the runtime images.
USER root
RUN apk add --no-cache age
USER node
WORKDIR /src
ENTRYPOINT []
CMD ["node", "scripts/db/prisma.mjs", "version"]

# -------------------------------------------------------------------------------------- web
FROM ${NGINX_IMAGE} AS web
USER root
RUN rm -f /etc/nginx/conf.d/default.conf
COPY infrastructure/nginx/nginx.conf /etc/nginx/nginx.conf
COPY infrastructure/nginx/snippets/ /etc/nginx/cm/
COPY infrastructure/nginx/templates/ /etc/nginx/templates/
COPY --from=build /src/nginx-security-headers.conf /etc/nginx/cm/security-headers.conf
COPY --from=build /src/apps/web/out/ /usr/share/nginx/html/
RUN chmod -R a-w /usr/share/nginx/html /etc/nginx
USER 101
EXPOSE 80 443
