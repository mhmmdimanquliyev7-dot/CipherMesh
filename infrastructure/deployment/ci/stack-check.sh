#!/usr/bin/env bash
# Full check of the CipherMesh production stack on one machine (ADR-014): the CI job
# "Cloud stack (linux/arm64)" runs it on GitHub's native arm64 runner (the Oracle A1 architecture),
# and `pnpm demo:verify` runs it on a laptop with Docker Desktop (Git Bash on Windows). It uses the
# local rehearsal (loopback only, throwaway CA): evidence from it is local or CI evidence, never
# cloud evidence.
#
#   infrastructure/deployment/ci/stack-check.sh <evidence-directory>
#   CM_SKIP_BUILD=1 ...      reuse the existing rehearsal images (the laptop)
#
# Steps: image build and architecture; stack up (database TLS, roles, migrations, bucket); container
# hardening and networks; external edge checks; database access rules; deployment smoke test and
# the collaboration test (invitation, burn secret, removal, key rotation) in Chromium, Firefox and
# WebKit; worker run; status collection; encrypted backup; isolated restore drill; full restore onto
# empty volumes; browser decryption of the restored note and file; resource use.
set -Eeuo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
repo="$(cd "$(dirname "$0")/../../.." && pwd)"
out="${1:?evidence directory}"
mkdir -p "${out}"
out="$(cd "${out}" && pwd)"
cd "${repo}"
native() { if command -v cygpath > /dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }
export CM_REHEARSAL_DIR="$(native "${CM_REHEARSAL_DIR:-${HOME}/.ciphermesh-rehearsal}")"
rehearsal=infrastructure/deployment/bin/cm-rehearsal
pg_image='postgres:17.11-alpine3.24@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24'
python=python3; python3 -c "import json" > /dev/null 2>&1 || python=python

step() { printf '\n==== %s\n' "$*" | tee -a "${out}/stack-check.log"; }
# On failure: container states and the last log lines of each (synthetic data, no secrets logged).
diagnose() {
  docker ps -a --format '{{.Names}}  {{.Status}}' | grep 'ciphermesh-' > "${out}/failure-containers.txt" || true
  for name in $(docker ps -a --format '{{.Names}}' | grep '^ciphermesh-'); do
    docker logs --tail 40 "${name}" > "${out}/failure-log-${name}.txt" 2>&1 || true
  done
}
trap 'diagnose' ERR

step "host"
{
  uname -sm
  docker version --format 'docker {{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}'
  docker info --format 'Docker host: {{.OperatingSystem}}, {{.NCPU}} CPUs, {{.MemTotal}} bytes of memory'
} | tee -a "${out}/stack-check.log"

if [[ "${CM_SKIP_BUILD:-}" != 1 ]]; then
  step "image build"
  "${rehearsal}" build 2>&1 | tee -a "${out}/stack-check.log"
fi
for image in api ops web; do
  docker image inspect "ciphermesh-${image}:rehearsal" --format "ciphermesh-${image}: {{.Os}}/{{.Architecture}} {{.Size}} bytes"
done | tee "${out}/images.txt"
for ref in "${pg_image}" "$(grep -o 'chrislusf/seaweedfs:[^ ]*@sha256:[0-9a-f]*' infrastructure/docker/compose.cloud.yml | head -n 1)"; do
  docker pull --quiet "${ref}" > /dev/null
  docker image inspect "${ref}" --format "${ref%%@*}: {{.Os}}/{{.Architecture}}"
done | tee -a "${out}/images.txt"

step "stack up"
"${rehearsal}" up 2>&1 | grep -v ' Container \| Network \| Volume \|migration.sql\|└─' | tee -a "${out}/stack-check.log"
docker ps --format '{{.Names}}  {{.Status}}  {{.Ports}}' | grep 'ciphermesh-' | grep -v 'ciphermesh-dev-' | tee "${out}/containers.txt"
for name in nginx api postgres object-storage; do
  docker inspect "ciphermesh-${name}-1" --format "${name}: user={{.Config.User}} readonly={{.HostConfig.ReadonlyRootfs}} privileged={{.HostConfig.Privileged}} capdrop={{.HostConfig.CapDrop}} capadd={{.HostConfig.CapAdd}} secopt={{.HostConfig.SecurityOpt}} memory={{.HostConfig.Memory}} published={{.HostConfig.PortBindings}}"
done | tee "${out}/container-hardening.txt"
# Names only: no secret may be an environment variable (CM-T071); values are never printed.
{
  printf 'api environment variable names: '
  docker inspect ciphermesh-api-1 --format '{{range .Config.Env}}{{println .}}{{end}}' | cut -d= -f1 | sort | paste -sd' ' -
  printf 'api secret files: '
  docker inspect ciphermesh-api-1 --format '{{range .Mounts}}{{println .Destination}}{{end}}' | grep '^/run/secrets/' | sort | paste -sd' ' -
} | tee -a "${out}/container-hardening.txt"
if docker inspect ciphermesh-api-1 --format '{{range .Config.Env}}{{println .}}{{end}}' \
  | grep -Eq '^(DATABASE_URL|TOTP_ENCRYPTION_KEY|IDENTIFIER_HMAC_KEY|STORAGE_SECRET_ACCESS_KEY)='; then
  echo 'a secret is an environment variable of the API container'
  exit 1
fi
for network in edge app data storage; do
  docker network inspect "ciphermesh_${network}" --format "network {{.Name}}: internal={{.Internal}} containers={{range .Containers}}{{.Name}} {{end}}"
done | tee -a "${out}/container-hardening.txt"

step "edge checks"
# 5432 is left out: a developer laptop may run its own PostgreSQL; the stack publishes no database
# port (published= above), and the cloud check scans it from outside (EV-19-05).
node scripts/cloud/edge-check.mjs --app https://app.localhost:8443 --files https://files.localhost:8443 \
  --connect 127.0.0.1 --ca "${CM_REHEARSAL_DIR}/rehearsal-ca.crt" --http-port 8080 \
  --ports 9333,8888,18080,4100,2375,2376 --json "${out}/edge-check.json" | tee "${out}/edge-check.txt"

step "database access rules"
{
  echo "-- runtime role without TLS from the data network (pg_hba must reject it):"
  docker run --rm --network ciphermesh_data -e PGPASSWORD=not-the-password -e PGSSLMODE=disable --entrypoint psql \
    "${pg_image}" -h postgres -U cm_api -d ciphermesh -c 'select 1' 2>&1 | sed 's/^/  /' || true
  echo "-- superuser over the network with TLS (no line allows it, and it has no password):"
  docker run --rm --network ciphermesh_data -e PGPASSWORD=guess -e PGSSLMODE=require --entrypoint psql \
    "${pg_image}" -h postgres -U postgres -d postgres -c 'select 1' 2>&1 | sed 's/^/  /' || true
  echo "-- TLS of the running API's connections (pg_stat_ssl):"
  docker exec -u postgres ciphermesh-postgres-1 psql -X -At -d postgres -c \
    "select a.usename, s.ssl, s.version from pg_stat_ssl s join pg_stat_activity a using (pid) where a.usename like 'cm_%' group by 1, 2, 3" \
    | sed 's/^/  /'
  echo "-- superuser password:"
  docker exec -u postgres ciphermesh-postgres-1 psql -X -At -d postgres -c \
    "select rolname, case when rolpassword is null then 'no password' else 'HAS A PASSWORD' end from pg_authid where rolname = 'postgres'" \
    | sed 's/^/  /'
  echo "-- the storage network from the database network (the API's database network cannot reach SeaweedFS):"
  docker run --rm --network ciphermesh_data --entrypoint sh "${pg_image}" -c \
    'nc -z -w 3 object-storage 8333 && echo "  object-storage reachable" || echo "  object-storage not reachable"'
} | tee "${out}/database-access.txt"
grep -q 'pg_hba.conf rejects connection' "${out}/database-access.txt"
grep -q 'no pg_hba.conf entry' "${out}/database-access.txt"
grep -q '^  postgres|no password' "${out}/database-access.txt"
grep -q '^  cm_api|t|TLSv1.3' "${out}/database-access.txt"
grep -q '^  object-storage not reachable' "${out}/database-access.txt"

step "browser tests: deployment smoke and collaboration (Chromium, Firefox, WebKit)"
accounts="${CM_REHEARSAL_DIR}/run/smoke-accounts"
CM_SMOKE_APP_ORIGIN=https://app.localhost:8443 CM_SMOKE_TRUST_LOCAL_CA=1 CM_SMOKE_RECORD_ACCOUNTS="${accounts}" \
  pnpm exec playwright test -c playwright.deployment.config.ts cloud-smoke collaboration 2>&1 | tee "${out}/browser-tests.txt"

step "worker run and status collection"
"${rehearsal}" worker 2>&1 | tail -n 3 | tee -a "${out}/stack-check.log"
"${rehearsal}" status
"${python}" -m json.tool "${CM_REHEARSAL_DIR}/status/host-status.json" | tee "${out}/host-status.json"

step "encrypted backup"
"${rehearsal}" backup 2>&1 | grep -v ' Container ' | tee "${out}/backup.txt"
archive="$(ls -1t "${CM_REHEARSAL_DIR}"/backups/ciphermesh-*.tar.age | head -n 1)"
"${python}" -m json.tool "${archive%.tar.age}.manifest.json" > "${out}/backup-manifest.json"
echo "plaintext canaries in the encrypted archive (must be 0): $(grep -c 'deployment-canary' "${archive}" || true)" \
  | tee -a "${out}/backup.txt"
grep -q '(must be 0): 0$' "${out}/backup.txt"

step "isolated restore drill"
"${rehearsal}" drill 2>&1 | tee "${out}/restore-drill.txt"

step "screenshots of the running demonstration (Chromium)"
"${rehearsal}" status
CM_SMOKE_APP_ORIGIN=https://app.localhost:8443 CM_SMOKE_TRUST_LOCAL_CA=1 CM_DEMO_EVIDENCE_DIR="${out}/screenshots" \
  pnpm exec playwright test -c playwright.deployment.config.ts demo-evidence --project=chromium 2>&1 | tee "${out}/screenshots.txt"

step "full restore onto empty volumes"
"${rehearsal}" down 2>&1 | tail -n 1
docker volume rm ciphermesh-postgres-data ciphermesh-object-storage-data
"${rehearsal}" restore 2>&1 | grep -v ' Container \| Network \| Volume ' | tee "${out}/restore.txt"

step "browser decryption after the restore"
CM_SMOKE_APP_ORIGIN=https://app.localhost:8443 CM_SMOKE_TRUST_LOCAL_CA=1 CM_SMOKE_RESTORED_ACCOUNTS="${accounts}" \
  pnpm exec playwright test -c playwright.deployment.config.ts restore-verify 2>&1 | tee "${out}/restore-verify.txt"

step "resource use"
docker stats --no-stream --format '{{.Name}}  cpu {{.CPUPerc}}  mem {{.MemUsage}}' | grep 'ciphermesh-' | grep -v 'ciphermesh-dev-' \
  | tee "${out}/resources.txt"
rm -rf "${accounts}"
step "stack check passed"
