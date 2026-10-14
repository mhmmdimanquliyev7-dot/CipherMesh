#!/usr/bin/env bash
# Full check of the cloud stack on a Linux host (ADR-014): the CI job "Cloud stack (linux/arm64)"
# runs it on GitHub's native arm64 runner, the same architecture as the Oracle A1 VM. It uses the
# local rehearsal (loopback only, throwaway CA), never a cloud account.
#
#   infrastructure/deployment/ci/stack-check.sh <evidence-directory>     (user in the docker group)
#
# Steps: native image build and architecture check; rehearsal stack up (database TLS, roles,
# migrations, bucket); external edge checks; database access rules; deployment smoke test in
# Chromium, Firefox and WebKit with recorded synthetic accounts; worker run; status collection;
# encrypted backup; isolated restore drill; full restore onto empty volumes; browser decryption of
# the restored note and file; resource use.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../../.." && pwd)"
out="${1:?evidence directory}"
mkdir -p "${out}"
out="$(cd "${out}" && pwd)"
cd "${repo}"
export CM_REHEARSAL_DIR="${CM_REHEARSAL_DIR:-/tmp/ciphermesh-rehearsal}"
bin=infrastructure/deployment/bin
pg_image='postgres:17.11-alpine3.24@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24'

step() { printf '\n==== %s\n' "$*" | tee -a "${out}/stack-check.log"; }
# The operator scripts with the rehearsal's paths (cm-rehearsal sets the same for itself).
rehearse() {
  CM_CONFIG="${CM_REHEARSAL_DIR}/cloud.env" CM_RELEASE_DIR="${repo}" CM_SECRETS_DIR="${CM_REHEARSAL_DIR}/secrets" \
    CM_STATUS_DIR="${CM_REHEARSAL_DIR}/status" CM_BACKUP_DIR="${CM_REHEARSAL_DIR}/backups" \
    CM_TLS_DIR="${CM_REHEARSAL_DIR}/tls" CM_ACME_DIR="${CM_REHEARSAL_DIR}/acme" \
    CM_EXTRA_CA_DIR="${CM_REHEARSAL_DIR}/extra-ca" CM_BACKUP_WORK_BASE="${CM_REHEARSAL_DIR}/run" CM_REHEARSAL=1 "$@"
}
build() {
  local target="$1" start=${SECONDS}
  shift
  docker build --quiet -f infrastructure/docker/Dockerfile --target "${target}" -t "ciphermesh-${target}:rehearsal" "$@" . > /dev/null
  echo "${target}: built in $((SECONDS - start)) s"
}

step "host"
{
  uname -sm
  (. /etc/os-release && echo "${PRETTY_NAME}")
  docker version --format 'docker {{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}'
  echo "cpus $(nproc)"
  free -m | head -n 2
} | tee -a "${out}/stack-check.log"

step "native image build"
build api | tee -a "${out}/stack-check.log"
build ops | tee -a "${out}/stack-check.log"
build web --build-arg CM_STORAGE_ORIGIN=https://files.localhost:8443 \
  --build-arg NEXT_PUBLIC_CM_ENVIRONMENT=cloud-demonstration | tee -a "${out}/stack-check.log"
for image in api ops web; do
  docker image inspect "ciphermesh-${image}:rehearsal" --format "ciphermesh-${image}: {{.Os}}/{{.Architecture}} {{.Size}} bytes"
done | tee "${out}/images.txt"
for ref in "${pg_image}" "$(grep -o 'chrislusf/seaweedfs:[^ ]*@sha256:[0-9a-f]*' infrastructure/docker/compose.cloud.yml | head -n 1)"; do
  docker pull --quiet "${ref}" > /dev/null
  docker image inspect "${ref}" --format "${ref%%@*}: {{.Os}}/{{.Architecture}}"
done | tee -a "${out}/images.txt"

step "rehearsal stack"
"${bin}/cm-rehearsal" up 2>&1 | grep -v ' Container \| Network \| Volume ' | tee -a "${out}/stack-check.log"
docker ps --format '{{.Names}}  {{.Status}}  {{.Ports}}' | grep 'ciphermesh-' | tee "${out}/containers.txt"
for name in nginx api postgres object-storage; do
  docker inspect "ciphermesh-${name}-1" --format "${name}: user={{.Config.User}} readonly={{.HostConfig.ReadonlyRootfs}} privileged={{.HostConfig.Privileged}} capdrop={{.HostConfig.CapDrop}} capadd={{.HostConfig.CapAdd}} secopt={{.HostConfig.SecurityOpt}} memory={{.HostConfig.Memory}} published={{.HostConfig.PortBindings}}"
done | tee "${out}/container-hardening.txt"
for network in edge app data storage; do
  docker network inspect "ciphermesh_${network}" --format "network {{.Name}}: internal={{.Internal}} containers={{range .Containers}}{{.Name}} {{end}}"
done | tee -a "${out}/container-hardening.txt"

step "edge checks"
node scripts/cloud/edge-check.mjs --app https://app.localhost:8443 --files https://files.localhost:8443 \
  --connect 127.0.0.1 --ca "${CM_REHEARSAL_DIR}/rehearsal-ca.crt" --http-port 8080 \
  --ports 5432,8333,9333,8888,18080,4100,2375,2376 --json "${out}/edge-check.json" | tee "${out}/edge-check.txt"

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
} | tee "${out}/database-access.txt"
grep -q 'pg_hba.conf rejects connection' "${out}/database-access.txt"
grep -q 'no pg_hba.conf entry' "${out}/database-access.txt"
grep -q '^  postgres|no password' "${out}/database-access.txt"
grep -q '^  cm_api|t|TLSv1.3' "${out}/database-access.txt"

step "deployment smoke test (Chromium, Firefox, WebKit)"
accounts="${CM_REHEARSAL_DIR}/run/smoke-accounts"
CM_SMOKE_APP_ORIGIN=https://app.localhost:8443 CM_SMOKE_TRUST_LOCAL_CA=1 CM_SMOKE_RECORD_ACCOUNTS="${accounts}" \
  pnpm exec playwright test -c playwright.deployment.config.ts cloud-smoke 2>&1 | tee "${out}/smoke.txt"

step "worker run and status collection"
rehearse "${bin}/cm-worker-run" 2>&1 | tail -n 3 | tee -a "${out}/stack-check.log"
rehearse "${bin}/cm-status-collect"
python3 -m json.tool "${CM_REHEARSAL_DIR}/status/host-status.json" | tee "${out}/host-status.json"

step "encrypted backup"
age-keygen -o "${CM_REHEARSAL_DIR}/run/backup-identity.txt" 2> "${CM_REHEARSAL_DIR}/run/recipient.txt"
recipient="$(grep -o 'age1[0-9a-z]*' "${CM_REHEARSAL_DIR}/run/recipient.txt")"
sed -i '/^CM_BACKUP_RECIPIENT=/d' "${CM_REHEARSAL_DIR}/cloud.env"
echo "CM_BACKUP_RECIPIENT=${recipient}" >> "${CM_REHEARSAL_DIR}/cloud.env"
rehearse "${bin}/cm-backup" 2>&1 | tee "${out}/backup.txt"
archive="$(ls -1t "${CM_REHEARSAL_DIR}"/backups/ciphermesh-*.tar.age | head -n 1)"
python3 -m json.tool "${archive%.tar.age}.manifest.json" > "${out}/backup-manifest.json"
echo "plaintext canaries in the encrypted archive (must be 0): $(grep -c 'deployment-canary' "${archive}" || true)" \
  | tee -a "${out}/backup.txt"
grep -q '(must be 0): 0$' "${out}/backup.txt"

step "isolated restore drill"
rehearse "${bin}/cm-restore-drill" "${archive}" < "${CM_REHEARSAL_DIR}/run/backup-identity.txt" 2>&1 | tee "${out}/restore-drill.txt"

step "full restore onto empty volumes"
rehearse docker compose --project-name ciphermesh -f infrastructure/docker/compose.cloud.yml \
  --env-file "${CM_REHEARSAL_DIR}/cloud.env" --profile jobs --profile ops down 2>&1 | tail -n 2
docker volume rm ciphermesh-postgres-data ciphermesh-object-storage-data
cat "${CM_REHEARSAL_DIR}/migrator-password.txt" "${CM_REHEARSAL_DIR}/run/backup-identity.txt" \
  | rehearse "${bin}/cm-restore" "${archive}" 2>&1 | grep -v ' Container \| Network \| Volume ' | tee "${out}/restore.txt"

step "browser decryption after the restore"
CM_SMOKE_APP_ORIGIN=https://app.localhost:8443 CM_SMOKE_TRUST_LOCAL_CA=1 CM_SMOKE_RESTORED_ACCOUNTS="${accounts}" \
  pnpm exec playwright test -c playwright.deployment.config.ts restore-verify 2>&1 | tee "${out}/restore-verify.txt"

step "resource use"
docker stats --no-stream --format '{{.Name}}  cpu {{.CPUPerc}}  mem {{.MemUsage}}' | grep 'ciphermesh-' | tee "${out}/resources.txt"
docker system df | tee -a "${out}/resources.txt"
rm -rf "${accounts}" "${CM_REHEARSAL_DIR}/run/backup-identity.txt"
step "stack check passed"
