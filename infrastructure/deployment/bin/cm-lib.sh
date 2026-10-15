# Shared helpers of the CipherMesh operator scripts (ADR-014). Sourced, never executed.
# Rules for every script (CLAUDE.md sections 8 and 9):
#   - never print a secret: values are read from files or standard input, never from arguments;
#   - never delete a volume, a backup or data; destructive steps need an explicit flag;
#   - fail on the first error (set -euo pipefail) and say which step failed.
set -euo pipefail
umask 077

# The VM layout (infrastructure/deployment/README.md). Every path can be overridden, which the
# local rehearsal (cm-rehearsal) uses on a development machine.
: "${CM_HOME:=/srv/ciphermesh}"
: "${CM_CONFIG:=${CM_HOME}/config/cloud.env}"
: "${CM_SECRETS_DIR:=${CM_HOME}/secrets}"
: "${CM_RELEASE_DIR:=${CM_HOME}/release}"
: "${CM_STATUS_DIR:=/var/lib/ciphermesh/status}"
: "${CM_BACKUP_DIR:=/var/backups/ciphermesh}"
: "${CM_TLS_DIR:=/etc/ciphermesh/tls}"
: "${CM_ACME_DIR:=/var/www/acme}"
export CM_HOME CM_CONFIG CM_SECRETS_DIR CM_RELEASE_DIR CM_STATUS_DIR CM_BACKUP_DIR CM_TLS_DIR CM_ACME_DIR

# Pinned like compose.cloud.yml; used for one-off helper containers (volume installs, backups).
CM_POSTGRES_IMAGE='postgres:17.11-alpine3.24@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24'
CM_SEAWEEDFS_IMAGE='chrislusf/seaweedfs:4.47@sha256:ce9e796f1fe6f06968f4c04bdaf8f678dad9c8acdfef3d244133d71bfa6bf882'

# Python for small JSON tasks: python3 on the VM, python on Windows (Git Bash).
# On Windows, python3 may be the Microsoft Store stub, so the interpreter must actually run.
CM_PYTHON=''
for candidate in python3 python; do
  if "${candidate}" -c 'import json' > /dev/null 2>&1; then
    CM_PYTHON="${candidate}"
    break
  fi
done

# age (LIB-10): the host's binary when installed (the VM), otherwise the one in the ops image
# (Docker Desktop on Windows). The container has no network and sees only standard input and,
# for decryption, the identity file's directory read-only.
cm_age_encrypt() { # <recipient> < plaintext > ciphertext
  if command -v age > /dev/null 2>&1; then
    age -r "$1"
  else
    docker run --rm -i --network none --entrypoint age "ciphermesh-ops:${CM_RELEASE}" -r "$1"
  fi
}
cm_age_decrypt() { # <identity file> < ciphertext > plaintext
  if command -v age > /dev/null 2>&1; then
    age -d -i "$1"
  else
    docker run --rm -i --network none -v "$(dirname "$1"):/identity:ro" --entrypoint age \
      "ciphermesh-ops:${CM_RELEASE}" -d -i "/identity/$(basename "$1")"
  fi
}
cm_age_keygen() { # > identity file (the public key is on its comment line)
  if command -v age-keygen > /dev/null 2>&1; then
    age-keygen 2> /dev/null
  else
    docker run --rm --network none --entrypoint age-keygen "ciphermesh-ops:${CM_RELEASE}" 2> /dev/null
  fi
}

cm_info() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
cm_die() {
  printf '[%s] ERROR: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2
  exit 1
}

# Reads KEY=value pairs of the non-secret configuration file into the environment.
cm_load_config() {
  [[ -r "${CM_CONFIG}" ]] || cm_die "configuration ${CM_CONFIG} not found (copy cloud.env.example)"
  set -a
  # shellcheck disable=SC1090
  . "${CM_CONFIG}"
  set +a
  local name
  for name in CM_APP_HOST CM_FILES_HOST CM_RELEASE; do
    [[ -n "${!name:-}" ]] || cm_die "${name} is not set in ${CM_CONFIG}"
  done
  [[ "${CM_APP_HOST}" != "${CM_FILES_HOST}" ]] || cm_die 'CM_APP_HOST and CM_FILES_HOST must differ (SF-07-01)'
  # Origins as browsers see them; they carry a port only in the local rehearsal.
  : "${CM_APP_ORIGIN:=https://${CM_APP_HOST}}"
  : "${CM_FILES_ORIGIN:=https://${CM_FILES_HOST}}"
  export CM_APP_ORIGIN CM_FILES_ORIGIN
}

cm_compose() {
  docker compose \
    --project-name ciphermesh \
    --file "${CM_RELEASE_DIR}/infrastructure/docker/compose.cloud.yml" \
    --env-file "${CM_CONFIG}" "$@"
}

cm_require() {
  local tool
  for tool in "$@"; do command -v "${tool}" > /dev/null 2>&1 || cm_die "${tool} is required"; done
}

# 32 random bytes, base64url without padding (the API's key format).
cm_random_key() { openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=\r\n'; }
# A random password of hex characters (safe in URLs and JSON without escaping).
cm_random_hex() { openssl rand -hex "${1:-24}" | tr -d '\r\n'; }

# Reads one line from standard input into the named variable, without a trailing CR.
cm_read_line() {
  local line=''
  IFS= read -r line || true
  printf -v "$1" '%s' "${line%$'\r'}"
}

# Writes standard input to a file atomically with mode 0600.
cm_write_private() {
  local target="$1" tmp
  tmp="$(mktemp "${target}.XXXXXX")"
  cat > "${tmp}"
  chmod 600 "${tmp}"
  mv -f "${tmp}" "${target}"
}

# Reads a value from a KEY=value file without sourcing it (values may contain shell characters).
cm_env_value() {
  local file="$1" key="$2" line
  line="$(grep -E "^${key}=" "${file}" | tail -n 1 || true)"
  [[ -n "${line}" ]] || cm_die "${key} missing in ${file}"
  printf '%s' "${line#*=}"
}

# Restores a SeaweedFS data volume from a tar archive on standard input. BusyBox tar as root does
# not give the volume root back to its owner, and SeaweedFS runs as uid 1000 (compose.cloud.yml),
# so the whole tree is handed to uid 1000 afterwards.
cm_restore_storage_volume() { # <volume> < archive
  docker volume create "$1" > /dev/null
  docker run --rm -i -v "$1:/data" --network none --entrypoint sh "${CM_POSTGRES_IMAGE}" \
    -c 'tar -C /data -xf - && chown -R 1000:1000 /data'
}

# Waits until the S3 gateway of a SeaweedFS container answers HTTP (an unsigned request is refused
# with 403 once the filer behind it is ready); fails after two minutes.
cm_wait_s3() { # <container>
  local _ answer
  for _ in $(seq 1 120); do
    # wget exits non-zero on the expected 403, so its output is captured first: in a pipeline
    # under pipefail that exit status would hide grep's match.
    answer="$(docker exec "$1" wget -S -O /dev/null http://127.0.0.1:8333/ 2>&1 || true)"
    grep -q 'HTTP/1.1 [0-9]' <<< "${answer}" && return 0
    sleep 1
  done
  cm_die "object storage in $1 did not become ready"
}

# Runs SQL from standard input as the superuser over the container socket (peer authentication).
# Arguments: the database, then extra psql options (for example -At).
cm_psql_superuser() {
  cm_compose exec -T -u postgres postgres psql -X -q -v ON_ERROR_STOP=1 --dbname "${1:-postgres}" "${@:2}"
}
