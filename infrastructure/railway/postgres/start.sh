#!/bin/sh
# Writes the TLS material from secret variables, then starts the image's entrypoint.
set -eu
umask 077
mkdir -p /tmp/tls
printf '%s' "${PG_SERVER_CRT_B64:?}" | base64 -d > /tmp/tls/server.crt
printf '%s' "${PG_SERVER_KEY_B64:?}" | base64 -d > /tmp/tls/server.key
chown postgres:postgres /tmp/tls /tmp/tls/server.crt /tmp/tls/server.key
chmod 0600 /tmp/tls/server.key
unset PG_SERVER_KEY_B64 PG_SERVER_CRT_B64
exec docker-entrypoint.sh postgres \
  -c hba_file=/etc/ciphermesh/pg_hba.conf \
  -c listen_addresses='*' \
  -c ssl=on -c ssl_cert_file=/tmp/tls/server.crt -c ssl_key_file=/tmp/tls/server.key \
  -c ssl_min_protocol_version=TLSv1.3 \
  -c password_encryption=scram-sha-256 \
  -c max_connections=40 -c shared_buffers=64MB -c work_mem=2MB -c maintenance_work_mem=32MB \
  -c log_statement=none -c log_parameter_max_length=0 -c log_parameter_max_length_on_error=0 \
  -c log_timezone=UTC -c timezone=UTC
