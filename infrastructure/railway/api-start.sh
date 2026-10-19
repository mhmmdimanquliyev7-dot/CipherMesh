#!/bin/sh
# Railway demonstration: the public CA certificate of the database arrives as a variable and is
# written where DATABASE_URL's sslrootcert points. The API still verifies certificate and host name.
set -eu
printf '%s' "${DB_CA_PEM_B64:?}" | base64 -d > /tmp/db-ca.crt
exec node --enable-source-maps "$@"
