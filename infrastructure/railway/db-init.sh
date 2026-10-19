#!/bin/sh
# One-off database initialization for the Railway demonstration (docs/deployment/railway-demo.md),
# run by a temporary service built from the ops image and deleted afterwards. Variables (secret):
# POSTGRES_HOST, POSTGRES_PASSWORD (temporary superuser password), MIGRATION_DATABASE_URL,
# DATABASE_URL, WORKER_DATABASE_URL, VERIFIER_DATABASE_URL (loopback-form carriers of the role
# passwords), DB_CA_PEM_B64 (the public CA certificate).
set -eu
umask 077
printf '%s' "${DB_CA_PEM_B64:?}" | base64 -d > /tmp/db-ca.crt
export POSTGRES_PORT=5432 POSTGRES_USER=postgres POSTGRES_DB=postgres POSTGRES_SSL_CA_FILE=/tmp/db-ca.crt
echo 'step 1: roles and database'
# bootstrap.mjs reads only the migrator's password from its URL and insists on a loopback host.
REAL_MIGRATION_URL="${MIGRATION_DATABASE_URL}"
MIGRATION_DATABASE_URL="$(printf '%s' "${REAL_MIGRATION_URL}" | sed -E 's#@[^/@]+/#@127.0.0.1:5432/#; s#\?.*$##')" node scripts/db/bootstrap.mjs
export MIGRATION_DATABASE_URL="${REAL_MIGRATION_URL}"
echo 'step 2: migrations as cm_migrator'
node scripts/db/prisma.mjs migrate deploy
node scripts/db/prisma.mjs migrate status
echo 'step 3: removing the temporary superuser password'
node --input-type=module -e "
import pg from 'pg';
import { readFileSync } from 'node:fs';
const c = new pg.Client({ host: process.env.POSTGRES_HOST, port: 5432, user: 'postgres', password: process.env.POSTGRES_PASSWORD, database: 'postgres',
  ssl: { ca: readFileSync('/tmp/db-ca.crt', 'utf8'), rejectUnauthorized: true, servername: process.env.POSTGRES_HOST } });
await c.connect();
await c.query('ALTER ROLE postgres PASSWORD NULL');
await c.end();
console.log('superuser password removed');
"
echo 'database initialized'
