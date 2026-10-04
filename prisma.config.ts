import { existsSync } from 'node:fs';
import { defineConfig } from 'prisma/config';

// Prisma CLI configuration (migrations, validation, client generation). The API runtime never
// reads this file: it connects as the least-privilege role from DATABASE_URL (apps/api/src/db).
//
// Migrations run as the migration role (MIGRATION_DATABASE_URL), which owns the schema. That
// credential belongs on a developer machine or a deployment pipeline, never on the VM (TB-05).
// Variables already set in the environment take precedence over the local .env file.
if (existsSync('.env')) process.loadEnvFile('.env');

const migrationUrl = process.env.MIGRATION_DATABASE_URL;

export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrations: { path: 'prisma/migrations' },
  // Absent when only validating or generating the client, which needs no connection.
  ...(migrationUrl === undefined || migrationUrl === '' ? {} : { datasource: { url: migrationUrl } }),
});
