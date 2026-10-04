import type { TestProject } from 'vitest/node';
import { createTestDatabase, dropDatabase } from '../helpers/database';

// One migrated database per test run, shared by the database suite. Tests isolate themselves
// with rolled-back transactions. tests/database/migrations.test.ts creates its own databases to
// test migrations from zero.
declare module 'vitest' {
  export interface ProvidedContext {
    databaseName: string;
  }
}

export default async function setup(project: TestProject): Promise<() => Promise<void>> {
  const database = await createTestDatabase({ migrate: true });
  project.provide('databaseName', database.name);
  return () => dropDatabase(database.name);
}
