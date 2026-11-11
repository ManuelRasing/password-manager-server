import { defineConfig } from 'vitest/config'
import { requireTestDatabaseUrl } from './scripts/test-database'

export default defineConfig({
  envDir: false,
  test: {
    env: {
      DATABASE_URL: requireTestDatabaseUrl(process.env.TEST_DATABASE_URL),
      ADMIN_KEY: 'synthetic-test-admin-key',
    },
    // Run serially because the test files share one disposable database.
    fileParallelism: false,
    hookTimeout: 30_000,
    testTimeout: 30_000,
    include: ['test/**/*.test.ts'],
  },
})
