import { defineConfig } from 'vitest/config'
import { config } from 'dotenv'

// Load the test env (DATABASE_URL → isolated `test` schema, ADMIN_KEY, etc.)
// at config-evaluation time, then forward it to the test workers so the Prisma
// client connects to the test schema — never to production `public`.
const testEnv = config({ path: '.env.test' }).parsed ?? {}

export default defineConfig({
  test: {
    env: testEnv,
    // All test files share the one `test` schema — run serially to avoid
    // one file's table-wipe clobbering another's data mid-run.
    fileParallelism: false,
    hookTimeout: 30_000,
    testTimeout: 30_000,
    include: ['test/**/*.test.ts'],
  },
})
