import { spawnSync } from 'node:child_process'
import { requireTestDatabaseUrl } from './test-database'

const databaseUrl = requireTestDatabaseUrl(process.env.TEST_DATABASE_URL)
const prismaCli = require.resolve('prisma/build/index.js')
const result = spawnSync(
  process.execPath,
  [prismaCli, 'db', 'push', '--skip-generate'],
  {
    env: { ...process.env, DATABASE_URL: databaseUrl },
    stdio: 'inherit',
  },
)

if (result.error) throw result.error
process.exitCode = result.status ?? 1
