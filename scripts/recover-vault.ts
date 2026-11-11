import { readFileSync } from 'node:fs'
import { link, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import type { PrismaClient } from '@prisma/client'
import {
  createRecoveryBackup,
  type VaultSnapshot,
  RecoveryError,
  restoreRecoveryBackup
} from './recovery-backup'
import { readRecoverySnapshot, restoreVaultSnapshot } from './vault-snapshot'

function getDatabaseUrl(operation: 'create' | 'restore'): string {
  const connection = process.env.RECOVERY_DATABASE_URL
  if (!connection) throw new RecoveryError('Set RECOVERY_DATABASE_URL to the intended database')

  let target: URL
  try {
    target = new URL(connection)
  } catch {
    throw new RecoveryError('RECOVERY_DATABASE_URL must be a PostgreSQL URL')
  }
  if (target.protocol !== 'postgresql:' && target.protocol !== 'postgres:') {
    throw new RecoveryError('RECOVERY_DATABASE_URL must be a PostgreSQL URL')
  }
  if (operation === 'restore' &&
      (!['127.0.0.1', '[::1]'].includes(target.hostname) ||
       !/^\/password_manager_recovery(?:_[a-z0-9]+)*$/.test(target.pathname) ||
       target.search || target.hash)) {
    throw new RecoveryError('Restore requires a local password_manager_recovery database with no URL options')
  }
  return connection
}

async function readVault(prisma: PrismaClient, username: string): Promise<VaultSnapshot> {
  return prisma.$transaction((tx) => readRecoverySnapshot(tx, username),
    { isolationLevel: 'RepeatableRead' })
}

async function writeBackup(path: string, body: string): Promise<void> {
  const directory = await mkdtemp(join(dirname(path), '.vault-recovery-'))
  try {
    const temporaryFile = join(directory, 'backup.json')
    await writeFile(temporaryFile, body, { mode: 0o600 })
    // Publish only a complete archive, without replacing an existing backup.
    await link(temporaryFile, path)
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}

async function main(): Promise<void> {
  const [operation, username, path, ...extraArgs] = process.argv.slice(2)
  if ((operation !== 'create' && operation !== 'restore') || !username || !path || extraArgs.length !== 0) {
    throw new RecoveryError('Usage: npm run vault:recovery -- <create|restore> <username> <backup-file>')
  }
  const datasourceUrl = getDatabaseUrl(operation)
  if (process.stdin.isTTY) {
    throw new RecoveryError('Supply the master password via standard input using a hidden terminal prompt')
  }
  const masterPassword = readFileSync(0, 'utf8').replace(/\r?\n$/, '')
  if (!masterPassword) throw new RecoveryError('The master password is required')

  let prisma: PrismaClient | undefined
  const connect = async () => {
    const { PrismaClient } = await import('@prisma/client')
    prisma = new PrismaClient({ datasourceUrl })
    return prisma
  }

  try {
    if (operation === 'create') {
      const snapshot = await readVault(await connect(), username)
      const backup = createRecoveryBackup(snapshot, masterPassword)
      await writeBackup(path, JSON.stringify(backup) + '\n')
      console.log(`Created recovery backup for ${snapshot.credentials.length} credential(s)`)
    } else {
      const backup: unknown = JSON.parse(await readFile(path, 'utf8'))
      await restoreRecoveryBackup(backup, masterPassword, async (snapshot) => {
        await restoreVaultSnapshot(await connect(), username, snapshot)
      })
      console.log('Restored recovery backup into the empty vault')
    }
  } finally {
    await prisma?.$disconnect()
  }
}

main().catch((error: unknown) => {
  // Driver errors can include connection information or credential data.
  console.error(error instanceof RecoveryError
    ? error.message
    : 'Recovery operation failed. Check the backup file, database connection, and permissions.')
  process.exitCode = 1
})
