import { readFileSync } from 'node:fs'
import { RecoveryError } from './recovery-backup'
import { migrateVault } from './vault-migration'
import { confirmLiveMigration, getMigrationTarget } from './migration-target'

async function main(): Promise<void> {
  const args = process.argv.slice(2)
  const live = args.length === 3 && args[0] === '--live'
  const [username, backupPath] = live ? args.slice(1) : args
  if (!username || !backupPath || (args.length !== 2 && !live)) {
    throw new RecoveryError('Usage: npm run vault:migrate -- [--live] <username> <verified-backup-file>')
  }
  const target = getMigrationTarget(process.env.MIGRATION_DATABASE_URL, live)
  const backupBytes = readFileSync(backupPath)
  if (live) {
    confirmLiveMigration(target, username, backupBytes, {
      owner: process.env.MIGRATION_CONFIRM_OWNER,
      target: process.env.MIGRATION_CONFIRM_TARGET,
      backupSha256: process.env.MIGRATION_VERIFIED_BACKUP_SHA256
    })
  }
  if (process.stdin.isTTY) throw new RecoveryError('Supply the master password through standard input using a hidden terminal prompt')
  const password = readFileSync(0, 'utf8').replace(/\r?\n$/, '')
  if (!password) throw new RecoveryError('The master password is required')
  const backup: unknown = JSON.parse(backupBytes.toString('utf8'))
  const { PrismaClient } = await import('@prisma/client')
  const prisma = new PrismaClient({ datasourceUrl: target.href })
  try {
    console.log('Vault ' + await migrateVault(prisma, username, backup, password))
  } finally {
    await prisma.$disconnect()
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof RecoveryError ? error.message : 'Migration failed. The vault transaction was rolled back.')
  process.exitCode = 1
})
