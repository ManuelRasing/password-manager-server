import { createHash } from 'node:crypto'
import { RecoveryError } from './recovery-backup'

const liveUrlSettings = new Map([
  ['sslmode', 'require'],
  ['channel_binding', 'require'],
  ['pgbouncer', 'true']
])

export function migrationTargetLabel(target: URL): string {
  return `${target.hostname.toLowerCase()}:${target.port || '5432'}/${decodeURIComponent(target.pathname.slice(1))}`
}

export function getMigrationTarget(input: string | undefined, live: boolean): URL {
  let target: URL
  try {
    target = new URL(input ?? '')
  } catch {
    throw new RecoveryError('Set MIGRATION_DATABASE_URL to the explicitly selected PostgreSQL database')
  }
  if (!['postgres:', 'postgresql:'].includes(target.protocol)) {
    throw new RecoveryError('Migration requires a PostgreSQL URL')
  }
  if (!live) {
    if (!['127.0.0.1', '[::1]'].includes(target.hostname) ||
        !/^\/password_manager_migration(?:_[a-z0-9]+)*$/.test(target.pathname) ||
        target.href.includes('?') || target.href.includes('#')) {
      throw new RecoveryError('Migration requires a local password_manager_migration database without URL options')
    }
    return target
  }

  let database: string
  try {
    database = decodeURIComponent(target.pathname.slice(1))
  } catch {
    throw new RecoveryError('Live migration requires a valid database name')
  }
  if (!target.hostname || !target.username || !target.password ||
      !/^[A-Za-z0-9_][A-Za-z0-9_-]{0,62}$/.test(database) ||
      target.href.includes('#')) {
    throw new RecoveryError('Live migration requires an explicit host, credentials, and database without a fragment')
  }
  const options = [...target.searchParams.entries()]
  if (new Set(options.map(([name]) => name)).size !== options.length ||
      target.searchParams.get('sslmode') !== 'require' ||
      options.some(([name, value]) => liveUrlSettings.get(name) !== value)) {
    throw new RecoveryError('Live migration requires sslmode=require and supports only channel_binding=require and pgbouncer=true as optional URL settings')
  }
  return target
}

export function confirmLiveMigration(
  target: URL,
  owner: string,
  backupBytes: Buffer,
  confirmation: { owner?: string, target?: string, backupSha256?: string }
): void {
  if (confirmation.owner !== owner) {
    throw new RecoveryError('MIGRATION_CONFIRM_OWNER must exactly match the vault owner')
  }
  if (confirmation.target !== migrationTargetLabel(target)) {
    throw new RecoveryError('MIGRATION_CONFIRM_TARGET must exactly match the selected host, port, and database')
  }
  if (!confirmation.backupSha256 || !/^[a-f0-9]{64}$/.test(confirmation.backupSha256) ||
      confirmation.backupSha256 !== createHash('sha256').update(backupBytes).digest('hex')) {
    throw new RecoveryError('MIGRATION_VERIFIED_BACKUP_SHA256 must match the verified encrypted backup file')
  }
}
