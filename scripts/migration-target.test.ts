import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createCipheriv, createHash, pbkdf2Sync, randomBytes } from 'node:crypto'
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { pathToFileURL } from 'node:url'
import { confirmLiveMigration, getMigrationTarget, migrationTargetLabel } from './migration-target'
import { createRecoveryBackup } from './recovery-backup'

const sourceUrl = 'postgresql://synthetic:synthetic@database.invalid/neondb?sslmode=require&channel_binding=require'
const owner = 'synthetic-owner'

test('local rehearsal remains the default target policy', () => {
  const local = 'postgresql://test:dummy@127.0.0.1:5432/password_manager_migration_guard'
  assert.equal(getMigrationTarget(local, false).href, local)
  for (const value of [undefined, sourceUrl, local + '?sslmode=require', 'postgresql://127.0.0.1/other']) {
    assert.throws(() => getMigrationTarget(value, false))
  }
})

test('live target labels identify the host, port, and decoded database without credentials', () => {
  const target = getMigrationTarget(sourceUrl, true)
  assert.equal(migrationTargetLabel(target), 'database.invalid:5432/neondb')
  const explicit = getMigrationTarget('postgresql://synthetic:synthetic@DATABASE.invalid:6543/%6Eeondb?sslmode=require&pgbouncer=true', true)
  assert.equal(migrationTargetLabel(explicit), 'database.invalid:6543/neondb')
})

test('live mode rejects insecure or target-altering URL settings', () => {
  for (const value of [
    'postgresql://synthetic:synthetic@database.invalid/neondb',
    sourceUrl + '&host=other.invalid',
    sourceUrl + '&schema=other',
    sourceUrl + '&options=search_path%3Dother',
    sourceUrl + '&search_path=other',
    sourceUrl + '&sslmode=require',
    sourceUrl + '#',
    sourceUrl.replace('sslmode=require', 'sslmode=disable'),
    sourceUrl.replace('channel_binding=require', 'channel_binding=prefer'),
    sourceUrl.replace('synthetic:synthetic@', ''),
    sourceUrl.replace('/neondb?', '/encoded%2Fdatabase?'),
    sourceUrl.replace('postgresql:', 'https:'),
  ]) {
    assert.throws(() => getMigrationTarget(value, true))
  }
})

test('live confirmation binds the exact owner, target, and verified backup bytes', () => {
  const target = getMigrationTarget(sourceUrl, true)
  const backup = Buffer.from('synthetic encrypted backup bytes\n')
  const confirmation = {
    owner,
    target: migrationTargetLabel(target),
    backupSha256: createHash('sha256').update(backup).digest('hex'),
  }
  assert.doesNotThrow(() => confirmLiveMigration(target, owner, backup, confirmation))
  assert.throws(() => confirmLiveMigration(target, owner, backup, { ...confirmation, owner: 'different-owner' }), /CONFIRM_OWNER/)
  assert.throws(() => confirmLiveMigration(target, owner, backup, { ...confirmation, target: 'other.invalid:5432/neondb' }), /CONFIRM_TARGET/)
  assert.throws(() => confirmLiveMigration(target, owner, Buffer.from('changed'), confirmation), /VERIFIED_BACKUP_SHA256/)
  assert.throws(() => confirmLiveMigration(target, owner, backup, { ...confirmation, backupSha256: undefined }), /VERIFIED_BACKUP_SHA256/)
})

function syntheticBackup(): string {
  const password = 'synthetic correct password'
  const salt = randomBytes(32)
  const iv = randomBytes(12)
  const masterKey = pbkdf2Sync(password, salt, 310_000, 32, 'sha256')
  const cipher = createCipheriv('aes-256-gcm', masterKey, iv)
  const wrapped = Buffer.concat([cipher.update(randomBytes(32)), cipher.final(), cipher.getAuthTag()])
  return JSON.stringify(createRecoveryBackup({
    config: { masterSalt: salt.toString('base64'), encryptedVaultKey: wrapped.toString('base64'), vaultKeyIv: iv.toString('base64') },
    credentials: [],
  }, password))
}

test('the CLI checks live confirmations and backup unlock before any database query', () => {
  const directory = mkdtempSync(join(tmpdir(), 'migration-live-guard-'))
  try {
    const scripts = join(directory, 'scripts')
    const client = join(directory, 'node_modules', '@prisma', 'client')
    mkdirSync(scripts, { recursive: true })
    mkdirSync(client, { recursive: true })
    for (const name of ['migrate-vault.ts', 'migration-target.ts', 'vault-migration.ts', 'vault-snapshot.ts', 'recovery-backup.ts']) {
      copyFileSync(resolve(__dirname, name), join(scripts, name))
    }
    writeFileSync(join(directory, 'package.json'), '{"private":true}')
    writeFileSync(join(client, 'package.json'), '{"main":"index.js"}')
    writeFileSync(join(client, 'index.js'), `
const fs = require('node:fs')
exports.PrismaClient = class PrismaClient {
  constructor() { fs.writeFileSync('client-created.marker', '') }
  async $transaction() { fs.writeFileSync('database-query.marker', ''); throw new Error('Unexpected query') }
  async $disconnect() {}
}
`)
    const bytes = syntheticBackup()
    const artifact = join(directory, 'verified-backup.json')
    writeFileSync(artifact, bytes, { mode: 0o600 })
    const confirmation = {
      MIGRATION_DATABASE_URL: sourceUrl,
      MIGRATION_CONFIRM_OWNER: owner,
      MIGRATION_CONFIRM_TARGET: 'database.invalid:5432/neondb',
      MIGRATION_VERIFIED_BACKUP_SHA256: createHash('sha256').update(bytes).digest('hex'),
    }
    const loader = pathToFileURL(require.resolve('tsx')).href
    const run = (environment: NodeJS.ProcessEnv) => spawnSync(process.execPath, [
      '--import', loader, join(scripts, 'migrate-vault.ts'), '--live', owner, artifact,
    ], { cwd: directory, env: environment, input: 'synthetic wrong password\n', encoding: 'utf8' })

    const defaultMode = spawnSync(process.execPath, [
      '--import', loader, join(scripts, 'migrate-vault.ts'), owner, artifact,
    ], { cwd: directory, env: confirmation, input: 'synthetic wrong password\n', encoding: 'utf8' })
    assert.equal(defaultMode.status, 1)
    assert.match(defaultMode.stderr, /Migration requires a local/)
    assert.equal(existsSync(join(directory, 'client-created.marker')), false)

    for (const environment of [
      { ...confirmation, MIGRATION_CONFIRM_OWNER: undefined },
      { ...confirmation, MIGRATION_CONFIRM_TARGET: 'other.invalid:5432/neondb' },
      { ...confirmation, MIGRATION_VERIFIED_BACKUP_SHA256: '0'.repeat(64) },
    ]) {
      const result = run(environment)
      assert.equal(result.status, 1)
      assert.match(result.stderr, /MIGRATION_CONFIRM_|MIGRATION_VERIFIED_BACKUP_SHA256/)
      assert.equal(existsSync(join(directory, 'client-created.marker')), false)
    }

    const accepted = run(confirmation)
    assert.equal(accepted.status, 1)
    assert.match(accepted.stderr, /Wrong master password or damaged recovery backup/)
    assert.equal(existsSync(join(directory, 'client-created.marker')), true)
    assert.equal(existsSync(join(directory, 'database-query.marker')), false)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})
