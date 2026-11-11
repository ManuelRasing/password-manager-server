import { createHash, randomBytes } from 'node:crypto'
import { spawn, spawnSync, type ChildProcess } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { access, chmod, mkdtemp, open, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises'
import { constants } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { isDeepStrictEqual } from 'node:util'
import type { PrismaClient } from '@prisma/client'
import { createRecoveryBackup, RecoveryError, restoreRecoveryBackup, type VaultSnapshot } from './recovery-backup'
import { readRecoverySnapshot, restoreVaultSnapshot } from './vault-snapshot'

class VerificationError extends Error {}

function sameSnapshot(expected: VaultSnapshot, actual: VaultSnapshot): boolean {
  const normalized = (snapshot: VaultSnapshot) => ({
    config: { ...snapshot.config, minCredentialFormat: snapshot.config.minCredentialFormat ?? 1 },
    credentials: [...snapshot.credentials].sort((left, right) => left.id.localeCompare(right.id))
  })
  return isDeepStrictEqual(normalized(expected), normalized(actual))
}

async function unusedPort(): Promise<number> {
  const server = createServer()
  await new Promise<void>((complete, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', complete)
  })
  const address = server.address()
  await new Promise<void>((complete, reject) => server.close((error) => error ? reject(error) : complete()))
  if (address === null || typeof address === 'string') throw new VerificationError('Could not allocate a local verification port')
  return address.port
}

function command(executable: string, args: string[], cwd: string, env: NodeJS.ProcessEnv): void {
  const result = spawnSync(executable, args, { cwd, env, encoding: 'utf8', timeout: 60_000 })
  if (result.error || result.status !== 0) throw new VerificationError('Could not prepare the temporary recovery database')
}

async function exited(child: ChildProcess, timeout: number): Promise<boolean> {
  if (child.exitCode !== null || child.signalCode !== null) return true
  return new Promise((complete) => {
    const done = () => {
      clearTimeout(timer)
      complete(true)
    }
    const timer = setTimeout(() => {
      child.removeListener('exit', done)
      complete(false)
    }, timeout)
    child.once('exit', done)
  })
}

async function stop(child: ChildProcess | undefined): Promise<void> {
  if (!child || child.pid === undefined || child.exitCode !== null || child.signalCode !== null) return
  child.kill('SIGTERM')
  if (await exited(child, 10_000)) return
  child.kill('SIGKILL')
  if (!await exited(child, 5_000)) throw new VerificationError('Temporary PostgreSQL could not be stopped')
}

async function main(): Promise<void> {
  process.umask(0o077)
  const [backupArgument, owner, receiptArgument, ...extra] = process.argv.slice(2)
  if (!backupArgument || !owner || !receiptArgument || extra.length !== 0) {
    throw new VerificationError('Usage: node --import tsx scripts/verify-recovery.ts BACKUP OWNER RECEIPT')
  }
  if (process.stdin.isTTY) throw new VerificationError('Supply the master password through standard input using a hidden prompt')
  const password = readFileSync(0, 'utf8').replace(/\r?\n$/, '')
  if (!password) throw new VerificationError('The master password is required')
  const backupPath = await realpath(resolve(backupArgument))
  const backupBytes = await readFile(backupPath)
  const backup: unknown = JSON.parse(backupBytes.toString('utf8'))
  let expected: VaultSnapshot | undefined
  await restoreRecoveryBackup(backup, password, async (snapshot) => { expected = snapshot })
  if (!expected) throw new VerificationError('Recovery backup validation failed')
  const configuredBin = process.env.ROLLOUT_POSTGRES_BIN
  if (!configuredBin) throw new VerificationError('Set ROLLOUT_POSTGRES_BIN to the trusted PostgreSQL binary directory')
  const bin = await realpath(configuredBin)
  for (const name of ['initdb', 'postgres']) await access(join(bin, name), constants.X_OK)
  const receiptPath = resolve(receiptArgument)
  const stage = await mkdtemp(join(tmpdir(), 'password-manager-restore-'))
  await chmod(stage, 0o700)
  let child: ChildProcess | undefined
  let admin: PrismaClient | undefined
  let destination: PrismaClient | undefined
  let count = 0
  try {
    const passwordFile = join(stage, 'admin-password')
    const adminPassword = randomBytes(32).toString('hex')
    await writeFile(passwordFile, adminPassword + '\n', { mode: 0o600 })
    const data = join(stage, 'cluster')
    const safeEnv: NodeJS.ProcessEnv = {
      PATH: process.env.PATH,
      LANG: 'C', LC_ALL: 'C', TMPDIR: stage,
      CI: 'true', CHECKPOINT_DISABLE: '1', PRISMA_HIDE_UPDATE_MESSAGE: '1',
      PRISMA_GENERATE_SKIP_AUTOINSTALL: 'true'
    }
    command(join(bin, 'initdb'), ['-D', data, '-U', 'recovery_verifier', '-A', 'scram-sha-256', '--pwfile=' + passwordFile, '--locale=C', '--encoding=UTF8'], stage, safeEnv)
    await rm(passwordFile)
    const port = await unusedPort()
    const serverRoot = resolve(__dirname, '..')
    await writeFile(join(stage, 'package.json'), '{"name":"password-manager-restore-verification","private":true}\n', { mode: 0o600 })
    await symlink(join(serverRoot, 'node_modules'), join(stage, 'node_modules'), 'dir')
    const schema = await readFile(join(serverRoot, 'prisma/schema.prisma'), 'utf8')
    if (!schema.includes('generator client {')) throw new VerificationError('Unsupported local Prisma generator configuration')
    const temporarySchema = schema.replace('generator client {', 'generator client {\n  output = "./client"')
    const schemaPath = join(stage, 'schema.prisma')
    await writeFile(schemaPath, temporarySchema, { mode: 0o600 })
    const adminUrl = `postgresql://recovery_verifier:${adminPassword}@127.0.0.1:${port}/postgres`
    const prismaCli = require.resolve('prisma/build/index.js')
    command(process.execPath, [prismaCli, 'generate', '--schema', schemaPath], stage, { ...safeEnv, DATABASE_URL: adminUrl })
    const { PrismaClient: TemporaryClient } = require(join(stage, 'client'))
    const administrator: PrismaClient = new TemporaryClient({ datasourceUrl: adminUrl })
    admin = administrator
    const log = await open(join(stage, 'postgres.log'), 'w', 0o600)
    let startError = false
    try {
      child = spawn(join(bin, 'postgres'), ['-D', data, '-h', '127.0.0.1', '-p', String(port), '-k', ''], { cwd: stage, env: safeEnv, stdio: ['ignore', log.fd, log.fd] })
      child.once('error', () => { startError = true })
    } finally {
      await log.close()
    }
    const deadline = Date.now() + 30_000
    let ready = false
    while (Date.now() < deadline) {
      if (startError || child.exitCode !== null || child.signalCode !== null) throw new VerificationError('Temporary PostgreSQL failed to start')
      try {
        await administrator.$connect()
        ready = true
        break
      } catch {
        await new Promise((complete) => setTimeout(complete, 100))
      }
    }
    if (!ready) throw new VerificationError('Temporary PostgreSQL was not ready in time')
    const directories = await administrator.$queryRawUnsafe<Array<{ data_directory: string }>>('SHOW data_directory')
    if (await realpath(directories[0].data_directory) !== await realpath(data)) {
      throw new VerificationError('Refusing to use a PostgreSQL server outside the temporary directory')
    }
    const database = 'password_manager_recovery_' + randomBytes(8).toString('hex')
    await administrator.$executeRawUnsafe('CREATE DATABASE "' + database + '"')
    const destinationUrl = new URL(adminUrl)
    destinationUrl.pathname = '/' + database
    command(process.execPath, [prismaCli, 'db', 'push', '--skip-generate', '--schema', schemaPath], stage, { ...safeEnv, DATABASE_URL: destinationUrl.href })
    const restoredDatabase: PrismaClient = new TemporaryClient({ datasourceUrl: destinationUrl.href })
    destination = restoredDatabase
    await restoredDatabase.user.create({ data: { username: owner, apiKey: randomBytes(32).toString('hex') } })
    await restoreVaultSnapshot(restoredDatabase, owner, expected)
    const actual = await restoredDatabase.$transaction((tx) => readRecoverySnapshot(tx, owner), { isolationLevel: 'RepeatableRead' })
    createRecoveryBackup(actual, password)
    if (!sameSnapshot(expected, actual)) throw new VerificationError('Restored vault did not match the recovery backup')
    count = actual.credentials.length
  } finally {
    await Promise.allSettled([admin?.$disconnect(), destination?.$disconnect()])
    await stop(child)
    await rm(stage, { recursive: true, force: true })
  }
  await writeFile(receiptPath, JSON.stringify({
    backupPath, sha256: createHash('sha256').update(backupBytes).digest('hex'), owner, count,
    verifiedAt: new Date().toISOString(), restoreVerified: true
  }, null, 2) + '\n', { mode: 0o600, flag: 'wx' })
  console.log(`Verified recovery of ${count} credential(s)`)
}

main().catch((error: unknown) => {
  console.error(error instanceof RecoveryError || error instanceof VerificationError
    ? error.message : 'Recovery verification failed. A verification receipt was not created.')
  process.exitCode = 1
})
