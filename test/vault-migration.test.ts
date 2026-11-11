import { createCipheriv, pbkdf2Sync, randomBytes } from 'node:crypto'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import type { FastifyInstance } from 'fastify'
import { createRecoveryBackup, decryptVaultPayload } from '../scripts/recovery-backup'
import { migrateVault } from '../scripts/vault-migration'
import { readVaultSnapshot } from '../scripts/vault-snapshot'
import { createUser, getTestApp, prisma, resetDb, signedHeaders } from './helpers'

const password = 'synthetic migration master password 🧪'
const aad = Buffer.from('password-manager:credential:v2')

function encrypted(text: string | Buffer, key: Buffer, associatedData?: Buffer) {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  if (associatedData) cipher.setAAD(associatedData)
  const bytes = typeof text === 'string' ? Buffer.from(text) : text
  return {
    encryptedPayload: Buffer.concat([cipher.update(bytes), cipher.final(), cipher.getAuthTag()]).toString('base64'),
    iv: iv.toString('base64')
  }
}

async function fixture(includeRecords = true) {
  const user = await createUser('migration-owner')
  const salt = randomBytes(32)
  const key = randomBytes(32)
  const wrapped = encrypted(key, pbkdf2Sync(password, salt, 310_000, 32, 'sha256'))
  await prisma.vaultConfig.create({
    data: { userId: user.id, masterSalt: salt.toString('base64'), encryptedVaultKey: wrapped.encryptedPayload, vaultKeyIv: wrapped.iv }
  })
  if (includeRecords) {
    const date = new Date('2026-01-01T00:00:00.000Z')
    await prisma.credential.createMany({ data: [
      { id: 'migration-a', userId: user.id, siteName: 'Legacy password', usernameHint: '', url: null, ...encrypted('old password', key), createdAt: date, updatedAt: date },
      { id: 'migration-b', userId: user.id, siteName: 'Legacy structured', usernameHint: 'synthetic-user', url: 'https://synthetic.invalid', ...encrypted(JSON.stringify({ password: 'structured password', notes: 'saved note' }), key), createdAt: date, updatedAt: date, deletedAt: date },
      { id: 'migration-c', userId: user.id, formatVersion: 2, siteName: null, usernameHint: null, url: null, ...encrypted(JSON.stringify({ siteName: 'Already encrypted', usernameHint: '', password: 'current password' }), key, aad), createdAt: date, updatedAt: date }
    ] })
  }
  const source = await prisma.$transaction((tx) => readVaultSnapshot(tx, user.username))
  return { user, key, source, backup: createRecoveryBackup(source.snapshot, password) }
}

describe('whole-vault migration', () => {
  let app: FastifyInstance
  beforeAll(async () => { app = getTestApp(); await app.ready() })
  beforeEach(resetDb)
  afterAll(async () => { await app.close(); await prisma.$disconnect() })

  it('preserves content and deletion state, seals metadata, blocks legacy writes, and repeats safely', async () => {
    const { user, key, source, backup } = await fixture()
    expect(await migrateVault(prisma, user.username, backup, password)).toBe('migrated')
    const after = await prisma.$transaction((tx) => readVaultSnapshot(tx, user.username))
    expect(after.minCredentialFormat).toBe(2)
    for (const row of after.snapshot.credentials) {
      const original = source.snapshot.credentials.find((entry) => entry.id === row.id)!
      expect(row.createdAt).toBe(original.createdAt)
      expect(row.updatedAt).toBe(original.updatedAt)
      expect(row.deletedAt).toBe(original.deletedAt)
      expect(row.formatVersion).toBe(2)
      const stored = await prisma.credential.findUniqueOrThrow({ where: { id: row.id } })
      expect([stored.siteName, stored.usernameHint, stored.url]).toEqual([null, null, null])
      const contents = JSON.parse(decryptVaultPayload(Buffer.from(row.encryptedPayload, 'base64'), Buffer.from(row.iv, 'base64'), key, aad).toString('utf8'))
      if (row.id === 'migration-a') expect(contents).toEqual({ siteName: 'Legacy password', usernameHint: '', password: 'old password' })
      if (row.id === 'migration-b') expect(contents).toEqual({ siteName: 'Legacy structured', usernameHint: 'synthetic-user', url: 'https://synthetic.invalid', password: 'structured password', notes: 'saved note' })
      if (row.id === 'migration-c') expect(row.encryptedPayload).toBe(original.encryptedPayload)
    }
    expect(await migrateVault(prisma, user.username, backup, password)).toBe('already migrated')
    expect((await prisma.$transaction((tx) => readVaultSnapshot(tx, user.username))).snapshot).toEqual(after.snapshot)
    const legacy = { siteName: 'Rejected legacy', ...encrypted('legacy password', key) }
    const result = await app.inject({ method: 'POST', url: '/credentials', headers: signedHeaders(user.apiKey, user.username, 'POST', '/credentials', legacy), payload: legacy })
    expect(result.statusCode).toBe(409)
    const current = { formatVersion: 2, ...encrypted(JSON.stringify({ siteName: 'New encrypted login', usernameHint: '', password: 'new password' }), key, aad) }
    const created = await app.inject({ method: 'POST', url: '/credentials', headers: signedHeaders(user.apiKey, user.username, 'POST', '/credentials', current), payload: current })
    expect(created.statusCode).toBe(201)
  })

  it('rejects an outdated backup before changing the gate or any credential', async () => {
    const { user, backup } = await fixture()
    await prisma.credential.update({ where: { id: 'migration-a' }, data: { usernameHint: 'changed after backup' } })
    const before = await prisma.$transaction((tx) => readVaultSnapshot(tx, user.username))
    await expect(migrateVault(prisma, user.username, backup, password)).rejects.toThrow(/changed since the recovery backup/)
    expect(await prisma.$transaction((tx) => readVaultSnapshot(tx, user.username))).toEqual(before)
  })

  it('rejects inconsistent migrated policy instead of treating legacy rows as already migrated', async () => {
    const { user, backup } = await fixture()
    await prisma.vaultConfig.update({ where: { userId: user.id }, data: { minCredentialFormat: 2 } })
    await expect(migrateVault(prisma, user.username, backup, password)).rejects.toThrow(/policy requires encrypted credentials/)
    expect(await prisma.credential.count({ where: { userId: user.id, formatVersion: 1 } })).toBe(2)
  })

  it('rolls back an interrupted transaction and succeeds on retry', async () => {
    const { user, source, backup } = await fixture()
    await prisma.$executeRawUnsafe('CREATE FUNCTION migration_test_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW."id" = \'migration-b\' AND NEW."formatVersion" = 2 THEN RAISE EXCEPTION \'synthetic interruption\'; END IF; RETURN NEW; END $$')
    await prisma.$executeRawUnsafe('CREATE TRIGGER migration_test_failure BEFORE UPDATE ON "Credential" FOR EACH ROW EXECUTE FUNCTION migration_test_failure()')
    try {
      await expect(migrateVault(prisma, user.username, backup, password)).rejects.toThrow()
      expect(await prisma.$transaction((tx) => readVaultSnapshot(tx, user.username))).toEqual(source)
    } finally {
      await prisma.$executeRawUnsafe('DROP TRIGGER migration_test_failure ON "Credential"')
      await prisma.$executeRawUnsafe('DROP FUNCTION migration_test_failure()')
    }
    expect(await migrateVault(prisma, user.username, backup, password)).toBe('migrated')
  })

  it('checks the format gate after a concurrent cutover releases its lock', async () => {
    const { user, key } = await fixture(false)
    let release!: () => void
    let acquired!: () => void
    const held = new Promise<void>((resolve) => { release = resolve })
    const locked = new Promise<void>((resolve) => { acquired = resolve })
    const cutover = prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM "User" WHERE id = ${user.id} FOR UPDATE`
      acquired()
      await held
      await tx.vaultConfig.update({ where: { userId: user.id }, data: { minCredentialFormat: 2 } })
    })
    await locked
    const payload = { siteName: 'Concurrent legacy', ...encrypted('old password', key) }
    const request = app.inject({ method: 'POST', url: '/credentials', headers: signedHeaders(user.apiKey, user.username, 'POST', '/credentials', payload), payload })
    const response = Promise.resolve(request)
    try {
      await new Promise((resolve) => setTimeout(resolve, 25))
    } finally {
      release()
    }
    await cutover
    expect((await response).statusCode).toBe(409)
    expect(await prisma.credential.count({ where: { userId: user.id } })).toBe(0)
  })
})
