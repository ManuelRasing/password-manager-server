import { afterAll, beforeEach, expect, it } from 'vitest'
import { readRecoverySnapshot } from '../scripts/vault-snapshot'
import { createUser, prisma, resetDb } from './helpers'

beforeEach(resetDb)
afterAll(() => prisma.$disconnect())

it('backs up legacy records before revision, policy, and format columns exist', async () => {
  const user = await createUser('legacy-backup-owner')
  const config = { masterSalt: 'synthetic-salt', encryptedVaultKey: 'synthetic-key', vaultKeyIv: 'synthetic-iv' }
  await prisma.vaultConfig.create({ data: { userId: user.id, ...config } })
  const credential = await prisma.credential.create({
    data: {
      userId: user.id, siteName: 'Legacy site', usernameHint: '',
      encryptedPayload: 'synthetic-ciphertext', iv: 'synthetic-nonce'
    }
  })
  const rollback = new Error('Rollback the temporary legacy schema')
  try {
    await prisma.$transaction(async (tx) => {
      await tx.$executeRawUnsafe('ALTER TABLE "VaultConfig" DROP COLUMN revision, DROP COLUMN "minCredentialFormat"')
      await tx.$executeRawUnsafe('ALTER TABLE "Credential" DROP COLUMN "formatVersion"')
      const snapshot = await readRecoverySnapshot(tx, user.username)
      expect(snapshot.config).toEqual(config)
      expect(snapshot.credentials).toEqual([{
        id: credential.id, siteName: 'Legacy site', usernameHint: '', url: null,
        encryptedPayload: 'synthetic-ciphertext', iv: 'synthetic-nonce',
        createdAt: credential.createdAt.toISOString(),
        updatedAt: credential.updatedAt.toISOString(), deletedAt: null
      }])
      throw rollback
    })
  } catch (error) {
    if (error !== rollback) throw error
  }
  expect((await prisma.credential.findUniqueOrThrow({ where: { id: credential.id } })).formatVersion).toBe(1)
})
