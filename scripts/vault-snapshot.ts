import type { Prisma, PrismaClient } from '@prisma/client'
import { RecoveryError, type VaultSnapshot } from './recovery-backup'

type StoredCredential = Pick<Prisma.CredentialGetPayload<{}>,
  'id' | 'formatVersion' | 'siteName' | 'usernameHint' | 'url' |
  'encryptedPayload' | 'iv' | 'createdAt' | 'updatedAt' | 'deletedAt'>

function snapshotFromRecords(
  config: VaultSnapshot['config'], credentials: StoredCredential[]
): VaultSnapshot {
  const snapshot: VaultSnapshot = {
    config,
    credentials: credentials.map(({ formatVersion, siteName, usernameHint, url, ...credential }) => {
      const fields = {
        ...credential,
        createdAt: credential.createdAt.toISOString(),
        updatedAt: credential.updatedAt.toISOString(),
        deletedAt: credential.deletedAt?.toISOString() ?? null
      }
      if (formatVersion === 2 && siteName === null && usernameHint === null && url === null) {
        return { ...fields, formatVersion }
      }
      if (formatVersion === 1 && siteName !== null && usernameHint !== null) {
        return { ...fields, siteName, usernameHint, url }
      }
      throw new RecoveryError('Invalid credential format or metadata in source vault')
    })
  }
  if (config.minCredentialFormat === 2 &&
      snapshot.credentials.some((credential) => credential.formatVersion !== 2)) {
    throw new RecoveryError('Vault policy requires encrypted credentials')
  }
  return snapshot
}

/** Read the original deployed schema before any upgrade is applied. */
export async function readRecoverySnapshot(
  tx: Prisma.TransactionClient, username: string
): Promise<VaultSnapshot> {
  const user = await tx.user.findUnique({ where: { username }, select: { id: true } })
  if (!user) throw new RecoveryError('Source vault owner does not exist')
  const configs = await tx.$queryRaw<Array<{
    masterSalt: string, encryptedVaultKey: string, vaultKeyIv: string,
    minCredentialFormat: number | null
  }>>`
    SELECT "masterSalt", "encryptedVaultKey", "vaultKeyIv",
      (to_jsonb(vault)->>'minCredentialFormat')::integer AS "minCredentialFormat"
    FROM "VaultConfig" vault WHERE "userId" = ${user.id}
  `
  const config = configs[0]
  if (!config) throw new RecoveryError('Source vault configuration does not exist')
  const { minCredentialFormat, ...unlock } = config
  if (minCredentialFormat !== null && minCredentialFormat !== 1 && minCredentialFormat !== 2) {
    throw new RecoveryError('Unsupported minimum credential format')
  }
  const credentials = await tx.$queryRaw<StoredCredential[]>`
    SELECT id, "siteName", "usernameHint", url, "encryptedPayload", iv,
      "createdAt", "updatedAt", "deletedAt",
      COALESCE((to_jsonb(credential)->>'formatVersion')::integer, 1) AS "formatVersion"
    FROM "Credential" credential WHERE "userId" = ${user.id} ORDER BY id
  `
  return snapshotFromRecords({
    ...unlock, ...(minCredentialFormat === null ? {} : { minCredentialFormat })
  }, credentials)
}

export async function readVaultSnapshot(tx: Prisma.TransactionClient, username: string) {
  const user = await tx.user.findUnique({ where: { username }, select: { id: true } })
  if (!user) throw new RecoveryError('Source vault owner does not exist')
  const config = await tx.vaultConfig.findUnique({
    where: { userId: user.id },
    select: { masterSalt: true, encryptedVaultKey: true, vaultKeyIv: true, revision: true, minCredentialFormat: true }
  })
  if (!config) throw new RecoveryError('Source vault configuration does not exist')
  const credentials = await tx.credential.findMany({
    where: { userId: user.id },
    orderBy: { id: 'asc' },
    select: {
      id: true, formatVersion: true, siteName: true, usernameHint: true, url: true,
      encryptedPayload: true, iv: true, createdAt: true, updatedAt: true, deletedAt: true
    }
  })
  const { revision, minCredentialFormat, ...unlock } = config
  if (minCredentialFormat !== 1 && minCredentialFormat !== 2) {
    throw new RecoveryError('Unsupported minimum credential format')
  }
  const snapshot = snapshotFromRecords({ ...unlock, minCredentialFormat }, credentials)
  return { userId: user.id, revision, minCredentialFormat, snapshot }
}

export async function restoreVaultSnapshot(
  prisma: PrismaClient, username: string, snapshot: VaultSnapshot
): Promise<void> {
  await prisma.$transaction(async (tx) => {
    const user = await tx.user.findUnique({ where: { username }, select: { id: true } })
    if (!user) throw new RecoveryError('Provision the destination vault owner before restoring')
    const config = await tx.vaultConfig.findUnique({ where: { userId: user.id }, select: { id: true } })
    const credentialCount = await tx.credential.count({ where: { userId: user.id } })
    if (config || credentialCount !== 0) throw new RecoveryError('Destination vault must be empty')
    await tx.vaultConfig.create({ data: { ...snapshot.config, userId: user.id } })
    if (snapshot.credentials.length !== 0) {
      await tx.credential.createMany({
        data: snapshot.credentials.map((credential) => ({ ...credential, userId: user.id }))
      })
    }
  }, { isolationLevel: 'Serializable' })
}
