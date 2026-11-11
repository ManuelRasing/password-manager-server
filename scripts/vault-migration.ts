import { createCipheriv, randomBytes } from 'node:crypto'
import { isDeepStrictEqual } from 'node:util'
import type { PrismaClient } from '@prisma/client'
import {
  createRecoveryBackup, decryptVaultPayload, RecoveryError,
  restoreRecoveryBackup, unlockVault, type VaultSnapshot
} from './recovery-backup'
import { readVaultSnapshot } from './vault-snapshot'

const credentialAad = Buffer.from('password-manager:credential:v2', 'utf8')

function comparable(snapshot: VaultSnapshot) {
  return {
    config: { ...snapshot.config, minCredentialFormat: snapshot.config.minCredentialFormat ?? 1 },
    credentials: [...snapshot.credentials].sort((left, right) => left.id.localeCompare(right.id))
  }
}

function requireMatchingSnapshot(expected: VaultSnapshot, actual: VaultSnapshot): void {
  if (!isDeepStrictEqual(comparable(expected), comparable(actual))) {
    throw new RecoveryError('Vault changed since the recovery backup. Create and verify a current backup before migrating.')
  }
}

function legacyContents(plaintext: string): { password: string, notes?: string } {
  try {
    const value: unknown = JSON.parse(plaintext)
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return { password: plaintext }
    const details = value as Record<string, unknown>
    const password = details.password ?? plaintext
    const notes = details.notes ?? undefined
    if (typeof password !== 'string' || (notes !== undefined && typeof notes !== 'string')) {
      return { password: plaintext }
    }
    return { password, ...(notes === undefined ? {} : { notes }) }
  } catch {
    return { password: plaintext }
  }
}

function encryptLegacyCredential(
  credential: VaultSnapshot['credentials'][number], vaultKey: Buffer
): VaultSnapshot['credentials'][number] {
  if (credential.formatVersion === 2) return credential
  if (!credential.siteName.trim()) throw new RecoveryError('A legacy credential has an empty site name. Correct it before migrating.')
  const plaintext = decryptVaultPayload(
    Buffer.from(credential.encryptedPayload, 'base64'), Buffer.from(credential.iv, 'base64'), vaultKey
  )
  try {
    const contents = {
      siteName: credential.siteName,
      usernameHint: credential.usernameHint,
      ...(credential.url === null ? {} : { url: credential.url }),
      ...legacyContents(plaintext.toString('utf8'))
    }
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', vaultKey, iv)
    cipher.setAAD(credentialAad)
    return {
      id: credential.id, formatVersion: 2,
      encryptedPayload: Buffer.concat([
        cipher.update(JSON.stringify(contents), 'utf8'), cipher.final(), cipher.getAuthTag()
      ]).toString('base64'),
      iv: iv.toString('base64'),
      createdAt: credential.createdAt, updatedAt: credential.updatedAt, deletedAt: credential.deletedAt
    }
  } finally {
    plaintext.fill(0)
  }
}

/** Run on the vault owner's machine against an explicitly selected database after CLI target checks. */
export async function migrateVault(
  prisma: PrismaClient, username: string, backup: unknown, masterPassword: string
): Promise<'migrated' | 'already migrated'> {
  let verifiedBackup: VaultSnapshot | undefined
  await restoreRecoveryBackup(backup, masterPassword, async (snapshot) => { verifiedBackup = snapshot })
  if (!verifiedBackup) throw new RecoveryError('Recovery backup could not be verified')
  const source = await prisma.$transaction((tx) => readVaultSnapshot(tx, username),
    { isolationLevel: 'RepeatableRead' })
  if (source.minCredentialFormat === 2) {
    createRecoveryBackup(source.snapshot, masterPassword)
    return 'already migrated'
  }
  requireMatchingSnapshot(verifiedBackup, source.snapshot)
  const vaultKey = unlockVault(source.snapshot.config, masterPassword)
  let migrated: VaultSnapshot['credentials']
  try {
    migrated = source.snapshot.credentials
      .filter((credential) => credential.formatVersion !== 2)
      .map((credential) => encryptLegacyCredential(credential, vaultKey))
  } finally {
    vaultKey.fill(0)
  }
  await prisma.$transaction(async (tx) => {
    const owners = await tx.$queryRaw<Array<{ id: string }>>`SELECT id FROM "User" WHERE id = ${source.userId} FOR UPDATE`
    if (owners.length !== 1) throw new RecoveryError('Source vault owner no longer exists')
    const current = await readVaultSnapshot(tx, username)
    if (current.revision !== source.revision) throw new RecoveryError('Vault configuration changed. Verify a new recovery backup before migrating.')
    requireMatchingSnapshot(source.snapshot, current.snapshot)
    await tx.vaultConfig.update({
      where: { userId: source.userId, revision: source.revision },
      data: { minCredentialFormat: 2 }
    })
    for (const credential of migrated) {
      await tx.credential.update({
        where: { id: credential.id, userId: source.userId, formatVersion: 1 },
        data: {
          formatVersion: 2, siteName: null, usernameHint: null, url: null,
          encryptedPayload: credential.encryptedPayload, iv: credential.iv,
          updatedAt: new Date(credential.updatedAt)
        }
      })
    }
  }, { timeout: 30_000 })
  return 'migrated'
}
