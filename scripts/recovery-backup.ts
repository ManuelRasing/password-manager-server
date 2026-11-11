import { isUtf8 } from 'node:buffer'
import {
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  pbkdf2Sync,
  randomBytes
} from 'node:crypto'

const FORMAT = 'password-manager-recovery'
const VERSION = 1
const CIPHER = 'aes-256-gcm'
const IV_BYTES = 12
const TAG_BYTES = 16

// These parameters match the original Flutter vault configuration.
const VAULT_KDF = { name: 'PBKDF2-SHA256', iterations: 310_000, keyBytes: 32 } as const
const ARCHIVE_KEY_CONTEXT = 'password-manager recovery backup v1'
const ENCRYPTED_CREDENTIAL_AAD = Buffer.from('password-manager:credential:v2', 'utf8')

export class RecoveryError extends Error {}

export interface VaultUnlockConfig {
  masterSalt: string
  encryptedVaultKey: string
  vaultKeyIv: string
  minCredentialFormat?: 1 | 2
}

interface CredentialSnapshotFields {
  id: string
  encryptedPayload: string
  iv: string
  createdAt: string
  updatedAt: string
  deletedAt: string | null
}

interface LegacyCredentialSnapshot extends CredentialSnapshotFields {
  formatVersion?: 1
  siteName: string
  usernameHint: string
  url: string | null
}

interface EncryptedCredentialSnapshot extends CredentialSnapshotFields {
  formatVersion: 2
}

type CredentialSnapshot = LegacyCredentialSnapshot | EncryptedCredentialSnapshot

export interface VaultSnapshot {
  config: VaultUnlockConfig
  credentials: CredentialSnapshot[]
}

interface BackupHeader {
  format: typeof FORMAT
  version: typeof VERSION
  cipher: typeof CIPHER
  kdf: typeof VAULT_KDF
  config: VaultUnlockConfig
  iv: string
}

interface RecoveryBackup extends BackupHeader {
  encryptedSnapshot: string
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new RecoveryError('Invalid recovery backup data')
  }
  return value as Record<string, unknown>
}

function string(value: unknown): string {
  if (typeof value !== 'string') throw new RecoveryError('Invalid recovery backup data')
  return value
}

function base64(value: string, expectedBytes?: number): Buffer {
  const bytes = Buffer.from(value, 'base64')
  if (bytes.toString('base64') !== value ||
      (expectedBytes !== undefined && bytes.length !== expectedBytes)) {
    throw new RecoveryError('Invalid recovery backup encoding')
  }
  return bytes
}

function timestamp(value: unknown): string {
  const input = string(value)
  const parsed = new Date(input)
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== input) {
    throw new RecoveryError('Invalid credential timestamp in recovery backup')
  }
  return input
}

function unlockConfig(value: unknown): VaultUnlockConfig {
  const config = record(value)
  if ('minCredentialFormat' in config && config.minCredentialFormat !== 1 && config.minCredentialFormat !== 2) {
    throw new RecoveryError('Unsupported minimum credential format')
  }
  return {
    masterSalt: string(config.masterSalt),
    encryptedVaultKey: string(config.encryptedVaultKey),
    vaultKeyIv: string(config.vaultKeyIv),
    ...('minCredentialFormat' in config ? { minCredentialFormat: config.minCredentialFormat as 1 | 2 } : {})
  }
}

function backupHeader(config: VaultUnlockConfig, iv: string): BackupHeader {
  return { format: FORMAT, version: VERSION, cipher: CIPHER, kdf: VAULT_KDF, config, iv }
}

export function decryptVaultPayload(ciphertext: Buffer, iv: Buffer, key: Buffer, aad?: Buffer): Buffer {
  if (ciphertext.length < TAG_BYTES) throw new RecoveryError('Invalid recovery backup ciphertext')
  const decipher = createDecipheriv(CIPHER, key, iv, { authTagLength: TAG_BYTES })
  decipher.setAuthTag(ciphertext.subarray(-TAG_BYTES))
  if (aad) decipher.setAAD(aad)
  return Buffer.concat([decipher.update(ciphertext.subarray(0, -TAG_BYTES)), decipher.final()])
}

export function unlockVault(config: VaultUnlockConfig, masterPassword: string): Buffer {
  const salt = base64(config.masterSalt, 32)
  const encryptedKey = base64(config.encryptedVaultKey, VAULT_KDF.keyBytes + TAG_BYTES)
  const iv = base64(config.vaultKeyIv, IV_BYTES)
  const masterKey = pbkdf2Sync(masterPassword, salt, VAULT_KDF.iterations, VAULT_KDF.keyBytes, 'sha256')
  try {
    return decryptVaultPayload(encryptedKey, iv, masterKey)
  } catch {
    throw new RecoveryError('Wrong master password or damaged recovery backup')
  } finally {
    masterKey.fill(0)
  }
}

function archiveKey(vaultKey: Buffer): Buffer {
  return Buffer.from(hkdfSync('sha256', vaultKey, Buffer.alloc(0), ARCHIVE_KEY_CONTEXT, VAULT_KDF.keyBytes))
}

function validateCredentials(value: unknown, vaultKey: Buffer): CredentialSnapshot[] {
  if (!Array.isArray(value)) throw new RecoveryError('Invalid credential list in recovery backup')
  const ids = new Set<string>()
  return value.map((item) => {
    const entry = record(item)
    const id = string(entry.id)
    if (!id || ids.has(id)) throw new RecoveryError('Invalid credential identity in recovery backup')
    ids.add(id)
    const fields = {
      id,
      encryptedPayload: string(entry.encryptedPayload),
      iv: string(entry.iv),
      createdAt: timestamp(entry.createdAt),
      updatedAt: timestamp(entry.updatedAt),
      deletedAt: entry.deletedAt === null ? null : timestamp(entry.deletedAt)
    }
    const formatVersion = entry.formatVersion
    let credential: CredentialSnapshot
    if (formatVersion === 2) {
      if ('siteName' in entry || 'usernameHint' in entry || 'url' in entry) {
        throw new RecoveryError('Encrypted credential has plaintext metadata')
      }
      credential = { ...fields, formatVersion }
    } else if (formatVersion === undefined || formatVersion === 1) {
      credential = {
        ...fields,
        siteName: string(entry.siteName),
        usernameHint: string(entry.usernameHint),
        url: entry.url === null ? null : string(entry.url)
      }
    } else {
      throw new RecoveryError('Unsupported credential format in recovery backup')
    }

    try {
      const plaintext = decryptVaultPayload(
        base64(credential.encryptedPayload),
        base64(credential.iv, IV_BYTES),
        vaultKey,
        formatVersion === 2 ? ENCRYPTED_CREDENTIAL_AAD : undefined
      )
      try {
        if (!isUtf8(plaintext)) throw new RecoveryError('Invalid credential payload encoding')
        if (formatVersion === 2) {
          const details = record(JSON.parse(plaintext.toString('utf8')))
          if (!string(details.siteName).trim() ||
              typeof details.usernameHint !== 'string' ||
              typeof details.password !== 'string' ||
              (details.url != null && typeof details.url !== 'string') ||
              (details.notes != null && typeof details.notes !== 'string')) {
            throw new RecoveryError('Invalid encrypted credential details')
          }
        }
      } finally {
        plaintext.fill(0)
      }
    } catch {
      throw new RecoveryError('A credential could not be unlocked with the backup vault key')
    }
    return credential
  })
}

export function createRecoveryBackup(snapshot: VaultSnapshot, masterPassword: string): RecoveryBackup {
  const header = backupHeader(unlockConfig(snapshot.config), randomBytes(IV_BYTES).toString('base64'))
  const vaultKey = unlockVault(header.config, masterPassword)
  const key = archiveKey(vaultKey)
  try {
    const credentials = validateCredentials(snapshot.credentials, vaultKey)
    if (header.config.minCredentialFormat === 2 && credentials.some((credential) => credential.formatVersion !== 2)) {
      throw new RecoveryError('Vault policy requires encrypted credentials')
    }
    const cipher = createCipheriv(CIPHER, key, base64(header.iv, IV_BYTES), { authTagLength: TAG_BYTES })
    cipher.setAAD(Buffer.from(JSON.stringify(header)))
    const encryptedSnapshot = Buffer.concat([
      cipher.update(JSON.stringify(credentials), 'utf8'),
      cipher.final(),
      cipher.getAuthTag()
    ]).toString('base64')
    return { ...header, encryptedSnapshot }
  } finally {
    key.fill(0)
    vaultKey.fill(0)
  }
}

function openRecoveryBackup(value: unknown, masterPassword: string): VaultSnapshot {
  const backup = record(value)
  if (backup.format !== FORMAT || backup.version !== VERSION || backup.cipher !== CIPHER) {
    throw new RecoveryError('Unsupported recovery backup format')
  }
  const kdf = record(backup.kdf)
  if (kdf.name !== VAULT_KDF.name || kdf.iterations !== VAULT_KDF.iterations || kdf.keyBytes !== VAULT_KDF.keyBytes) {
    throw new RecoveryError('Unsupported recovery backup key derivation parameters')
  }
  const header = backupHeader(unlockConfig(backup.config), string(backup.iv))
  const encryptedSnapshot = base64(string(backup.encryptedSnapshot))
  const iv = base64(header.iv, IV_BYTES)
  const vaultKey = unlockVault(header.config, masterPassword)
  const key = archiveKey(vaultKey)
  try {
    let plaintext: Buffer
    try {
      plaintext = decryptVaultPayload(encryptedSnapshot, iv, key, Buffer.from(JSON.stringify(header)))
    } catch {
      throw new RecoveryError('Wrong master password or damaged recovery backup')
    }
    try {
      const credentials = validateCredentials(JSON.parse(plaintext.toString('utf8')), vaultKey)
      if (header.config.minCredentialFormat === 2 && credentials.some((credential) => credential.formatVersion !== 2)) {
        throw new RecoveryError('Vault policy requires encrypted credentials')
      }
      return { config: header.config, credentials }
    } finally {
      plaintext.fill(0)
    }
  } finally {
    key.fill(0)
    vaultKey.fill(0)
  }
}

/** Validate and unlock the complete archive before starting a destination write. */
export async function restoreRecoveryBackup(
  backup: unknown,
  masterPassword: string,
  restoreIntoEmptyVault: (snapshot: VaultSnapshot) => Promise<void>
): Promise<void> {
  const snapshot = openRecoveryBackup(backup, masterPassword)
  await restoreIntoEmptyVault(snapshot)
}
