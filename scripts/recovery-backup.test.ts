import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'node:crypto'
import { resolve } from 'node:path'
import { test } from 'node:test'
import {
  createRecoveryBackup,
  type VaultSnapshot,
  restoreRecoveryBackup
} from './recovery-backup'

const masterPassword = 'synthetic owner password  🧪'
const credentialAad = Buffer.from('password-manager:credential:v2', 'utf8')

function encryptBytes(data: Buffer, key: Buffer, aad?: Buffer): [ciphertext: string, iv: string] {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  if (aad) cipher.setAAD(aad)
  const ciphertext = Buffer.concat([cipher.update(data), cipher.final(), cipher.getAuthTag()])
  return [ciphertext.toString('base64'), iv.toString('base64')]
}

function decryptBytes(ciphertext: string, iv: string, key: Buffer, aad?: Buffer): Buffer {
  const encrypted = Buffer.from(ciphertext, 'base64')
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'))
  decipher.setAuthTag(encrypted.subarray(-16))
  if (aad) decipher.setAAD(aad)
  return Buffer.concat([decipher.update(encrypted.subarray(0, -16)), decipher.final()])
}

function syntheticVault(): VaultSnapshot {
  const masterSalt = randomBytes(32)
  const masterKey = pbkdf2Sync(masterPassword, masterSalt, 310_000, 32, 'sha256')
  const vaultKey = randomBytes(32)
  const [encryptedVaultKey, vaultKeyIv] = encryptBytes(vaultKey, masterKey)
  const [oldPayload, oldIv] = encryptBytes(Buffer.from('legacy-password'), vaultKey)
  const structured = JSON.stringify({ password: 'new-password', notes: 'synthetic recovery note' })
  const [structuredPayload, structuredIv] = encryptBytes(Buffer.from(structured), vaultKey)
  const date = '2026-01-01T00:00:00.000Z'
  return {
    config: { masterSalt: masterSalt.toString('base64'), encryptedVaultKey, vaultKeyIv },
    credentials: [
      {
        id: 'old',
        siteName: 'Synthetic old site',
        usernameHint: '',
        url: null,
        encryptedPayload: oldPayload,
        iv: oldIv,
        createdAt: date,
        updatedAt: date,
        deletedAt: null
      },
      {
        id: 'structured',
        siteName: 'Synthetic structured site',
        usernameHint: 'synthetic-user',
        url: 'https://synthetic.invalid/login',
        encryptedPayload: structuredPayload,
        iv: structuredIv,
        createdAt: date,
        updatedAt: date,
        deletedAt: '2026-01-02T00:00:00.000Z'
      }
    ]
  }
}

function unlockSyntheticVault({ config }: VaultSnapshot): Buffer {
  const masterKey = pbkdf2Sync(masterPassword, Buffer.from(config.masterSalt, 'base64'), 310_000, 32, 'sha256')
  return decryptBytes(config.encryptedVaultKey, config.vaultKeyIv, masterKey)
}

test('a portable backup restores an empty synthetic vault and its credentials can be unlocked', async () => {
  const source = syntheticVault()
  const serialized = JSON.stringify(createRecoveryBackup(source, masterPassword))
  for (const value of [
    'Synthetic old site',
    'Synthetic structured site',
    'synthetic-user',
    'https://synthetic.invalid/login',
    'legacy-password',
    'new-password',
    'synthetic recovery note'
  ]) {
    assert.equal(serialized.includes(value), false)
  }

  const destination: VaultSnapshot[] = []
  await restoreRecoveryBackup(JSON.parse(serialized), masterPassword, async (snapshot) => {
    assert.equal(destination.length, 0)
    destination.push(snapshot)
  })
  assert.deepEqual(destination, [source])

  const restored = destination[0]
  const vaultKey = unlockSyntheticVault(restored)
  const [legacy, structured] = restored.credentials.map((credential) =>
    decryptBytes(credential.encryptedPayload, credential.iv, vaultKey).toString('utf8')
  )
  assert.equal(legacy, 'legacy-password')
  assert.deepEqual(JSON.parse(structured), { password: 'new-password', notes: 'synthetic recovery note' })
  assert.equal(restored.credentials[0].deletedAt, null)
  assert.equal(restored.credentials[1].deletedAt, '2026-01-02T00:00:00.000Z')
})

test('a mixed backup preserves the authenticated encrypted record format', async () => {
  const source = syntheticVault()
  const details = {
    siteName: 'Synthetic encrypted site',
    usernameHint: 'Synthetic encrypted username',
    url: 'https://encrypted.invalid',
    password: 'synthetic encrypted password',
    notes: 'synthetic encrypted note',
  }
  const [encryptedPayload, iv] = encryptBytes(
    Buffer.from(JSON.stringify(details)),
    unlockSyntheticVault(source),
    credentialAad,
  )
  const date = '2026-01-01T00:00:00.000Z'
  source.credentials.push({
    formatVersion: 2,
    id: 'encrypted',
    encryptedPayload,
    iv,
    createdAt: date,
    updatedAt: date,
    deletedAt: null,
  })

  const serialized = JSON.stringify(createRecoveryBackup(source, masterPassword))
  for (const value of Object.values(details)) assert.equal(serialized.includes(value), false)
  await restoreRecoveryBackup(JSON.parse(serialized), masterPassword, async (restored) => {
    assert.deepEqual(restored, source)
    const entry = restored.credentials[2]
    assert.equal(entry.formatVersion, 2)
    const plaintext = decryptBytes(entry.encryptedPayload, entry.iv, unlockSyntheticVault(restored), credentialAad)
    assert.deepEqual(JSON.parse(plaintext.toString('utf8')), details)
  })
})

test('an authenticated v2 payload must contain complete login details', () => {
  const source = syntheticVault()
  const [encryptedPayload, iv] = encryptBytes(
    Buffer.from(JSON.stringify({ password: 'synthetic password only' })),
    unlockSyntheticVault(source),
    credentialAad,
  )
  const date = '2026-01-01T00:00:00.000Z'
  source.credentials.push({
    formatVersion: 2,
    id: 'incomplete',
    encryptedPayload,
    iv,
    createdAt: date,
    updatedAt: date,
    deletedAt: null,
  })
  assert.throws(() => createRecoveryBackup(source, masterPassword), /credential could not be unlocked/)
})

test('v2 ciphertext cannot be reinterpreted as a legacy credential', () => {
  const source = syntheticVault()
  const [encryptedPayload, iv] = encryptBytes(
    Buffer.from(JSON.stringify({
      siteName: 'Synthetic encrypted site',
      usernameHint: '',
      password: 'synthetic encrypted password',
    })),
    unlockSyntheticVault(source),
    credentialAad,
  )
  const date = '2026-01-01T00:00:00.000Z'
  source.credentials.push({
    id: 'mislabeled',
    siteName: 'Claimed legacy site',
    usernameHint: 'claimed legacy username',
    url: 'https://claimed.invalid',
    encryptedPayload,
    iv,
    createdAt: date,
    updatedAt: date,
    deletedAt: null,
  })

  assert.throws(() => createRecoveryBackup(source, masterPassword), /credential could not be unlocked/)
})

test('wrong password, tampering, and unsupported parameters cannot start a restore', async () => {
  const backup = createRecoveryBackup(syntheticVault(), masterPassword)
  const tampered = Buffer.from(backup.encryptedSnapshot, 'base64')
  tampered[tampered.length - 1] ^= 1
  const write = async () => {
    assert.fail('Destination write must not start')
  }

  await assert.rejects(restoreRecoveryBackup(backup, 'wrong synthetic password', write), /master password/)
  await assert.rejects(restoreRecoveryBackup({
    ...backup,
    encryptedSnapshot: tampered.toString('base64')
  }, masterPassword, write), /damaged recovery backup/)
  await assert.rejects(restoreRecoveryBackup({
    ...backup,
    kdf: { ...backup.kdf, iterations: Number.MAX_SAFE_INTEGER }
  }, masterPassword, write), /key derivation/)
})

test('a credential from another vault is rejected before creating a backup', () => {
  const source = syntheticVault()
  source.credentials[0] = syntheticVault().credentials[0]
  assert.throws(() => createRecoveryBackup(source, masterPassword), /credential could not be unlocked/)
})

test('the restore command rejects ambient and non-rehearsal database targets', () => {
  const targets = [
    [undefined, /Set RECOVERY_DATABASE_URL/],
    ['postgresql://127.0.0.1:1/other', /Restore requires a local/],
    ['postgresql://recovery.invalid/password_manager_recovery', /Restore requires a local/],
    ['postgresql://127.0.0.1:1/password_manager_recovery?schema=test', /Restore requires a local/]
  ] as const

  for (const [target, expectedError] of targets) {
    const result = spawnSync(process.execPath, [
      '--import', 'tsx', 'scripts/recover-vault.ts', 'restore', 'fixture', 'missing-backup.json'
    ], {
      cwd: resolve(__dirname, '..'),
      encoding: 'utf8',
      env: {
        DATABASE_URL: 'postgresql://127.0.0.1:1/ambient',
        ...(target ? { RECOVERY_DATABASE_URL: target } : {})
      },
      input: masterPassword
    })
    assert.equal(result.status, 1)
    assert.match(result.stderr, expectedError)
  }
})

test('an empty migrated vault preserves its explicit format policy in recovery', async () => {
  const source = syntheticVault()
  source.credentials = []
  source.config.minCredentialFormat = 2
  const backup = createRecoveryBackup(source, masterPassword)
  await restoreRecoveryBackup(backup, masterPassword, async (restored) => {
    assert.deepEqual(restored, source)
  })
  const mustNotWrite = async () => { assert.fail('Invalid policy must not write') }
  await assert.rejects(restoreRecoveryBackup({
    ...backup, config: { ...backup.config, minCredentialFormat: 3 }
  }, masterPassword, mustNotWrite), /minimum credential format/)
  await assert.rejects(restoreRecoveryBackup({
    ...backup, config: { ...backup.config, minCredentialFormat: 1 }
  }, masterPassword, mustNotWrite), /damaged recovery backup/)
})

test('a migrated policy cannot claim legacy credential records', () => {
  const source = syntheticVault()
  source.config.minCredentialFormat = 2
  assert.throws(() => createRecoveryBackup(source, masterPassword), /policy requires encrypted credentials/)
})
