import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createCipheriv, createHash, pbkdf2Sync, randomBytes } from 'node:crypto'
import { mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { createRecoveryBackup, type VaultSnapshot } from './recovery-backup'

const password = 'synthetic owner verification password 🧪'
const owner = 'synthetic-owner'

function encrypted(bytes: Buffer, key: Buffer, aad?: Buffer) {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  if (aad) cipher.setAAD(aad)
  return {
    encryptedPayload: Buffer.concat([cipher.update(bytes), cipher.final(), cipher.getAuthTag()]).toString('base64'),
    iv: iv.toString('base64')
  }
}

function fixture(empty = false): VaultSnapshot {
  const salt = randomBytes(32)
  const key = randomBytes(32)
  const wrapped = encrypted(key, pbkdf2Sync(password, salt, 310_000, 32, 'sha256'))
  const date = '2026-01-01T00:00:00.000Z'
  const config = {
    masterSalt: salt.toString('base64'),
    encryptedVaultKey: wrapped.encryptedPayload,
    vaultKeyIv: wrapped.iv
  }
  if (empty) return { config: { ...config, minCredentialFormat: 2 }, credentials: [] }
  return {
    config,
    credentials: [
      {
        id: 'synthetic-legacy', siteName: 'Synthetic private site', usernameHint: 'synthetic-private-user', url: null,
        ...encrypted(Buffer.from('synthetic private password'), key),
        createdAt: date, updatedAt: date, deletedAt: null
      },
      {
        id: 'synthetic-encrypted', formatVersion: 2,
        ...encrypted(Buffer.from(JSON.stringify({
          siteName: 'Synthetic encrypted site', usernameHint: '', password: 'synthetic encrypted password'
        })), key, Buffer.from('password-manager:credential:v2')),
        createdAt: date, updatedAt: date, deletedAt: date
      }
    ]
  }
}

async function verify(empty: boolean, submittedPassword: string, binaries: string) {
  const directory = await mkdtemp(join(tmpdir(), 'password-manager-verifier-test-'))
  const backup = join(directory, 'backup.json')
  const receipt = join(directory, 'receipt.json')
  const artifact = JSON.stringify(createRecoveryBackup(fixture(empty), password)) + '\n'
  await writeFile(backup, artifact, { mode: 0o600 })
  const result = spawnSync(process.execPath, [
    '--import', 'tsx', 'scripts/verify-recovery.ts', backup, owner, receipt
  ], {
    cwd: resolve(__dirname, '..'),
    env: { PATH: process.env.PATH, TMPDIR: directory, TSX_DISABLE_CACHE: '1', ROLLOUT_POSTGRES_BIN: binaries },
    input: submittedPassword + '\n', encoding: 'utf8', timeout: 90_000
  })
  return { directory, backup, receipt, artifact, result }
}

test('wrong password fails before starting PostgreSQL or writing a receipt', async () => {
  const attempt = await verify(false, 'incorrect synthetic password', '/does-not-exist')
  try {
    assert.equal(attempt.result.status, 1)
    assert.match(attempt.result.stderr, /master password/)
    assert.equal(attempt.result.stdout, '')
    assert.deepEqual(await readdir(attempt.directory), ['backup.json'])
  } finally {
    await rm(attempt.directory, { recursive: true, force: true })
  }
})

for (const empty of [false, true]) {
  test(`a real PostgreSQL restore verifies ${empty ? 'an empty migrated vault' : 'mixed legacy and encrypted records'} and cleans up`, {
    skip: !process.env.ROLLOUT_POSTGRES_BIN
  }, async () => {
    const attempt = await verify(empty, password, process.env.ROLLOUT_POSTGRES_BIN!)
    try {
      assert.equal(attempt.result.status, 0, attempt.result.stderr)
      assert.equal(attempt.result.stdout, `Verified recovery of ${empty ? 0 : 2} credential(s)\n`)
      assert.equal(attempt.result.stderr, '')
      const receipt = JSON.parse(await readFile(attempt.receipt, 'utf8'))
      assert.deepEqual(Object.keys(receipt).sort(), ['backupPath', 'count', 'owner', 'restoreVerified', 'sha256', 'verifiedAt'].sort())
      assert.equal(receipt.backupPath, await realpath(attempt.backup))
      assert.equal(receipt.owner, owner)
      assert.equal(receipt.count, empty ? 0 : 2)
      assert.equal(receipt.restoreVerified, true)
      assert.equal(receipt.sha256, createHash('sha256').update(attempt.artifact).digest('hex'))
      assert(Number.isFinite(Date.parse(receipt.verifiedAt)))
      assert.equal((await stat(attempt.receipt)).mode & 0o777, 0o600)
      assert.deepEqual((await readdir(attempt.directory)).sort(), ['backup.json', 'receipt.json'])
    } finally {
      await rm(attempt.directory, { recursive: true, force: true })
    }
  })
}
