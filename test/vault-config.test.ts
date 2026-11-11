import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import type { FastifyInstance } from 'fastify'
import { createUser, getTestApp, prisma, resetDb, signedHeaders } from './helpers'

const vaultBody = (salt = 'salt-b64') => ({
  masterSalt: salt,
  encryptedVaultKey: 'wrapped-key-b64',
  vaultKeyIv: 'iv-b64',
})

describe('vault-config (per-user)', () => {
  let app: FastifyInstance
  let alice: Awaited<ReturnType<typeof createUser>>
  let bob: Awaited<ReturnType<typeof createUser>>

  beforeAll(async () => {
    app = getTestApp()
    await app.ready()
  })

  afterAll(async () => {
    await app.close()
    await prisma.$disconnect()
  })

  beforeEach(async () => {
    await resetDb()
    alice = await createUser('alice')
    bob = await createUser('bob')
  })

  function inject(
    user: typeof alice,
    method: 'GET' | 'POST' | 'PUT',
    payload?: ReturnType<typeof vaultBody> & { revision?: number },
  ) {
    const url = '/vault-config'
    return app.inject({
      method,
      url,
      headers: signedHeaders(user.apiKey, user.username, method, url, payload),
      payload,
    })
  }

  it('returns 404 when no config exists', async () => {
    expect((await inject(alice, 'GET')).statusCode).toBe(404)
  })

  it('returns existing config fields and their initial revision', async () => {
    const payload = vaultBody()
    await prisma.vaultConfig.create({ data: { userId: alice.id, ...payload } })
    const get = await inject(alice, 'GET')
    expect(get.statusCode).toBe(200)
    expect(get.json()).toEqual({ ...payload, revision: 1 })
  })

  it('accepts one concurrent setup and preserves its config', async () => {
    const setups = await Promise.all([
      inject(alice, 'POST', vaultBody('salt-1')),
      inject(alice, 'POST', vaultBody('salt-2')),
    ])
    expect(setups.map(response => response.statusCode).sort()).toEqual([201, 409])
    const created = setups.find(response => response.statusCode === 201)!
    expect(created.json().revision).toBe(1)
    expect((await inject(alice, 'GET')).json()).toEqual(created.json())
    expect(await prisma.vaultConfig.count({ where: { userId: alice.id } })).toBe(1)
  })

  it('rejects a rotation when no config exists', async () => {
    const update = await inject(alice, 'PUT', { ...vaultBody(), revision: 1 })
    expect(update.statusCode).toBe(409)
    expect((await inject(alice, 'GET')).statusCode).toBe(404)
  })

  it('requires a revision and rejects a stale rotation', async () => {
    await inject(alice, 'POST', vaultBody('initial-salt'))
    expect((await inject(alice, 'PUT', vaultBody())).statusCode).toBe(400)

    const update = await inject(alice, 'PUT', { ...vaultBody('new-salt'), revision: 1 })
    expect(update.statusCode).toBe(200)
    expect(update.json()).toEqual({ ...vaultBody('new-salt'), revision: 2 })
    const stale = await inject(alice, 'PUT', { ...vaultBody('stale-salt'), revision: 1 })
    expect(stale.statusCode).toBe(409)
    expect((await inject(alice, 'GET')).json()).toEqual(update.json())
  })

  it('accepts one concurrent rotation from the same revision', async () => {
    await inject(alice, 'POST', vaultBody('initial-salt'))
    const rotations = await Promise.all([
      inject(alice, 'PUT', { ...vaultBody('salt-1'), revision: 1 }),
      inject(alice, 'PUT', { ...vaultBody('salt-2'), revision: 1 }),
    ])
    expect(rotations.map(response => response.statusCode).sort()).toEqual([200, 409])
    const accepted = rotations.find(response => response.statusCode === 200)!
    expect(accepted.json().revision).toBe(2)
    expect((await inject(alice, 'GET')).json()).toEqual(accepted.json())
  })

  it('isolates setup and rotations between users', async () => {
    await inject(alice, 'POST', vaultBody('alice-salt'))
    expect((await inject(bob, 'GET')).statusCode).toBe(404)
    await inject(bob, 'POST', vaultBody('bob-salt'))

    const update = await inject(alice, 'PUT', { ...vaultBody('alice-new-salt'), revision: 1 })
    expect(update.statusCode).toBe(200)
    expect((await inject(bob, 'GET')).json()).toEqual({ ...vaultBody('bob-salt'), revision: 1 })
  })
})
