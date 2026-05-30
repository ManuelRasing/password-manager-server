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

  it('GET returns 404 when not configured', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/vault-config',
      headers: signedHeaders(alice.apiKey, 'alice', 'GET', '/vault-config'),
    })
    expect(res.statusCode).toBe(404)
  })

  it('PUT creates, GET returns it', async () => {
    const payload = vaultBody()
    const put = await app.inject({
      method: 'PUT',
      url: '/vault-config',
      headers: signedHeaders(alice.apiKey, 'alice', 'PUT', '/vault-config', payload),
      payload,
    })
    expect(put.statusCode).toBe(200)

    const get = await app.inject({
      method: 'GET',
      url: '/vault-config',
      headers: signedHeaders(alice.apiKey, 'alice', 'GET', '/vault-config'),
    })
    expect(get.statusCode).toBe(200)
    expect(get.json().masterSalt).toBe('salt-b64')
  })

  it('PUT again overwrites (rotation)', async () => {
    const first = vaultBody('salt-1')
    await app.inject({
      method: 'PUT',
      url: '/vault-config',
      headers: signedHeaders(alice.apiKey, 'alice', 'PUT', '/vault-config', first),
      payload: first,
    })
    const second = vaultBody('salt-2')
    await app.inject({
      method: 'PUT',
      url: '/vault-config',
      headers: signedHeaders(alice.apiKey, 'alice', 'PUT', '/vault-config', second),
      payload: second,
    })

    const get = await app.inject({
      method: 'GET',
      url: '/vault-config',
      headers: signedHeaders(alice.apiKey, 'alice', 'GET', '/vault-config'),
    })
    expect(get.json().masterSalt).toBe('salt-2')

    // Exactly one row for this user
    const count = await prisma.vaultConfig.count({ where: { userId: alice.id } })
    expect(count).toBe(1)
  })

  it('one user’s PUT does not affect another user’s vault', async () => {
    const aliceBody = vaultBody('alice-salt')
    await app.inject({
      method: 'PUT',
      url: '/vault-config',
      headers: signedHeaders(alice.apiKey, 'alice', 'PUT', '/vault-config', aliceBody),
      payload: aliceBody,
    })

    // Bob has no vault yet
    const bobGet = await app.inject({
      method: 'GET',
      url: '/vault-config',
      headers: signedHeaders(bob.apiKey, 'bob', 'GET', '/vault-config'),
    })
    expect(bobGet.statusCode).toBe(404)
  })
})
