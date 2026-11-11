import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import type { FastifyInstance } from 'fastify'
import { createUser, getTestApp, prisma, resetDb, signedHeaders } from './helpers'

const body = (siteName: string) => ({
  siteName,
  usernameHint: `${siteName}@example.com`,
  url: 'https://login.example.com',
  encryptedPayload: 'ZmFrZS1jaXBoZXJ0ZXh0', // base64 placeholder — server is opaque
  iv: 'ZmFrZS1pdg==',
})

const encryptedBody = (marker = 7) => ({
  formatVersion: 2,
  encryptedPayload: Buffer.alloc(32, marker).toString('base64'),
  iv: Buffer.alloc(12, marker).toString('base64'),
})

// POST a credential as `user`, returning the created record.
async function createCredential(
  app: FastifyInstance,
  user: { apiKey: string; username: string },
  siteName: string,
) {
  const payload = body(siteName)
  const res = await app.inject({
    method: 'POST',
    url: '/credentials',
    headers: signedHeaders(user.apiKey, user.username, 'POST', '/credentials', payload),
    payload,
  })
  expect(res.statusCode).toBe(201)
  return res.json()
}

describe('credentials CRUD + per-user scoping', () => {
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

  it('POST creates a credential owned by the authenticated user', async () => {
    const created = await createCredential(app, alice, 'GitHub')
    expect(created.siteName).toBe('GitHub')

    const row = await prisma.credential.findUnique({ where: { id: created.id } })
    expect(row?.userId).toBe(alice.id)
  })

  it('GET returns only the requesting user’s credentials', async () => {
    await createCredential(app, alice, 'GitHub')
    await createCredential(app, bob, 'GitLab')

    const res = await app.inject({
      method: 'GET',
      url: '/credentials',
      headers: signedHeaders(alice.apiKey, 'alice', 'GET', '/credentials'),
    })
    const list = res.json()
    expect(list).toHaveLength(1)
    expect(list[0].siteName).toBe('GitHub')
  })

  it('stores and returns fully encrypted credentials alongside legacy credentials', async () => {
    const legacy = await createCredential(app, alice, 'Legacy')
    const payload = encryptedBody()
    const create = await app.inject({
      method: 'POST',
      url: '/credentials',
      headers: signedHeaders(alice.apiKey, alice.username, 'POST', '/credentials', payload),
      payload,
    })
    expect(create.statusCode).toBe(201)
    const created = create.json()
    expect(created).toEqual({
      ...payload,
      id: expect.any(String),
      createdAt: expect.any(String),
      updatedAt: expect.any(String),
    })
    const row = await prisma.credential.findUnique({ where: { id: created.id } })
    expect(row).toMatchObject({
      ...payload,
      siteName: null,
      usernameHint: null,
      url: null,
    })

    const list = await app.inject({
      method: 'GET',
      url: '/credentials',
      headers: signedHeaders(alice.apiKey, alice.username, 'GET', '/credentials'),
    })
    expect(list.statusCode).toBe(200)
    expect(list.json()).toEqual(expect.arrayContaining([legacy, created]))
  })

  it.each([
    { ...encryptedBody(), siteName: 'Unexpected plaintext' },
    { ...encryptedBody(), usernameHint: 'Unexpected plaintext' },
    { ...encryptedBody(), url: 'https://example.com' },
    { ...encryptedBody(), iv: 'invalid' },
    { ...encryptedBody(), encryptedPayload: 'invalid' },
  ])('rejects malformed encrypted records without storing them', async (payload) => {
    const response = await app.inject({
      method: 'POST',
      url: '/credentials',
      headers: signedHeaders(alice.apiKey, alice.username, 'POST', '/credentials', payload),
      payload,
    })
    expect(response.statusCode).toBe(400)
    expect(await prisma.credential.count({ where: { userId: alice.id } })).toBe(0)
  })

  it('upgrades a legacy credential without retaining metadata or permitting a downgrade', async () => {
    const legacy = await createCredential(app, alice, 'Legacy')
    const path = `/credentials/${legacy.id}`
    const upgrade = encryptedBody()
    const edit = encryptedBody(8)

    for (const payload of [upgrade, edit]) {
      const response = await app.inject({
        method: 'PUT',
        url: path,
        headers: signedHeaders(alice.apiKey, alice.username, 'PUT', path, payload),
        payload,
      })
      expect(response.statusCode).toBe(200)
      expect(response.json()).toEqual({
        ...payload,
        id: legacy.id,
        createdAt: legacy.createdAt,
        updatedAt: expect.any(String),
      })
    }

    const downgrade = body('Legacy replacement')
    const response = await app.inject({
      method: 'PUT',
      url: path,
      headers: signedHeaders(alice.apiKey, alice.username, 'PUT', path, downgrade),
      payload: downgrade,
    })
    expect(response.statusCode).toBe(409)
    const row = await prisma.credential.findUnique({ where: { id: legacy.id } })
    expect(row).toMatchObject({ ...edit, siteName: null, usernameHint: null, url: null })
  })

  it('keeps encrypted records scoped to their owner and preserves soft deletion', async () => {
    const payload = encryptedBody()
    const create = await app.inject({
      method: 'POST',
      url: '/credentials',
      headers: signedHeaders(alice.apiKey, alice.username, 'POST', '/credentials', payload),
      payload,
    })
    expect(create.statusCode).toBe(201)
    const created = create.json()
    const path = `/credentials/${created.id}`

    for (const method of ['PUT', 'DELETE'] as const) {
      const body = method === 'PUT' ? encryptedBody(8) : undefined
      const response = await app.inject({
        method,
        url: path,
        headers: signedHeaders(bob.apiKey, bob.username, method, path, body),
        ...(body ? { payload: body } : {}),
      })
      expect(response.statusCode).toBe(404)
    }

    const deletion = await app.inject({
      method: 'DELETE',
      url: path,
      headers: signedHeaders(alice.apiKey, alice.username, 'DELETE', path),
    })
    expect(deletion.statusCode).toBe(204)
    expect(await prisma.credential.findUnique({ where: { id: created.id } })).toMatchObject({
      ...payload,
      deletedAt: expect.any(Date),
    })

    const update = encryptedBody(9)
    const edit = await app.inject({
      method: 'PUT',
      url: path,
      headers: signedHeaders(alice.apiKey, alice.username, 'PUT', path, update),
      payload: update,
    })
    expect(edit.statusCode).toBe(404)
    const list = await app.inject({
      method: 'GET',
      url: '/credentials',
      headers: signedHeaders(alice.apiKey, alice.username, 'GET', '/credentials'),
    })
    expect(list.statusCode).toBe(200)
    expect(list.json()).toEqual([])
  })

  it('User B cannot UPDATE User A’s credential (404, not 403)', async () => {
    const aliceCred = await createCredential(app, alice, 'GitHub')
    const path = `/credentials/${aliceCred.id}`
    const payload = body('Hacked')
    const res = await app.inject({
      method: 'PUT',
      url: path,
      headers: signedHeaders(bob.apiKey, 'bob', 'PUT', path, payload),
      payload,
    })
    expect(res.statusCode).toBe(404)

    // Unchanged in DB
    const row = await prisma.credential.findUnique({ where: { id: aliceCred.id } })
    expect(row?.siteName).toBe('GitHub')
  })

  it('User B cannot DELETE User A’s credential (404)', async () => {
    const aliceCred = await createCredential(app, alice, 'GitHub')
    const path = `/credentials/${aliceCred.id}`
    const res = await app.inject({
      method: 'DELETE',
      url: path,
      headers: signedHeaders(bob.apiKey, 'bob', 'DELETE', path),
    })
    expect(res.statusCode).toBe(404)

    const row = await prisma.credential.findUnique({ where: { id: aliceCred.id } })
    expect(row?.deletedAt).toBeNull()
  })

  it('DELETE soft-deletes (row remains, deletedAt set)', async () => {
    const cred = await createCredential(app, alice, 'GitHub')
    const path = `/credentials/${cred.id}`
    const res = await app.inject({
      method: 'DELETE',
      url: path,
      headers: signedHeaders(alice.apiKey, 'alice', 'DELETE', path),
    })
    expect(res.statusCode).toBe(204)

    const row = await prisma.credential.findUnique({ where: { id: cred.id } })
    expect(row).not.toBeNull()
    expect(row?.deletedAt).toBeInstanceOf(Date)
  })

  it('soft-deleted credentials do not appear in GET', async () => {
    const cred = await createCredential(app, alice, 'GitHub')
    const path = `/credentials/${cred.id}`
    await app.inject({
      method: 'DELETE',
      url: path,
      headers: signedHeaders(alice.apiKey, 'alice', 'DELETE', path),
    })

    const res = await app.inject({
      method: 'GET',
      url: '/credentials',
      headers: signedHeaders(alice.apiKey, 'alice', 'GET', '/credentials'),
    })
    expect(res.json()).toHaveLength(0)
  })

  it('cannot UPDATE a soft-deleted credential (404)', async () => {
    const cred = await createCredential(app, alice, 'GitHub')
    const path = `/credentials/${cred.id}`
    await app.inject({
      method: 'DELETE',
      url: path,
      headers: signedHeaders(alice.apiKey, 'alice', 'DELETE', path),
    })

    const payload = body('Resurrected')
    const res = await app.inject({
      method: 'PUT',
      url: path,
      headers: signedHeaders(alice.apiKey, 'alice', 'PUT', path, payload),
      payload,
    })
    expect(res.statusCode).toBe(404)
  })
})
