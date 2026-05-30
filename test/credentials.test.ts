import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import type { FastifyInstance } from 'fastify'
import { createUser, getTestApp, prisma, resetDb, signedHeaders } from './helpers'

const body = (siteName: string) => ({
  siteName,
  usernameHint: `${siteName}@example.com`,
  encryptedPayload: 'ZmFrZS1jaXBoZXJ0ZXh0', // base64 placeholder — server is opaque
  iv: 'ZmFrZS1pdg==',
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
