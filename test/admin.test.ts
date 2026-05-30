import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import type { FastifyInstance } from 'fastify'
import { adminHeaders, createUser, getTestApp, prisma, resetDb, signedHeaders } from './helpers'

describe('admin API', () => {
  let app: FastifyInstance

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
  })

  it('rejects a missing admin key', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/admin/users',
      headers: { 'content-type': 'application/json' },
    })
    expect(res.statusCode).toBe(401)
  })

  it('rejects a wrong admin key', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/admin/users',
      headers: adminHeaders('wrong-key'),
    })
    expect(res.statusCode).toBe(401)
  })

  it('POST /users creates a user and returns the API key once', async () => {
    const payload = { username: 'charlie' }
    const res = await app.inject({
      method: 'POST',
      url: '/admin/users',
      headers: adminHeaders(),
      payload,
    })
    expect(res.statusCode).toBe(201)
    const out = res.json()
    expect(out.username).toBe('charlie')
    expect(out.apiKey).toMatch(/^[0-9a-f]{64}$/) // 32 random bytes hex

    // The key is persisted and matches
    const row = await prisma.user.findUnique({ where: { username: 'charlie' } })
    expect(row?.apiKey).toBe(out.apiKey)

    // GET /users never returns keys
    const list = await app.inject({
      method: 'GET',
      url: '/admin/users',
      headers: adminHeaders(),
    })
    expect(list.json()[0].apiKey).toBeUndefined()
  })

  it('rejects a duplicate username (409)', async () => {
    const payload = { username: 'charlie' }
    await app.inject({ method: 'POST', url: '/admin/users', headers: adminHeaders(), payload })
    const dup = await app.inject({ method: 'POST', url: '/admin/users', headers: adminHeaders(), payload })
    expect(dup.statusCode).toBe(409)
  })

  it('DELETE /users cascades credentials + vault config', async () => {
    // Create a user via admin so they have an id + key
    const created = (
      await app.inject({
        method: 'POST',
        url: '/admin/users',
        headers: adminHeaders(),
        payload: { username: 'dave' },
      })
    ).json()

    // Give dave a credential + vault config
    const credPayload = {
      siteName: 'GitHub',
      encryptedPayload: 'ZmFrZQ==',
      iv: 'aXY=',
    }
    await app.inject({
      method: 'POST',
      url: '/credentials',
      headers: signedHeaders(created.apiKey, 'dave', 'POST', '/credentials', credPayload),
      payload: credPayload,
    })
    const vaultPayload = { masterSalt: 's', encryptedVaultKey: 'k', vaultKeyIv: 'i' }
    await app.inject({
      method: 'PUT',
      url: '/vault-config',
      headers: signedHeaders(created.apiKey, 'dave', 'PUT', '/vault-config', vaultPayload),
      payload: vaultPayload,
    })

    // Delete the user
    const del = await app.inject({
      method: 'DELETE',
      url: `/admin/users/${created.id}`,
      headers: adminHeaders(),
    })
    expect(del.statusCode).toBe(204)

    // Everything is gone
    expect(await prisma.user.count({ where: { id: created.id } })).toBe(0)
    expect(await prisma.credential.count({ where: { userId: created.id } })).toBe(0)
    expect(await prisma.vaultConfig.count({ where: { userId: created.id } })).toBe(0)
  })

  it('POST /credentials/cleanup hard-deletes rows trashed >30 days ago', async () => {
    const u = await createUser('erin')
    // Two soft-deleted credentials: one old, one recent
    const old = await prisma.credential.create({
      data: {
        userId: u.id, siteName: 'Old', encryptedPayload: 'x', iv: 'y',
        deletedAt: new Date(Date.now() - 31 * 24 * 60 * 60 * 1000),
      },
    })
    const recent = await prisma.credential.create({
      data: {
        userId: u.id, siteName: 'Recent', encryptedPayload: 'x', iv: 'y',
        deletedAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000),
      },
    })

    const res = await app.inject({
      method: 'POST',
      url: '/admin/credentials/cleanup',
      headers: adminHeaders(),
    })
    expect(res.statusCode).toBe(200)
    expect(res.json().deleted).toBe(1)

    expect(await prisma.credential.findUnique({ where: { id: old.id } })).toBeNull()
    expect(await prisma.credential.findUnique({ where: { id: recent.id } })).not.toBeNull()
  })
})
