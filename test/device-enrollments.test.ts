import { createHash } from 'node:crypto'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import type { FastifyInstance } from 'fastify'
import { buildApp } from '../src/app'
import { createUser, getTestApp, prisma, resetDb, signedHeaders } from './helpers'

describe('read-only device enrollment', () => {
  let app: FastifyInstance
  let alice: Awaited<ReturnType<typeof createUser>>

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
  })

  async function issueCode() {
    const payload = { deviceName: 'My Mac' }
    const response = await app.inject({
      method: 'POST',
      url: '/device-enrollments',
      headers: signedHeaders(alice.apiKey, alice.username, 'POST', '/device-enrollments', payload),
      payload,
    })
    expect(response.statusCode).toBe(201)
    return response.json() as { code: string; expiresAt: string }
  }

  async function enroll() {
    const { code } = await issueCode()
    const response = await app.inject({
      method: 'POST', url: '/device-enrollments/redeem', payload: { code },
    })
    expect(response.statusCode).toBe(201)
    return response.json() as { deviceId: string; deviceName: string; deviceToken: string }
  }

  it('exchanges an owner-issued code once and stores only secret hashes', async () => {
    const before = Date.now()
    const { code, expiresAt } = await issueCode()
    expect(code).toMatch(/^[A-Za-z0-9_-]{22}$/)
    expect(new Date(expiresAt).getTime()).toBeGreaterThan(before)
    expect(new Date(expiresAt).getTime()).toBeLessThanOrEqual(Date.now() + 5 * 60 * 1000)
    const pending = await prisma.deviceEnrollment.findUniqueOrThrow({
      where: { codeHash: createHash('sha256').update(code).digest('hex') },
    })
    expect(pending.userId).toBe(alice.id)
    expect(pending.consumedAt).toBeNull()
    expect(JSON.stringify(pending)).not.toContain(code)

    const responses = await Promise.all([0, 1].map(() => app.inject({
      method: 'POST', url: '/device-enrollments/redeem', payload: { code },
    })))
    expect(responses.map((response) => response.statusCode).sort()).toEqual([201, 401])
    const enrolled = responses.find((response) => response.statusCode === 201)!.json()
    expect(enrolled.deviceName).toBe('My Mac')
    expect(enrolled.deviceToken).toMatch(/^pm_device_[A-Za-z0-9_-]{43}$/)
    const stored = await prisma.deviceAccess.findUniqueOrThrow({ where: { id: enrolled.deviceId } })
    expect(stored.tokenHash).toBe(createHash('sha256').update(enrolled.deviceToken).digest('hex'))
    expect(stored.userId).toBe(alice.id)
    expect(JSON.stringify(stored)).not.toContain(enrolled.deviceToken)
    expect(await prisma.deviceAccess.count({ where: { userId: alice.id } })).toBe(1)
    expect((await prisma.deviceEnrollment.findUniqueOrThrow({ where: { id: pending.id } })).consumedAt)
      .toBeInstanceOf(Date)
  })

  it('rejects expired and unknown codes without issuing device access', async () => {
    const { code } = await issueCode()
    await prisma.deviceEnrollment.updateMany({
      where: { userId: alice.id }, data: { expiresAt: new Date(0) },
    })
    for (const invalidCode of [code, 'z'.repeat(22)]) {
      const response = await app.inject({
        method: 'POST', url: '/device-enrollments/redeem', payload: { code: invalidCode },
      })
      expect(response.statusCode).toBe(401)
    }
    expect(await prisma.deviceAccess.count()).toBe(0)
  })

  it('requires the owner HMAC to issue enrollment codes', async () => {
    const response = await app.inject({
      method: 'POST', url: '/device-enrollments', payload: { deviceName: 'My Mac' },
    })
    expect(response.statusCode).toBe(401)
    expect(await prisma.deviceEnrollment.count()).toBe(0)
  })

  it('permits only the enrolled owner’s vault reads', async () => {
    const bob = await createUser('bob')
    const config = { masterSalt: 'synthetic-salt', encryptedVaultKey: 'synthetic-key', vaultKeyIv: 'synthetic-iv' }
    await prisma.vaultConfig.create({ data: { ...config, userId: alice.id } })
    const credential = await prisma.credential.create({
      data: { userId: alice.id, siteName: 'Alice login', usernameHint: '', encryptedPayload: 'synthetic', iv: 'synthetic' },
    })
    await prisma.credential.create({
      data: { userId: bob.id, siteName: 'Bob login', usernameHint: '', encryptedPayload: 'synthetic', iv: 'synthetic' },
    })
    const { deviceToken } = await enroll()
    const headers = { authorization: `Bearer ${deviceToken}` }
    const credentials = await app.inject({ method: 'GET', url: '/credentials', headers })
    expect(credentials.statusCode).toBe(200)
    expect(credentials.json().map((entry: { id: string }) => entry.id)).toEqual([credential.id])
    const vault = await app.inject({ method: 'GET', url: '/vault-config', headers })
    expect(vault.statusCode).toBe(200)
    expect(vault.json()).toMatchObject(config)

    const payload = { siteName: 'Forbidden', encryptedPayload: 'synthetic', iv: 'synthetic' }
    const writes = [
      { method: 'POST', url: '/credentials', payload },
      { method: 'PUT', url: `/credentials/${credential.id}`, payload },
      { method: 'DELETE', url: `/credentials/${credential.id}` },
      { method: 'POST', url: '/vault-config', payload: config },
      { method: 'PUT', url: '/vault-config', payload: { ...config, revision: 1 } },
      { method: 'POST', url: '/backup/google-drive' },
      { method: 'POST', url: '/device-enrollments', payload: { deviceName: 'Another Mac' } },
    ] as const
    for (const request of writes) {
      const response = await app.inject({ ...request, headers })
      expect(response.statusCode).toBe(403)
    }
    expect(await prisma.credential.count({ where: { userId: alice.id, deletedAt: null } })).toBe(1)
  })

  it('rejects revoked or mixed device authentication while owner access continues', async () => {
    const { deviceId, deviceToken } = await enroll()
    const mixed = await app.inject({
      method: 'GET',
      url: '/credentials',
      headers: {
        ...signedHeaders(alice.apiKey, alice.username, 'GET', '/credentials'),
        authorization: `Bearer ${deviceToken}`,
      },
    })
    expect(mixed.statusCode).toBe(401)
    await prisma.deviceAccess.update({ where: { id: deviceId }, data: { revokedAt: new Date() } })
    const revoked = await app.inject({
      method: 'GET', url: '/credentials', headers: { authorization: `Bearer ${deviceToken}` },
    })
    expect(revoked.statusCode).toBe(401)
    const owner = await app.inject({
      method: 'GET', url: '/credentials', headers: signedHeaders(alice.apiKey, alice.username, 'GET', '/credentials'),
    })
    expect(owner.statusCode).toBe(200)
  })

  it('rate-limits public enrollment redemption', async () => {
    const limited = buildApp({ logger: false })
    await limited.ready()
    try {
      for (let index = 0; index < 20; index++) {
        const response = await limited.inject({
          method: 'POST', url: '/device-enrollments/redeem', payload: { code: 'z'.repeat(22) },
          remoteAddress: '198.51.100.7',
        })
        expect(response.statusCode).toBe(401)
      }
      const response = await limited.inject({
        method: 'POST', url: '/device-enrollments/redeem', payload: { code: 'z'.repeat(22) },
        remoteAddress: '198.51.100.7',
      })
      expect(response.statusCode).toBe(429)
    } finally {
      await limited.close()
    }
  })

  it('lets the owner revoke one device and enroll again without reviving its token', async () => {
    const bob = await createUser('bob')
    const lost = await enroll()
    const other = await enroll()
    const listing = await app.inject({
      method: 'GET', url: '/devices',
      headers: signedHeaders(alice.apiKey, alice.username, 'GET', '/devices')
    })
    expect(listing.statusCode).toBe(200)
    expect(listing.json()).toHaveLength(2)
    expect(Object.keys(listing.json()[0]).sort()).toEqual(['createdAt', 'deviceName', 'id', 'revokedAt'])
    const path = '/devices/' + lost.deviceId
    const denied = await app.inject({
      method: 'DELETE', url: path,
      headers: signedHeaders(bob.apiKey, bob.username, 'DELETE', path)
    })
    expect(denied.statusCode).toBe(404)
    for (const method of ['GET', 'DELETE'] as const) {
      const response = await app.inject({
        method, url: method === 'GET' ? '/devices' : path,
        headers: { authorization: 'Bearer ' + other.deviceToken }
      })
      expect(response.statusCode).toBe(403)
    }
    const revoke = () => app.inject({
      method: 'DELETE', url: path,
      headers: signedHeaders(alice.apiKey, alice.username, 'DELETE', path)
    })
    expect((await revoke()).statusCode).toBe(204)
    const firstRevocation = (await prisma.deviceAccess.findUniqueOrThrow({
      where: { id: lost.deviceId }
    })).revokedAt
    expect((await revoke()).statusCode).toBe(204)
    expect((await prisma.deviceAccess.findUniqueOrThrow({
      where: { id: lost.deviceId }
    })).revokedAt).toEqual(firstRevocation)
    const replacement = await enroll()
    expect(replacement.deviceId).not.toBe(lost.deviceId)
    for (const [token, expected] of [
      [lost.deviceToken, 401], [other.deviceToken, 200], [replacement.deviceToken, 200]
    ] as const) {
      expect((await app.inject({
        method: 'GET', url: '/credentials',
        headers: { authorization: 'Bearer ' + token }
      })).statusCode).toBe(expected)
    }
    expect((await app.inject({
      method: 'GET', url: '/credentials',
      headers: signedHeaders(alice.apiKey, alice.username, 'GET', '/credentials')
    })).statusCode).toBe(200)
  })
})
