import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import type { FastifyInstance } from 'fastify'
import { createUser, getTestApp, prisma, resetDb, signedHeaders } from './helpers'

describe('HMAC auth', () => {
  let app: FastifyInstance
  let user: Awaited<ReturnType<typeof createUser>>

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
    user = await createUser('alice')
  })

  it('accepts a valid signature', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/credentials',
      headers: signedHeaders(user.apiKey, 'alice', 'GET', '/credentials'),
    })
    expect(res.statusCode).toBe(200)
  })

  it('rejects a missing X-Username', async () => {
    const headers = signedHeaders(user.apiKey, 'alice', 'GET', '/credentials')
    delete (headers as Record<string, string>)['x-username']
    const res = await app.inject({ method: 'GET', url: '/credentials', headers })
    expect(res.statusCode).toBe(401)
  })

  it('rejects a missing X-Timestamp', async () => {
    const headers = signedHeaders(user.apiKey, 'alice', 'GET', '/credentials')
    delete (headers as Record<string, string>)['x-timestamp']
    const res = await app.inject({ method: 'GET', url: '/credentials', headers })
    expect(res.statusCode).toBe(401)
  })

  it('rejects a missing X-Signature', async () => {
    const headers = signedHeaders(user.apiKey, 'alice', 'GET', '/credentials')
    delete (headers as Record<string, string>)['x-signature']
    const res = await app.inject({ method: 'GET', url: '/credentials', headers })
    expect(res.statusCode).toBe(401)
  })

  it('rejects an expired timestamp (40s old)', async () => {
    const old = (Math.floor(Date.now() / 1000) - 40).toString()
    const res = await app.inject({
      method: 'GET',
      url: '/credentials',
      headers: signedHeaders(user.apiKey, 'alice', 'GET', '/credentials', undefined, {
        timestamp: old,
      }),
    })
    expect(res.statusCode).toBe(401)
  })

  it('rejects a nonexistent username', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/credentials',
      headers: signedHeaders(user.apiKey, 'ghost', 'GET', '/credentials'),
    })
    expect(res.statusCode).toBe(401)
  })

  it('rejects a valid username with a wrong signature', async () => {
    const headers = signedHeaders(user.apiKey, 'alice', 'GET', '/credentials')
    headers['x-signature'] = 'deadbeef'.repeat(8) // wrong but well-formed hex
    const res = await app.inject({ method: 'GET', url: '/credentials', headers })
    expect(res.statusCode).toBe(401)
    // Same generic message as an unknown user — no account enumeration.
    expect(res.json().error).toBe('Invalid credentials')
  })
})
