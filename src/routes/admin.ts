import crypto from 'crypto'
import { FastifyInstance } from 'fastify'
import prisma from '../lib/prisma'
import { CreateUserBody, UserParams } from '../types'

// Admin routes are protected by a separate ADMIN_KEY env var (NOT a per-user key).
// They are registered outside the HMAC-protected scope and use a simple
// constant-time header comparison instead.
const adminKeyHeader = 'x-admin-key'

const createBodySchema = {
  type: 'object',
  required: ['username'],
  properties: {
    username: { type: 'string', minLength: 1, maxLength: 64, pattern: '^[A-Za-z0-9_.-]+$' }
  },
  additionalProperties: false
}

const idParamSchema = {
  type: 'object',
  required: ['id'],
  properties: { id: { type: 'string', minLength: 1 } }
}

function timingSafeStringEq(a: string, b: string): boolean {
  const aBuf = Buffer.from(a)
  const bBuf = Buffer.from(b)
  if (aBuf.length !== bBuf.length) return false
  return crypto.timingSafeEqual(aBuf, bBuf)
}

export async function adminRoutes(app: FastifyInstance) {
  app.addHook('preHandler', async (request, reply) => {
    const adminKey = process.env.ADMIN_KEY
    if (!adminKey) {
      return reply.status(503).send({ error: 'Admin API disabled — ADMIN_KEY not set' })
    }
    const provided = request.headers[adminKeyHeader] as string | undefined
    if (!provided || !timingSafeStringEq(provided, adminKey)) {
      return reply.status(401).send({ error: 'Invalid admin key' })
    }
  })

  // POST /admin/users — create a new user. API key returned ONCE.
  app.post<{ Body: CreateUserBody }>('/users', {
    schema: { body: createBodySchema }
  }, async (req, reply) => {
    const { username } = req.body
    const existing = await prisma.user.findUnique({ where: { username } })
    if (existing) return reply.status(409).send({ error: 'Username already taken' })

    const apiKey = crypto.randomBytes(32).toString('hex')
    const user = await prisma.user.create({
      data: { username, apiKey },
      select: { id: true, username: true, createdAt: true }
    })

    return reply.status(201).send({
      ...user,
      apiKey,        // shown ONCE; the admin must distribute this securely
      note: 'Save this API key now — it will not be shown again.'
    })
  })

  // GET /admin/users — list all users (no keys).
  app.get('/users', async (_req, reply) => {
    const users = await prisma.user.findMany({
      select: { id: true, username: true, createdAt: true },
      orderBy: { createdAt: 'asc' }
    })
    return reply.send(users)
  })

  // DELETE /admin/users/:id — delete a user.
  // Credentials and VaultConfig are NOT cascaded by Prisma (no @relation in schema),
  // so we delete them explicitly inside a transaction.
  app.delete<{ Params: UserParams }>('/users/:id', {
    schema: { params: idParamSchema }
  }, async (req, reply) => {
    const { id } = req.params
    const existing = await prisma.user.findUnique({ where: { id } })
    if (!existing) return reply.status(404).send({ error: 'User not found' })

    await prisma.$transaction([
      prisma.credential.deleteMany({  where: { userId: id } }),
      prisma.vaultConfig.deleteMany({ where: { userId: id } }),
      prisma.user.delete({            where: { id } })
    ])

    return reply.status(204).send()
  })

  // POST /admin/credentials/cleanup — permanently remove soft-deleted credentials
  // older than 30 days. Run manually; no cron needed at our scale.
  app.post('/credentials/cleanup', async (_req, reply) => {
    const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // 30 days ago
    const result = await prisma.credential.deleteMany({
      where: { deletedAt: { lt: cutoff } }
    })
    return reply.send({ deleted: result.count, cutoff: cutoff.toISOString() })
  })
}
