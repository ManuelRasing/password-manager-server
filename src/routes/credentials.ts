import { FastifyInstance } from 'fastify'
import prisma from '../lib/prisma'
import { CredentialBody, CredentialParams } from '../types'

const bodySchema = {
  type: 'object',
  required: ['siteName', 'encryptedPayload', 'iv'],
  properties: {
    siteName:         { type: 'string', minLength: 1, maxLength: 255 },
    usernameHint:     { type: 'string', maxLength: 255 },
    url:              { type: 'string', maxLength: 2048 },
    encryptedPayload: { type: 'string', minLength: 1 },
    iv:               { type: 'string', minLength: 1, maxLength: 64 }
  },
  additionalProperties: false
}

const idParamSchema = {
  type: 'object',
  required: ['id'],
  properties: {
    id: { type: 'string', minLength: 1 }
  }
}

// Fields returned to the client — kept in one place to stay in sync across routes.
const credentialSelect = {
  id: true,
  siteName: true,
  usernameHint: true,
  url: true,
  encryptedPayload: true,
  iv: true,
  createdAt: true,
  updatedAt: true
} as const

export async function credentialRoutes(app: FastifyInstance) {
  app.get('/', async (req, reply) => {
    const credentials = await prisma.credential.findMany({
      where: { userId: req.userId, deletedAt: null },
      orderBy: { updatedAt: 'desc' },
      select: credentialSelect
    })
    return reply.send(credentials)
  })

  app.post<{ Body: CredentialBody }>('/', {
    schema: { body: bodySchema }
  }, async (req, reply) => {
    const { siteName, usernameHint = '', url, encryptedPayload, iv } = req.body
    const credential = await prisma.credential.create({
      data: { userId: req.userId, siteName, usernameHint, url, encryptedPayload, iv },
      select: credentialSelect
    })
    return reply.status(201).send(credential)
  })

  app.put<{ Params: CredentialParams; Body: CredentialBody }>('/:id', {
    schema: { params: idParamSchema, body: bodySchema }
  }, async (req, reply) => {
    const { id } = req.params
    const { siteName, usernameHint = '', url, encryptedPayload, iv } = req.body

    // Scoped lookup — a wrong owner (or soft-deleted row) gets a 404, not 403,
    // to avoid leaking existence.
    const existing = await prisma.credential.findFirst({
      where: { id, userId: req.userId, deletedAt: null }
    })
    if (!existing) return reply.status(404).send({ error: 'Credential not found' })

    const updated = await prisma.credential.update({
      where: { id },
      data: { siteName, usernameHint, url, encryptedPayload, iv },
      select: credentialSelect
    })
    return reply.send(updated)
  })

  app.delete<{ Params: CredentialParams }>('/:id', {
    schema: { params: idParamSchema }
  }, async (req, reply) => {
    const { id } = req.params

    const existing = await prisma.credential.findFirst({
      where: { id, userId: req.userId, deletedAt: null }
    })
    if (!existing) return reply.status(404).send({ error: 'Credential not found' })

    // Soft delete — the row stays in the DB (recoverable) but is hidden everywhere.
    await prisma.credential.update({
      where: { id },
      data: { deletedAt: new Date() }
    })
    return reply.status(204).send()
  })
}
