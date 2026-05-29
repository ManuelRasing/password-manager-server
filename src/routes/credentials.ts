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

export async function credentialRoutes(app: FastifyInstance) {
  app.get('/', async (_req, reply) => {
    const credentials = await prisma.credential.findMany({
      orderBy: { updatedAt: 'desc' },
      select: {
        id: true,
        siteName: true,
        usernameHint: true,
        url: true,
        encryptedPayload: true,
        iv: true,
        createdAt: true,
        updatedAt: true
      }
    })
    return reply.send(credentials)
  })

  app.post<{ Body: CredentialBody }>('/', {
    schema: { body: bodySchema }
  }, async (req, reply) => {
    const { siteName, usernameHint = '', url, encryptedPayload, iv } = req.body
    const credential = await prisma.credential.create({
      data: { siteName, usernameHint, url, encryptedPayload, iv }
    })
    return reply.status(201).send(credential)
  })

  app.put<{ Params: CredentialParams; Body: CredentialBody }>('/:id', {
    schema: { params: idParamSchema, body: bodySchema }
  }, async (req, reply) => {
    const { id } = req.params
    const { siteName, usernameHint = '', url, encryptedPayload, iv } = req.body

    const existing = await prisma.credential.findUnique({ where: { id } })
    if (!existing) return reply.status(404).send({ error: 'Credential not found' })

    const updated = await prisma.credential.update({
      where: { id },
      data: { siteName, usernameHint, url, encryptedPayload, iv }
    })
    return reply.send(updated)
  })

  app.delete<{ Params: CredentialParams }>('/:id', {
    schema: { params: idParamSchema }
  }, async (req, reply) => {
    const { id } = req.params

    const existing = await prisma.credential.findUnique({ where: { id } })
    if (!existing) return reply.status(404).send({ error: 'Credential not found' })

    await prisma.credential.delete({ where: { id } })
    return reply.status(204).send()
  })
}
