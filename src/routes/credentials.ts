import { FastifyInstance } from 'fastify'
import { Prisma } from '@prisma/client'
import { credentialSelect, serializeCredential, withCredentialWrite } from '../lib/credential'
import prisma from '../lib/prisma'
import { CredentialBody, CredentialParams } from '../types'

const bodySchema = {
  type: 'object',
  required: ['encryptedPayload', 'iv'],
  properties: {
    formatVersion:    { type: 'integer', enum: [1, 2] },
    siteName:         { type: 'string', minLength: 1, maxLength: 255 },
    usernameHint:     { type: 'string', maxLength: 255 },
    url:              { type: 'string', maxLength: 2048 },
    encryptedPayload: { type: 'string', minLength: 1 },
    iv:               { type: 'string', minLength: 1, maxLength: 64 }
  },
  additionalProperties: false,
  if: { required: ['formatVersion'], properties: { formatVersion: { const: 2 } } },
  then: { not: { anyOf: [
    { required: ['siteName'] },
    { required: ['usernameHint'] },
    { required: ['url'] }
  ] } },
  else: { required: ['siteName'] }
}

const idParamSchema = {
  type: 'object',
  required: ['id'],
  properties: {
    id: { type: 'string', minLength: 1 }
  }
}

function credentialData(body: CredentialBody) {
  const { encryptedPayload, iv } = body
  if (body.formatVersion === 2) {
    const ciphertext = Buffer.from(encryptedPayload, 'base64')
    const nonce = Buffer.from(iv, 'base64')
    if (ciphertext.length < 16 || ciphertext.toString('base64') !== encryptedPayload ||
        nonce.length !== 12 || nonce.toString('base64') !== iv) {
      return null
    }
    return { formatVersion: 2, siteName: null, usernameHint: null, url: null, encryptedPayload, iv }
  }
  const { siteName, usernameHint = '', url } = body
  return { formatVersion: 1, siteName, usernameHint, url, encryptedPayload, iv }
}

export async function credentialRoutes(app: FastifyInstance) {
  app.get('/', { config: { allowDeviceRead: true } }, async (req, reply) => {
    const credentials = await prisma.credential.findMany({
      where: { userId: req.userId, deletedAt: null },
      orderBy: { updatedAt: 'desc' },
      select: credentialSelect
    })
    return reply.send(credentials.map(serializeCredential))
  })

  app.post<{ Body: CredentialBody }>('/', {
    schema: { body: bodySchema }
  }, async (req, reply) => {
    const data = credentialData(req.body)
    if (!data) return reply.status(400).send({ error: 'Invalid encrypted credential encoding' })
    const credential = await withCredentialWrite(req.userId, async (tx, minimumFormat) => {
      if (data.formatVersion < minimumFormat) return null
      return tx.credential.create({
        data: { userId: req.userId, ...data }, select: credentialSelect
      })
    })
    if (!credential) return reply.status(409).send({ error: 'Vault requires an updated client' })
    return reply.status(201).send(serializeCredential(credential))
  })

  app.put<{ Params: CredentialParams; Body: CredentialBody }>('/:id', {
    schema: { params: idParamSchema, body: bodySchema }
  }, async (req, reply) => {
    const { id } = req.params
    const data = credentialData(req.body)
    if (!data) return reply.status(400).send({ error: 'Invalid encrypted credential encoding' })
    const where = { id, userId: req.userId, deletedAt: null }

    try {
      const updated = await withCredentialWrite(req.userId, async (tx, minimumFormat) => {
        if (data.formatVersion < minimumFormat) return null
        return tx.credential.update({
          where: data.formatVersion === 1 ? { ...where, formatVersion: 1 } : where,
          data, select: credentialSelect
        })
      })
      if (!updated) return reply.status(409).send({ error: 'Vault requires an updated client' })
      return reply.send(serializeCredential(updated))
    } catch (error) {
      if (!(error instanceof Prisma.PrismaClientKnownRequestError) || error.code !== 'P2025') throw error

      if (data.formatVersion === 1 && await prisma.credential.count({ where: { ...where, formatVersion: 2 } })) {
        return reply.status(409).send({ error: 'Encrypted credential requires an updated client' })
      }
      return reply.status(404).send({ error: 'Credential not found' })
    }
  })

  app.delete<{ Params: CredentialParams }>('/:id', {
    schema: { params: idParamSchema }
  }, async (req, reply) => {
    const { id } = req.params

    try {
      await withCredentialWrite(req.userId, async (tx) => {
        await tx.credential.update({
          where: { id, userId: req.userId, deletedAt: null },
          data: { deletedAt: new Date() }
        })
      })
      return reply.status(204).send()
    } catch (error) {
      if (!(error instanceof Prisma.PrismaClientKnownRequestError) || error.code !== 'P2025') throw error
      return reply.status(404).send({ error: 'Credential not found' })
    }
  })
}
