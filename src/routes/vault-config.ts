import { FastifyInstance } from 'fastify'
import { Prisma } from '@prisma/client'
import prisma from '../lib/prisma'
import { UpdateVaultConfigBody, VaultConfigBody } from '../types'

const bodySchema = {
  type: 'object',
  required: ['masterSalt', 'encryptedVaultKey', 'vaultKeyIv'],
  properties: {
    masterSalt:        { type: 'string', minLength: 1 },
    encryptedVaultKey: { type: 'string', minLength: 1 },
    vaultKeyIv:        { type: 'string', minLength: 1 }
  },
  additionalProperties: false
}

const updateBodySchema = {
  ...bodySchema,
  required: [...bodySchema.required, 'revision'],
  properties: {
    ...bodySchema.properties,
    revision: { type: 'integer', minimum: 1, maximum: 2_147_483_646 }
  }
}

const vaultConfigSelect = {
  masterSalt: true,
  encryptedVaultKey: true,
  vaultKeyIv: true,
  revision: true
} as const

export async function vaultConfigRoutes(app: FastifyInstance) {
  // GET /vault-config — returns this user's vault config, or 404 if not set up.
  app.get('/', { config: { allowDeviceRead: true } }, async (req, reply) => {
    const config = await prisma.vaultConfig.findUnique({
      where:  { userId: req.userId },
      select: vaultConfigSelect
    })
    if (!config) return reply.status(404).send({ error: 'Vault not configured' })
    return reply.send(config)
  })

  app.post<{ Body: VaultConfigBody }>('/', {
    schema: { body: bodySchema }
  }, async (req, reply) => {
    const { masterSalt, encryptedVaultKey, vaultKeyIv } = req.body
    try {
      const config = await prisma.vaultConfig.create({
        data: { userId: req.userId, masterSalt, encryptedVaultKey, vaultKeyIv },
        select: vaultConfigSelect
      })
      return reply.status(201).send(config)
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
        return reply.status(409).send({ error: 'Vault already configured' })
      }
      throw error
    }
  })

  app.put<{ Body: UpdateVaultConfigBody }>('/', {
    schema: { body: updateBodySchema }
  }, async (req, reply) => {
    const { revision, masterSalt, encryptedVaultKey, vaultKeyIv } = req.body
    try {
      const config = await prisma.vaultConfig.update({
        where: { userId: req.userId, revision },
        data: { masterSalt, encryptedVaultKey, vaultKeyIv, revision: { increment: 1 } },
        select: vaultConfigSelect
      })
      return reply.send(config)
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2025') {
        return reply.status(409).send({ error: 'Vault configuration is missing or has changed' })
      }
      throw error
    }
  })
}
