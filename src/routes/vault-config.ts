import { FastifyInstance } from 'fastify'
import prisma from '../lib/prisma'
import { VaultConfigBody } from '../types'

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

const vaultConfigSelect = {
  masterSalt: true,
  encryptedVaultKey: true,
  vaultKeyIv: true
} as const

export async function vaultConfigRoutes(app: FastifyInstance) {
  // GET /vault-config — returns this user's vault config, or 404 if not set up.
  app.get('/', async (req, reply) => {
    const config = await prisma.vaultConfig.findUnique({
      where:  { userId: req.userId },
      select: vaultConfigSelect
    })
    if (!config) return reply.status(404).send({ error: 'Vault not configured' })
    return reply.send(config)
  })

  // PUT /vault-config — upserts this user's vault config (first setup or rotation).
  app.put<{ Body: VaultConfigBody }>('/', {
    schema: { body: bodySchema }
  }, async (req, reply) => {
    const { masterSalt, encryptedVaultKey, vaultKeyIv } = req.body
    const config = await prisma.vaultConfig.upsert({
      where:  { userId: req.userId },
      update: { masterSalt, encryptedVaultKey, vaultKeyIv },
      create: { userId: req.userId, masterSalt, encryptedVaultKey, vaultKeyIv },
      select: vaultConfigSelect
    })
    return reply.send(config)
  })
}
