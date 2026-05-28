import { FastifyInstance } from 'fastify'
import prisma from '../lib/prisma'
import { VaultConfigBody } from '../types'

// There is always exactly one vault config per deployment.
const SINGLETON_ID = 'vault'

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

export async function vaultConfigRoutes(app: FastifyInstance) {
  // GET /vault-config
  // Returns the stored vault config, or 404 if the vault has never been set up.
  app.get('/', async (_req, reply) => {
    const config = await prisma.vaultConfig.findUnique({
      where: { id: SINGLETON_ID }
    })
    if (!config) {
      return reply.status(404).send({ error: 'Vault not configured' })
    }
    return reply.send({
      masterSalt:        config.masterSalt,
      encryptedVaultKey: config.encryptedVaultKey,
      vaultKeyIv:        config.vaultKeyIv
    })
  })

  // PUT /vault-config
  // Creates or replaces the vault config (upsert).
  // Called on first setup and whenever the master password is changed.
  app.put<{ Body: VaultConfigBody }>('/', {
    schema: { body: bodySchema }
  }, async (req, reply) => {
    const { masterSalt, encryptedVaultKey, vaultKeyIv } = req.body
    const config = await prisma.vaultConfig.upsert({
      where:  { id: SINGLETON_ID },
      update: { masterSalt, encryptedVaultKey, vaultKeyIv },
      create: { id: SINGLETON_ID, masterSalt, encryptedVaultKey, vaultKeyIv }
    })
    return reply.send({
      masterSalt:        config.masterSalt,
      encryptedVaultKey: config.encryptedVaultKey,
      vaultKeyIv:        config.vaultKeyIv
    })
  })
}
