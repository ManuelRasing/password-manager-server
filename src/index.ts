import 'dotenv/config'
import Fastify from 'fastify'
import rateLimit from '@fastify/rate-limit'
import prisma from './lib/prisma'
import authPlugin from './plugins/auth'
import { credentialRoutes } from './routes/credentials'
import { backupRoutes } from './routes/backup'
import { vaultConfigRoutes } from './routes/vault-config'
import { adminRoutes } from './routes/admin'

const app = Fastify({
  logger: {
    level: process.env.LOG_LEVEL ?? 'info',
    // Never log auth headers or encrypted payloads
    redact: [
      'req.headers["x-signature"]',
      'req.headers["x-timestamp"]',
      'req.headers["x-username"]',
      'req.headers["x-admin-key"]',
      'req.body.encryptedPayload',
      'req.body.iv'
    ]
  }
})

/**
 * One-shot migration: if no users exist yet but legacy single-tenant data does,
 * create an "admin" user owning the existing API_KEY and assign all "migrating"
 * rows to it. Idempotent — runs only when the User table is empty.
 */
async function bootstrapAdminIfNeeded() {
  const userCount = await prisma.user.count()
  if (userCount > 0) return

  const apiKey = process.env.API_KEY
  if (!apiKey) {
    app.log.warn('[bootstrap] No users and no API_KEY — skipping admin bootstrap')
    return
  }

  const admin = await prisma.user.create({
    data: { username: 'admin', apiKey }
  })

  const [credUpdate, vaultUpdate] = await prisma.$transaction([
    prisma.credential.updateMany({
      where: { userId: 'migrating' },
      data:  { userId: admin.id }
    }),
    prisma.vaultConfig.updateMany({
      where: { userId: 'migrating' },
      data:  { userId: admin.id }
    })
  ])

  app.log.info(
    `[bootstrap] Created admin user (id=${admin.id}). ` +
    `Reassigned ${credUpdate.count} credentials and ${vaultUpdate.count} vault config(s). ` +
    `Update the mobile Settings: Username = "admin", API Key = your existing API_KEY.`
  )
}

async function start() {
  await bootstrapAdminIfNeeded()

  await app.register(rateLimit, {
    max: 20,
    timeWindow: '1 minute',
    errorResponseBuilder: (_req, context) => ({
      error: 'Too many requests',
      retryAfter: context.after
    })
  })

  // Public route — no auth required
  app.get('/health', async () => ({ status: 'ok', timestamp: new Date().toISOString() }))

  // Admin scope — secured by ADMIN_KEY (separate from per-user API keys)
  app.register(async (adminScope) => {
    adminScope.register(adminRoutes, { prefix: '/admin' })
  })

  // Authenticated scope — all routes below require valid HMAC signature + X-Username
  app.register(async (protectedScope) => {
    protectedScope.register(authPlugin)
    protectedScope.register(credentialRoutes,  { prefix: '/credentials' })
    protectedScope.register(backupRoutes,      { prefix: '/backup' })
    protectedScope.register(vaultConfigRoutes, { prefix: '/vault-config' })
  })

  const port = parseInt(process.env.PORT ?? '3000', 10)
  await app.listen({ port, host: '0.0.0.0' })
}

start().catch(err => {
  app.log.error(err)
  process.exit(1)
})
